"""
Consultation et cycle de vie des alertes.

L'ancien endpoint retournait la totalité de l'historique sans pagination, sans
filtre et sans notion de prise en charge. Le statut et l'affectation permettent
maintenant à plusieurs analystes de se répartir les alertes en voyant en temps
réel ce que font les autres.

L'endpoint /investigation reconstruit une chronologie et des alertes corrélées
à partir des données déjà persistées (pas de télémétrie Sysmon brute stockée).
Le pack /contain regroupe prise en charge + kill + isolation en une seule action
N2 pour réduire le temps de confinement.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from api import audit_service
from api.audit_service import AuditAction
from api.db import get_db
from api.models import (
    Alert,
    AlertStatus,
    Command,
    CommandAction,
    CommandOrigin,
    CommandStatus,
    Machine,
    User,
)
from api.realtime import (
    CHANNEL_ALERTS,
    CHANNEL_AUDIT,
    CHANNEL_COMMANDS,
    CHANNEL_MACHINES,
    hub,
)
from api.schemas import (
    AlertInvestigationOut,
    AlertListOut,
    AlertOut,
    AlertStatusUpdate,
    ContainOut,
    ContainRequest,
    PlaybookStepOut,
    TimelineEventOut,
)
from api.security import CurrentUser, require_n1, require_n2

router = APIRouter(prefix="/alerts", tags=["alerts"])

OPEN_STATES = (
    AlertStatus.NEW.value,
    AlertStatus.ACKNOWLEDGED.value,
    AlertStatus.IN_PROGRESS.value,
)

CORRELATION_WINDOW_MINUTES = 15


def _to_alert_out(alert: Alert, machine_id: Optional[str], assignee_email: Optional[str]) -> AlertOut:
    return AlertOut(
        id=alert.id,
        detected_at=alert.detected_at,
        machine_id=machine_id,
        source=alert.source,
        severity=alert.severity,
        score=alert.score,
        confidence=alert.confidence,
        pid=alert.pid,
        process_name=alert.process_name,
        parent_name=alert.parent_name,
        parent_pid=alert.parent_pid,
        reasons=alert.reasons or [],
        payload=alert.payload or {},
        status=alert.status,
        assigned_to=alert.assigned_to,
        assigned_to_email=assignee_email,
        acknowledged_at=alert.acknowledged_at,
        closed_at=alert.closed_at,
        resolution_note=alert.resolution_note,
    )


async def _load_alert_row(
    db: AsyncSession, alert_id: int
) -> Tuple[Alert, Optional[str], Optional[str]]:
    assignee = aliased(User)
    row = (
        await db.execute(
            select(Alert, Machine.machine_id, assignee.email)
            .outerjoin(Machine, Machine.id == Alert.machine_pk)
            .outerjoin(assignee, assignee.id == Alert.assigned_to)
            .where(Alert.id == alert_id)
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alerte introuvable")
    return row


def _build_timeline(
    alert: Alert,
    machine_id: Optional[str],
    related: List[AlertOut],
    commands: List[Command],
) -> List[TimelineEventOut]:
    """
    Chronologie d'attaque approximative à partir de la fiche d'alerte.

    On ne stocke pas chaque événement Sysmon brut : on reconstruit une séquence
    exploitable pour un analyste à partir des preuves déjà persistées
    (parent, stats de fenêtre, motifs, commandes, alertes voisines).
    """
    events: List[TimelineEventOut] = []
    detected = alert.detected_at
    payload = alert.payload or {}
    stats = payload.get("stats") or {}

    if alert.parent_name:
        events.append(
            TimelineEventOut(
                at=detected - timedelta(seconds=8),
                kind="parent",
                title=f"Processus parent observé : {alert.parent_name}",
                detail=(
                    f"PID {alert.parent_pid} sur {machine_id}"
                    if alert.parent_pid
                    else f"Sur {machine_id or 'terminal inconnu'}"
                ),
                tone="muted",
            )
        )

    if stats.get("network_connections"):
        events.append(
            TimelineEventOut(
                at=detected - timedelta(seconds=6),
                kind="network",
                title="Activité réseau suspecte",
                detail=f"{stats['network_connections']} connexion(s) dans la fenêtre d'analyse",
                tone="warning",
            )
        )

    if stats.get("processes_created"):
        events.append(
            TimelineEventOut(
                at=detected - timedelta(seconds=4),
                kind="child_process",
                title="Création de processus enfants",
                detail=f"{stats['processes_created']} processus enfant(s) observé(s)",
                tone="warning",
            )
        )

    files_created = int(stats.get("files_created") or 0)
    if files_created:
        events.append(
            TimelineEventOut(
                at=detected - timedelta(seconds=2),
                kind="encryption",
                title="Création massive de fichiers",
                detail=f"{files_created} fichier(s) créés — signature typique de chiffrement",
                tone="danger",
            )
        )

    entropy = float(stats.get("entropy") or 0)
    if entropy > 5.0:
        events.append(
            TimelineEventOut(
                at=detected - timedelta(seconds=1),
                kind="entropy",
                title="Entropie élevée des noms de fichiers",
                detail=f"Entropie de Shannon = {entropy:.3f} (seuil typique : 5.0)",
                tone="danger",
            )
        )

    events.append(
        TimelineEventOut(
            at=detected,
            kind="detection",
            title=f"Alerte #{alert.id} levée — score {alert.score}/100",
            detail=(
                f"Source {alert.source} · confiance {alert.confidence}"
                + (f" · PID {alert.pid}" if alert.pid else "")
            ),
            tone="danger",
            alert_id=alert.id,
        )
    )

    for reason in (alert.reasons or [])[:6]:
        events.append(
            TimelineEventOut(
                at=detected,
                kind="reason",
                title=reason,
                detail="Motif retenu par le moteur",
                tone="muted",
                alert_id=alert.id,
            )
        )

    for sibling in related:
        if sibling.id == alert.id:
            continue
        events.append(
            TimelineEventOut(
                at=sibling.detected_at,
                kind="related_alert",
                title=f"Alerte corrélée #{sibling.id} — {sibling.process_name or 'processus'}",
                detail=f"Score {sibling.score} · {sibling.source} · même terminal / processus proche",
                tone="warning",
                alert_id=sibling.id,
            )
        )

    if alert.acknowledged_at:
        events.append(
            TimelineEventOut(
                at=alert.acknowledged_at,
                kind="assignment",
                title="Prise en charge par un analyste",
                detail="Statut passé en cours de traitement",
                tone="info",
                alert_id=alert.id,
            )
        )

    for command in commands:
        stamp = command.created_at
        label = {
            CommandAction.KILL.value: "Ordre d'arrêt de processus",
            CommandAction.ISOLATE.value: "Ordre d'isolation réseau",
            CommandAction.UNISOLATE.value: "Ordre de levée d'isolation",
        }.get(command.action, command.action)
        events.append(
            TimelineEventOut(
                at=stamp,
                kind="command",
                title=f"{label} ({command.status})",
                detail=(
                    f"Origine {command.origin}"
                    + (f" · PID {command.target_pid}" if command.target_pid else "")
                ),
                tone="info" if command.status != CommandStatus.FAILED.value else "danger",
                command_id=command.id,
                alert_id=alert.id,
            )
        )
        if command.acked_at:
            success = (command.result or {}).get("success")
            events.append(
                TimelineEventOut(
                    at=command.acked_at,
                    kind="command_ack",
                    title=(
                        "Commande exécutée par l'agent"
                        if success is not False
                        else "Échec d'exécution côté agent"
                    ),
                    detail=(command.result or {}).get("message"),
                    tone="success" if success is not False else "danger",
                    command_id=command.id,
                )
            )

    if alert.closed_at:
        events.append(
            TimelineEventOut(
                at=alert.closed_at,
                kind="closure",
                title=(
                    "Clôturée comme faux positif"
                    if alert.status == AlertStatus.FALSE_POSITIVE.value
                    else "Alerte clôturée"
                ),
                detail=alert.resolution_note,
                tone="success",
                alert_id=alert.id,
            )
        )

    events.sort(key=lambda item: (item.at, item.kind))
    return events


def _build_playbook(alert: Alert, machine: Optional[Machine], commands: List[Command]) -> List[PlaybookStepOut]:
    has_kill = any(
        c.action == CommandAction.KILL.value
        and c.status
        in (
            CommandStatus.PENDING.value,
            CommandStatus.SENT.value,
            CommandStatus.ACKED.value,
        )
        for c in commands
    )
    has_isolate = (machine.is_isolated if machine else False) or any(
        c.action == CommandAction.ISOLATE.value
        and c.status
        in (
            CommandStatus.PENDING.value,
            CommandStatus.SENT.value,
            CommandStatus.ACKED.value,
        )
        for c in commands
    )
    closed = alert.status in (AlertStatus.CLOSED.value, AlertStatus.FALSE_POSITIVE.value)

    return [
        PlaybookStepOut(
            id="assign",
            label="Prendre l'alerte en charge",
            done=alert.assigned_to is not None
            or alert.status != AlertStatus.NEW.value,
            hint="Évite que deux analystes traitent le même incident en parallèle",
        ),
        PlaybookStepOut(
            id="kill",
            label="Arrêter le processus suspect",
            done=has_kill or alert.pid is None,
            required_role="N2",
            hint="Niveau N2 requis · frappe ciblée par PID",
        ),
        PlaybookStepOut(
            id="isolate",
            label="Isoler le terminal du réseau",
            done=has_isolate,
            required_role="N2",
            hint="Coupe la propagation tout en gardant le canal vers l'API",
        ),
        PlaybookStepOut(
            id="qualify",
            label="Qualifier et clôturer l'incident",
            done=closed,
            hint="Ajouter une note de résolution pour le journal d'audit",
        ),
    ]


@router.get("", response_model=AlertListOut)
async def list_alerts(
    status_filter: Optional[AlertStatus] = Query(default=None, alias="status"),
    machine_id: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None, pattern="^(low|medium|high)$"),
    open_only: bool = Query(default=False),
    unassigned_only: bool = Query(
        default=False, description="File de triage : alertes sans analyste affecté"
    ),
    sort: str = Query(
        default="detected_at",
        pattern="^(detected_at|score)$",
        description="Tri de la file (score utile pour le triage SOC)",
    ),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    assignee = aliased(User)
    query = (
        select(Alert, Machine.machine_id, assignee.email)
        .outerjoin(Machine, Machine.id == Alert.machine_pk)
        .outerjoin(assignee, assignee.id == Alert.assigned_to)
    )
    count_query = select(func.count()).select_from(Alert)

    if status_filter is not None:
        query = query.where(Alert.status == status_filter.value)
        count_query = count_query.where(Alert.status == status_filter.value)

    if open_only:
        query = query.where(Alert.status.in_(OPEN_STATES))
        count_query = count_query.where(Alert.status.in_(OPEN_STATES))

    if unassigned_only:
        query = query.where(Alert.assigned_to.is_(None))
        count_query = count_query.where(Alert.assigned_to.is_(None))

    if machine_id:
        query = query.where(Machine.machine_id == machine_id)
        count_query = count_query.where(
            Alert.machine_pk.in_(select(Machine.id).where(Machine.machine_id == machine_id))
        )

    if severity:
        query = query.where(Alert.severity == severity)
        count_query = count_query.where(Alert.severity == severity)

    total = await db.scalar(count_query) or 0

    if sort == "score":
        ordering = (Alert.score.desc(), Alert.detected_at.desc(), Alert.id.desc())
    else:
        ordering = (Alert.detected_at.desc(), Alert.id.desc())

    rows = await db.execute(query.order_by(*ordering).limit(limit).offset(offset))

    return AlertListOut(
        items=[_to_alert_out(alert, mid, email) for alert, mid, email in rows.all()],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(
    alert_id: int,
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    alert, machine_id, assignee_email = await _load_alert_row(db, alert_id)
    return _to_alert_out(alert, machine_id, assignee_email)


@router.get("/{alert_id}/investigation", response_model=AlertInvestigationOut)
async def investigate_alert(
    alert_id: int,
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    """
    Dossier d'investigation pour un analyste SOC.

    Regroupe chronologie, alertes corrélées (même machine / même PID ou
    processus dans une fenêtre de 15 minutes) et état du playbook de réponse.
    """
    alert, machine_id, assignee_email = await _load_alert_row(db, alert_id)
    machine = await db.get(Machine, alert.machine_pk) if alert.machine_pk else None

    window_start = alert.detected_at - timedelta(minutes=CORRELATION_WINDOW_MINUTES)
    window_end = alert.detected_at + timedelta(minutes=CORRELATION_WINDOW_MINUTES)

    related_items: List[AlertOut] = []
    if alert.machine_pk is not None:
        identity_filters = []
        if alert.pid is not None:
            identity_filters.append(Alert.pid == alert.pid)
        if alert.process_name:
            identity_filters.append(Alert.process_name == alert.process_name)
        if alert.parent_pid is not None:
            identity_filters.append(Alert.parent_pid == alert.parent_pid)

        related_query = (
            select(Alert, Machine.machine_id, User.email)
            .outerjoin(Machine, Machine.id == Alert.machine_pk)
            .outerjoin(User, User.id == Alert.assigned_to)
            .where(
                Alert.machine_pk == alert.machine_pk,
                Alert.id != alert.id,
                Alert.detected_at >= window_start,
                Alert.detected_at <= window_end,
            )
            .order_by(Alert.detected_at.asc(), Alert.id.asc())
            .limit(25)
        )
        if identity_filters:
            related_query = related_query.where(or_(*identity_filters))

        related_rows = (await db.execute(related_query)).all()
        related_items = [
            _to_alert_out(item, mid, email) for item, mid, email in related_rows
        ]

    commands: List[Command] = []
    if alert.machine_pk is not None:
        cmd_rows = await db.scalars(
            select(Command)
            .where(
                Command.machine_pk == alert.machine_pk,
                or_(
                    Command.alert_id == alert.id,
                    and_(
                        Command.created_at >= window_start,
                        Command.created_at <= window_end + timedelta(minutes=30),
                    ),
                ),
            )
            .order_by(Command.created_at.asc(), Command.id.asc())
            .limit(40)
        )
        commands = list(cmd_rows)

    alert_out = _to_alert_out(alert, machine_id, assignee_email)
    return AlertInvestigationOut(
        alert=alert_out,
        timeline=_build_timeline(alert, machine_id, related_items, commands),
        related=related_items,
        playbook=_build_playbook(alert, machine, commands),
        correlation_window_minutes=CORRELATION_WINDOW_MINUTES,
    )


@router.post("/{alert_id}/assign", response_model=AlertOut)
async def assign_alert(
    alert_id: int,
    user_id: Optional[int] = Query(
        default=None, description="Cible de l'affectation ; par défaut soi-même"
    ),
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alerte introuvable")

    target_id = user_id if user_id is not None else current.id
    target = await db.get(User, target_id)
    if target is None or not target.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Analyste cible invalide"
        )

    alert.assigned_to = target.id
    if alert.status == AlertStatus.NEW.value:
        alert.status = AlertStatus.IN_PROGRESS.value
        alert.acknowledged_at = datetime.now(timezone.utc)
        alert.acknowledged_by = current.id

    await audit_service.record_user_action(
        db,
        current,
        action=AuditAction.ALERT_ASSIGNED,
        target=f"alert:{alert.id}",
        details={"assigned_to": target.email, "status": alert.status},
    )
    await db.commit()
    await hub.broadcast(CHANNEL_ALERTS, {"alert_id": alert.id, "action": "assigned"})

    machine_id = await db.scalar(select(Machine.machine_id).where(Machine.id == alert.machine_pk))
    return _to_alert_out(alert, machine_id, target.email)


@router.post("/{alert_id}/contain", response_model=ContainOut)
async def contain_alert(
    alert_id: int,
    payload: ContainRequest,
    current: CurrentUser = Depends(require_n2),
    db: AsyncSession = Depends(get_db),
):
    """
    Pack de confinement SOC : prise en charge + arrêt du PID + isolation.

    Une seule action N2 pour réduire le délai entre détection et confinement,
    tout en laissant une trace d'audit unique et des commandes distinctes.
    """
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alerte introuvable")
    if alert.machine_pk is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Alerte sans terminal rattaché : confinement impossible",
        )

    machine = await db.get(Machine, alert.machine_pk)
    if machine is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Terminal introuvable")

    now = datetime.now(timezone.utc)
    alert.assigned_to = current.id
    if alert.status == AlertStatus.NEW.value:
        alert.status = AlertStatus.IN_PROGRESS.value
    if alert.acknowledged_at is None:
        alert.acknowledged_at = now
        alert.acknowledged_by = current.id
    if payload.note:
        alert.resolution_note = payload.note

    kill_command_id: Optional[int] = None
    isolate_command_id: Optional[int] = None
    already_isolated = machine.is_isolated

    if payload.kill and alert.pid:
        existing_kill = await db.scalar(
            select(Command).where(
                Command.machine_pk == machine.id,
                Command.action == CommandAction.KILL.value,
                Command.target_pid == alert.pid,
                Command.status.in_((CommandStatus.PENDING.value, CommandStatus.SENT.value)),
            )
        )
        if existing_kill is not None:
            kill_command_id = existing_kill.id
        else:
            kill_cmd = Command(
                machine_pk=machine.id,
                alert_id=alert.id,
                action=CommandAction.KILL.value,
                target_pid=alert.pid,
                payload={
                    "action": "KILL",
                    "pid": alert.pid,
                    "process": alert.process_name,
                    "reason": f"Containment pack sur alerte #{alert.id}",
                },
                status=CommandStatus.PENDING.value,
                origin=CommandOrigin.MANUAL.value,
                created_by=current.id,
            )
            db.add(kill_cmd)
            await db.flush()
            kill_command_id = kill_cmd.id

    if payload.isolate and not machine.is_isolated:
        isolate_cmd = Command(
            machine_pk=machine.id,
            alert_id=alert.id,
            action=CommandAction.ISOLATE.value,
            payload={
                "action": "ISOLATE",
                "target": "NETWORK",
                "reason": f"Containment pack sur alerte #{alert.id}",
            },
            status=CommandStatus.PENDING.value,
            origin=CommandOrigin.MANUAL.value,
            created_by=current.id,
        )
        db.add(isolate_cmd)
        machine.is_isolated = True
        await db.flush()
        isolate_command_id = isolate_cmd.id

    await audit_service.record_user_action(
        db,
        current,
        action=AuditAction.ALERT_CONTAINED,
        target=f"alert:{alert.id}",
        details={
            "machine_id": machine.machine_id,
            "pid": alert.pid,
            "kill_command_id": kill_command_id,
            "isolate_command_id": isolate_command_id,
            "already_isolated": already_isolated,
            "note": payload.note,
        },
    )
    await db.commit()
    await hub.broadcast_many(
        [CHANNEL_ALERTS, CHANNEL_COMMANDS, CHANNEL_MACHINES, CHANNEL_AUDIT]
    )

    parts = ["prise en charge"]
    if kill_command_id:
        parts.append(f"KILL PID {alert.pid}")
    if isolate_command_id:
        parts.append("isolation réseau")
    elif already_isolated and payload.isolate:
        parts.append("terminal déjà isolé")

    return ContainOut(
        alert=_to_alert_out(alert, machine.machine_id, current.email),
        kill_command_id=kill_command_id,
        isolate_command_id=isolate_command_id,
        already_isolated=already_isolated,
        message="Containment : " + " + ".join(parts),
    )


@router.patch("/{alert_id}/status", response_model=AlertOut)
async def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alerte introuvable")

    previous = alert.status
    now = datetime.now(timezone.utc)
    alert.status = payload.status.value

    if payload.status in (AlertStatus.ACKNOWLEDGED, AlertStatus.IN_PROGRESS):
        if alert.acknowledged_at is None:
            alert.acknowledged_at = now
            alert.acknowledged_by = current.id
        alert.closed_at = None
        alert.closed_by = None
    elif payload.status in (AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE):
        alert.closed_at = now
        alert.closed_by = current.id
    else:  # retour à NEW : on remet le cycle de vie à zéro
        alert.acknowledged_at = None
        alert.acknowledged_by = None
        alert.closed_at = None
        alert.closed_by = None

    if payload.resolution_note is not None:
        alert.resolution_note = payload.resolution_note

    await audit_service.record_user_action(
        db,
        current,
        action=AuditAction.ALERT_STATUS_CHANGED,
        target=f"alert:{alert.id}",
        details={
            "from": previous,
            "to": alert.status,
            "note": payload.resolution_note,
            "process": alert.process_name,
        },
    )
    await db.commit()
    await hub.broadcast(
        CHANNEL_ALERTS, {"alert_id": alert.id, "action": "status", "status": alert.status}
    )

    machine_id = await db.scalar(select(Machine.machine_id).where(Machine.id == alert.machine_pk))
    assignee_email = (
        await db.scalar(select(User.email).where(User.id == alert.assigned_to))
        if alert.assigned_to
        else None
    )
    return _to_alert_out(alert, machine_id, assignee_email)
