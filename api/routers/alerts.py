"""
Consultation et cycle de vie des alertes.

L'ancien endpoint retournait la totalité de l'historique sans pagination, sans
filtre et sans notion de prise en charge. Le statut et l'affectation permettent
maintenant à plusieurs analystes de se répartir les alertes en voyant en temps
réel ce que font les autres.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from api import audit_service
from api.audit_service import AuditAction
from api.db import get_db
from api.models import Alert, AlertStatus, Machine, User
from api.realtime import CHANNEL_ALERTS, hub
from api.schemas import AlertListOut, AlertOut, AlertStatusUpdate
from api.security import CurrentUser, require_n1

router = APIRouter(prefix="/alerts", tags=["alerts"])


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


@router.get("", response_model=AlertListOut)
async def list_alerts(
    status_filter: Optional[AlertStatus] = Query(default=None, alias="status"),
    machine_id: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None, pattern="^(low|medium|high)$"),
    open_only: bool = Query(default=False),
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
        open_states = [AlertStatus.NEW.value, AlertStatus.ACKNOWLEDGED.value, AlertStatus.IN_PROGRESS.value]
        query = query.where(Alert.status.in_(open_states))
        count_query = count_query.where(Alert.status.in_(open_states))

    if machine_id:
        query = query.where(Machine.machine_id == machine_id)
        count_query = count_query.where(
            Alert.machine_pk.in_(select(Machine.id).where(Machine.machine_id == machine_id))
        )

    if severity:
        query = query.where(Alert.severity == severity)
        count_query = count_query.where(Alert.severity == severity)

    total = await db.scalar(count_query) or 0

    rows = await db.execute(
        query.order_by(Alert.detected_at.desc(), Alert.id.desc()).limit(limit).offset(offset)
    )

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

    alert, machine_id, assignee_email = row
    return _to_alert_out(alert, machine_id, assignee_email)


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
