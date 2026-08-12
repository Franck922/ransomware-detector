"""
Ingestion des événements Sysmon et file de commandes des agents.

Changements structurels :
  - les endpoints exigent le token d'agent (auparavant totalement ouverts :
    n'importe qui sur le réseau pouvait empoisonner la baseline ou dépiler les
    commandes KILL destinées à un poste compromis) ;
  - chaque fenêtre de features fermée est persistée dans `metrics`, ce qui
    alimente le graphique partagé du dashboard au lieu de constantes JSX ;
  - les alertes et les commandes de réponse vont en base, pas dans des listes
    Python : elles survivent au redémarrage et sont vues par tous les analystes ;
  - le pipeline lourd tourne dans un thread worker pour ne pas bloquer la boucle
    d'événements pendant l'inférence du modèle.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from api import audit_service
from api.audit_service import AuditAction
from api.config import settings
from api.db import get_db
from api.detection import IngestResult, engine
from api.models import (
    Alert,
    AlertStatus,
    Command,
    CommandAction,
    CommandOrigin,
    CommandStatus,
    Exclusion,
    Machine,
    Metric,
)
from api.realtime import (
    CHANNEL_ALERTS,
    CHANNEL_AUDIT,
    CHANNEL_COMMANDS,
    CHANNEL_MACHINES,
    CHANNEL_METRICS,
    hub,
)
from api.schemas import CommandAckRequest, IngestPayload, ResponseMessage
from api.security import require_agent_token

logger = logging.getLogger("api.ingest")

router = APIRouter(tags=["ingest"])

# Les exclusions changent rarement : on évite une lecture base par lot ingéré,
# tout en garantissant qu'une modification devient effective en quelques secondes.
_EXCLUSIONS_TTL_SECONDS = 10
_exclusions_loaded_at = 0.0


async def _refresh_exclusions(db: AsyncSession) -> None:
    global _exclusions_loaded_at
    now = time.monotonic()
    if now - _exclusions_loaded_at < _EXCLUSIONS_TTL_SECONDS:
        return

    rows = await db.execute(
        select(Exclusion.type, Exclusion.path).where(Exclusion.enabled.is_(True))
    )
    engine.set_exclusions([{"type": t, "path": p} for t, p in rows.all()])
    _exclusions_loaded_at = now


def _severity_from_score(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


async def _upsert_machine(db: AsyncSession, result: IngestResult) -> int:
    """
    Enregistre ou met à jour la machine émettrice et retourne sa clé primaire.
    L'ancienne API se contentait de journaliser le machine_id sans le stocker.
    """
    now = datetime.now(timezone.utc)
    values: Dict[str, Any] = {
        "machine_id": result.machine_id,
        "hostname": result.hostname or result.machine_id,
        "last_seen_at": now,
        "events_received": result.received,
    }
    if result.ip_address:
        values["ip_address"] = result.ip_address
    if result.os_name:
        values["os_name"] = result.os_name
    if result.agent_version:
        values["agent_version"] = result.agent_version

    update_set: Dict[str, Any] = {
        "last_seen_at": now,
        "events_received": Machine.__table__.c.events_received + result.received,
    }
    for field in ("hostname", "ip_address", "os_name", "agent_version"):
        if values.get(field):
            update_set[field] = values[field]

    stmt = (
        pg_insert(Machine)
        .values(**values)
        .on_conflict_do_update(index_elements=[Machine.machine_id], set_=update_set)
        .returning(Machine.id)
    )
    return int((await db.execute(stmt)).scalar_one())


def _write_forensic_report(payload: Dict[str, Any], machine_id: str) -> Optional[str]:
    """Artefact JSON conservé pour l'analyse hors ligne (volume ./reports)."""
    try:
        os.makedirs("reports", exist_ok=True)
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        process = payload.get("process") or "unknown"
        safe_process = "".join(c for c in process if c.isalnum() or c in "._-")
        filename = f"reports/{stamp}_{machine_id}_{safe_process}.json"
        with open(filename, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=4, ensure_ascii=False)
        return filename
    except Exception as exc:
        logger.error("Écriture du rapport forensics impossible : %s", exc)
        return None


async def _persist_result(
    db: AsyncSession, result: IngestResult, touch_machine: bool = True
) -> Tuple[int, int]:
    """
    Écrit métriques, alertes et commandes automatiques.
    Retourne (nb_alertes_créées, nb_commandes_créées).

    `touch_machine=False` pour l'évaluation d'une fenêtre inactive : celle-ci a
    précisément lieu parce que l'agent s'est tu, donc rafraîchir `last_seen_at`
    ferait apparaître en ligne un poste qui ne l'est plus.
    """
    if touch_machine:
        machine_pk = await _upsert_machine(db, result)
    else:
        machine_pk = await db.scalar(
            select(Machine.id).where(Machine.machine_id == result.machine_id)
        )
        if machine_pk is None:
            return 0, 0

    alerts_created = 0
    commands_created = 0
    now = datetime.now(timezone.utc)

    for window in result.windows:
        features = window.features

        db.add(
            Metric(
                machine_pk=machine_pk,
                bucket_at=now,
                window_seconds=10,
                files_created=int(features.get("nb_files_created", 0)),
                files_deleted=int(features.get("nb_files_deleted", 0)),
                files_renamed=int(features.get("nb_files_renamed", 0)),
                unique_extensions=int(features.get("nb_unique_extensions", 0)),
                entropy_filenames=float(features.get("entropy_filenames", 0.0)),
                processes_created=int(features.get("nb_processes_created", 0)),
                child_processes=int(features.get("nb_child_processes", 0)),
                process_depth=int(features.get("process_depth", 0)),
                connections=int(features.get("nb_connections", 0)),
                unique_ips=int(features.get("nb_unique_ips", 0)),
                external_connections=int(features.get("nb_external_connections", 0)),
                dns_queries=int(features.get("nb_dns_queries", 0)),
                risk_score=window.risk_score,
                is_alert=window.is_alert,
                baseline_trained=window.baseline_trained,
            )
        )

        if not window.is_alert:
            continue

        suspect = window.top_suspect
        if not suspect:
            logger.warning(
                "[%s] Alerte %s sans processus suspect identifiable",
                result.machine_id,
                window.detection_source,
            )
            continue

        # Score normalisé sur 100 : le compteur d'activité du processus suspect
        # n'est pas borné et ne peut donc pas servir de niveau de gravité.
        score = window.alert_score
        stats = suspect.get("stats", {}) or {}

        reasons: List[str] = []
        if stats.get("files_created"):
            reasons.append(f"{stats['files_created']} fichiers créés")
        if stats.get("files_deleted"):
            reasons.append(f"{stats['files_deleted']} fichiers supprimés")
        if float(stats.get("entropy", 0) or 0) > 5.0:
            reasons.append(f"Entropie élevée des noms de fichiers ({stats['entropy']})")
        if stats.get("network_connections"):
            reasons.append(f"{stats['network_connections']} connexions réseau")
        if stats.get("processes_created"):
            reasons.append(f"{stats['processes_created']} processus enfants créés")
        reasons.extend(window.triggered_rules)

        payload = {
            "action": "KILL",
            "machine_id": result.machine_id,
            "pid": suspect.get("pid"),
            "process": suspect.get("process_name"),
            "parent": suspect.get("parent_name", "unknown"),
            "parent_pid": suspect.get("parent_pid"),
            "score": score,
            "confidence": "HIGH" if score >= 80 else ("MEDIUM" if score >= 50 else "LOW"),
            "detection_source": window.detection_source,
            "rules_score": round(window.risk_score * 100),
            "ml_probability": (
                round(window.ml_probability, 4) if window.ml_probability is not None else None
            ),
            # Conservé comme élément de preuve, mais dissocié du score de gravité.
            "activity_points": int(suspect.get("score", 0)),
            "stats": stats,
            "reasons": reasons,
            "window_features": {k: v for k, v in features.items() if not isinstance(v, dict)},
        }

        alert = Alert(
            machine_pk=machine_pk,
            detected_at=now,
            source=window.detection_source,
            severity=_severity_from_score(score),
            score=score,
            confidence=payload["confidence"],
            pid=suspect.get("pid"),
            process_name=suspect.get("process_name"),
            parent_name=suspect.get("parent_name"),
            parent_pid=suspect.get("parent_pid"),
            reasons=reasons,
            payload=payload,
            status=AlertStatus.NEW.value,
        )
        db.add(alert)
        await db.flush()
        alerts_created += 1

        if score >= settings.auto_kill_score_threshold:
            logger.error(
                "[%s] ALERTE CRITIQUE (score %s, %s) — KILL automatique du PID %s",
                result.machine_id,
                score,
                window.detection_source,
                suspect.get("pid"),
            )
            report_path = _write_forensic_report(payload, result.machine_id)

            command = Command(
                machine_pk=machine_pk,
                alert_id=alert.id,
                action=CommandAction.KILL.value,
                target_pid=suspect.get("pid"),
                payload=payload,
                status=CommandStatus.PENDING.value,
                origin=CommandOrigin.AUTO.value,
                created_by=None,
            )
            db.add(command)
            await db.flush()
            commands_created += 1

            # Une réponse active automatique doit être auditée comme une action
            # d'analyste : c'est une exigence de traçabilité SOC.
            await audit_service.record_engine_action(
                db,
                action=AuditAction.AUTO_KILL,
                target=f"{result.machine_id}:pid={suspect.get('pid')}",
                details={
                    "alert_id": alert.id,
                    "command_id": command.id,
                    "score": score,
                    "source": window.detection_source,
                    "process": suspect.get("process_name"),
                    "report": report_path,
                },
            )
        else:
            await audit_service.record_engine_action(
                db,
                action=AuditAction.AUTO_ALERT,
                target=f"{result.machine_id}:pid={suspect.get('pid')}",
                details={
                    "alert_id": alert.id,
                    "score": score,
                    "source": window.detection_source,
                    "severity": alert.severity,
                },
            )

    return alerts_created, commands_created


async def persist_and_notify(
    db: AsyncSession, result: IngestResult, touch_machine: bool = True
) -> Tuple[int, int]:
    """
    Écrit le résultat d'analyse et notifie les dashboards.

    Partagé par l'ingestion et par la tâche de fond qui évalue les fenêtres
    inactives, afin qu'une alerte ait exactement les mêmes effets — persistance,
    audit, réponse automatique, temps réel — quelle que soit son origine.
    """
    alerts_created, commands_created = await _persist_result(db, result, touch_machine)
    await db.commit()

    channels = [CHANNEL_MACHINES]
    if result.windows:
        channels.append(CHANNEL_METRICS)
    if alerts_created:
        channels.extend([CHANNEL_ALERTS, CHANNEL_AUDIT])
    if commands_created:
        channels.append(CHANNEL_COMMANDS)
    await hub.broadcast_many(channels)

    return alerts_created, commands_created


async def _ingest(db: AsyncSession, machine_id: str, batch: List[Dict[str, Any]]) -> IngestResult:
    await _refresh_exclusions(db)

    # Pipeline synchrone et coûteux (parsing, agrégation, inférence RF) : exécuté
    # hors de la boucle d'événements pour ne pas geler les autres requêtes.
    result: IngestResult = await run_in_threadpool(engine.process_batch, machine_id, batch)

    alerts_created, commands_created = await persist_and_notify(db, result)

    logger.info(
        "[%s] %d/%d événements pertinents, %d fenêtre(s), %d alerte(s), %d commande(s)",
        machine_id,
        result.relevant,
        result.received,
        len(result.windows),
        alerts_created,
        commands_created,
    )
    return result


# ─────────────────────────────────────────────────────────────────────
# Endpoints d'ingestion
# ─────────────────────────────────────────────────────────────────────


@router.post("/ingest", response_model=ResponseMessage)
async def ingest_logs(
    payload: IngestPayload,
    _: str = Depends(require_agent_token),
    db: AsyncSession = Depends(get_db),
):
    result = await _ingest(db, payload.machine_id, payload.batch)
    return ResponseMessage(
        status="success",
        message="Lot ingéré et analysé",
        processed_events=result.relevant,
    )


@router.post("/_bulk")
async def receive_winlogbeat_bulk(
    request: Request,
    _: str = Depends(require_agent_token),
    db: AsyncSession = Depends(get_db),
):
    """
    Simule l'API Bulk d'Elasticsearch pour recevoir directement les logs
    Winlogbeat, sans script intermédiaire sur la VM surveillée.
    """
    body = await request.body()

    if request.headers.get("content-encoding") == "gzip":
        try:
            body = gzip.decompress(body)
        except Exception as exc:
            logger.error("Décompression gzip impossible : %s", exc)

    events: List[Dict[str, Any]] = []
    # Le NDJSON bulk alterne une ligne d'action et une ligne de document.
    lines = body.decode("utf-8", errors="replace").split("\n")
    for index in range(1, len(lines), 2):
        line = lines[index].strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if events:
        # Le nom réel de la machine est extrait des événements (host.name /
        # winlog.computer_name) plutôt que figé sur une valeur générique.
        machine_id = _machine_id_from_events(events)
        await _ingest(db, machine_id, events)

    return {"errors": False, "items": [{"create": {"status": 201}} for _ in events]}


def _machine_id_from_events(events: List[Dict[str, Any]]) -> str:
    for event in events:
        if not isinstance(event, dict):
            continue
        host = event.get("host") or {}
        if isinstance(host, dict) and host.get("name"):
            return str(host["name"])
        winlog = event.get("winlog") or {}
        if isinstance(winlog, dict) and winlog.get("computer_name"):
            return str(winlog["computer_name"])
    return "unknown-host"


# ─────────────────────────────────────────────────────────────────────
# File de commandes consommée par l'agent PowerShell
# ─────────────────────────────────────────────────────────────────────


@router.get("/agent/commands")
async def get_agent_commands(
    machine_id: Optional[str] = None,
    _: str = Depends(require_agent_token),
    db: AsyncSession = Depends(get_db),
):
    """
    Retourne la commande la plus ancienne en attente pour cette machine.

    La commande passe en `sent` mais n'est pas supprimée : elle reste visible
    dans le journal des réponses et l'agent doit l'acquitter. Dans la version
    précédente, `pending_commands.pop(0)` détruisait l'ordre sans trace et sans
    filtrage par machine — un poste pouvait recevoir le KILL destiné à un autre.
    """
    query = (
        select(Command, Machine.machine_id)
        .outerjoin(Machine, Machine.id == Command.machine_pk)
        .where(Command.status == CommandStatus.PENDING.value)
        .order_by(Command.created_at, Command.id)
        .limit(1)
    )
    if machine_id:
        query = query.where(Machine.machine_id == machine_id)

    row = (await db.execute(query)).first()
    if row is None:
        return {"action": "NONE"}

    command, resolved_machine = row
    command.status = CommandStatus.SENT.value
    command.sent_at = datetime.now(timezone.utc)
    await db.commit()
    await hub.broadcast(CHANNEL_COMMANDS, {"command_id": command.id, "action": "sent"})

    return {
        "command_id": command.id,
        "action": command.action,
        "target": command.target_pid if command.action == CommandAction.KILL.value else "NETWORK",
        "pid": command.target_pid,
        "machine_id": resolved_machine,
        "payload": command.payload or {},
    }


@router.post("/agent/commands/ack")
async def ack_agent_command(
    payload: CommandAckRequest,
    _: str = Depends(require_agent_token),
    db: AsyncSession = Depends(get_db),
):
    """Acquittement par l'agent : c'est ce qui rend la file fiable."""
    command = await db.get(Command, payload.command_id)
    if command is None:
        return {"status": "unknown_command"}

    command.status = (
        CommandStatus.ACKED.value if payload.success else CommandStatus.FAILED.value
    )
    command.acked_at = datetime.now(timezone.utc)
    command.result = {"success": payload.success, "message": payload.message}

    machine_id = await db.scalar(
        select(Machine.machine_id).where(Machine.id == command.machine_pk)
    )
    await audit_service.record_engine_action(
        db,
        action=AuditAction.COMMAND_ACKED,
        target=f"{machine_id}:command={command.id}",
        details={
            "action": command.action,
            "success": payload.success,
            "message": payload.message,
        },
    )
    await db.commit()
    await hub.broadcast_many([CHANNEL_COMMANDS, CHANNEL_AUDIT])

    return {"status": "success", "command_status": command.status}


# ─────────────────────────────────────────────────────────────────────
# Compatibilité Winlogbeat / sortie Elasticsearch
# ─────────────────────────────────────────────────────────────────────


@router.get("/", include_in_schema=False)
def elasticsearch_root():
    """Réponse imitant Elasticsearch 8.x, attendue par Winlogbeat au démarrage."""
    return {
        "name": "ransomware-detector",
        "cluster_name": "ransomware-detector",
        "cluster_uuid": "123456789",
        "version": {
            "number": "8.0.0",
            "build_flavor": "default",
            "build_type": "tar",
            "build_hash": "12345",
            "build_date": "2026-01-01T00:00:00.000Z",
            "build_snapshot": False,
            "lucene_version": "9.0.0",
            "minimum_wire_compatibility_version": "7.17.0",
            "minimum_index_compatibility_version": "7.0.0",
        },
        "tagline": "You Know, for Search",
    }


@router.get("/_license", include_in_schema=False)
def elasticsearch_license():
    return {"license": {"status": "active", "type": "basic"}}


@router.get("/_xpack", include_in_schema=False)
def elasticsearch_xpack():
    return {"features": {"monitoring": {"enabled": False}}}


@router.api_route(
    "/_{path_name:path}",
    methods=["GET", "POST", "PUT", "DELETE", "HEAD"],
    include_in_schema=False,
)
async def elasticsearch_stub(path_name: str):
    """
    Répond OK aux sondages annexes de Winlogbeat (ILM, templates, pipelines).

    Volontairement restreint aux chemins commençant par « _ ». L'ancienne route
    attrape-tout `/{path_name:path}` masquait toutes les 404 de l'API en
    renvoyant `{"acknowledged": true}`, ce qui rendait le débogage impossible.
    """
    return {"acknowledged": True}
