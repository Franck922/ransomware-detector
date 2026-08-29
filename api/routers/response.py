"""
Réponse active : arrêt de processus et isolation réseau.

Ces deux actions étaient auparavant accessibles sans aucune authentification
(`POST /response/kill/{pid}` et `POST /response/isolate`), et la commande était
empilée dans une liste Python en mémoire. Elles exigent maintenant le niveau N2,
sont tracées nominativement, et transitent par la table `commands` : persistées,
rattachées à une machine, et acquittées par l'agent.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api import audit_service
from api.audit_service import AuditAction
from api.db import get_db
from api.models import (
    Alert,
    Command,
    CommandAction,
    CommandOrigin,
    CommandStatus,
    Machine,
    User,
)
from api.realtime import CHANNEL_AUDIT, CHANNEL_COMMANDS, CHANNEL_MACHINES, hub
from api.schemas import CommandOut, IsolateRequest, KillRequest
from api.security import CurrentUser, require_n1, require_n2

router = APIRouter(prefix="/response", tags=["response"])


async def _require_machine(db: AsyncSession, machine_id: str) -> Machine:
    machine = await db.scalar(select(Machine).where(Machine.machine_id == machine_id))
    if machine is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Machine inconnue : {machine_id}",
        )
    return machine


def _to_command_out(
    command: Command, machine_id: Optional[str], author_email: Optional[str]
) -> CommandOut:
    return CommandOut(
        id=command.id,
        machine_id=machine_id,
        action=command.action,
        target_pid=command.target_pid,
        status=command.status,
        origin=command.origin,
        created_at=command.created_at,
        created_by_email=author_email,
        sent_at=command.sent_at,
        acked_at=command.acked_at,
        result=command.result,
        payload=command.payload or {},
    )


@router.post("/kill", response_model=CommandOut, status_code=status.HTTP_201_CREATED)
async def kill_process(
    payload: KillRequest,
    current: CurrentUser = Depends(require_n2),
    db: AsyncSession = Depends(get_db),
):
    machine = await _require_machine(db, payload.machine_id)

    alert: Optional[Alert] = None
    if payload.alert_id is not None:
        alert = await db.get(Alert, payload.alert_id)
        if alert is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Alerte de référence introuvable"
            )

    # Idempotence : inutile d'empiler deux ordres KILL identiques non traités
    # pour le même processus, l'agent ne pourrait en honorer qu'un.
    existing = await db.scalar(
        select(Command).where(
            Command.machine_pk == machine.id,
            Command.action == CommandAction.KILL.value,
            Command.target_pid == payload.pid,
            Command.status.in_((CommandStatus.PENDING.value, CommandStatus.SENT.value)),
        )
    )
    if existing is not None:
        # L'ordre n'est pas dupliqué, mais l'intention de l'analyste doit être
        # tracée : un audit ne consigne pas seulement les changements d'état.
        await audit_service.record_user_action(
            db,
            current,
            action=AuditAction.RESPONSE_KILL,
            target=f"{machine.machine_id}:pid={payload.pid}",
            details={
                "command_id": existing.id,
                "deduplicated": True,
                "existing_origin": existing.origin,
                "existing_status": existing.status,
                "reason": payload.reason,
            },
        )
        await db.commit()
        await hub.broadcast(CHANNEL_AUDIT)
        return _to_command_out(existing, machine.machine_id, current.email)

    command = Command(
        machine_pk=machine.id,
        alert_id=alert.id if alert else None,
        action=CommandAction.KILL.value,
        target_pid=payload.pid,
        payload={
            "action": "KILL",
            "pid": payload.pid,
            "process": alert.process_name if alert else None,
            "reason": payload.reason,
        },
        status=CommandStatus.PENDING.value,
        origin=CommandOrigin.MANUAL.value,
        created_by=current.id,
    )
    db.add(command)
    await db.flush()

    await audit_service.record_user_action(
        db,
        current,
        action=AuditAction.RESPONSE_KILL,
        target=f"{machine.machine_id}:pid={payload.pid}",
        details={
            "command_id": command.id,
            "alert_id": payload.alert_id,
            "process": alert.process_name if alert else None,
            "reason": payload.reason,
        },
    )
    await db.commit()
    await hub.broadcast_many([CHANNEL_COMMANDS, CHANNEL_AUDIT])

    return _to_command_out(command, machine.machine_id, current.email)


@router.post("/isolate", response_model=CommandOut, status_code=status.HTTP_201_CREATED)
async def isolate_machine(
    payload: IsolateRequest,
    current: CurrentUser = Depends(require_n2),
    db: AsyncSession = Depends(get_db),
):
    machine = await _require_machine(db, payload.machine_id)

    if machine.is_isolated:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{machine.machine_id} est déjà isolée du réseau",
        )

    command = Command(
        machine_pk=machine.id,
        action=CommandAction.ISOLATE.value,
        payload={"action": "ISOLATE", "target": "NETWORK", "reason": payload.reason},
        status=CommandStatus.PENDING.value,
        origin=CommandOrigin.MANUAL.value,
        created_by=current.id,
    )
    db.add(command)
    machine.is_isolated = True
    await db.flush()

    await audit_service.record_user_action(
        db,
        current,
        action=AuditAction.RESPONSE_ISOLATE,
        target=machine.machine_id,
        details={"command_id": command.id, "reason": payload.reason},
    )
    await db.commit()
    await hub.broadcast_many([CHANNEL_COMMANDS, CHANNEL_MACHINES, CHANNEL_AUDIT])

    return _to_command_out(command, machine.machine_id, current.email)


@router.post("/unisolate", response_model=CommandOut, status_code=status.HTTP_201_CREATED)
async def unisolate_machine(
    payload: IsolateRequest,
    current: CurrentUser = Depends(require_n2),
    db: AsyncSession = Depends(get_db),
):
    machine = await _require_machine(db, payload.machine_id)

    if not machine.is_isolated:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{machine.machine_id} n'est pas isolée",
        )

    command = Command(
        machine_pk=machine.id,
        action=CommandAction.UNISOLATE.value,
        payload={"action": "UNISOLATE", "target": "NETWORK", "reason": payload.reason},
        status=CommandStatus.PENDING.value,
        origin=CommandOrigin.MANUAL.value,
        created_by=current.id,
    )
    db.add(command)
    machine.is_isolated = False
    await db.flush()

    await audit_service.record_user_action(
        db,
        current,
        action=AuditAction.RESPONSE_UNISOLATE,
        target=machine.machine_id,
        details={"command_id": command.id, "reason": payload.reason},
    )
    await db.commit()
    await hub.broadcast_many([CHANNEL_COMMANDS, CHANNEL_MACHINES, CHANNEL_AUDIT])

    return _to_command_out(command, machine.machine_id, current.email)


@router.get("/commands", response_model=List[CommandOut])
async def list_commands(
    machine_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    """Journal des réponses actives, tous statuts confondus."""
    query = (
        select(Command, Machine.machine_id, User.email)
        .outerjoin(Machine, Machine.id == Command.machine_pk)
        .outerjoin(User, User.id == Command.created_by)
        .order_by(Command.created_at.desc(), Command.id.desc())
        .limit(limit)
    )
    if machine_id:
        query = query.where(Machine.machine_id == machine_id)

    rows = (await db.execute(query)).all()
    return [_to_command_out(cmd, mid, email) for cmd, mid, email in rows]
