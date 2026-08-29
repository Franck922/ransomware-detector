"""
Inventaire des postes surveillés.

L'ancienne API ne persistait pas le `machine_id` reçu à l'ingestion : le
dashboard affichait un unique terminal « VM-WIN10-LAB » écrit en dur dans le
JSX. Les machines sont maintenant enregistrées et mises à jour à chaque lot
d'événements reçu.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db import get_db
from api.models import Alert, AlertStatus, Machine, MachineStatus
from api.schemas import MachineOut
from api.security import CurrentUser, require_n1

router = APIRouter(prefix="/machines", tags=["machines"])

OPEN_STATES = (
    AlertStatus.NEW.value,
    AlertStatus.ACKNOWLEDGED.value,
    AlertStatus.IN_PROGRESS.value,
)

ONLINE_WINDOW_SECONDS = 120


def _effective_status(machine: Machine, online_since: datetime) -> str:
    """
    Le statut est dérivé de la dernière activité réelle plutôt que stocké tel
    quel : un agent qui cesse d'émettre apparaît hors ligne sans intervention.
    """
    if machine.is_isolated:
        return MachineStatus.ISOLATED.value
    if machine.last_seen_at >= online_since:
        return MachineStatus.ONLINE.value
    return MachineStatus.OFFLINE.value


@router.get("", response_model=List[MachineOut])
async def list_machines(
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    online_since = datetime.now(timezone.utc) - timedelta(seconds=ONLINE_WINDOW_SECONDS)

    rows = (
        await db.execute(
            select(Machine, func.count(Alert.id))
            .outerjoin(
                Alert, (Alert.machine_pk == Machine.id) & (Alert.status.in_(OPEN_STATES))
            )
            .group_by(Machine.id)
            .order_by(Machine.machine_id)
        )
    ).all()

    return [
        MachineOut(
            id=machine.id,
            machine_id=machine.machine_id,
            hostname=machine.hostname,
            ip_address=machine.ip_address,
            os_name=machine.os_name,
            agent_version=machine.agent_version,
            status=_effective_status(machine, online_since),
            is_isolated=machine.is_isolated,
            first_seen_at=machine.first_seen_at,
            last_seen_at=machine.last_seen_at,
            events_received=machine.events_received,
            open_alerts=open_alerts,
        )
        for machine, open_alerts in rows
    ]


@router.get("/{machine_id}", response_model=MachineOut)
async def get_machine(
    machine_id: str,
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    machine = await db.scalar(select(Machine).where(Machine.machine_id == machine_id))
    if machine is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine inconnue")

    online_since = datetime.now(timezone.utc) - timedelta(seconds=ONLINE_WINDOW_SECONDS)
    open_alerts = (
        await db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.machine_pk == machine.id, Alert.status.in_(OPEN_STATES))
        )
        or 0
    )

    return MachineOut(
        id=machine.id,
        machine_id=machine.machine_id,
        hostname=machine.hostname,
        ip_address=machine.ip_address,
        os_name=machine.os_name,
        agent_version=machine.agent_version,
        status=_effective_status(machine, online_since),
        is_isolated=machine.is_isolated,
        first_seen_at=machine.first_seen_at,
        last_seen_at=machine.last_seen_at,
        events_received=machine.events_received,
        open_alerts=open_alerts,
    )
