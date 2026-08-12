"""
Règles d'exclusion du moteur de détection.

Deux corrections : la modification exige désormais le niveau N3 (elle réduit la
couverture de détection, c'est une action sensible), et les exclusions sont
réellement appliquées par le pipeline — elles étaient jusqu'ici stockées et
affichées sans qu'aucun composant ne les lise.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api import audit_service
from api.audit_service import AuditAction
from api.db import get_db
from api.models import Exclusion, User
from api.realtime import CHANNEL_EXCLUSIONS, hub
from api.schemas import ExclusionCreate, ExclusionOut
from api.security import CurrentUser, require_n1, require_n3

router = APIRouter(prefix="/exclusions", tags=["exclusions"])


def _to_out(exclusion: Exclusion, author_email: str | None) -> ExclusionOut:
    return ExclusionOut(
        id=exclusion.id,
        type=exclusion.type,
        path=exclusion.path,
        comment=exclusion.comment,
        enabled=exclusion.enabled,
        created_at=exclusion.created_at,
        created_by_email=author_email,
    )


@router.get("", response_model=List[ExclusionOut])
async def list_exclusions(
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    rows = (
        await db.execute(
            select(Exclusion, User.email)
            .outerjoin(User, User.id == Exclusion.created_by)
            .order_by(Exclusion.type, Exclusion.path)
        )
    ).all()
    return [_to_out(exc, email) for exc, email in rows]


@router.post("", response_model=ExclusionOut, status_code=status.HTTP_201_CREATED)
async def create_exclusion(
    payload: ExclusionCreate,
    current: CurrentUser = Depends(require_n3),
    db: AsyncSession = Depends(get_db),
):
    path = payload.path.strip()
    existing = await db.scalar(
        select(Exclusion).where(Exclusion.type == payload.type, Exclusion.path == path)
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Cette exclusion existe déjà"
        )

    exclusion = Exclusion(
        type=payload.type,
        path=path,
        comment=payload.comment.strip(),
        enabled=True,
        created_by=current.id,
    )
    db.add(exclusion)
    await db.flush()

    await audit_service.record_user_action(
        db,
        current,
        action=AuditAction.EXCLUSION_CREATED,
        target=f"{payload.type}:{path}",
        details={"comment": exclusion.comment},
    )
    await db.commit()
    await hub.broadcast(CHANNEL_EXCLUSIONS, {"exclusion_id": exclusion.id, "action": "created"})

    return _to_out(exclusion, current.email)


@router.patch("/{exclusion_id}/toggle", response_model=ExclusionOut)
async def toggle_exclusion(
    exclusion_id: int,
    current: CurrentUser = Depends(require_n3),
    db: AsyncSession = Depends(get_db),
):
    exclusion = await db.get(Exclusion, exclusion_id)
    if exclusion is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exclusion introuvable")

    exclusion.enabled = not exclusion.enabled

    await audit_service.record_user_action(
        db,
        current,
        action=AuditAction.EXCLUSION_TOGGLED,
        target=f"{exclusion.type}:{exclusion.path}",
        details={"enabled": exclusion.enabled},
    )
    await db.commit()
    await hub.broadcast(CHANNEL_EXCLUSIONS, {"exclusion_id": exclusion.id, "action": "toggled"})

    author_email = (
        await db.scalar(select(User.email).where(User.id == exclusion.created_by))
        if exclusion.created_by
        else None
    )
    return _to_out(exclusion, author_email)


@router.delete("/{exclusion_id}")
async def delete_exclusion(
    exclusion_id: int,
    current: CurrentUser = Depends(require_n3),
    db: AsyncSession = Depends(get_db),
):
    exclusion = await db.get(Exclusion, exclusion_id)
    if exclusion is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exclusion introuvable")

    label = f"{exclusion.type}:{exclusion.path}"
    await db.delete(exclusion)

    await audit_service.record_user_action(
        db, current, action=AuditAction.EXCLUSION_DELETED, target=label
    )
    await db.commit()
    await hub.broadcast(CHANNEL_EXCLUSIONS, {"action": "deleted"})

    return {"status": "success", "message": "Exclusion retirée"}
