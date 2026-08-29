"""
Consultation du journal d'audit.

L'endpoint d'écriture publique a été supprimé : le client ne peut plus forger
d'entrée ni déclarer une fausse IP source. Seul le serveur alimente ce journal
(voir api/audit_service.py). L'ancienne API fabriquait aussi une entrée fictive
quand le journal était vide, ce qui rendait le registre non fiable ; ce n'est
plus le cas.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db import get_db
from api.models import AuditLog
from api.schemas import AuditListOut, AuditLogOut
from api.security import CurrentUser, require_n1

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=AuditListOut)
async def list_audit_logs(
    action: Optional[str] = Query(default=None, max_length=80),
    actor: Optional[str] = Query(default=None, max_length=255),
    hours: Optional[int] = Query(default=None, ge=1, le=24 * 365),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditLog)
    count_query = select(func.count()).select_from(AuditLog)

    if action:
        query = query.where(AuditLog.action == action)
        count_query = count_query.where(AuditLog.action == action)

    if actor:
        pattern = f"%{actor}%"
        query = query.where(AuditLog.actor_label.ilike(pattern))
        count_query = count_query.where(AuditLog.actor_label.ilike(pattern))

    if hours:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        query = query.where(AuditLog.occurred_at >= since)
        count_query = count_query.where(AuditLog.occurred_at >= since)

    total = await db.scalar(count_query) or 0
    rows = await db.scalars(
        query.order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc()).limit(limit).offset(offset)
    )

    return AuditListOut(
        items=[AuditLogOut.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/actions", response_model=List[str])
async def list_actions(
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    """Actions réellement présentes en base, pour alimenter le filtre de l'UI."""
    rows = await db.scalars(select(AuditLog.action).distinct().order_by(AuditLog.action))
    return list(rows)
