"""
Écriture du journal d'audit.

Auparavant le dashboard appelait POST /audit avec le nom d'utilisateur, le
libellé de l'action ET l'adresse IP source — tous falsifiables, et l'IP était de
surcroît codée en dur côté client. Désormais, seul le serveur écrit dans ce
journal, à partir du contexte authentifié de la requête.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from api.models import AuditLog
from api.security import CurrentUser


# Actions normalisées, pour que le journal reste filtrable.
class AuditAction:
    LOGIN = "auth.login"
    LOGIN_FAILED = "auth.login_failed"
    LOGOUT = "auth.logout"
    PASSWORD_CHANGED = "auth.password_changed"
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    ALERT_STATUS_CHANGED = "alert.status_changed"
    ALERT_ASSIGNED = "alert.assigned"
    ALERT_CONTAINED = "alert.contained"
    RESPONSE_KILL = "response.kill"
    RESPONSE_ISOLATE = "response.isolate"
    RESPONSE_UNISOLATE = "response.unisolate"
    COMMAND_ACKED = "response.command_acked"
    EXCLUSION_CREATED = "exclusion.created"
    EXCLUSION_DELETED = "exclusion.deleted"
    EXCLUSION_TOGGLED = "exclusion.toggled"
    SETTING_UPDATED = "settings.updated"
    AUTO_KILL = "engine.auto_kill"
    AUTO_ALERT = "engine.alert_raised"


async def record(
    db: AsyncSession,
    *,
    action: str,
    actor_label: str,
    user_id: Optional[int] = None,
    target: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_source: Optional[str] = None,
    user_agent: Optional[str] = None,
    result: str = "success",
) -> AuditLog:
    entry = AuditLog(
        user_id=user_id,
        actor_label=actor_label[:255],
        action=action[:80],
        target=target[:255] if target else None,
        details=details,
        ip_source=ip_source,
        user_agent=user_agent,
        result=result,
    )
    db.add(entry)
    await db.flush()
    return entry


async def record_user_action(
    db: AsyncSession,
    current: CurrentUser,
    *,
    action: str,
    target: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    result: str = "success",
) -> AuditLog:
    """Trace une action réalisée par un analyste authentifié."""
    return await record(
        db,
        action=action,
        actor_label=current.email,
        user_id=current.id,
        target=target,
        details=details,
        ip_source=current.ip,
        user_agent=current.user_agent,
        result=result,
    )


async def record_engine_action(
    db: AsyncSession,
    *,
    action: str,
    target: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Trace une action automatique du moteur de détection. Une réponse active
    déclenchée sans intervention humaine doit être auditée au même titre qu'une
    action d'analyste.
    """
    return await record(
        db,
        action=action,
        actor_label="Moteur de détection EDR",
        user_id=None,
        target=target,
        details=details,
        ip_source="system",
    )
