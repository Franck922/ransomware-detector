"""
Configuration système persistée.

L'onglet Configuration du dashboard ne faisait qu'afficher un `alert()`
« Configuration sauvegardée » sans rien enregistrer. Les valeurs sont maintenant
stockées en base, partagées par tous les analystes et modifiables par un N3.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api import audit_service
from api.audit_service import AuditAction
from api.db import get_db
from api.models import AppSetting, User
from api.schemas import SettingOut, SettingUpdate
from api.security import CurrentUser, require_n1, require_n3

router = APIRouter(prefix="/settings", tags=["settings"])

ALLOWED_KEYS = {"detection", "retention", "notifications"}


async def _to_out(db: AsyncSession, setting: AppSetting) -> SettingOut:
    email = (
        await db.scalar(select(User.email).where(User.id == setting.updated_by))
        if setting.updated_by
        else None
    )
    return SettingOut(
        key=setting.key,
        value=setting.value,
        updated_at=setting.updated_at,
        updated_by_email=email,
    )


@router.get("", response_model=List[SettingOut])
async def list_settings(
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    rows = await db.scalars(select(AppSetting).order_by(AppSetting.key))
    return [await _to_out(db, row) for row in rows]


@router.put("/{key}", response_model=SettingOut)
async def update_setting(
    key: str,
    payload: SettingUpdate,
    current: CurrentUser = Depends(require_n3),
    db: AsyncSession = Depends(get_db),
):
    if key not in ALLOWED_KEYS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Clé de configuration inconnue. Valeurs admises : {sorted(ALLOWED_KEYS)}",
        )

    setting = await db.get(AppSetting, key)
    previous = dict(setting.value) if setting else None

    if setting is None:
        setting = AppSetting(key=key, value=payload.value, updated_by=current.id)
        db.add(setting)
    else:
        setting.value = payload.value
        setting.updated_at = datetime.now(timezone.utc)
        setting.updated_by = current.id

    await audit_service.record_user_action(
        db,
        current,
        action=AuditAction.SETTING_UPDATED,
        target=key,
        details={"from": previous, "to": payload.value},
    )
    await db.commit()

    return await _to_out(db, setting)
