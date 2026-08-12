"""
Authentification et gestion des comptes analystes.

Différences majeures avec l'implémentation précédente :
  - argon2id salé au lieu de SHA-256 nu ;
  - session serveur vérifiable, transmise par cookie HttpOnly ;
  - verrouillage temporaire du compte après N échecs ;
  - création de compte réservée au niveau N3 (le client ne choisit plus son rôle) ;
  - réponse d'erreur uniforme pour ne pas révéler l'existence d'un compte ;
  - chaque événement d'authentification est audité côté serveur.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api import audit_service
from api.audit_service import AuditAction
from api.config import settings
from api.db import get_db
from api.models import Role, User
from api.realtime import hub
from api.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    SessionInfo,
    UserCreateRequest,
    UserOut,
    UserUpdateRequest,
)
from api.security import (
    CurrentUser,
    clear_session_cookie,
    client_ip,
    create_session,
    get_current_user,
    hash_password,
    needs_rehash,
    require_n3,
    revoke_all_user_sessions,
    revoke_session,
    set_session_cookie,
    validate_password_strength,
    verify_password,
)

logger = logging.getLogger("api.auth")
router = APIRouter(prefix="/auth", tags=["auth"])

INVALID_CREDENTIALS = "Identifiants invalides"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _to_user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        role=user.role,
        role_label=user.role_label,
        permissions=user.permissions,
        full_name=user.full_name,
        is_active=user.is_active,
        must_change_password=user.must_change_password,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
    )


@router.post("/login", response_model=SessionInfo)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    email = payload.email.lower().strip()
    user = await db.scalar(select(User).where(func.lower(User.email) == email))

    # Message identique dans tous les cas d'échec : on ne renseigne pas
    # l'attaquant sur l'existence du compte (énumération d'utilisateurs).
    if user is None:
        await audit_service.record(
            db,
            action=AuditAction.LOGIN_FAILED,
            actor_label=email,
            details={"reason": "compte inexistant"},
            ip_source=client_ip(request),
            user_agent=(request.headers.get("user-agent") or "")[:400],
            result="failure",
        )
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS)

    if not user.is_active:
        await audit_service.record(
            db,
            action=AuditAction.LOGIN_FAILED,
            actor_label=user.email,
            user_id=user.id,
            details={"reason": "compte désactivé"},
            ip_source=client_ip(request),
            result="failure",
        )
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS)

    if user.locked_until and user.locked_until > _now():
        remaining = int((user.locked_until - _now()).total_seconds() // 60) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Compte temporairement verrouillé. Réessayez dans {remaining} minute(s).",
        )

    if not verify_password(payload.password, user.password_hash, user.hash_algo):
        user.failed_login_count += 1
        locked = False
        if user.failed_login_count >= settings.max_failed_logins:
            user.locked_until = _now() + timedelta(minutes=settings.lockout_minutes)
            user.failed_login_count = 0
            locked = True

        await audit_service.record(
            db,
            action=AuditAction.LOGIN_FAILED,
            actor_label=user.email,
            user_id=user.id,
            details={"reason": "mot de passe incorrect", "account_locked": locked},
            ip_source=client_ip(request),
            user_agent=(request.headers.get("user-agent") or "")[:400],
            result="failure",
        )
        await db.commit()

        if locked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Trop de tentatives échouées. Compte verrouillé "
                    f"{settings.lockout_minutes} minutes."
                ),
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS)

    # ── Authentification réussie ────────────────────────────────────
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = _now()

    # Migration transparente des hachages SHA-256 héités de SQLite.
    if needs_rehash(user.password_hash, user.hash_algo):
        user.password_hash = hash_password(payload.password)
        user.hash_algo = "argon2"
        logger.info("Hachage du compte %s migré vers argon2id", user.email)

    session, raw_token = await create_session(db, user, request)

    await audit_service.record(
        db,
        action=AuditAction.LOGIN,
        actor_label=user.email,
        user_id=user.id,
        details={"role": user.role, "must_change_password": user.must_change_password},
        ip_source=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:400],
    )
    await db.commit()

    set_session_cookie(response, raw_token)

    return SessionInfo(
        user=_to_user_out(user),
        expires_at=session.expires_at,
        connected_analysts=hub.connection_count,
    )


@router.post("/logout")
async def logout(
    response: Response,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await revoke_session(db, current.session)
    await audit_service.record_user_action(db, current, action=AuditAction.LOGOUT)
    await db.commit()

    clear_session_cookie(response)
    return {"status": "success", "message": "Session terminée"}


@router.get("/me", response_model=SessionInfo)
async def me(current: CurrentUser = Depends(get_current_user)):
    return SessionInfo(
        user=_to_user_out(current.user),
        expires_at=current.session.expires_at,
        connected_analysts=hub.connection_count,
    )


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    response: Response,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not verify_password(
        payload.current_password, current.user.password_hash, current.user.hash_algo
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Mot de passe actuel incorrect"
        )

    if payload.new_password == payload.current_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Le nouveau mot de passe doit être différent de l'actuel",
        )

    validate_password_strength(payload.new_password)

    current.user.password_hash = hash_password(payload.new_password)
    current.user.hash_algo = "argon2"
    current.user.must_change_password = False

    # Un changement de mot de passe invalide les autres sessions : si un tiers
    # avait volé un cookie, il perd l'accès immédiatement.
    revoked = await revoke_all_user_sessions(
        db, current.user.id, except_session_id=current.session.id
    )

    await audit_service.record_user_action(
        db,
        current,
        action=AuditAction.PASSWORD_CHANGED,
        details={"other_sessions_revoked": revoked},
    )
    await db.commit()

    return {
        "status": "success",
        "message": "Mot de passe mis à jour",
        "other_sessions_revoked": revoked,
    }


# ─────────────────────────────────────────────────────────────────────
# Administration des comptes (N3 uniquement)
# ─────────────────────────────────────────────────────────────────────


@router.get("/users", response_model=List[UserOut])
async def list_users(
    current: CurrentUser = Depends(require_n3),
    db: AsyncSession = Depends(get_db),
):
    users = await db.scalars(select(User).order_by(User.email))
    return [_to_user_out(u) for u in users]


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreateRequest,
    current: CurrentUser = Depends(require_n3),
    db: AsyncSession = Depends(get_db),
):
    email = payload.email.lower().strip()
    if await db.scalar(select(User).where(func.lower(User.email) == email)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Cette adresse est déjà utilisée"
        )

    validate_password_strength(payload.password)

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        hash_algo="argon2",
        role=payload.role.value,
        full_name=payload.full_name,
        is_active=True,
        must_change_password=True,
    )
    db.add(user)
    await db.flush()

    await audit_service.record_user_action(
        db,
        current,
        action=AuditAction.USER_CREATED,
        target=user.email,
        details={"role": user.role},
    )
    await db.commit()

    return _to_user_out(user)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    current: CurrentUser = Depends(require_n3),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Compte introuvable")

    changes: dict = {}

    if payload.role is not None and payload.role.value != user.role:
        # Garde-fou : ne pas se retirer soi-même le dernier accès N3.
        if user.id == current.id and payload.role != Role.N3:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Vous ne pouvez pas réduire votre propre niveau de privilège",
            )
        if user.role == Role.N3.value and payload.role != Role.N3:
            remaining = await db.scalar(
                select(func.count())
                .select_from(User)
                .where(User.role == Role.N3.value, User.is_active.is_(True), User.id != user.id)
            )
            if not remaining:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Il doit rester au moins un SOC Manager (N3) actif",
                )
        changes["role"] = {"from": user.role, "to": payload.role.value}
        user.role = payload.role.value

    if payload.is_active is not None and payload.is_active != user.is_active:
        if user.id == current.id and not payload.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Vous ne pouvez pas désactiver votre propre compte",
            )
        changes["is_active"] = {"from": user.is_active, "to": payload.is_active}
        user.is_active = payload.is_active
        if not payload.is_active:
            # Désactiver un compte doit couper ses sessions en cours.
            await revoke_all_user_sessions(db, user.id)

    if payload.full_name is not None and payload.full_name != user.full_name:
        changes["full_name"] = {"from": user.full_name, "to": payload.full_name}
        user.full_name = payload.full_name

    if changes:
        await audit_service.record_user_action(
            db,
            current,
            action=AuditAction.USER_UPDATED,
            target=user.email,
            details=changes,
        )
    await db.commit()

    return _to_user_out(user)


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    current: CurrentUser = Depends(require_n3),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Compte introuvable")
    if user.id == current.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vous ne pouvez pas supprimer votre propre compte",
        )

    email = user.email
    await db.delete(user)
    await audit_service.record_user_action(
        db, current, action=AuditAction.USER_DELETED, target=email
    )
    await db.commit()

    return {"status": "success", "message": f"Compte {email} supprimé"}
