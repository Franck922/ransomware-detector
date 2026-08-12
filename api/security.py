"""
Authentification, sessions et contrôle d'accès basé sur les rôles (RBAC).

Remplace l'ancien dispositif dans lequel :
  - les mots de passe étaient hachés en SHA-256 sans sel ;
  - le token retourné au login (`session_{email}_{hash8}`) n'était jamais vérifié ;
  - la « session » vivait dans le localStorage du navigateur ;
  - tout appelant anonyme pouvait déclencher un KILL ou une isolation réseau ;
  - le client choisissait librement son propre rôle à l'inscription.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.db import get_db
from api.models import Role, Session as SessionModel, User

logger = logging.getLogger("api.security")

# Paramètres OWASP-compatibles pour un usage interactif (~50 ms/hachage).
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

LEGACY_ALGO = "sha256-legacy"
SESSION_TOKEN_BYTES = 32


# ─────────────────────────────────────────────────────────────────────
# Mots de passe
# ─────────────────────────────────────────────────────────────────────


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(plain: str, stored_hash: str, algo: str) -> bool:
    """
    Vérifie un mot de passe. Supporte les hachages SHA-256 héités de l'ancienne
    base SQLite pour ne pas casser les comptes existants ; ils sont réhachés en
    argon2 au premier login réussi (voir `needs_rehash`).
    """
    if algo == LEGACY_ALGO:
        legacy = hashlib.sha256(plain.encode()).hexdigest()
        return hmac.compare_digest(legacy, stored_hash)

    try:
        return _hasher.verify(stored_hash, plain)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception as exc:  # hachage corrompu en base
        logger.warning("Échec inattendu de vérification argon2 : %s", exc)
        return False


def needs_rehash(stored_hash: str, algo: str) -> bool:
    if algo == LEGACY_ALGO:
        return True
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except Exception:
        return False


def validate_password_strength(plain: str) -> None:
    """Lève une 422 explicite si la politique de mot de passe n'est pas respectée."""
    problems = []
    if len(plain) < settings.password_min_length:
        problems.append(f"au moins {settings.password_min_length} caractères")
    if not any(c.islower() for c in plain):
        problems.append("une minuscule")
    if not any(c.isupper() for c in plain):
        problems.append("une majuscule")
    if not any(c.isdigit() for c in plain):
        problems.append("un chiffre")

    if problems:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Le mot de passe doit contenir " + ", ".join(problems) + ".",
        )


# ─────────────────────────────────────────────────────────────────────
# Sessions serveur
# ─────────────────────────────────────────────────────────────────────


def _hash_token(token: str) -> str:
    """
    Le token brut n'est jamais stocké. On applique un HMAC avec SESSION_SECRET :
    une base exfiltrée ne suffit pas à forger ou rejouer une session.
    """
    return hmac.new(
        settings.session_secret.encode(), token.encode(), hashlib.sha256
    ).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def create_session(
    db: AsyncSession, user: User, request: Request
) -> tuple[SessionModel, str]:
    raw_token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    session = SessionModel(
        user_id=user.id,
        token_hash=_hash_token(raw_token),
        expires_at=_now() + timedelta(hours=settings.session_ttl_hours),
        ip_source=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:400],
    )
    db.add(session)
    await db.flush()
    return session, raw_token


def set_session_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,  # inaccessible au JavaScript : neutralise le vol par XSS
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
    )


async def resolve_session(
    db: AsyncSession, raw_token: Optional[str]
) -> Optional[tuple[SessionModel, User]]:
    """Retourne (session, user) si le token est valide, actif et non expiré."""
    if not raw_token:
        return None

    result = await db.execute(
        select(SessionModel, User)
        .join(User, User.id == SessionModel.user_id)
        .where(SessionModel.token_hash == _hash_token(raw_token))
    )
    row = result.first()
    if not row:
        return None

    session, user = row
    if session.revoked_at is not None:
        return None
    if session.expires_at <= _now():
        return None
    if not user.is_active:
        return None

    return session, user


async def revoke_session(db: AsyncSession, session: SessionModel) -> None:
    session.revoked_at = _now()
    await db.flush()


async def revoke_all_user_sessions(
    db: AsyncSession, user_id: int, except_session_id: Optional[int] = None
) -> int:
    result = await db.execute(
        select(SessionModel).where(
            SessionModel.user_id == user_id, SessionModel.revoked_at.is_(None)
        )
    )
    count = 0
    for session in result.scalars():
        if except_session_id is not None and session.id == except_session_id:
            continue
        session.revoked_at = _now()
        count += 1
    await db.flush()
    return count


def client_ip(request: Request) -> str:
    """
    IP réelle du client. Derrière le reverse proxy nginx, on lit X-Forwarded-For
    (uvicorn est lancé avec --proxy-headers), sinon l'IP de socket.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


# ─────────────────────────────────────────────────────────────────────
# Dépendances FastAPI : authentification et RBAC
# ─────────────────────────────────────────────────────────────────────


class CurrentUser:
    """Contexte d'appel authentifié, injecté dans les endpoints protégés."""

    def __init__(self, user: User, session: SessionModel, request: Request):
        self.user = user
        self.session = session
        self.request = request

    @property
    def id(self) -> int:
        return self.user.id

    @property
    def email(self) -> str:
        return self.user.email

    @property
    def role(self) -> Role:
        return self.user.role_enum

    @property
    def ip(self) -> str:
        return client_ip(self.request)

    @property
    def user_agent(self) -> str:
        return (self.request.headers.get("user-agent") or "")[:400]


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    edr_session: Optional[str] = Cookie(default=None, alias=settings.session_cookie_name),
) -> CurrentUser:
    resolved = await resolve_session(db, edr_session)
    if resolved is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalide ou expirée",
        )

    session, user = resolved

    # Glissement de la date de dernière activité (au plus une écriture/minute
    # pour ne pas transformer chaque lecture en écriture).
    if (_now() - session.last_seen_at).total_seconds() > 60:
        session.last_seen_at = _now()
        await db.flush()

    return CurrentUser(user=user, session=session, request=request)


def require_role(minimum: Role):
    """
    Fabrique une dépendance exigeant au moins le niveau `minimum`.
    L'autorisation est vérifiée côté serveur : masquer un bouton dans l'UI ne
    constitue pas un contrôle d'accès.
    """

    async def _guard(current: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        # Un compte dont le mot de passe doit être renouvelé ne peut rien faire
        # d'autre que le renouveler (endpoints /auth/me, /auth/change-password
        # et /auth/logout, qui dépendent directement de get_current_user).
        if current.user.must_change_password:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Changement de mot de passe obligatoire avant toute autre action",
                headers={"X-Password-Change-Required": "1"},
            )

        if not current.role.satisfies(minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Action réservée au niveau {minimum.value} ou supérieur "
                    f"(votre rôle : {current.role.value})"
                ),
            )
        return current

    return _guard


require_n1 = require_role(Role.N1)
require_n2 = require_role(Role.N2)
require_n3 = require_role(Role.N3)


# ─────────────────────────────────────────────────────────────────────
# Authentification des agents (VM surveillées)
# ─────────────────────────────────────────────────────────────────────


async def require_agent_token(request: Request) -> str:
    """
    Protège les endpoints d'ingestion et la file de commandes.

    Sans cela, n'importe qui sur le réseau peut injecter de faux événements
    Sysmon (empoisonnement de la baseline) ou dépiler les commandes KILL
    destinées à un poste compromis.

    Le token est accepté via l'en-tête X-Agent-Token ou Authorization: Bearer,
    Winlogbeat ne permettant pas d'ajouter d'en-tête arbitraire dans toutes les
    versions.
    """
    provided = request.headers.get("x-agent-token")
    auth = request.headers.get("authorization", "")

    if not provided and auth.lower().startswith("bearer "):
        provided = auth[7:].strip()

    if not provided and auth.lower().startswith("basic "):
        # Winlogbeat en sortie Elasticsearch transmet ses identifiants en Basic :
        # on accepte le mot de passe Basic comme porteur du token.
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8", "ignore")
            if ":" in decoded:
                provided = decoded.split(":", 1)[1]
        except Exception:
            provided = None

    if not provided or not hmac.compare_digest(provided, settings.agent_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token d'agent invalide ou absent",
        )

    return provided
