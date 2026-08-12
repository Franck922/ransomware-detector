"""
Utilitaire d'administration en ligne de commande.

Indispensable en exploitation : la création de compte est réservée aux N3 via
l'API, il faut donc un accès hors bande pour débloquer un compte, réinitialiser
un mot de passe oublié ou promouvoir le premier administrateur.

Exemples :
    python -m scripts.manage list-users
    python -m scripts.manage create-user --email soc@x.local --role N2
    python -m scripts.manage reset-password --email soc@x.local
    python -m scripts.manage unlock --email soc@x.local
    python -m scripts.manage set-role --email soc@x.local --role N3
    python -m scripts.manage revoke-sessions --email soc@x.local
"""

from __future__ import annotations

import argparse
import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session as OrmSession

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.config import settings  # noqa: E402
from api.models import ROLE_LABELS, Role, Session as SessionModel, User  # noqa: E402
from api.security import hash_password  # noqa: E402


def _session() -> OrmSession:
    return OrmSession(create_engine(settings.sync_database_url))


def _find(db: OrmSession, email: str) -> User:
    user = db.scalar(select(User).where(func.lower(User.email) == email.lower().strip()))
    if user is None:
        raise SystemExit(f"[!] Aucun compte pour {email}")
    return user


def _read_password(provided: str | None) -> str:
    if provided:
        return provided
    first = getpass.getpass("Nouveau mot de passe : ")
    second = getpass.getpass("Confirmation : ")
    if first != second:
        raise SystemExit("[!] Les mots de passe ne correspondent pas")
    if len(first) < settings.password_min_length:
        raise SystemExit(f"[!] Minimum {settings.password_min_length} caractères")
    return first


def cmd_list_users(args) -> int:
    with _session() as db:
        users = db.scalars(select(User).order_by(User.email)).all()
        if not users:
            print("Aucun compte.")
            return 0
        print(f"{'EMAIL':<34} {'RÔLE':<24} {'ACTIF':<6} {'ROTATION':<9} DERNIER LOGIN")
        print("-" * 96)
        for user in users:
            last = user.last_login_at.strftime("%Y-%m-%d %H:%M") if user.last_login_at else "jamais"
            locked = " (verrouillé)" if user.locked_until and user.locked_until > datetime.now(
                timezone.utc
            ) else ""
            print(
                f"{user.email:<34} {ROLE_LABELS.get(user.role, user.role):<24} "
                f"{'oui' if user.is_active else 'non':<6} "
                f"{'requise' if user.must_change_password else '-':<9} {last}{locked}"
            )
    return 0


def cmd_create_user(args) -> int:
    password = _read_password(args.password)
    with _session() as db:
        email = args.email.lower().strip()
        if db.scalar(select(User).where(func.lower(User.email) == email)):
            raise SystemExit(f"[!] {email} existe déjà")
        user = User(
            email=email,
            password_hash=hash_password(password),
            hash_algo="argon2",
            role=Role(args.role).value,
            full_name=args.full_name,
            is_active=True,
            must_change_password=not args.no_rotation,
        )
        db.add(user)
        db.commit()
        print(f"Compte {email} créé avec le rôle {ROLE_LABELS[user.role]}.")
        if user.must_change_password:
            print("Changement de mot de passe requis à la première connexion.")
    return 0


def cmd_reset_password(args) -> int:
    password = _read_password(args.password)
    with _session() as db:
        user = _find(db, args.email)
        user.password_hash = hash_password(password)
        user.hash_algo = "argon2"
        user.must_change_password = not args.no_rotation
        user.failed_login_count = 0
        user.locked_until = None
        # Toute session active devient invalide : c'est le comportement attendu
        # après une réinitialisation administrative.
        revoked = 0
        for session in db.scalars(
            select(SessionModel).where(
                SessionModel.user_id == user.id, SessionModel.revoked_at.is_(None)
            )
        ):
            session.revoked_at = datetime.now(timezone.utc)
            revoked += 1
        db.commit()
        print(f"Mot de passe de {user.email} réinitialisé ({revoked} session(s) révoquée(s)).")
    return 0


def cmd_unlock(args) -> int:
    with _session() as db:
        user = _find(db, args.email)
        user.failed_login_count = 0
        user.locked_until = None
        user.is_active = True
        db.commit()
        print(f"{user.email} déverrouillé et réactivé.")
    return 0


def cmd_set_role(args) -> int:
    with _session() as db:
        user = _find(db, args.email)
        previous = user.role
        user.role = Role(args.role).value
        db.commit()
        print(f"{user.email} : {previous} -> {user.role} ({ROLE_LABELS[user.role]})")
    return 0


def cmd_revoke_sessions(args) -> int:
    with _session() as db:
        user = _find(db, args.email)
        revoked = 0
        for session in db.scalars(
            select(SessionModel).where(
                SessionModel.user_id == user.id, SessionModel.revoked_at.is_(None)
            )
        ):
            session.revoked_at = datetime.now(timezone.utc)
            revoked += 1
        db.commit()
        print(f"{revoked} session(s) révoquée(s) pour {user.email}.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Administration des comptes EDR")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list-users", help="Liste les comptes").set_defaults(func=cmd_list_users)

    create = sub.add_parser("create-user", help="Crée un compte")
    create.add_argument("--email", required=True)
    create.add_argument("--password", help="Demandé de façon masquée si omis")
    create.add_argument("--role", default="N1", choices=[r.value for r in Role])
    create.add_argument("--full-name")
    create.add_argument(
        "--no-rotation", action="store_true", help="N'impose pas le changement au 1er login"
    )
    create.set_defaults(func=cmd_create_user)

    reset = sub.add_parser("reset-password", help="Réinitialise un mot de passe")
    reset.add_argument("--email", required=True)
    reset.add_argument("--password", help="Demandé de façon masquée si omis")
    reset.add_argument("--no-rotation", action="store_true")
    reset.set_defaults(func=cmd_reset_password)

    unlock = sub.add_parser("unlock", help="Déverrouille un compte")
    unlock.add_argument("--email", required=True)
    unlock.set_defaults(func=cmd_unlock)

    role = sub.add_parser("set-role", help="Change le rôle d'un compte")
    role.add_argument("--email", required=True)
    role.add_argument("--role", required=True, choices=[r.value for r in Role])
    role.set_defaults(func=cmd_set_role)

    revoke = sub.add_parser("revoke-sessions", help="Révoque les sessions actives")
    revoke.add_argument("--email", required=True)
    revoke.set_defaults(func=cmd_revoke_sessions)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
