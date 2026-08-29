"""
Amorçage au démarrage : compte administrateur initial et configuration par défaut.

Le compte d'origine était créé en dur dans le code avec le mot de passe
`admin123`. Il provient désormais de BOOTSTRAP_ADMIN_* et n'est créé que si la
table des utilisateurs est vide.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from sqlalchemy import func, select

from api.config import settings
from api.db import SessionFactory
from api.models import AppSetting, Role, User
from api.security import hash_password

logger = logging.getLogger("api.bootstrap")

DEFAULT_SETTINGS: Dict[str, Dict[str, Any]] = {
    "detection": {
        "auto_kill_score_threshold": settings.auto_kill_score_threshold,
        "rules_alert_threshold": settings.rules_alert_threshold,
        "baseline_min_vectors": settings.baseline_min_vectors,
    },
    "retention": {"metrics_days": settings.metrics_retention_days, "alerts_days": 365},
    "notifications": {"email_enabled": False, "webhook_url": ""},
}


async def bootstrap() -> None:
    async with SessionFactory() as db:
        user_count = await db.scalar(select(func.count()).select_from(User)) or 0

        if user_count == 0:
            if not settings.bootstrap_admin_password:
                logger.warning(
                    "Aucun utilisateur en base et BOOTSTRAP_ADMIN_PASSWORD est vide : "
                    "renseignez-le dans .env pour créer le premier compte SOC Manager."
                )
            else:
                admin = User(
                    email=settings.bootstrap_admin_email.lower().strip(),
                    password_hash=hash_password(settings.bootstrap_admin_password),
                    hash_algo="argon2",
                    role=Role.N3.value,
                    full_name="Administrateur SOC",
                    is_active=True,
                    # Le mot de passe transite par un fichier .env : rotation
                    # imposée à la première connexion.
                    must_change_password=True,
                )
                db.add(admin)
                logger.info(
                    "Compte SOC Manager initial créé : %s (changement de mot de passe requis)",
                    admin.email,
                )

        for key, value in DEFAULT_SETTINGS.items():
            if await db.get(AppSetting, key) is None:
                db.add(AppSetting(key=key, value=value))

        await db.commit()

    problems = settings.assert_production_ready()
    if problems:
        level = logger.error if settings.is_production else logger.warning
        for problem in problems:
            level("Configuration de sécurité à corriger : %s", problem)
        if settings.is_production:
            raise RuntimeError(
                "Démarrage refusé en production avec des secrets de développement : "
                + " ; ".join(problems)
            )
