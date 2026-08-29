"""
Accès à la base de données : moteur asynchrone unique et pool de connexions
partagé par toute l'application.

Remplace les `sqlite3.connect(DB_PATH)` dispersés dans l'ancien main.py, qui
ouvraient et fermaient une connexion par requête sur un chemin relatif au
répertoire de travail courant.
"""

from __future__ import annotations

import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from api.config import settings

logger = logging.getLogger("api.db")

engine: AsyncEngine = create_async_engine(
    settings.database_url,
    echo=settings.db_echo,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_pre_ping=True,  # recycle les connexions coupées par le redémarrage du conteneur
    pool_recycle=1800,
)

SessionFactory: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dépendance FastAPI : une session par requête, rollback automatique."""
    async with SessionFactory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    await engine.dispose()


async def check_connection() -> bool:
    from sqlalchemy import text

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.error("Connexion PostgreSQL impossible : %s", exc)
        return False
