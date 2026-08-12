"""
Point d'entrée de l'API EDR.

Ce module ne contient plus de logique métier : il assemble les routers, la
sécurité, le canal temps réel et les tâches de fond. La détection vit dans
api/detection.py, la persistance dans api/models.py, l'autorisation dans
api/security.py.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.bootstrap import bootstrap
from api.config import settings
from api.db import SessionFactory, check_connection, dispose_engine, get_db
from api.detection import engine
from api.models import Command, CommandStatus, Metric, Session as SessionModel
from api.realtime import Connection, hub
from api.routers import alerts, audit, exclusions, ingest, machines, metrics, response
from api.routers import auth as auth_router
from api.routers import settings_router
from api.schemas import StatusOut
from api.security import require_n1, resolve_session

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
)
logger = logging.getLogger("api")

API_VERSION = "2.0.0"

# Une commande jamais acquittée par l'agent finit par expirer : sans cela, un
# poste éteint au mauvais moment laisse un ordre KILL en attente indéfiniment.
COMMAND_TIMEOUT_MINUTES = 15
MAINTENANCE_INTERVAL_SECONDS = 300

# Une fenêtre d'analyse ne se ferme qu'à l'arrivée d'un événement postérieur.
# Si un rançongiciel neutralise l'agent ou éteint le poste juste après son
# passage, la dernière fenêtre — la plus incriminante — ne serait jamais évaluée.
# On la force donc après un court silence.
WINDOW_FLUSH_INTERVAL_SECONDS = 5
WINDOW_IDLE_SECONDS = 12


async def _maintenance_loop() -> None:
    """Purge périodique : sessions expirées, commandes orphelines, vieilles métriques."""
    while True:
        try:
            await asyncio.sleep(MAINTENANCE_INTERVAL_SECONDS)
            now = datetime.now(timezone.utc)

            async with SessionFactory() as db:
                expired_sessions = await db.execute(
                    delete(SessionModel).where(
                        SessionModel.expires_at < now - timedelta(days=7)
                    )
                )

                stale_cutoff = now - timedelta(minutes=COMMAND_TIMEOUT_MINUTES)
                stale = await db.scalars(
                    select(Command).where(
                        Command.status.in_(
                            (CommandStatus.PENDING.value, CommandStatus.SENT.value)
                        ),
                        Command.created_at < stale_cutoff,
                    )
                )
                expired_commands = 0
                for command in stale:
                    command.status = CommandStatus.EXPIRED.value
                    command.result = {
                        "success": False,
                        "message": f"Non acquittée après {COMMAND_TIMEOUT_MINUTES} minutes",
                    }
                    expired_commands += 1

                retention_cutoff = now - timedelta(days=settings.metrics_retention_days)
                purged_metrics = await db.execute(
                    delete(Metric).where(Metric.bucket_at < retention_cutoff)
                )

                await db.commit()

            if expired_sessions.rowcount or expired_commands or purged_metrics.rowcount:
                logger.info(
                    "Maintenance : %s session(s), %s commande(s) expirée(s), %s métrique(s) purgée(s)",
                    expired_sessions.rowcount,
                    expired_commands,
                    purged_metrics.rowcount,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Erreur pendant la maintenance périodique : %s", exc)


async def _window_flush_loop() -> None:
    """Évalue les fenêtres laissées ouvertes par un agent devenu silencieux."""
    while True:
        try:
            await asyncio.sleep(WINDOW_FLUSH_INTERVAL_SECONDS)

            results = await asyncio.get_running_loop().run_in_executor(
                None, engine.flush_idle_windows, WINDOW_IDLE_SECONDS
            )
            if not results:
                continue

            async with SessionFactory() as db:
                for result in results:
                    # touch_machine=False : le poste est justement silencieux,
                    # le marquer « vu à l'instant » serait faux.
                    await ingest.persist_and_notify(db, result, touch_machine=False)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Erreur pendant l'évaluation des fenêtres inactives : %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not await check_connection():
        logger.error(
            "PostgreSQL injoignable. Vérifiez DATABASE_URL dans .env "
            "et que le conteneur est démarré (docker compose up -d db)."
        )
    else:
        await bootstrap()
        logger.info("API EDR %s prête — moteur ML %s", API_VERSION,
                    "actif" if engine.ml_enabled else "inactif")

    tasks = [
        asyncio.create_task(_maintenance_loop()),
        asyncio.create_task(_window_flush_loop()),
    ]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await dispose_engine()


app = FastAPI(
    title="Ransomware Detector API",
    description=(
        "Plateforme EDR multi-analystes : ingestion Sysmon, détection heuristique "
        "et ML, réponse active tracée, synchronisation temps réel."
    ),
    version=API_VERSION,
    lifespan=lifespan,
    # La documentation interactive cartographie l'intégralité de la surface
    # exposée, jusqu'aux routes d'agent. Précieuse en développement, elle offre
    # cette carte à n'importe quel visiteur en production : on la retire.
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)

# Liste blanche explicite. La configuration précédente combinait
# allow_origins=["*"] et allow_credentials=True, ce que les navigateurs
# refusent, et qui autorisait de fait n'importe quelle origine.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Agent-Token", "Authorization"],
)


@app.get("/status", response_model=StatusOut, tags=["system"])
async def get_status(db: AsyncSession = Depends(get_db)):
    """Sonde de santé publique : ne divulgue aucune donnée métier."""
    db_ok = await check_connection()
    pending = 0
    if db_ok:
        pending = (
            await db.scalar(
                select(func.count())
                .select_from(Command)
                .where(
                    Command.status.in_((CommandStatus.PENDING.value, CommandStatus.SENT.value))
                )
            )
            or 0
        )

    return StatusOut(
        status="online" if db_ok else "degraded",
        ml_enabled=engine.ml_enabled,
        database="up" if db_ok else "down",
        version=API_VERSION,
        connected_analysts=hub.connection_count,
        commands_pending=pending,
    )


@app.get("/presence", tags=["system"])
async def presence(current=Depends(require_n1)):
    """Analystes actuellement connectés au canal temps réel."""
    return {"analysts": hub.connected_analysts(), "total_connections": hub.connection_count}


@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    edr_session: str | None = Cookie(default=None, alias=settings.session_cookie_name),
):
    """
    Canal d'invalidation temps réel.

    Authentifié par le même cookie de session que l'API : une connexion anonyme
    est refusée avant l'acceptation du handshake.
    """
    async with SessionFactory() as db:
        resolved = await resolve_session(db, edr_session)

    if resolved is None:
        # 1008 = Policy Violation : le client sait qu'il doit se réauthentifier.
        await websocket.close(code=1008, reason="Session invalide")
        return

    session, user = resolved
    await websocket.accept()
    connection = Connection(
        websocket=websocket, user_id=user.id, email=user.email, role=user.role
    )
    await hub.register(connection)

    try:
        while True:
            # Le client envoie un ping applicatif ; cela maintient la connexion
            # ouverte à travers les proxys et détecte les liens morts.
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("Fermeture du WebSocket de %s : %s", user.email, exc)
    finally:
        await hub.unregister(connection)


app.include_router(auth_router.router)
app.include_router(alerts.router)
app.include_router(metrics.router)
app.include_router(machines.router)
app.include_router(response.router)
app.include_router(exclusions.router)
app.include_router(audit.router)
app.include_router(settings_router.router)
# En dernier : ce router porte les routes de compatibilité Winlogbeat, dont un
# gabarit `/_{path}` qui doit être évalué après toutes les routes applicatives.
app.include_router(ingest.router)
