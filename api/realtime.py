"""
Hub de diffusion temps réel.

Modèle retenu : le WebSocket ne transporte PAS les données métier, seulement des
notifications d'invalidation (« la ressource alerts a changé »). Chaque client
relit ensuite l'endpoint REST correspondant.

Pourquoi ce choix plutôt que pousser les objets complets :
  - la base reste la seule source de vérité, donc deux analystes ne peuvent pas
    afficher des états divergents à cause d'un message perdu ou réordonné ;
  - un client qui se reconnecte après une coupure se resynchronise
    automatiquement, sans rejeu d'historique ;
  - les autorisations sont réévaluées à chaque lecture REST, donc un analyste ne
    peut pas recevoir par le canal temps réel des données que son rôle
    lui interdit.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Set

from fastapi import WebSocket

logger = logging.getLogger("api.realtime")

# Canaux d'invalidation connus du frontend.
CHANNEL_ALERTS = "alerts"
CHANNEL_METRICS = "metrics"
CHANNEL_MACHINES = "machines"
CHANNEL_COMMANDS = "commands"
CHANNEL_AUDIT = "audit"
CHANNEL_EXCLUSIONS = "exclusions"


class Connection:
    __slots__ = ("websocket", "user_id", "email", "role")

    def __init__(self, websocket: WebSocket, user_id: int, email: str, role: str):
        self.websocket = websocket
        self.user_id = user_id
        self.email = email
        self.role = role


class RealtimeHub:
    """Registre des dashboards connectés et diffusion des invalidations."""

    def __init__(self) -> None:
        self._connections: Set[Connection] = set()
        self._lock = asyncio.Lock()

    async def register(self, connection: Connection) -> None:
        async with self._lock:
            self._connections.add(connection)
        logger.info(
            "Dashboard connecté : %s (%s) — %d session(s) active(s)",
            connection.email,
            connection.role,
            len(self._connections),
        )
        await self._send(connection, {"type": "hello", "channels": list(ALL_CHANNELS)})

    async def unregister(self, connection: Connection) -> None:
        async with self._lock:
            self._connections.discard(connection)
        logger.info(
            "Dashboard déconnecté : %s — %d session(s) restante(s)",
            connection.email,
            len(self._connections),
        )

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    def connected_analysts(self) -> list[dict]:
        """Liste des analystes actuellement connectés, pour la présence dans l'UI."""
        seen: Dict[int, dict] = {}
        for conn in self._connections:
            entry = seen.setdefault(
                conn.user_id,
                {"user_id": conn.user_id, "email": conn.email, "role": conn.role, "connections": 0},
            )
            entry["connections"] += 1
        return sorted(seen.values(), key=lambda item: item["email"])

    async def broadcast(self, channel: str, payload: Dict[str, Any] | None = None) -> None:
        """
        Notifie tous les dashboards qu'un canal a changé.

        Ne lève jamais : une panne de diffusion temps réel ne doit pas faire
        échouer l'écriture métier qui vient d'aboutir en base. Les clients
        retombent sur leur polling de repli.
        """
        message = {
            "type": "invalidate",
            "channel": channel,
            "at": datetime.now(timezone.utc).isoformat(),
        }
        if payload:
            message["payload"] = payload

        async with self._lock:
            targets = list(self._connections)

        if not targets:
            return

        results = await asyncio.gather(
            *(self._send(conn, message) for conn in targets), return_exceptions=True
        )

        dead = [conn for conn, result in zip(targets, results) if result is not True]
        if dead:
            async with self._lock:
                for conn in dead:
                    self._connections.discard(conn)

    async def broadcast_many(self, channels: list[str]) -> None:
        for channel in channels:
            await self.broadcast(channel)

    @staticmethod
    async def _send(connection: Connection, message: Dict[str, Any]) -> bool:
        try:
            await connection.websocket.send_json(message)
            return True
        except Exception:
            return False


ALL_CHANNELS = (
    CHANNEL_ALERTS,
    CHANNEL_METRICS,
    CHANNEL_MACHINES,
    CHANNEL_COMMANDS,
    CHANNEL_AUDIT,
    CHANNEL_EXCLUSIONS,
)

hub = RealtimeHub()
