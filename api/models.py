"""
Modèle de données PostgreSQL de la plateforme EDR.

Principe directeur : la base est la SEULE source de vérité. Aucun état
opérationnel partagé entre analystes ne réside en mémoire du processus API,
afin que tous les postes connectés voient rigoureusement les mêmes données.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ─────────────────────────────────────────────────────────────────────
# Énumérations métier (validées côté Python, stockées en texte pour
# rester migrables sans ALTER TYPE)
# ─────────────────────────────────────────────────────────────────────


class Role(str, enum.Enum):
    """Niveaux SOC. L'ordre définit la hiérarchie de privilèges."""

    N1 = "N1"  # Analyste SOC — lecture, prise en charge d'alertes
    N2 = "N2"  # Analyste EDR — réponse active (kill, isolation)
    N3 = "N3"  # SOC Manager — administration complète

    @property
    def level(self) -> int:
        return {"N1": 1, "N2": 2, "N3": 3}[self.value]

    def satisfies(self, required: "Role") -> bool:
        return self.level >= required.level


ROLE_LABELS: Dict[str, str] = {
    "N1": "Analyste SOC (N1)",
    "N2": "Analyste EDR (N2)",
    "N3": "SOC Manager (N3)",
}

ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "N1": ["Lecture", "Analyse", "Prise en charge d'alerte"],
    "N2": ["Lecture", "Analyse", "Prise en charge d'alerte", "Kill process", "Isolation réseau"],
    "N3": [
        "Lecture",
        "Analyse",
        "Prise en charge d'alerte",
        "Kill process",
        "Isolation réseau",
        "Exclusions",
        "Gestion des comptes",
        "Configuration système",
    ],
}


class AlertStatus(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class CommandAction(str, enum.Enum):
    KILL = "KILL"
    ISOLATE = "ISOLATE"
    UNISOLATE = "UNISOLATE"


class CommandStatus(str, enum.Enum):
    PENDING = "pending"
    SENT = "sent"
    ACKED = "acked"
    FAILED = "failed"
    EXPIRED = "expired"


class CommandOrigin(str, enum.Enum):
    AUTO = "auto"  # déclenchée par le moteur de détection
    MANUAL = "manual"  # déclenchée par un analyste


class MachineStatus(str, enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    ISOLATED = "isolated"


# ─────────────────────────────────────────────────────────────────────
# Comptes et sessions
# ─────────────────────────────────────────────────────────────────────


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    # "argon2" pour les comptes modernes, "sha256-legacy" pour les comptes
    # importés de l'ancienne base SQLite (réhachés au premier login réussi).
    hash_algo: Mapped[str] = mapped_column(String(32), nullable=False, default="argon2")
    role: Mapped[str] = mapped_column(String(2), nullable=False, default=Role.N1.value)
    full_name: Mapped[Optional[str]] = mapped_column(String(120))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    sessions: Mapped[List["Session"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint("role IN ('N1','N2','N3')", name="ck_users_role"),
    )

    @property
    def role_enum(self) -> Role:
        return Role(self.role)

    @property
    def role_label(self) -> str:
        return ROLE_LABELS.get(self.role, self.role)

    @property
    def permissions(self) -> List[str]:
        return ROLE_PERMISSIONS.get(self.role, [])


class Session(Base):
    """
    Session serveur opaque. Seul le SHA-256 du token est stocké : une fuite de
    base ne permet pas de rejouer les sessions.
    """

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    ip_source: Mapped[Optional[str]] = mapped_column(String(64))
    user_agent: Mapped[Optional[str]] = mapped_column(String(400))

    user: Mapped["User"] = relationship(back_populates="sessions")


# ─────────────────────────────────────────────────────────────────────
# Parc surveillé
# ─────────────────────────────────────────────────────────────────────


class Machine(Base):
    __tablename__ = "machines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    machine_id: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(120))
    ip_address: Mapped[Optional[str]] = mapped_column(String(64))
    os_name: Mapped[Optional[str]] = mapped_column(String(120))
    agent_version: Mapped[Optional[str]] = mapped_column(String(32))

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=MachineStatus.ONLINE.value
    )
    is_isolated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    events_received: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    alerts: Mapped[List["Alert"]] = relationship(back_populates="machine")


# ─────────────────────────────────────────────────────────────────────
# Alertes
# ─────────────────────────────────────────────────────────────────────


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    machine_pk: Mapped[Optional[int]] = mapped_column(
        ForeignKey("machines.id", ondelete="SET NULL"), index=True
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    source: Mapped[str] = mapped_column(String(40), nullable=False)  # RulesEngine | RandomForest
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # low | medium | high
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="LOW")

    pid: Mapped[Optional[int]] = mapped_column(Integer)
    process_name: Mapped[Optional[str]] = mapped_column(String(255))
    parent_name: Mapped[Optional[str]] = mapped_column(String(255))
    parent_pid: Mapped[Optional[int]] = mapped_column(Integer)

    reasons: Mapped[List[str]] = mapped_column(JSONB, nullable=False, default=list)
    # Charge utile complète (stats du top suspect, payload KILL) conservée pour
    # le volet forensics du dashboard.
    payload: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # Cycle de vie collaboratif : c'est ce qui permet à plusieurs analystes de
    # se répartir le travail sans se marcher dessus.
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=AlertStatus.NEW.value, index=True
    )
    assigned_to: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    closed_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    resolution_note: Mapped[Optional[str]] = mapped_column(Text)

    machine: Mapped[Optional["Machine"]] = relationship(back_populates="alerts")
    assignee: Mapped[Optional["User"]] = relationship(foreign_keys=[assigned_to])

    __table_args__ = (
        Index("ix_alerts_detected_desc", detected_at.desc()),
        Index("ix_alerts_status_detected", "status", detected_at.desc()),
        CheckConstraint(
            "status IN ('new','acknowledged','in_progress','closed','false_positive')",
            name="ck_alerts_status",
        ),
    )


# ─────────────────────────────────────────────────────────────────────
# Séries temporelles (alimentent le graphique partagé du dashboard)
# ─────────────────────────────────────────────────────────────────────


class Metric(Base):
    """
    Une ligne par fenêtre de features fermée, par machine. C'est la table qui
    remplace les données codées en dur du graphique « Vue d'ensemble du SOC ».
    """

    __tablename__ = "metrics"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    machine_pk: Mapped[Optional[int]] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), index=True
    )
    bucket_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=10)

    files_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    files_deleted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    files_renamed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_extensions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    entropy_filenames: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    processes_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    child_processes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    process_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    connections: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_ips: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    external_connections: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dns_queries: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    is_alert: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    baseline_trained: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        Index("ix_metrics_machine_bucket", "machine_pk", bucket_at.desc()),
    )


# ─────────────────────────────────────────────────────────────────────
# File de commandes de réponse active
# ─────────────────────────────────────────────────────────────────────


class Command(Base):
    """
    Remplace la liste `pending_commands` qui vivait en RAM. Persistée, tracée,
    idempotente et acquittée par l'agent : une commande n'est plus perdue au
    redémarrage ni consommée par le mauvais worker.
    """

    __tablename__ = "commands"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    machine_pk: Mapped[Optional[int]] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), index=True
    )
    alert_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL")
    )

    action: Mapped[str] = mapped_column(String(20), nullable=False)
    target_pid: Mapped[Optional[int]] = mapped_column(Integer)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=CommandStatus.PENDING.value, index=True
    )
    origin: Mapped[str] = mapped_column(String(10), nullable=False, default=CommandOrigin.AUTO.value)

    created_by: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    acked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    result: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)

    machine: Mapped[Optional["Machine"]] = relationship()
    author: Mapped[Optional["User"]] = relationship()

    __table_args__ = (
        CheckConstraint("action IN ('KILL','ISOLATE','UNISOLATE')", name="ck_commands_action"),
        CheckConstraint(
            "status IN ('pending','sent','acked','failed','expired')",
            name="ck_commands_status",
        ),
        Index("ix_commands_dispatch", "machine_pk", "status", "created_at"),
    )


# ─────────────────────────────────────────────────────────────────────
# Exclusions, audit, configuration
# ─────────────────────────────────────────────────────────────────────


class Exclusion(Base):
    __tablename__ = "exclusions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(20), nullable=False)  # Folder | Process | Extension
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    comment: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_by: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    author: Mapped[Optional["User"]] = relationship()

    __table_args__ = (
        UniqueConstraint("type", "path", name="uq_exclusions_type_path"),
        CheckConstraint("type IN ('Folder','Process','Extension')", name="ck_exclusions_type"),
    )


class AuditLog(Base):
    """
    Journal d'audit écrit exclusivement par le serveur. Le client ne peut plus
    forger d'entrée ni déclarer une fausse IP source.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    # Libellé figé au moment de l'action (survit à la suppression du compte, et
    # permet de tracer les actions automatiques du moteur).
    actor_label: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    target: Mapped[Optional[str]] = mapped_column(String(255))
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    ip_source: Mapped[Optional[str]] = mapped_column(String(64))
    user_agent: Mapped[Optional[str]] = mapped_column(String(400))
    result: Mapped[str] = mapped_column(String(16), nullable=False, default="success")

    user: Mapped[Optional["User"]] = relationship()

    __table_args__ = (Index("ix_audit_occurred_desc", occurred_at.desc()),)


class AppSetting(Base):
    """Configuration système modifiable depuis l'onglet Configuration (N3)."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_by: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
