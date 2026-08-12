"""Schémas Pydantic : contrat d'entrée/sortie de l'API EDR."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from api.models import AlertStatus, Role

# `EmailStr` de Pydantic refuse les TLD à usage réservé, dont `.local` — or les
# comptes du SOC sont sur un domaine interne (franck@soc.edr.local). On valide
# donc la forme de l'adresse, en normalisant casse et espaces.
EmailField = Annotated[
    str,
    StringConstraints(
        pattern=r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$",
        min_length=5,
        max_length=255,
        strip_whitespace=True,
        to_lower=True,
    ),
]


# ─────────────────────────────────────────────────────────────────────
# Ingestion (inchangé côté agents)
# ─────────────────────────────────────────────────────────────────────


class IngestPayload(BaseModel):
    """Format attendu par /ingest."""

    machine_id: str = Field(..., description="Identifiant de la machine source (ex: VM-WIN10-LAB)")
    batch: List[Dict[str, Any]] = Field(..., description="Événements Sysmon bruts ou normalisés")


class ResponseMessage(BaseModel):
    status: str
    message: str
    processed_events: Optional[int] = 0


# ─────────────────────────────────────────────────────────────────────
# Authentification
# ─────────────────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    email: EmailField
    password: str = Field(..., min_length=1, max_length=200)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=200)
    new_password: str = Field(..., min_length=1, max_length=200)


class UserCreateRequest(BaseModel):
    """
    Création de compte réservée au N3. Le rôle n'est plus choisi par
    l'utilisateur qui s'inscrit : c'était une escalade de privilèges directe.
    """

    email: EmailField
    password: str = Field(..., min_length=1, max_length=200)
    role: Role = Role.N1
    full_name: Optional[str] = Field(default=None, max_length=120)


class UserUpdateRequest(BaseModel):
    role: Optional[Role] = None
    is_active: Optional[bool] = None
    full_name: Optional[str] = Field(default=None, max_length=120)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    role: str
    role_label: str
    permissions: List[str]
    full_name: Optional[str] = None
    is_active: bool
    must_change_password: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime


class SessionInfo(BaseModel):
    user: UserOut
    expires_at: datetime
    connected_analysts: int


# ─────────────────────────────────────────────────────────────────────
# Machines
# ─────────────────────────────────────────────────────────────────────


class MachineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    machine_id: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_name: Optional[str] = None
    agent_version: Optional[str] = None
    status: str
    is_isolated: bool
    first_seen_at: datetime
    last_seen_at: datetime
    events_received: int
    open_alerts: int = 0


# ─────────────────────────────────────────────────────────────────────
# Alertes
# ─────────────────────────────────────────────────────────────────────


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    detected_at: datetime
    machine_id: Optional[str] = None
    source: str
    severity: str
    score: int
    confidence: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    parent_name: Optional[str] = None
    parent_pid: Optional[int] = None
    reasons: List[str] = []
    payload: Dict[str, Any] = {}
    status: str
    assigned_to: Optional[int] = None
    assigned_to_email: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    resolution_note: Optional[str] = None


class AlertListOut(BaseModel):
    items: List[AlertOut]
    total: int
    limit: int
    offset: int


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    resolution_note: Optional[str] = Field(default=None, max_length=2000)


# ─────────────────────────────────────────────────────────────────────
# Métriques / vue d'ensemble
# ─────────────────────────────────────────────────────────────────────


class TimeseriePoint(BaseModel):
    bucket: datetime
    files_created: int
    files_deleted: int
    files_renamed: int
    entropy_max: float
    entropy_avg: float
    processes_created: int
    connections: int
    external_connections: int
    alerts: int


class TimeserieOut(BaseModel):
    window_minutes: int
    bucket_seconds: int
    machine_id: Optional[str] = None
    points: List[TimeseriePoint]


class OverviewOut(BaseModel):
    """
    Tous les indicateurs du tableau de bord, calculés côté serveur : c'est ce
    qui garantit que deux analystes lisent exactement les mêmes chiffres.
    """

    generated_at: datetime
    machines_total: int
    machines_online: int
    machines_isolated: int
    alerts_total: int
    alerts_open: int
    alerts_last_24h: int
    alerts_critical_open: int
    commands_pending: int
    risk_score: int
    risk_label: str
    ml_enabled: bool
    baseline_trained_machines: int
    events_last_hour: int
    connected_analysts: int


# ─────────────────────────────────────────────────────────────────────
# Réponse active
# ─────────────────────────────────────────────────────────────────────


class KillRequest(BaseModel):
    machine_id: str
    pid: int = Field(..., gt=0)
    alert_id: Optional[int] = None
    reason: Optional[str] = Field(default=None, max_length=500)


class IsolateRequest(BaseModel):
    machine_id: str
    reason: Optional[str] = Field(default=None, max_length=500)


class CommandOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    machine_id: Optional[str] = None
    action: str
    target_pid: Optional[int] = None
    status: str
    origin: str
    created_at: datetime
    created_by_email: Optional[str] = None
    sent_at: Optional[datetime] = None
    acked_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    payload: Dict[str, Any] = {}


class CommandAckRequest(BaseModel):
    command_id: int
    success: bool = True
    message: Optional[str] = Field(default=None, max_length=1000)


# ─────────────────────────────────────────────────────────────────────
# Exclusions / audit / configuration
# ─────────────────────────────────────────────────────────────────────


class ExclusionCreate(BaseModel):
    type: str = Field(..., pattern="^(Folder|Process|Extension)$")
    path: str = Field(..., min_length=1, max_length=500)
    comment: str = Field(default="", max_length=500)


class ExclusionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    type: str
    path: str
    comment: str
    enabled: bool
    created_at: datetime
    created_by_email: Optional[str] = None


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    occurred_at: datetime
    actor_label: str
    action: str
    target: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    ip_source: Optional[str] = None
    result: str


class AuditListOut(BaseModel):
    items: List[AuditLogOut]
    total: int
    limit: int
    offset: int


class SettingUpdate(BaseModel):
    value: Dict[str, Any]


class SettingOut(BaseModel):
    key: str
    value: Dict[str, Any]
    updated_at: datetime
    updated_by_email: Optional[str] = None


class StatusOut(BaseModel):
    status: str
    ml_enabled: bool
    database: str
    version: str
    connected_analysts: int
    commands_pending: int
