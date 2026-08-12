"""
Configuration centralisée de l'API EDR.

Toutes les valeurs sont surchargeables par variables d'environnement ou via le
fichier .env à la racine du projet. Plus aucun secret ni chemin n'est codé en dur
dans le code applicatif.
"""

from functools import lru_cache
from pathlib import Path
from typing import List, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # ── Environnement ────────────────────────────────────────────────
    app_env: Literal["development", "production"] = "development"
    log_level: str = "INFO"

    # ── Base de données ──────────────────────────────────────────────
    # Format asyncpg. Alembic dérive automatiquement l'URL synchrone.
    database_url: str = "postgresql+asyncpg://edr:edr_dev_password@localhost:5432/edr"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_echo: bool = False

    # ── Sessions / cookies ───────────────────────────────────────────
    session_secret: str = "dev-only-secret-change-me"
    session_cookie_name: str = "edr_session"
    session_ttl_hours: int = 12
    # En production derrière HTTPS, cookie_secure doit valoir True.
    cookie_secure: bool = False
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"

    # ── Politique de mots de passe / anti-bruteforce ──────────────────
    password_min_length: int = 12
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    # ── CORS ─────────────────────────────────────────────────────────
    # Inutile derrière le reverse proxy (origine unique), conservé pour le
    # mode dev où Vite tourne sur un port distinct.
    # Déclaré en chaîne : pydantic-settings tenterait un décodage JSON sur une
    # annotation List[str] lue depuis .env.
    allowed_origins_raw: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173",
        alias="ALLOWED_ORIGINS",
    )

    # ── Authentification des agents (VM surveillées) ──────────────────
    agent_token: str = "dev-agent-token-change-me"

    # ── Compte d'amorçage ────────────────────────────────────────────
    bootstrap_admin_email: str = "franck@soc.edr.local"
    bootstrap_admin_password: str = ""

    # ── Rétention des métriques ──────────────────────────────────────
    metrics_retention_days: int = 30

    # ── Moteur de détection ──────────────────────────────────────────
    auto_kill_score_threshold: int = 80
    baseline_min_vectors: int = 10
    rules_alert_threshold: float = 0.70

    @property
    def allowed_origins(self) -> List[str]:
        return [item.strip() for item in self.allowed_origins_raw.split(",") if item.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def sync_database_url(self) -> str:
        """URL synchrone (psycopg2) utilisée par Alembic et les scripts."""
        return self.database_url.replace("+asyncpg", "+psycopg2")

    def assert_production_ready(self) -> List[str]:
        """
        Retourne la liste des secrets laissés à leur valeur de développement.
        Bloquant en production, simple avertissement en développement.
        """
        problems = []
        if self.session_secret == "dev-only-secret-change-me":
            problems.append("SESSION_SECRET utilise la valeur de développement")
        if self.agent_token == "dev-agent-token-change-me":
            problems.append("AGENT_TOKEN utilise la valeur de développement")
        if not self.cookie_secure:
            problems.append("COOKIE_SECURE=false (cookies transmis en clair)")
        if "*" in self.allowed_origins:
            problems.append("ALLOWED_ORIGINS contient un joker '*'")
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
