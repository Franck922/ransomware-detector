"""
Reprise des données de l'ancienne base SQLite (alerts.db) vers PostgreSQL.

Script idempotent : il peut être relancé sans créer de doublon. Le fichier
alerts.db n'est jamais modifié ni supprimé, il reste disponible comme
sauvegarde.

Usage :
    python -m scripts.migrate_sqlite_to_pg [--sqlite alerts.db] [--dry-run]

Points de vigilance traités :
  - les rôles de l'ancienne base sont des libellés libres ("SOC Manager (N3)")
    et sont normalisés vers N1/N2/N3 ;
  - les mots de passe SHA-256 non salés sont conservés avec l'algorithme marqué
    `sha256-legacy` et un changement de mot de passe obligatoire, puisqu'ils
    proviennent tous du même secret de démonstration ;
  - certaines chaînes de l'ancienne base ont été écrites en cp1252 et ne sont
    pas de l'UTF-8 valide : elles sont décodées avec repli.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session as OrmSession

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.config import settings  # noqa: E402
from api.models import (  # noqa: E402
    Alert,
    AlertStatus,
    AppSetting,
    AuditLog,
    Exclusion,
    Machine,
    Role,
    User,
)
from api.security import LEGACY_ALGO  # noqa: E402

DEFAULT_SETTINGS: dict[str, Any] = {
    "detection": {
        "auto_kill_score_threshold": settings.auto_kill_score_threshold,
        "rules_alert_threshold": settings.rules_alert_threshold,
        "baseline_min_vectors": settings.baseline_min_vectors,
    },
    "retention": {"metrics_days": settings.metrics_retention_days, "alerts_days": 365},
    "notifications": {"email_enabled": False, "webhook_url": ""},
}


def decode_text(raw: Any) -> Optional[str]:
    """Décode une valeur SQLite lue en bytes, avec repli cp1252/latin-1."""
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (int, float)):
        return str(raw)
    for encoding in ("utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, AttributeError):
            continue
    return raw.decode("utf-8", errors="replace")


def normalize_role(label: Optional[str]) -> str:
    """"SOC Manager (N3)" -> "N3". Repli prudent sur le rôle le moins privilégié."""
    if not label:
        return Role.N1.value
    upper = label.upper()
    for level in ("N3", "N2", "N1"):
        if level in upper:
            return level
    if "MANAGER" in upper or "ADMIN" in upper:
        return Role.N3.value
    return Role.N1.value


def parse_timestamp(raw: Optional[str]) -> datetime:
    """
    Les horodatages de l'ancienne base sont naïfs ('YYYY-MM-DD HH:MM:SS') et ont
    été produits par datetime.now(), donc en heure locale du serveur.
    """
    text = decode_text(raw)
    if not text:
        return datetime.now(timezone.utc)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(text, fmt).astimezone()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text).astimezone()
    except ValueError:
        return datetime.now(timezone.utc)


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


class Report:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def add(self, table: str, imported: int, skipped: int) -> None:
        self.lines.append(f"  {table:<14} importées={imported:<5} déjà présentes={skipped}")

    def render(self) -> str:
        return "\n".join(self.lines)


def migrate(sqlite_path: Path, dry_run: bool = False) -> int:
    if not sqlite_path.exists():
        print(f"[!] Base SQLite introuvable : {sqlite_path}")
        print("    Rien à reprendre, la base PostgreSQL restera vide.")
        return 0

    sqlite_conn = sqlite3.connect(str(sqlite_path))
    sqlite_conn.text_factory = bytes  # décodage géré manuellement
    sqlite_conn.row_factory = sqlite3.Row

    engine = create_engine(settings.sync_database_url)
    report = Report()

    def table_exists(name: str) -> bool:
        row = sqlite_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        return row is not None

    with OrmSession(engine) as db:
        # ── Utilisateurs ────────────────────────────────────────────
        imported = skipped = 0
        if table_exists("users"):
            for row in sqlite_conn.execute("SELECT * FROM users"):
                email = decode_text(row["email"])
                if not email:
                    continue
                existing = db.scalar(select(User).where(User.email == email))
                if existing:
                    skipped += 1
                    continue
                db.add(
                    User(
                        email=email,
                        password_hash=decode_text(row["password_hash"]) or "",
                        hash_algo=LEGACY_ALGO,
                        role=normalize_role(decode_text(row["role"])),
                        is_active=True,
                        # Tous les comptes de l'ancienne base partagent le même
                        # secret de démonstration : rotation imposée.
                        must_change_password=True,
                    )
                )
                imported += 1
        report.add("users", imported, skipped)

        # ── Exclusions ──────────────────────────────────────────────
        imported = skipped = 0
        if table_exists("exclusions"):
            for row in sqlite_conn.execute("SELECT * FROM exclusions"):
                exc_type = decode_text(row["type"]) or "Folder"
                path = decode_text(row["path"])
                if not path:
                    continue
                if exc_type not in ("Folder", "Process", "Extension"):
                    exc_type = "Folder"
                existing = db.scalar(
                    select(Exclusion).where(Exclusion.type == exc_type, Exclusion.path == path)
                )
                if existing:
                    skipped += 1
                    continue
                db.add(
                    Exclusion(
                        type=exc_type,
                        path=path,
                        comment=decode_text(row["comment"]) or "",
                        enabled=True,
                    )
                )
                imported += 1
        report.add("exclusions", imported, skipped)

        db.flush()

        # ── Journal d'audit ─────────────────────────────────────────
        # Rattachement au compte quand l'email correspond, sinon on conserve
        # seulement le libellé d'acteur.
        users_by_email = {u.email: u.id for u in db.scalars(select(User))}

        imported = skipped = 0
        if table_exists("audit_logs"):
            for row in sqlite_conn.execute("SELECT * FROM audit_logs ORDER BY id"):
                occurred_at = parse_timestamp(row["timestamp"])
                actor = decode_text(row["username"]) or "inconnu"
                action = (decode_text(row["action"]) or "action")[:80]

                existing = db.scalar(
                    select(AuditLog).where(
                        AuditLog.occurred_at == occurred_at,
                        AuditLog.actor_label == actor,
                        AuditLog.action == action,
                    )
                )
                if existing:
                    skipped += 1
                    continue

                db.add(
                    AuditLog(
                        occurred_at=occurred_at,
                        user_id=users_by_email.get(actor),
                        actor_label=actor[:255],
                        action=action,
                        details={
                            "message": decode_text(row["details"]) or "",
                            "imported_from": "sqlite",
                        },
                        ip_source=decode_text(row["ip_source"]),
                        result="success",
                    )
                )
                imported += 1
        report.add("audit_logs", imported, skipped)

        # ── Alertes ─────────────────────────────────────────────────
        imported = skipped = 0
        machines_cache: dict[str, Machine] = {}

        if table_exists("alerts"):
            for row in sqlite_conn.execute("SELECT * FROM alerts ORDER BY id"):
                detected_at = parse_timestamp(row["timestamp"])
                source = (decode_text(row["source"]) or "RulesEngine")[:40]

                try:
                    payload = json.loads(decode_text(row["kill_payload"]) or "{}")
                except json.JSONDecodeError:
                    payload = {}

                existing = db.scalar(
                    select(Alert).where(
                        Alert.detected_at == detected_at,
                        Alert.source == source,
                        Alert.pid == payload.get("pid"),
                    )
                )
                if existing:
                    skipped += 1
                    continue

                # L'ancien schéma ne stockait pas la machine : on rattache au
                # poste unique du lab pour ne pas perdre le contexte.
                machine_key = payload.get("machine_id") or "VM-WIN10-LAB"
                machine = machines_cache.get(machine_key)
                if machine is None:
                    machine = db.scalar(select(Machine).where(Machine.machine_id == machine_key))
                    if machine is None:
                        machine = Machine(
                            machine_id=machine_key,
                            hostname=machine_key,
                            status="offline",
                        )
                        db.add(machine)
                        db.flush()
                    machines_cache[machine_key] = machine

                score = int(payload.get("score") or 0)
                db.add(
                    Alert(
                        machine_pk=machine.id,
                        detected_at=detected_at,
                        source=source,
                        severity=severity_from_score(score),
                        score=score,
                        confidence=payload.get("confidence", "LOW"),
                        pid=payload.get("pid"),
                        process_name=payload.get("process"),
                        parent_name=payload.get("parent"),
                        parent_pid=payload.get("parent_pid"),
                        reasons=payload.get("reasons") or [],
                        payload=payload,
                        status=AlertStatus.NEW.value,
                    )
                )
                imported += 1
        report.add("alerts", imported, skipped)

        # ── Configuration système par défaut ────────────────────────
        imported = skipped = 0
        for key, value in DEFAULT_SETTINGS.items():
            if db.get(AppSetting, key):
                skipped += 1
                continue
            db.add(AppSetting(key=key, value=value))
            imported += 1
        report.add("app_settings", imported, skipped)

        if dry_run:
            db.rollback()
            print("[dry-run] Aucune écriture effectuée.\n")
        else:
            db.commit()

    sqlite_conn.close()

    print("Reprise SQLite -> PostgreSQL terminée.")
    print(report.render())
    if not dry_run:
        print(f"\n  Sauvegarde conservée : {sqlite_path}")
        print("  Les comptes importés doivent changer de mot de passe au prochain login.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Reprise SQLite -> PostgreSQL")
    parser.add_argument("--sqlite", default="alerts.db", help="Chemin de l'ancienne base")
    parser.add_argument("--dry-run", action="store_true", help="Simule sans écrire")
    args = parser.parse_args()

    return migrate(Path(args.sqlite).resolve(), dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
