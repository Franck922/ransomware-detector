"""
Séries temporelles et indicateurs de la vue d'ensemble du SOC.

C'est le remplacement direct des données codées en dur du dashboard :
l'AreaChart, la jauge de risque, les compteurs de terminaux et les
« performances ML » étaient des constantes dans le JSX. Tout est désormais
agrégé en base côté serveur, donc identique pour chaque analyste connecté.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.db import get_db
from api.detection import engine
from api.models import Alert, AlertStatus, Command, CommandStatus, Machine, Metric
from api.realtime import hub
from api.schemas import OverviewOut, TimeseriePoint, TimeserieOut
from api.security import CurrentUser, require_n1

router = APIRouter(prefix="/metrics", tags=["metrics"])

OPEN_STATES = (
    AlertStatus.NEW.value,
    AlertStatus.ACKNOWLEDGED.value,
    AlertStatus.IN_PROGRESS.value,
)

ONLINE_WINDOW_SECONDS = 120


def _risk_label(score: int) -> str:
    if score >= 75:
        return "Critique"
    if score >= 50:
        return "Élevé"
    if score >= 25:
        return "Modéré"
    return "Faible"


@router.get("/timeseries", response_model=TimeserieOut)
async def timeseries(
    window_minutes: int = Query(default=15, ge=1, le=1440),
    bucket_seconds: int = Query(default=10, ge=10, le=3600),
    machine_id: Optional[str] = Query(default=None),
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    """
    Agrège la table `metrics` en intervalles réguliers. Les intervalles sans
    activité sont renvoyés à zéro afin que la courbe reste continue côté client
    sans qu'il ait à inventer de données.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=window_minutes)

    machine_pk: Optional[int] = None
    if machine_id:
        machine_pk = await db.scalar(select(Machine.id).where(Machine.machine_id == machine_id))
        if machine_pk is None:
            return TimeserieOut(
                window_minutes=window_minutes,
                bucket_seconds=bucket_seconds,
                machine_id=machine_id,
                points=[],
            )

    # date_bin (PostgreSQL 14+) aligne les intervalles sur une origine fixe :
    # tous les clients obtiennent donc exactement les mêmes bornes.
    # Les paramètres sont castés explicitement : asyncpg ne sait pas inférer le
    # type d'un paramètre valant NULL (filtre machine facultatif).
    metrics_sql = text(
        """
        SELECT date_bin(make_interval(secs => CAST(:bucket AS INTEGER)), bucket_at,
                        TIMESTAMPTZ '2000-01-01 00:00:00+00') AS bucket,
               COALESCE(SUM(files_created), 0)        AS files_created,
               COALESCE(SUM(files_deleted), 0)        AS files_deleted,
               COALESCE(SUM(files_renamed), 0)        AS files_renamed,
               COALESCE(MAX(entropy_filenames), 0)    AS entropy_max,
               COALESCE(AVG(entropy_filenames), 0)    AS entropy_avg,
               COALESCE(SUM(processes_created), 0)    AS processes_created,
               COALESCE(SUM(connections), 0)          AS connections,
               COALESCE(SUM(external_connections), 0) AS external_connections
          FROM metrics
         WHERE bucket_at >= CAST(:since AS TIMESTAMPTZ)
           AND (CAST(:machine_pk AS INTEGER) IS NULL
                OR machine_pk = CAST(:machine_pk AS INTEGER))
         GROUP BY bucket
         ORDER BY bucket
        """
    )

    alerts_sql = text(
        """
        SELECT date_bin(make_interval(secs => CAST(:bucket AS INTEGER)), detected_at,
                        TIMESTAMPTZ '2000-01-01 00:00:00+00') AS bucket,
               COUNT(*) AS alerts
          FROM alerts
         WHERE detected_at >= CAST(:since AS TIMESTAMPTZ)
           AND (CAST(:machine_pk AS INTEGER) IS NULL
                OR machine_pk = CAST(:machine_pk AS INTEGER))
         GROUP BY bucket
         ORDER BY bucket
        """
    )

    params = {"bucket": bucket_seconds, "since": since, "machine_pk": machine_pk}
    metric_rows = (await db.execute(metrics_sql, params)).mappings().all()
    alert_rows = (await db.execute(alerts_sql, params)).mappings().all()

    by_bucket: Dict[datetime, dict] = {row["bucket"]: dict(row) for row in metric_rows}
    alerts_by_bucket: Dict[datetime, int] = {row["bucket"]: row["alerts"] for row in alert_rows}

    # Reconstruction de la grille complète pour éviter les trous visuels.
    step = timedelta(seconds=bucket_seconds)
    origin = datetime(2000, 1, 1, tzinfo=timezone.utc)
    aligned_start = origin + step * ((since - origin) // step)

    points: List[TimeseriePoint] = []
    cursor = aligned_start
    while cursor <= now:
        row = by_bucket.get(cursor)
        points.append(
            TimeseriePoint(
                bucket=cursor,
                files_created=int(row["files_created"]) if row else 0,
                files_deleted=int(row["files_deleted"]) if row else 0,
                files_renamed=int(row["files_renamed"]) if row else 0,
                entropy_max=round(float(row["entropy_max"]), 3) if row else 0.0,
                entropy_avg=round(float(row["entropy_avg"]), 3) if row else 0.0,
                processes_created=int(row["processes_created"]) if row else 0,
                connections=int(row["connections"]) if row else 0,
                external_connections=int(row["external_connections"]) if row else 0,
                alerts=int(alerts_by_bucket.get(cursor, 0)),
            )
        )
        cursor += step

    return TimeserieOut(
        window_minutes=window_minutes,
        bucket_seconds=bucket_seconds,
        machine_id=machine_id,
        points=points,
    )


@router.get("/overview", response_model=OverviewOut)
async def overview(
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    online_since = now - timedelta(seconds=ONLINE_WINDOW_SECONDS)
    day_ago = now - timedelta(hours=24)
    hour_ago = now - timedelta(hours=1)

    machines_total = await db.scalar(select(func.count()).select_from(Machine)) or 0
    machines_online = (
        await db.scalar(
            select(func.count())
            .select_from(Machine)
            .where(Machine.last_seen_at >= online_since, Machine.is_isolated.is_(False))
        )
        or 0
    )
    machines_isolated = (
        await db.scalar(
            select(func.count()).select_from(Machine).where(Machine.is_isolated.is_(True))
        )
        or 0
    )

    alerts_total = await db.scalar(select(func.count()).select_from(Alert)) or 0
    alerts_open = (
        await db.scalar(select(func.count()).select_from(Alert).where(Alert.status.in_(OPEN_STATES)))
        or 0
    )
    alerts_last_24h = (
        await db.scalar(select(func.count()).select_from(Alert).where(Alert.detected_at >= day_ago))
        or 0
    )
    alerts_critical_open = (
        await db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.status.in_(OPEN_STATES), Alert.severity == "high")
        )
        or 0
    )
    alerts_medium_open = (
        await db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.status.in_(OPEN_STATES), Alert.severity == "medium")
        )
        or 0
    )

    commands_pending = (
        await db.scalar(
            select(func.count())
            .select_from(Command)
            .where(Command.status.in_((CommandStatus.PENDING.value, CommandStatus.SENT.value)))
        )
        or 0
    )

    events_last_hour = (
        await db.scalar(
            select(
                func.coalesce(
                    func.sum(
                        Metric.files_created
                        + Metric.files_deleted
                        + Metric.processes_created
                        + Metric.connections
                    ),
                    0,
                )
            ).where(Metric.bucket_at >= hour_ago)
        )
        or 0
    )

    # Score de risque explicable et reproductible : mêmes entrées => même
    # sortie pour tous les analystes, contrairement au « 92 % » forfaitaire.
    low_open = max(alerts_open - alerts_critical_open - alerts_medium_open, 0)
    risk = 0
    risk += min(50, 10 * alerts_critical_open)
    risk += min(20, 4 * alerts_medium_open)
    risk += min(10, 2 * low_open)
    risk += 15 if machines_isolated else 0
    risk += min(5, commands_pending)
    risk = min(risk, 100)

    return OverviewOut(
        generated_at=now,
        machines_total=machines_total,
        machines_online=machines_online,
        machines_isolated=machines_isolated,
        alerts_total=alerts_total,
        alerts_open=alerts_open,
        alerts_last_24h=alerts_last_24h,
        alerts_critical_open=alerts_critical_open,
        commands_pending=commands_pending,
        risk_score=risk,
        risk_label=_risk_label(risk),
        ml_enabled=engine.ml_enabled,
        baseline_trained_machines=engine.baseline_trained_machines(),
        events_last_hour=int(events_last_hour),
        connected_analysts=hub.connection_count,
    )


@router.get("/ml-insights")
async def ml_insights(
    current: CurrentUser = Depends(require_n1),
    db: AsyncSession = Depends(get_db),
):
    """Caractéristiques réelles du modèle chargé et avancement des baselines."""
    detections_by_source = (
        await db.execute(
            select(Alert.source, func.count()).group_by(Alert.source).order_by(func.count().desc())
        )
    ).all()

    return {
        "model": engine.model_info(),
        "feature_importances": engine.feature_importances(),
        "detections_by_source": [
            {"source": source, "count": count} for source, count in detections_by_source
        ],
        "baseline_progress": engine.baseline_progress(),
    }
