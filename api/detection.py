"""
Moteur de détection : orchestration parser -> features -> baseline -> règles + ML.

Deux corrections structurelles par rapport à l'ancien main.py :

1. L'état du pipeline est désormais cloisonné PAR MACHINE. Auparavant un unique
   `FeatureExtractor` et une unique `BaselineEngine` étaient partagés par tous
   les postes surveillés : les événements de deux machines se mélangeaient dans
   la même fenêtre de 10 s, ce qui faussait les compteurs et rendait la baseline
   inexploitable dès qu'un second agent était déployé.

2. Le code est purement synchrone et sans accès base. Il est exécuté dans un
   thread worker par l'endpoint d'ingestion, ce qui évite de bloquer la boucle
   d'événements pendant l'inférence du Random Forest, et laisse l'écriture en
   base au routeur.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from baseline.baseline_engine import BaselineEngine
from detector.rules_engine import RulesEngine
from features.feature_extractor import FeatureExtractor
from parser.sysmon_parser import SysmonParser

from api.config import settings

logger = logging.getLogger("api.detection")

FEATURE_KEYS = (
    "nb_files_created",
    "nb_files_deleted",
    "nb_files_renamed",
    "nb_unique_extensions",
    "entropy_filenames",
    "nb_processes_created",
    "nb_child_processes",
    "process_depth",
    "nb_connections",
    "nb_unique_ips",
    "nb_external_connections",
    "nb_dns_queries",
)


@dataclass
class WindowResult:
    """Résultat d'une fenêtre de features fermée, prêt à être persisté."""

    features: Dict[str, Any]
    risk_score: float
    is_alert: bool
    detection_source: str
    baseline_trained: bool
    triggered_rules: List[str] = field(default_factory=list)
    top_suspect: Optional[Dict[str, Any]] = None
    ml_probability: Optional[float] = None

    @property
    def alert_score(self) -> int:
        """
        Score d'alerte sur 100, comparable d'une alerte à l'autre.

        Le compteur porté par `top_suspect["score"]` ne convient pas pour cet
        usage : il additionne 1 point par fichier créé, 2 par suppression et 2
        par connexion, sans borne. Une alerte affichait donc « 146/100 », et le
        seuil d'arrêt automatique se déclenchait sur un volume d'activité plutôt
        que sur un niveau de certitude — un serveur de fichiers actif pouvait
        dépasser le seuil sans qu'aucune règle ne se déclenche.

        On retient donc le maximum entre le score normalisé du moteur
        heuristique (dont les pondérations sont documentées) et la probabilité
        rendue par le modèle. Le compteur d'activité reste conservé dans la
        charge utile de l'alerte comme élément de preuve.
        """
        rules_component = self.risk_score
        ml_component = self.ml_probability or 0.0
        return int(round(min(1.0, max(rules_component, ml_component)) * 100))


@dataclass
class IngestResult:
    machine_id: str
    received: int
    relevant: int
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_name: Optional[str] = None
    agent_version: Optional[str] = None
    windows: List[WindowResult] = field(default_factory=list)


class MachinePipeline:
    """Automate à état propre à une machine surveillée."""

    def __init__(self, machine_id: str) -> None:
        self.machine_id = machine_id
        self.extractor_10s = FeatureExtractor(window_seconds=10)
        self.extractor_30s = FeatureExtractor(window_seconds=30)
        self.baseline = BaselineEngine(min_vectors=settings.baseline_min_vectors)
        # Horloge du serveur, volontairement : elle sert à décider quand forcer
        # l'évaluation d'une fenêtre restée ouverte, et ne doit donc pas
        # dépendre de l'horloge de la machine surveillée.
        self.last_ingest_at: float = time.monotonic()


class DetectionEngine:
    def __init__(self) -> None:
        self.parser = SysmonParser()
        self.rules = RulesEngine(alert_threshold=settings.rules_alert_threshold)
        self._pipelines: Dict[str, MachinePipeline] = {}
        self._lock = threading.Lock()

        self.ml_enabled = False
        self._model = None
        self._scaler = None
        self._load_model()

        # Rafraîchies depuis la base à chaque ingestion : une exclusion ajoutée
        # par un analyste devient donc effective sans redémarrage.
        self._excluded_folders: List[str] = []
        self._excluded_processes: List[str] = []
        self._excluded_extensions: List[str] = []

    # ── Modèle ML ────────────────────────────────────────────────────

    def _load_model(self) -> None:
        try:
            import joblib

            self._model = joblib.load("models/random_forest_model.pkl")
            self._scaler = joblib.load("models/scaler.pkl")
            self.ml_enabled = True
            logger.info("Modèle Random Forest chargé, détection ML active.")
        except Exception as exc:
            logger.warning("Modèle ML indisponible (%s) — détection heuristique seule.", exc)

    # ── Exclusions ───────────────────────────────────────────────────

    def set_exclusions(self, exclusions: List[Dict[str, str]]) -> None:
        """
        Applique les exclusions définies par les analystes.

        Dans l'implémentation précédente, les exclusions étaient stockées en base
        et affichées dans l'interface, mais aucun composant du pipeline ne les
        lisait : elles n'avaient donc strictement aucun effet sur la détection.
        """
        folders, processes, extensions = [], [], []
        for exc in exclusions:
            path = (exc.get("path") or "").strip().lower()
            if not path:
                continue
            kind = exc.get("type")
            if kind == "Folder":
                folders.append(path.replace("/", "\\"))
            elif kind == "Process":
                processes.append(os.path.basename(path.replace("/", "\\")))
            elif kind == "Extension":
                extensions.append(path if path.startswith(".") else f".{path}")

        self._excluded_folders = folders
        self._excluded_processes = processes
        self._excluded_extensions = extensions

    def _is_excluded(self, event: Dict[str, Any]) -> bool:
        process_path = (event.get("process_path") or "").lower().replace("/", "\\")
        process_name = (event.get("process_name") or "").lower()
        target_file = (event.get("target_file") or "").lower().replace("/", "\\")

        if process_name and process_name in self._excluded_processes:
            return True

        for folder in self._excluded_folders:
            if process_path.startswith(folder) or (target_file and target_file.startswith(folder)):
                return True

        if target_file:
            ext = os.path.splitext(target_file)[1]
            if ext and ext in self._excluded_extensions:
                return True

        return False

    # ── Pipelines par machine ────────────────────────────────────────

    def _pipeline_for(self, machine_id: str) -> MachinePipeline:
        with self._lock:
            pipeline = self._pipelines.get(machine_id)
            if pipeline is None:
                pipeline = MachinePipeline(machine_id)
                self._pipelines[machine_id] = pipeline
                logger.info("Pipeline de détection initialisé pour [%s]", machine_id)
            return pipeline

    def baseline_trained_machines(self) -> int:
        return sum(1 for p in self._pipelines.values() if p.baseline.is_trained)

    def known_machines(self) -> List[str]:
        return list(self._pipelines.keys())

    def baseline_progress(self) -> Dict[str, Dict[str, Any]]:
        """Avancement de l'apprentissage, par machine, pour affichage dans l'UI."""
        return {
            machine_id: {
                "trained": pipeline.baseline.is_trained,
                "vectors": len(pipeline.baseline.history),
                "required": pipeline.baseline.min_vectors,
            }
            for machine_id, pipeline in self._pipelines.items()
        }

    def feature_importances(self) -> List[Dict[str, Any]]:
        """
        Importances réelles du Random Forest entraîné.

        L'onglet « Statistiques ML » affichait jusqu'ici des valeurs écrites en
        dur dans le JSX ; elles proviennent maintenant du modèle chargé.
        """
        if not self.ml_enabled or self._model is None:
            return []
        try:
            importances = getattr(self._model, "feature_importances_", None)
            if importances is None:
                return []
            names = list(getattr(self._model, "feature_names_in_", FEATURE_KEYS))
            pairs = [
                {"feature": name, "importance": round(float(value), 4)}
                for name, value in zip(names, importances)
            ]
            return sorted(pairs, key=lambda item: item["importance"], reverse=True)
        except Exception as exc:
            logger.error("Lecture des importances impossible : %s", exc)
            return []

    def model_info(self) -> Dict[str, Any]:
        if not self.ml_enabled or self._model is None:
            return {"enabled": False}
        return {
            "enabled": True,
            "algorithm": type(self._model).__name__,
            "n_estimators": getattr(self._model, "n_estimators", None),
            "max_depth": getattr(self._model, "max_depth", None),
            "n_features": int(getattr(self._model, "n_features_in_", 0)) or None,
            "classes": [int(c) for c in getattr(self._model, "classes_", [])],
        }

    # ── Traitement d'un lot ──────────────────────────────────────────

    def process_batch(
        self, machine_id: str, batch: List[Dict[str, Any]]
    ) -> IngestResult:
        """
        Traite un lot d'événements bruts. Fonction synchrone et sans I/O base :
        l'appelant l'exécute dans un thread worker.
        """
        pipeline = self._pipeline_for(machine_id)
        pipeline.last_ingest_at = time.monotonic()
        result = IngestResult(machine_id=machine_id, received=len(batch), relevant=0)

        for raw_event in batch:
            # Métadonnées d'inventaire : Winlogbeat les fournit, l'ancienne
            # version les ignorait complètement.
            self._collect_host_metadata(raw_event, result)

            parsed = self.parser.parse_event(raw_event)
            if not parsed:
                continue
            if self._is_excluded(parsed):
                continue

            result.relevant += 1

            if pipeline.extractor_10s.add_event(parsed):
                window = self._close_window(pipeline)
                pipeline.extractor_10s.reset_window()
                pipeline.extractor_10s.add_event(parsed)
                if window:
                    result.windows.append(window)

            # La fenêtre 30 s alimente l'analyse long terme ; on la fait
            # tourner pour rester fidèle au pipeline d'origine.
            if pipeline.extractor_30s.add_event(parsed):
                pipeline.extractor_30s.extract_features()
                pipeline.extractor_30s.reset_window()
                pipeline.extractor_30s.add_event(parsed)

        return result

    def flush_idle_windows(self, idle_seconds: float) -> List[IngestResult]:
        """
        Évalue les fenêtres restées ouvertes faute d'événement suivant.

        Une fenêtre ne se fermait qu'à l'arrivée d'un événement postérieur. La
        dernière fenêtre d'une attaque — la plus incriminante — n'était donc
        jamais analysée si le poste s'arrêtait ou si le rançongiciel neutralisait
        l'agent juste après. Cette méthode est appelée périodiquement par l'API
        et force l'évaluation au bout d'un délai d'inactivité.
        """
        now = time.monotonic()
        flushed: List[IngestResult] = []

        with self._lock:
            candidates = [
                pipeline
                for pipeline in self._pipelines.values()
                if now - pipeline.last_ingest_at >= idle_seconds
                and pipeline.extractor_10s.has_pending_events()
            ]

        for pipeline in candidates:
            window = self._close_window(pipeline)
            pipeline.extractor_10s.reset_window()
            pipeline.last_ingest_at = now
            if window is None:
                continue

            result = IngestResult(
                machine_id=pipeline.machine_id, received=0, relevant=0, windows=[window]
            )
            flushed.append(result)
            if window.is_alert:
                logger.warning(
                    "[%s] Fenêtre inactive évaluée après %.0f s : alerte (score %d)",
                    pipeline.machine_id,
                    idle_seconds,
                    window.alert_score,
                )

        return flushed

    def _close_window(self, pipeline: MachinePipeline) -> Optional[WindowResult]:
        features = pipeline.extractor_10s.extract_features()

        if not pipeline.baseline.is_trained:
            pipeline.baseline.add_vector(features)
            return WindowResult(
                features=features,
                risk_score=0.0,
                is_alert=False,
                detection_source="baseline_learning",
                baseline_trained=False,
                top_suspect=features.get("top_suspect"),
            )

        deviations = pipeline.baseline.get_deviations(features)
        analysis = self.rules.evaluate(features, deviations)

        rules_alert = bool(analysis["alert"])
        risk_score = float(analysis["risk_score"])
        ml_alert = False
        ml_probability: Optional[float] = None

        if self.ml_enabled:
            try:
                import pandas as pd

                numeric = {k: features.get(k, 0) for k in FEATURE_KEYS}
                frame = pd.DataFrame([numeric])
                scaled = self._scaler.transform(frame)
                scaled_frame = pd.DataFrame(scaled, columns=frame.columns)
                ml_alert = int(self._model.predict(scaled_frame)[0]) == 1

                # La probabilité sert à donner un score exploitable aux
                # détections purement ML : sans elle, une alerte levée par le
                # seul modèle aurait un score nul et serait classée « faible »
                # alors qu'elle justifie une investigation.
                if hasattr(self._model, "predict_proba"):
                    ml_probability = float(self._model.predict_proba(scaled_frame)[0][1])
            except Exception as exc:
                logger.error("Erreur d'inférence ML : %s", exc)

        # La source est explicite quand les deux moteurs concordent : c'est
        # l'information qui permet à l'analyste de juger la fiabilité.
        if rules_alert and ml_alert:
            source = "RulesEngine+RandomForest"
        elif ml_alert:
            source = "RandomForest"
        else:
            source = "RulesEngine"

        return WindowResult(
            features=features,
            risk_score=risk_score,
            is_alert=rules_alert or ml_alert,
            detection_source=source,
            baseline_trained=True,
            triggered_rules=list(analysis.get("triggered_rules", [])),
            top_suspect=features.get("top_suspect"),
            ml_probability=ml_probability,
        )

    @staticmethod
    def _collect_host_metadata(raw_event: Dict[str, Any], result: IngestResult) -> None:
        if not isinstance(raw_event, dict):
            return

        host = raw_event.get("host") or {}
        if isinstance(host, dict):
            if not result.hostname:
                result.hostname = host.get("name")
            os_info = host.get("os") or {}
            if isinstance(os_info, dict) and not result.os_name:
                result.os_name = os_info.get("name") or os_info.get("full")
            ips = host.get("ip")
            if not result.ip_address and isinstance(ips, list) and ips:
                # On privilégie l'IPv4 privée, la plus parlante pour un analyste.
                ipv4 = [addr for addr in ips if isinstance(addr, str) and addr.count(".") == 3]
                result.ip_address = ipv4[0] if ipv4 else str(ips[0])
            elif not result.ip_address and isinstance(ips, str):
                result.ip_address = ips

        if not result.hostname:
            winlog = raw_event.get("winlog") or {}
            if isinstance(winlog, dict):
                result.hostname = winlog.get("computer_name")

        agent = raw_event.get("agent") or {}
        if isinstance(agent, dict) and not result.agent_version:
            result.agent_version = agent.get("version")


engine = DetectionEngine()
