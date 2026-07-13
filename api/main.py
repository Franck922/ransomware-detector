from fastapi import FastAPI, HTTPException
from api.schemas import IngestPayload, ResponseMessage
from parser.sysmon_parser import SysmonParser
from features.feature_extractor import FeatureExtractor
from baseline.baseline_engine import BaselineEngine
import logging

# Configuration basique des logs
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("api")

app = FastAPI(
    title="Ransomware Detector API",
    description="API de réception et d'analyse des logs Sysmon pour la détection de ransomware",
    version="1.0.0"
)

# Instanciation globale des composants
parser = SysmonParser()
extractor_10s = FeatureExtractor(window_seconds=10)
extractor_30s = FeatureExtractor(window_seconds=30)
baseline_engine = BaselineEngine()

@app.get("/")
def read_root():
    return {"message": "Ransomware Detector API is running."}

@app.post("/ingest", response_model=ResponseMessage)
def ingest_logs(payload: IngestPayload):
    """
    Reçoit un lot d'événements depuis Winlogbeat (ou agent).
    Parse, filtre, puis envoie aux Feature Extractors.
    """
    logger.info(f"Reçu un batch de {len(payload.batch)} événements depuis {payload.machine_id}")
    
    normalized_events = []
    
    for raw_event in payload.batch:
        parsed = parser.parse_event(raw_event)
        if parsed:
            normalized_events.append(parsed)
            
            # --- Câblage du Feature Extractor (10s) ---
            if extractor_10s.add_event(parsed):
                features_10s = extractor_10s.extract_features()
                logger.info(f"[Fenêtre 10s] Nouvelles features calculées : {features_10s}")
                
                # Réinitialise la fenêtre et ajoute l'événement qui a déclenché le débordement
                extractor_10s.reset_window()
                extractor_10s.add_event(parsed)
                
                # Apprentissage vs Détection
                if not baseline_engine.is_trained:
                    baseline_engine.add_vector(features_10s)
                else:
                    deviations = baseline_engine.get_deviations(features_10s)
                    # logger.info(f"Déviations par rapport à la normale : {deviations}")
                    # Le Moteur de Règles (Phase 3) interviendra ici !
                    
            # --- Câblage du Feature Extractor (30s) ---
            if extractor_30s.add_event(parsed):
                features_30s = extractor_30s.extract_features()
                extractor_30s.reset_window()
                extractor_30s.add_event(parsed)
            
    return ResponseMessage(
        status="success",
        message="Batch ingéré et traité par le pipeline complet",
        processed_events=len(normalized_events)
    )
