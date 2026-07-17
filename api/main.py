from fastapi import FastAPI, HTTPException, Request
from api.schemas import IngestPayload, ResponseMessage
from parser.sysmon_parser import SysmonParser
from features.feature_extractor import FeatureExtractor
from baseline.baseline_engine import BaselineEngine
from detector.rules_engine import RulesEngine
import logging
import json
import gzip
import joblib
import pandas as pd

# Variables globales pour le Response Engine
ML_ENABLED = False
rf_model = None
scaler = None

try:
    rf_model = joblib.load("models/random_forest_model.pkl")
    scaler = joblib.load("models/scaler.pkl")
    ML_ENABLED = True
except Exception as e:
    pass

# File d'attente des commandes pour l'Agent PowerShell
pending_commands = []
alert_history = []

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
baseline_engine = BaselineEngine(min_vectors=10)  # 10 pour les tests, 90 en production (15 min)
rules_engine = RulesEngine()

@app.get("/")
def read_root():
    # Simulation de la réponse d'Elasticsearch (version 8) pour tromper Winlogbeat
    return {
        "name" : "ransomware-detector",
        "cluster_name" : "ransomware-detector",
        "cluster_uuid" : "123456789",
        "version" : {
            "number" : "8.0.0",
            "build_flavor" : "default",
            "build_type" : "tar",
            "build_hash" : "12345",
            "build_date" : "2026-01-01T00:00:00.000Z",
            "build_snapshot" : False,
            "lucene_version" : "9.0.0",
            "minimum_wire_compatibility_version" : "7.17.0",
            "minimum_index_compatibility_version" : "7.0.0"
        },
        "tagline" : "You Know, for Search"
    }

@app.get("/_license")
def get_license():
    return {
        "license": {
            "status": "active",
            "type": "basic"
        }
    }

@app.get("/_xpack")
def get_xpack():
    return {
        "features": {
            "monitoring": {"enabled": False}
        }
    }

@app.post("/ingest", response_model=ResponseMessage)
def ingest_logs(payload: IngestPayload):
    """
    Reçoit un lot d'événements depuis Winlogbeat (ou agent).
    Parse, filtre, puis envoie aux Feature Extractors.
    """
    logger.info(f"━━━ Reçu un batch de {len(payload.batch)} événements depuis [{payload.machine_id}] ━━━")
    
    normalized_events = []
    
    for raw_event in payload.batch:
        parsed = parser.parse_event(raw_event)
        if parsed:
            normalized_events.append(parsed)
            
            # --- Câblage du Feature Extractor (10s) ---
            if extractor_10s.add_event(parsed):
                features_10s = extractor_10s.extract_features()
                logger.info(f"📈 [Fenêtre 10s] Features calculées : "
                            f"fichiers créés={features_10s['nb_files_created']}, "
                            f"supprimés={features_10s['nb_files_deleted']}, "
                            f"entropie={features_10s['entropy_filenames']}")
                
                # Réinitialise la fenêtre et ajoute l'événement qui a déclenché le débordement
                extractor_10s.reset_window()
                extractor_10s.add_event(parsed)
                
                # Apprentissage vs Détection
                if not baseline_engine.is_trained:
                    baseline_engine.add_vector(features_10s)
                else:
                    deviations = baseline_engine.get_deviations(features_10s)
                    logger.info(f"🔍 [Mode Détection] Z-Scores : "
                                f"création={deviations.get('nb_files_created', 0)}, "
                                f"suppression={deviations.get('nb_files_deleted', 0)}, "
                                f"entropie={deviations.get('entropy_filenames', 0)}")
                    
                    # Analyse heuristique par le Moteur de Règles
                    analysis_result = rules_engine.evaluate(features_10s, deviations)
                    
                    is_alert = analysis_result["alert"]
                    detection_source = "RulesEngine"
                    
                    # Analyse par le modèle Machine Learning (Random Forest)
                    if ML_ENABLED:
                        df_features = pd.DataFrame([features_10s])
                        try:
                            # Standardiser les features
                            X_scaled = scaler.transform(df_features)
                            # Prédire (0 = Normal, 1 = Ransomware)
                            prediction = rf_model.predict(X_scaled)[0]
                            if prediction == 1:
                                is_alert = True
                                detection_source = "RandomForest"
                        except Exception as e:
                            logger.error(f"Erreur ML prédiction: {e}")
                    
                    if is_alert:
                        logger.error(f"🚨🚨🚨 ALERTE CRITIQUE : Ransomware Détecté par {detection_source} ! 🚨🚨🚨")
                        alert_data = {
                            "timestamp": "now",
                            "source": detection_source,
                            "features": features_10s
                        }
                        alert_history.append(alert_data)
                        
                        # --- DÉCLENCHEMENT DU RESPONSE ENGINE ---
                        pending_commands.append({"action": "KILL", "target": "ALL_SUSPICIOUS"})
                        logger.warning("🔨 Commande KILL ajoutée à la file d'attente de l'Agent PowerShell.")
                        
                    else:
                        logger.info(f"✅ [Normal] Aucune menace détectée.")
                    
            # --- Câblage du Feature Extractor (30s) ---
            if extractor_30s.add_event(parsed):
                features_30s = extractor_30s.extract_features()
                extractor_30s.reset_window()
                extractor_30s.add_event(parsed)
    
    # Résumé du batch traité        
    logger.info(f"━━━ Résultat : {len(normalized_events)} événements pertinents sur {len(payload.batch)} reçus ━━━")
            
    return ResponseMessage(
        status="success",
        message="Batch ingéré et traité par le pipeline complet",
        processed_events=len(normalized_events)
    )

@app.post("/_bulk")
async def receive_winlogbeat_bulk(request: Request):
    """
    Simule l'endpoint Bulk d'Elasticsearch pour recevoir directement 
    les logs Winlogbeat sans aucun script Python intermédiaire sur la VM.
    """
    body = await request.body()
    
    if request.headers.get("content-encoding") == "gzip":
        try:
            body = gzip.decompress(body)
        except Exception as e:
            logger.error(f"GZIP decompression failed: {e}")
            
    lines = body.decode("utf-8").split("\n")
    
    events = []
    # Le format NDJSON Bulk a toujours une ligne d'action suivie d'une ligne de document
    for i in range(1, len(lines), 2):
        if not lines[i].strip():
            continue
        try:
            events.append(json.loads(lines[i]))
        except Exception as e:
            pass
            
    if events:
        # On utilise notre logique d'ingestion classique !
        payload = IngestPayload(machine_id="Winlogbeat-Native", batch=events)
        ingest_logs(payload)
        
    # On renvoie une fausse réponse Elasticsearch de succès massif
    return {
        "errors": False,
        "items": [{"create": {"status": 201}} for _ in events]
    }

@app.get("/status")
def get_status():
    return {
        "status": "online",
        "ml_enabled": ML_ENABLED,
        "baseline_trained": baseline_engine.is_trained,
        "pending_commands_count": len(pending_commands)
    }

@app.get("/alerts")
def get_alerts():
    return {"alerts": alert_history}

@app.post("/response/kill/{pid}")
def response_kill(pid: int):
    pending_commands.append({"action": "KILL", "target": pid})
    return {"message": f"Ordre de KILL pour le PID {pid} envoyé à l'agent."}

@app.post("/response/isolate")
def response_isolate():
    pending_commands.append({"action": "ISOLATE", "target": "NETWORK"})
    return {"message": "Ordre d'isolation réseau envoyé à l'agent."}

@app.get("/agent/commands")
def get_agent_commands():
    """L'agent PowerShell appelle cette route toutes les 2 secondes."""
    if pending_commands:
        # On dépile la plus ancienne commande
        cmd = pending_commands.pop(0)
        return cmd
    return {"action": "NONE"}

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
async def catch_all_elastic_checks(request: Request, path_name: str):
    """
    Route 'attrape-tout' pour répondre 'OK' à toutes les vérifications 
    annexes de Winlogbeat (ILM, Templates, Pipelines, etc.)
    """
    return {"acknowledged": True}
