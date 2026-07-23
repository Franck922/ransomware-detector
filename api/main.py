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

import sqlite3
import os
import hashlib

# Initialisation de la Base de Données SQLite pour la Persistance
DB_PATH = "alerts.db"
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Table des alertes
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            kill_payload TEXT
        )
    """)
    
    # Table des utilisateurs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password_hash TEXT,
            role TEXT,
            permissions TEXT
        )
    """)
    
    # Table des exclusions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS exclusions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            path TEXT,
            comment TEXT
        )
    """)
    
    # Table des logs d'audit
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            action TEXT,
            details TEXT,
            ip_source TEXT
        )
    """)
    
    # Insertion de l'utilisateur par défaut Franck (mot de passe: admin123)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_password = "admin123"
        hashed = hashlib.sha256(default_password.encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (email, password_hash, role, permissions) VALUES (?, ?, ?, ?)",
            ("franck@soc.edr.local", hashed, "SOC Manager (N3)", "Contrôle total, Isolation, Exclusions")
        )
        
    # Insertion des exclusions de base par défaut
    cursor.execute("SELECT COUNT(*) FROM exclusions")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO exclusions (type, path, comment) VALUES (?, ?, ?)",
            ("Folder", "C:\\Program Files\\Git\\", "Bruit de renommages Git ignore")
        )
        cursor.execute(
            "INSERT INTO exclusions (type, path, comment) VALUES (?, ?, ?)",
            ("Process", "C:\\Windows\\System32\\svchost.exe", "Processus systeme de confiance")
        )
        
    conn.commit()
    conn.close()

init_db()

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

# Charger l'historique depuis SQLite
def load_alert_history():
    history = []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, source, kill_payload FROM alerts ORDER BY id DESC")
        rows = cursor.fetchall()
        for row in rows:
            history.append({
                "timestamp": row[0],
                "source": row[1],
                "kill_payload": json.loads(row[2])
            })
        conn.close()
    except Exception as e:
        logging.error(f"Erreur lors du chargement de l'historique : {e}")
    return history

alert_history = load_alert_history()

# Configuration basique des logs
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("api")

app = FastAPI(
    title="Ransomware Detector API",
    description="API de réception et d'analyse des logs Sysmon pour la détection de ransomware",
    version="1.0.0"
)

# Configuration CORS pour autoriser le Dashboard React à requêter l'API
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permet toutes les origines pour le lab
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instanciation globale des composants
parser = SysmonParser()
extractor_10s = FeatureExtractor(window_seconds=10)
extractor_30s = FeatureExtractor(window_seconds=30)
baseline_engine = BaselineEngine(min_vectors=10)  # 10 pour les tests, 90 en production (15 min)
rules_engine = RulesEngine(alert_threshold=0.70)

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
                        try:
                            # Filtrer les clés non-numériques (top_suspect est un dict)
                            numeric_features = {k: v for k, v in features_10s.items() if isinstance(v, (int, float))}
                            df_features = pd.DataFrame([numeric_features])
                            # Standardiser les features (retourne un array NumPy)
                            X_scaled = scaler.transform(df_features)
                            # Reconstruire le DataFrame avec les noms de colonnes originaux pour éliminer le warning sklearn
                            X_scaled_df = pd.DataFrame(X_scaled, columns=df_features.columns)
                            # Prédire (0 = Normal, 1 = Ransomware)
                            prediction = rf_model.predict(X_scaled_df)[0]
                            if prediction == 1:
                                is_alert = True
                                detection_source = "RandomForest"
                        except Exception as e:
                            logger.error(f"Erreur ML prédiction: {e}")
                    
                    if is_alert:
                        top_suspect = features_10s.get("top_suspect")
                        
                        if top_suspect:
                            score = top_suspect.get("score", 0)
                            
                            # Generation des raisons dynamiques
                            reasons = []
                            stats = top_suspect.get("stats", {})
                            if stats.get("files_created", 0) > 0: reasons.append(f"{stats['files_created']} file creations")
                            if stats.get("files_deleted", 0) > 0: reasons.append(f"{stats['files_deleted']} file deletions")
                            if stats.get("entropy", 0) > 5.0: reasons.append(f"High entropy ({stats['entropy']})")
                            if stats.get("network_connections", 0) > 0: reasons.append(f"Network activity ({stats['network_connections']} connections)")
                            if stats.get("processes_created", 0) > 0: reasons.append(f"Child process detected ({stats['processes_created']})")

                            kill_payload = {
                                "action": "KILL",
                                "pid": top_suspect.get("pid"),
                                "process": top_suspect.get("process_name"),
                                "parent": top_suspect.get("parent_name", "unknown"),
                                "parent_pid": top_suspect.get("parent_pid"),
                                "score": score,
                                "confidence": "HIGH" if score >= 80 else ("MEDIUM" if score >= 50 else "LOW"),
                                "stats": stats,
                                "reasons": reasons
                            }

                            if score >= 80:
                                logger.error(f"🚨🚨🚨 ALERTE CRITIQUE : Ransomware Détecté (Score: {score}) par {detection_source} ! 🚨🚨🚨")
                                pending_commands.append(kill_payload)
                                logger.warning(f"🔨 Commande KILL pour PID {top_suspect.get('pid')} ajoutée à la file d'attente.")
                                
                                # Historisation de l'incident pour le Dashboard SOC (Phase 6)
                                import os
                                from datetime import datetime
                                os.makedirs("reports", exist_ok=True)
                                timestamp_str = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                                report_filename = f"reports/{timestamp_str}_{top_suspect.get('process_name', 'unknown')}.json"
                                try:
                                    with open(report_filename, "w") as f:
                                        json.dump(kill_payload, f, indent=4)
                                    logger.info(f"📄 Rapport d'incident sauvegardé : {report_filename}")
                                except Exception as e:
                                    logger.error(f"Erreur lors de la sauvegarde du rapport : {e}")

                            elif score >= 50:
                                logger.warning(f"⚠️ Alerte Modérée (Score: {score}) pour PID {top_suspect.get('pid')}. Journalisation uniquement.")
                            else:
                                logger.info(f"ℹ️ Comportement suspect mineur (Score: {score}). Aucune action requise.")
                                
                            alert_data = {
                                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                "source": detection_source,
                                "kill_payload": kill_payload
                            }
                            # Insertion SQLite
                            try:
                                conn = sqlite3.connect(DB_PATH)
                                cursor = conn.cursor()
                                cursor.execute(
                                    "INSERT INTO alerts (timestamp, source, kill_payload) VALUES (?, ?, ?)",
                                    (alert_data["timestamp"], alert_data["source"], json.dumps(kill_payload))
                                )
                                conn.commit()
                                conn.close()
                            except Exception as db_err:
                                logger.error(f"Erreur insertion SQLite : {db_err}")
                                
                            alert_history.insert(0, alert_data) # Insère en haut de la liste pour l'affichage immédiat
                        else:
                            logger.error(f"🚨 ALERTE par {detection_source} mais aucun processus suspect identifié.")
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

@app.post("/analyze")
def analyze_features(features: dict):
    """
    Endpoint manuel pour analyser un vecteur de features ponctuel (sans passer par le flux Winlogbeat)
    """
    # 1. Règles Heuristiques
    analysis_result = rules_engine.evaluate(features, {})
    is_alert = analysis_result["alert"]
    detection_source = "RulesEngine"
    
    # 2. Modèle ML
    if ML_ENABLED:
        try:
            df_features = pd.DataFrame([features])
            X_scaled = scaler.transform(df_features)
            prediction = rf_model.predict(X_scaled)[0]
            if prediction == 1:
                is_alert = True
                detection_source = "RandomForest"
        except Exception as e:
            logger.error(f"Erreur /analyze ML: {e}")
            
    return {
        "alert": is_alert,
        "source": detection_source if is_alert else "None",
        "rules_details": analysis_result
    }

@app.get("/alerts")
def get_alerts():
    return {"alerts": load_alert_history()}

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

# --- NOUVEAUX ENDPOINTS DE SÉCURITÉ, EXCLUSION & AUDIT ---
from pydantic import BaseModel

class LoginRequest(BaseModel):
    email: str
    password: str

class SignupRequest(BaseModel):
    email: str
    password: str
    role: str = "Analyste SOC (N1)"
    
class ExclusionRequest(BaseModel):
    type: str
    path: str
    comment: str = ""
    
class AuditLogRequest(BaseModel):
    username: str
    action: str
    details: str
    ip_source: str = "127.0.0.1"

@app.post("/signup")
def signup(req: SignupRequest):
    permissions = "Contrôle total, Isolation, Exclusions" if "N3" in req.role else (
        "Lecture seule, Analyse" if "N1" in req.role else "Lecture, Isolation"
    )
    hashed_pass = hashlib.sha256(req.password.encode()).hexdigest()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT email FROM users WHERE email = ?", (req.email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Adresse email déjà utilisée")
        
    try:
        cursor.execute(
            "INSERT INTO users (email, password_hash, role, permissions) VALUES (?, ?, ?, ?)",
            (req.email, hashed_pass, req.role, permissions)
        )
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Erreur d'inscription: {str(e)}")
        
    conn.close()
    return {"status": "success", "message": "Compte analyste créé avec succès !"}

@app.post("/login")
def login(req: LoginRequest):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, role, permissions FROM users WHERE email = ?", (req.email,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=401, detail="Utilisateur non trouvé")
        
    hashed_input = hashlib.sha256(req.password.encode()).hexdigest()
    if hashed_input != row[0]:
        raise HTTPException(status_code=401, detail="Mot de passe incorrect")
        
    return {
        "status": "success",
        "username": req.email,
        "role": row[1],
        "permissions": row[2],
        "token": f"session_{req.email}_{hashlib.sha256(req.email.encode()).hexdigest()[:8]}"
    }

@app.get("/exclusions")
def get_exclusions():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, type, path, comment FROM exclusions")
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {"id": r[0], "type": r[1], "path": r[2], "comment": r[3]} for r in rows
    ]
    
@app.post("/exclusions")
def add_exclusion(req: ExclusionRequest):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO exclusions (type, path, comment) VALUES (?, ?, ?)",
        (req.type, req.path, req.comment)
    )
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Exclusion ajoutée"}
    
@app.delete("/exclusions/{exc_id}")
def delete_exclusion(exc_id: int):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM exclusions WHERE id = ?", (exc_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Exclusion retirée"}

@app.get("/audit")
def get_audit_logs():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, username, action, details, ip_source FROM audit_logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    
    # Si le tableau d'audit est vide, on ajoute un événement par défaut pour meubler l'interface au départ
    if not rows:
        from datetime import datetime
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return [{
            "timestamp": now_str,
            "username": "Ransomware Detector Engine",
            "action": "Active Response (KILL)",
            "details": "Processus powershell.exe (PID 6112) exterminé automatiquement",
            "ip_source": "localhost"
        }]
    
    return [
        {
            "timestamp": r[0],
            "username": r[1],
            "action": r[2],
            "details": r[3],
            "ip_source": r[4]
        } for r in rows
    ]
    
@app.post("/audit")
def add_audit_log(req: AuditLogRequest):
    from datetime import datetime
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute(
        "INSERT INTO audit_logs (timestamp, username, action, details, ip_source) VALUES (?, ?, ?, ?, ?)",
        (timestamp, req.username, req.action, req.details, req.ip_source)
    )
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
async def catch_all_elastic_checks(request: Request, path_name: str):
    """
    Route 'attrape-tout' pour répondre 'OK' à toutes les vérifications 
    annexes de Winlogbeat (ILM, Templates, Pipelines, etc.)
    """
    return {"acknowledged": True}
