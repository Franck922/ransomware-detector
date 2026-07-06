# 🔐 Ransomware Detector — MVP EDR Académique

Système de détection et réponse précoce aux ransomwares par analyse comportementale
des signaux système (logs Sysmon, activité fichiers, appels processus).

**ECE Paris — Bachelor 3 Réseaux & Cybersécurité — Promotion 2026**

---

## 📌 Présentation

Ce projet implémente un EDR (Endpoint Detection and Response) académique capable de :

- Collecter en temps réel les logs Sysmon depuis une VM Windows via Winlogbeat
- Extraire des features comportementales sur des fenêtres temporelles glissantes
- Détecter un ransomware via un moteur de règles adaptatives, un Random Forest et un LSTM
- Déclencher automatiquement une réponse (kill processus, isolation réseau)
- Afficher les alertes en temps réel dans un dashboard web

---

## 🏗️ Architecture

```
VM Windows (Victime)
  └── Sysmon → Winlogbeat → POST /ingest
                                  │
                          Serveur Docker (Hôte)
                                  │
                    ┌─────────────▼─────────────┐
                    │         FastAPI            │
                    │  /ingest /analyze /alerts  │
                    │  /response/kill /isolate   │
                    └──────────┬────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
           Parser         Detector         Dashboard
        (sysmon_parser) (rules+RF+LSTM)   (HTML/JS)
              │                │
              ▼                ▼
        Feature           Response
        Extractor          Engine
        (baseline)      (PowerShell)
```

---

## 👥 Répartition de l'équipe

| Membre   | Domaine                | Modules                                       |
|----------|------------------------|-----------------------------------------------|
| Membre 1 | Pipeline & Connector   | `agent/`, `parser/`, `baseline/`, `features/` |
| Membre 2 | Modèle de détection    | `detector/`                                   |
| Membre 3 | API, Dashboard, Docker | `api/`, `dashboard/`, `docker-compose.yml`    |

---

## 🚀 Installation

### Prérequis

- Python 3.11.x
- Git
- Docker Desktop (pour la partie serveur)
- VM Windows 10 avec Sysmon installé (voir `docs/lab_setup.md`)

### Installation du serveur d'analyse

```bash
git clone https://github.com/TON_USERNAME/ransomware-detector.git
cd ransomware-detector

python -m venv venv
source venv/Scripts/activate   # Windows Git Bash
pip install -r requirements.txt --prefer-binary
```

### Lancer l'API (développement)

```bash
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Lancer avec Docker (production)

```bash
docker-compose up
```

---

## 📡 Formats JSON des interfaces entre modules

> ⚠️ Ces formats sont le **contrat entre les membres**. Tout le monde doit
> les respecter pour que l'intégration fonctionne sans friction.

### 1. Événement Sysmon normalisé (Parser → Feature Extractor)

Un événement produit par le parser après normalisation d'un log Sysmon brut.

```json
{
  "event_id": 11,
  "timestamp": "2026-07-05T14:23:45.123Z",
  "process_name": "unknown.exe",
  "process_id": 4821,
  "process_path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\unknown.exe",
  "parent_process": "explorer.exe",
  "target_file": "C:\\Users\\Admin\\Documents\\rapport.docx.encrypted",
  "action": "file_create",
  "network_ip": null,
  "network_port": null
}
```

**Champs obligatoires :** `event_id`, `timestamp`, `process_name`, `action`
**Champs optionnels :** `target_file` (EventID 11/23), `network_ip` + `network_port` (EventID 3)
**Valeur null** si le champ ne s'applique pas à l'EventID

---

### 2. Vecteur de features (Feature Extractor → Detector)

Un vecteur calculé sur une fenêtre temporelle de 10 secondes.

```json
{
  "window_start": "2026-07-05T14:23:40.000Z",
  "window_end": "2026-07-05T14:23:50.000Z",
  "window_seconds": 10,
  "features": {
    "nb_files_created": 3,
    "nb_files_deleted": 0,
    "nb_files_renamed": 1,
    "nb_unique_extensions": 2,
    "entropy_filenames": 2.8,
    "nb_processes_created": 1,
    "nb_child_processes": 0,
    "process_depth": 2,
    "nb_connections": 0,
    "nb_unique_ips": 0,
    "nb_external_connections": 0,
    "nb_dns_queries": 0
  },
  "baseline_deviations": {
    "nb_files_created": 0.4,
    "nb_files_renamed": 0.1,
    "nb_connections": 0.0
  }
}
```

**`baseline_deviations`** : écart en nombre d'écarts-types par rapport au baseline.
Ex : `2.8` signifie que la valeur est 2.8 fois au-dessus de la normale.

---

### 3. Payload /ingest (Agent → API)

Ce que Winlogbeat (ou le script agent) envoie à l'API.

```json
{
  "machine_id": "VM-WIN10-LAB",
  "batch": [
    {
      "event_id": 11,
      "timestamp": "2026-07-05T14:23:45.123Z",
      "process_name": "unknown.exe",
      "process_id": 4821,
      "process_path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\unknown.exe",
      "parent_process": "explorer.exe",
      "target_file": "C:\\Users\\Admin\\Documents\\rapport.docx.encrypted",
      "action": "file_create",
      "network_ip": null,
      "network_port": null
    }
  ]
}
```

---

### 4. Réponse /analyze (API → Client)

Ce que l'API retourne après analyse d'un batch de logs.

```json
{
  "machine_id": "VM-WIN10-LAB",
  "timestamp": "2026-07-05T14:23:50.000Z",
  "risk_score": 0.87,
  "alert": true,
  "model_used": "rules_engine",
  "triggered_rules": [
    "nb_files_renamed > 10x baseline (+30pts)",
    "entropy_filenames > 3.5 (+20pts)"
  ],
  "top_features": {
    "nb_files_renamed": 312,
    "entropy_filenames": 3.9,
    "nb_files_deleted": 280
  },
  "response_triggered": false,
  "response_mode": "learning"
}
```

---

### 5. Réponse /alerts (API → Dashboard)

```json
{
  "alerts": [
    {
      "id": "alert-001",
      "timestamp": "2026-07-05T14:23:50.000Z",
      "machine_id": "VM-WIN10-LAB",
      "risk_score": 0.87,
      "model_used": "rules_engine",
      "triggered_rules": ["nb_files_renamed > 10x baseline (+30pts)"],
      "response_action": null,
      "status": "open"
    }
  ],
  "total": 1
}
```

---

## 📁 Structure du projet

```
ransomware-detector/
├── agent/                  # Script Winlogbeat + agent PowerShell (VM Windows)
├── parser/                 # Parse et normalise les logs Sysmon
├── baseline/               # Calcule l'activité normale de référence
├── features/               # Extrait les features comportementales
├── detector/               # Moteur de règles + Random Forest + LSTM
│   └── models/             # Modèles entraînés sauvegardés
├── api/                    # FastAPI — tous les endpoints
├── dashboard/              # Interface web HTML/JS
├── data/
│   ├── raw/                # Logs bruts (ignorés par Git)
│   ├── processed/          # Données normalisées (ignorées par Git)
│   └── synthetic/          # Logs synthétiques pour les tests
├── docs/                   # Documentation technique
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## 📊 Métriques cibles

| Critère                              | Objectif            |
|--------------------------------------|---------------------|
| Taux de détection (moteur de règles) | ≥ 90%               |
| F1-Score Random Forest               | ≥ 0.85              |
| Latence POST /ingest                 | < 200 ms            |
| Délai réponse automatique            | < 2 secondes        |
| Démarrage complet                    | `docker-compose up` |

---

## 📅 Planning

| Phase | Période          | Objectif                                |
|-------|------------------|-----------------------------------------|
| 1     | 5–11 juillet     | Environnement, VM, Sysmon, Winlogbeat   |
| 2     | 12–19 juillet    | Pipeline de données, baseline, features |
| 3     | 20–26 juillet    | Moteur de règles, tests synthétiques    |
| 4     | 27 juillet–4 août| Random Forest, LSTM, comparaison        |
| 5     | 5–10 août        | API complète, Response Engine           |
| 6     | 11–16 août       | Dashboard, Docker, intégration          |
| 7     | 17–20 août       | Documentation, rapport, démo            |

---

## 📄 Licence

Projet académique — ECE Paris 2026. Usage strictement pédagogique.