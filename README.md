# Ransomware Detector - MVP EDR Académique

Système de **Détection et Réponse aux Incidents** (EDR) capable d'identifier et de neutraliser en temps réel des comportements de ransomwares sur un poste Windows, grâce à l'analyse comportementale des signaux système (Sysmon), des algorithmes de Machine Learning (Random Forest, LSTM) et un moteur de règles heuristiques.

**ECE Paris - Bachelor 3 Réseaux & Cybersécurité FALL 2026**  
**Projet de substitution de stage - Juillet / Août 2026**

---

## Table des matières

1. [Contexte du projet](#-contexte-du-projet)
2. [Objectifs](#-objectifs)
3. [Architecture globale](#-architecture-globale)
4. [Technologies utilisées](#-technologies-utilisées)
5. [Structure du projet](#-structure-du-projet)
6. [Phases du projet](#-phases-du-projet)
7. [Fonctionnalités implémentées](#-fonctionnalités-implémentées)
8. [Installation et déploiement](#-installation-et-déploiement)
9. [Guide d'utilisation](#-guide-dutilisation)
10. [Formats JSON des interfaces](#-formats-json-des-interfaces)
11. [Métriques et résultats](#-métriques-et-résultats)
12. [Équipe](#-équipe)
13. [Documentation](#-documentation)
14. [Licence](#-licence)

---

## 🎯 Contexte du projet

Les ransomwares représentent aujourd'hui l'une des menaces les plus destructrices en cybersécurité. En 2025, le coût moyen d'une attaque par ransomware dépasse les 4,5 millions de dollars (source : IBM Cost of a Data Breach Report). Les solutions EDR commerciales (CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint) reposent sur des architectures sophistiquées de collecte de télémétrie, d'analyse comportementale et de réponse automatisée.

Ce projet académique a pour ambition de **reproduire cette architecture de bout en bout** dans un environnement de laboratoire contrôlé, afin de comprendre et de démontrer les mécanismes internes d'un EDR moderne.

---

## 🏆 Objectifs

1. **Collecter** la télémétrie système Windows en temps réel via Sysmon et Winlogbeat.
2. **Normaliser** les événements bruts (Event ID 1, 3, 11, 23) en un format structuré exploitable.
3. **Agréger** les événements sur des fenêtres temporelles glissantes (10s / 30s) pour extraire 12 features comportementales.
4. **Apprendre** le comportement normal de la machine (Baseline) via des moyennes et écarts-types sur 15 minutes d'observation.
5. **Détecter** les anomalies par un double moteur : règles heuristiques adaptatives (Z-Scores) et Machine Learning (Random Forest / LSTM).
6. **Répondre** automatiquement en ordonnant la destruction ciblée (par PID) du processus malveillant via un Agent PowerShell.
7. **Tracer** chaque décision dans un rapport JSON archivé pour investigation post-mortem.
8. **Visualiser** les alertes en temps réel dans un Dashboard Web SOC (jauge de risque, timeline, historique des alertes).
9. **Conteneuriser** l'ensemble du serveur backend (API + Dashboard) via Docker et `docker-compose` pour un déploiement en une seule commande.

---

## 🏗️ Architecture globale

```
┌─────────────────────────────────────────────────────────────┐
│                    VM WINDOWS (Victime)                      │
│                                                             │
│  Sysmon (ETW)  ──>  Winlogbeat  ──>  HTTP POST :8000       │
│                                                             │
│  Agent PowerShell  <──  HTTP GET /agent/commands (2s poll)  │
│       │                                                     │
│       └──>  Stop-Process -Id <PID>  (Frappe chirurgicale)   │
└──────────────────────────┬──────────────────────────────────┘
                           │ Réseau VMnet1 (192.168.10.0/24)
                           │
┌──────────────────────────▼──────────────────────────────────┐
│          SERVEUR BACKEND (Hôte) — Docker Container          │
│                                                             │
│  ┌───────────┐   ┌──────────────────┐   ┌───────────────┐  │
│  │  Parser   │──>│ Feature Extractor │──>│ Baseline      │  │
│  │ (Sysmon)  │   │ (12 Features +   │   │ Engine        │  │
│  │           │   │  PID Tracker)     │   │ (Z-Scores)    │  │
│  └───────────┘   └──────────────────┘   └───────┬───────┘  │
│                                                  │          │
│                  ┌───────────────────────────────▼────────┐ │
│                  │         MOTEUR DE DÉCISION             │ │
│                  │                                        │ │
│                  │  Rules Engine    Random Forest  (LSTM)  │ │
│                  │  (Heuristique)   (ML Supervisé)        │ │
│                  └───────────────────────┬────────────────┘ │
│                                          │                  │
│                  ┌───────────────────────▼────────────────┐ │
│                  │       RESPONSE ENGINE                  │ │
│                  │  Score < 50  → Log                     │ │
│                  │  Score 50-79 → Alerte                  │ │
│                  │  Score >= 80 → KILL (PID)              │ │
│                  └───────────────────────┬────────────────┘ │
│                                          │                  │
│                  ┌───────────────────────▼────────────────┐ │
│                  │  reports/  (JSON SOC)                  │ │
│                  └───────────────────────────────────────-┘ │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              DASHBOARD WEB SOC (:8080)                  ││
│  │                                                         ││
│  │  Jauge de risque │ Timeline │ Alertes │ Journal réponse ││
│  │  Polling API /alerts toutes les 2s                      ││
│  │  (HTML / JS / Chart.js)                                 ││
│  └─────────────────────────────────────────────────────────┘│
│                                                             │
│  docker-compose up  ──>  Démarre API + Dashboard            │
└─────────────────────────────────────────────────────────────┘
```

### Rôle de Docker dans le projet

Docker est utilisé pour **conteneuriser le serveur backend** (API FastAPI + Dashboard Web) en un seul déploiement reproductible. Grâce à `docker-compose`, l'ensemble du serveur d'analyse démarre en une seule commande (`docker-compose up`), sans avoir à installer manuellement Python, les dépendances, ou configurer Uvicorn. Cela garantit :
- **Portabilité** : Le serveur peut être déployé sur n'importe quelle machine Linux/Windows/Mac disposant de Docker.
- **Reproductibilité** : L'environnement est identique en développement et en production.
- **Simplicité de démonstration** : Lors de la soutenance, un seul `docker-compose up` suffit pour lancer toute l'infrastructure serveur.

---

## 🛠️ Technologies utilisées

| Catégorie | Technologie | Rôle |
|-----------|-------------|------|
| Télémétrie | Sysmon (v15+) | Capture des événements système Windows (ETW) |
| Transport | Winlogbeat (8.18.3) | Expédition des logs JSON vers l'API |
| API | FastAPI + Uvicorn | Serveur HTTP asynchrone pour la réception et l'analyse |
| Parsing | Python (json, gzip) | Normalisation des événements Sysmon bruts |
| Features | NumPy, Pandas | Calcul vectoriel des 12 features comportementales |
| ML Classique | scikit-learn (Random Forest) | Classification binaire (Normal vs Ransomware) |
| Deep Learning | PyTorch (LSTM) | Modèle séquentiel (expérimental) |
| Sérialisation | joblib | Export/Import des modèles entraînés (.pkl) |
| Agent | PowerShell natif | Exécution des ordres de réponse sur l'endpoint |
| Virtualisation | VMware Workstation Pro | Isolation de l'environnement de test |
| Versioning | Git / GitHub | Collaboration et historique du code |
| Conteneurisation | Docker / docker-compose | Déploiement du serveur (production) |

---

## 📁 Structure du projet

```
ransomware-detector/
├── agent/                          # Scripts déployés sur la VM Windows
│   ├── agent_ps.ps1                # Agent de Réponse Active (Polling + Kill)
│   ├── forwarder.ps1               # Script d'envoi manuel de logs
│   ├── simulate_ransomware.ps1     # Simulateur V1 (création de fichiers)
│   ├── simulate_ransomware_v2.ps1  # Simulateur V2 (APT complet : C2 + vssadmin + chiffrement)
│   └── winlogbeat.yml              # Configuration Winlogbeat pour la VM
│
├── api/                            # API FastAPI (Cerveau Central)
│   ├── main.py                     # Endpoints et logique d'orchestration
│   └── schemas.py                  # Modèles Pydantic (validation JSON)
│
├── parser/                         # Normalisation des logs
│   └── sysmon_parser.py            # Filtre Event ID 1/3/11/23 et normalise
│
├── features/                       # Extraction comportementale
│   └── feature_extractor.py        # Fenêtrage 10s, 12 features, PID Tracker
│
├── baseline/                       # Apprentissage du comportement normal
│   └── baseline_engine.py          # Moyenne + Ecart-type + Z-Score
│
├── detector/                       # Moteurs de détection
│   ├── rules_engine.py             # Règles heuristiques pondérées
│   ├── random_forest.py            # Entraînement du modèle RF
│   └── lstm_model.py               # Modèle LSTM (PyTorch)
│
├── models/                         # Modèles entraînés (sérialisés)
│   ├── random_forest_model.pkl     # Random Forest (joblib)
│   ├── scaler.pkl                  # StandardScaler (joblib)
│   └── lstm_model.pth              # LSTM (PyTorch)
│
├── scripts/                        # Scripts utilitaires
│   ├── prepare_dataset.py          # Génération du dataset (14 874 lignes)
│   └── train_model.py              # Entraînement automatisé du RF
│
├── data/                           # Données
│   ├── raw/                        # Logs bruts Sysmon (gitignored)
│   ├── processed/                  # dataset.csv (649 Ko, 14 874 lignes)
│   ├── synthetic/                  # Logs synthétiques de test
│   └── external/                   # Datasets externes (Stratosphere IPS)
│
├── reports/                        # Rapports d'incidents JSON (générés automatiquement)
│
├── dashboard/                      # Interface Web SOC (Phase 6)
│
├── notebooks/                      # Jupyter Notebooks d'exploration
│   └── exploration_eda.ipynb       # EDA et visualisations
│
├── docs/                           # Documentation technique détaillée
│   ├── lab_setup.md                # Guide de configuration du laboratoire
│   ├── architecture.md             # Architecture technique
│   ├── api_reference.md            # Référence API (Swagger)
│   ├── phase1_results.md           # Résultats Phase 1
│   ├── phase2_results.md           # Résultats Phase 2
│   ├── phase3_results.md           # Résultats Phase 3
│   ├── phase4_results.md           # Résultats Phase 4
│   └── phase5_results.md           # Résultats Phase 5
│
├── docker-compose.yml              # Orchestration Docker
├── requirements.txt                # Dépendances Python
└── README.md                       # Ce fichier
```

---

## 📅 Phases du projet

### Phase 1 - Environnement de Laboratoire (5–11 juillet)
Mise en place de l'infrastructure : VM Windows 10 sous VMware, installation de Sysmon (config SwiftOnSecurity), Winlogbeat, réseau VMnet1 (192.168.10.0/24), snapshot de référence, dépôt GitHub.

### Phase 2 - Pipeline de Données & Baseline (12–19 juillet)
Développement du Parser Sysmon (filtrage Event ID 1/3/11/23), du Feature Extractor (12 features sur fenêtres de 10s et 30s), du Baseline Engine (calcul de moyenne et écart-type sur 15 min d'activité normale), et de l'endpoint `/ingest` sur FastAPI.

### Phase 3 - Moteur de Règles & Tests (20–26 juillet)
Implémentation du Rules Engine : système de scoring pondéré avec 4 règles calibrées sur le baseline (création massive > seuil, entropie > 5.0, processus enfants suspects, connexions réseau). Création du premier simulateur de ransomware (V1). Validation des seuils et ajustement pour minimiser les faux positifs.

### Phase 4 - Machine Learning (27 juillet – 4 août)
Génération d'un dataset synthétique de 14 874 lignes avec 3 profils de ransomware (A : chiffrement massif, B : exfiltration réseau, C : wiper). Entraînement d'un Random Forest (scikit-learn) avec précision et rappel de 100% sur le jeu de test. Entraînement d'un LSTM (PyTorch) pour comparaison. Analyse de la feature importance (entropie et fichiers créés sont les plus discriminants).

### Phase 5 - API Complète & Response Engine (5–10 août) ✅
Développement du Response Engine V2.1 avec ciblage chirurgical par PID. Implémentation d'un système de score pondéré intra-processus (+1 file create, +2 file delete, +2 process create, +2 network, +10 entropie > 5.0). Réponse proportionnée (Score < 50 : log, 50-79 : alerte, >= 80 : KILL). Extraction de l'arbre généalogique (Parent PID/Name). Archivage JSON automatique dans `reports/`. Création du simulateur V2 (APT complet avec C2, vssadmin, chiffrement massif).

### Phase 6 - Dashboard, Docker & Intégration Finale (11–16 août) ⏳
- **Dashboard Web SOC** : Développement de l'interface graphique (HTML/JS/Chart.js) destinée aux analystes. Composants prévus : jauge de risque en temps réel, timeline des événements Sysmon, liste des alertes avec détails (PID, Score, Preuves), journal des réponses automatiques (Kill/Isolate).
- **Conteneurisation Docker** : Écriture du `Dockerfile` pour le backend Python (FastAPI + modèles ML) et du `docker-compose.yml` orchestrant l'API (port 8000) et le Dashboard (port 8080). Objectif : `docker-compose up` démarre tout le serveur en une commande.
- **Intégration IA (optionnel)** : Connexion d'un LLM (Gemini ou Mistral) pour générer des recommandations post-incident à partir des rapports JSON.

### Phase 7 - Documentation, Rapport & Soutenance (17–20 août) ⏳
Documentation technique finale complète, rédaction du rapport académique (contexte, choix techniques justifiés, résultats, perspectives), répétition de la démonstration live (exécution ransomware → détection → réponse automatique visible dans le Dashboard).

---

## 🔥 Fonctionnalités implémentées

### Collecte de Télémétrie
- Capture des événements Sysmon (Event ID 1, 3, 11, 23) via ETW
- Transport JSON via Winlogbeat vers l'API (HTTP POST sur le port 8000)
- Simulation de l'API Elasticsearch pour compatibilité native Winlogbeat (pas de script intermédiaire)

### Extraction Comportementale (12 Features)
| # | Feature | Description |
|---|---------|-------------|
| 1 | `nb_files_created` | Nombre de fichiers créés dans la fenêtre |
| 2 | `nb_files_deleted` | Nombre de fichiers supprimés |
| 3 | `nb_files_renamed` | Nombre de fichiers renommés |
| 4 | `nb_unique_extensions` | Nombre d'extensions uniques observées |
| 5 | `entropy_filenames` | Entropie de Shannon des noms de fichiers (0–8) |
| 6 | `nb_processes_created` | Nombre de processus créés |
| 7 | `nb_child_processes` | Nombre de processus enfants non-système |
| 8 | `process_depth` | Profondeur de l'arborescence de processus |
| 9 | `nb_connections` | Nombre de connexions réseau |
| 10 | `nb_unique_ips` | Nombre d'adresses IP uniques contactées |
| 11 | `nb_external_connections` | Nombre de connexions vers des IP publiques |
| 12 | `nb_dns_queries` | Nombre de requêtes DNS |

### Détection Hybride
- **Baseline Engine** : Apprentissage sur 10 fenêtres (mode lab) / 90 fenêtres (production). Calcul des Z-Scores pour chaque feature. Écart-type minimum forcé à 1.0 pour éviter les divisions par zéro.
- **Rules Engine** : Scoring pondéré basé sur les déviations Z-Score et les seuils absolus. Seuil d'alerte configurable (défaut : 0.70).
- **Random Forest** : Modèle supervisé entraîné sur 14 874 échantillons. Exporté via joblib. Inférence en temps réel sur chaque fenêtre de 10s.

### Réponse Active (Response Engine V2.1)
- **Tracking par PID** : Chaque processus est suivi individuellement avec un score de menace pondéré.
- **Arbre Généalogique** : Le processus parent (ParentImage, ParentProcessId) est extrait pour tracer la chaîne de causalité.
- **Proportionnalité** : 3 niveaux de réponse selon le score (log / alerte / kill).
- **Frappe Chirurgicale** : `Stop-Process -Id <PID>` avec fallback sur le nom.
- **Traçabilité & Persistance** : Rapport JSON complet archivé dans `reports/` et persistance automatique de l'historique complet dans une base de données **SQLite** locale (`alerts.db`).
- **Sécurité & Contrôle d'Accès** : Écran d'authentification des analystes (Franck / admin123) verrouillant l'accès à la console. Traçabilité complète et nominative des actions de réponse dans la base d'audit.

### Endpoints API

| Méthode | Route | Description |
|---------|-------|-------------|
| `GET` | `/` | Simulation Elasticsearch (compatibilité Winlogbeat) |
| `POST` | `/_bulk` | Réception native des logs Winlogbeat (NDJSON) |
| `POST` | `/ingest` | Ingestion manuelle d'un batch d'événements |
| `POST` | `/analyze` | Analyse ponctuelle d'un vecteur de features |
| `GET` | `/status` | État du système (ML activé, baseline entraînée) |
| `GET` | `/alerts` | Historique des alertes (chargé depuis SQLite) |
| `GET` | `/agent/commands` | File d'attente des ordres pour l'Agent (polling) |
| `POST` | `/response/kill/{pid}` | Ordre manuel de KILL |
| `POST` | `/response/isolate` | Ordre manuel d'isolation réseau |
| `POST` | `/login` | Authentification des analystes (Franck / admin123) |
| `GET`/`POST`/`DELETE` | `/exclusions` | Lecture et gestion des exclusions de sécurité |
| `GET`/`POST` | `/audit` | Lecture et insertion dans les journaux d'audit |

---

## 🚀 Installation et déploiement

### Prérequis
- **PC Hôte** : Python 3.11+, Git
- **VM Windows** : Windows 10/11, Sysmon installé, Winlogbeat configuré, PowerShell 5.1+
- **Réseau** : VMnet1 Host-Only (192.168.10.0/24)

### 1. Cloner le projet
```bash
git clone https://github.com/Franck922/ransomware-detector.git
cd ransomware-detector
```

### 2. Installer les dépendances Python
```bash
python -m venv venv
.\venv\Scripts\activate        # Windows
pip install -r requirements.txt --prefer-binary
```

### 3. Démarrer le serveur API
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### 4. Configurer la VM Windows
Voir le guide complet dans `docs/lab_setup.md`. En résumé :
- Installer Sysmon avec la configuration SwiftOnSecurity
- Configurer Winlogbeat pour pointer vers `http://192.168.10.2:8000`
- Copier `agent_ps.ps1` sur la VM

### 5. Lancer l'Agent de Réponse (sur la VM)
```powershell
Set-ExecutionPolicy Unrestricted -Force
.\agent_ps.ps1
```

### 6. Déploiement Conteneurisé avec Docker 🐳 (Recommandé)

Pour déployer l'intégralité du SOC EDR (API FastAPI + Console React servie par Nginx) en une seule ligne de commande sans configurer Python ou Node.js sur votre machine hôte :

1. S'assurer que le dossier `dashboard/dist` est bien compilé (exécuter `npm run build` dans le dossier `/dashboard` au préalable si nécessaire pour générer les fichiers de production).
2. Démarrer les services avec Docker Compose :
   ```bash
   docker-compose up -d --build
   ```
3. Accéder aux services :
   * **Console SOC (Dashboard React + Nginx)** : [http://localhost:8080](http://localhost:8080)
   * **API de contrôle EDR (FastAPI)** : [http://localhost:8000](http://localhost:8000) (ou swagger sur [http://localhost:8000/docs](http://localhost:8000/docs))
4. Pour arrêter les conteneurs proprement :
   ```bash
   docker-compose down
   ```

> [!TIP]
> **Persistance SQLite** : La base de données SQLite `alerts.db` est montée en volume (`- ./alerts.db:/app/alerts.db`) afin de préserver définitivement vos alertes, exclusions, comptes d'analystes et logs d'audit sur votre machine physique hôte, même après l'arrêt ou la recréation des conteneurs.

---

## 📖 Guide d'utilisation & Intégration (VM Windows <──> Docker Hôte)

Pour faire fonctionner l'ensemble du laboratoire EDR chez vous (ou pour le faire tourner auprès de votre encadreur/membres du groupe) :

### 1. Démarrer la stack Docker (sur l'Hôte physique)
```bash
docker-compose up -d --build
```
*Votre console SOC sera accessible sur `http://localhost:8080` (Identifiants : `franck@soc.edr.local` / `admin123`).*

### 2. Récupérer l'IP réseau Host-Only de votre Hôte
Pour que la VM puisse envoyer ses logs au serveur Docker et recevoir les commandes de riposte :
* **Sous Windows** : Lancer `ipconfig` dans un terminal et noter l'adresse IPv4 de la carte réseau virtuelle (ex: VMnet1 / Host-Only), typiquement `192.168.10.1` ou `192.168.10.2`.
* **Sous Linux/macOS** : Lancer `ip a` ou `ifconfig` et noter l'adresse de la carte correspondante.

### 3. Configurer et démarrer la VM Windows (Sensor & Agent)

#### A. Rediriger l'expédition de logs (Winlogbeat)
Sur la VM Windows, éditez le fichier de configuration de Winlogbeat (généralement `C:\Program Files\Winlogbeat\winlogbeat.yml`) et modifiez l'IP de destination pour pointer vers le serveur API Docker de l'hôte (port 8000) :
```yaml
output.elasticsearch:
  hosts: ["http://<IP_RESEAU_DE_L_HOTE>:8000"]
```
*Redémarrez ensuite le service Winlogbeat : `Restart-Service winlogbeat`.*

#### B. Lancer l'Agent de Réponse EDR (sur la VM)
1. Ouvrez le fichier script `agent_ps.ps1` (ou `agent.ps1`) présent dans le dossier `/agent`.
2. Assurez-vous que l'adresse URL du serveur pointe vers l'hôte :
   ```powershell
   $ServerUrl = "http://<IP_RESEAU_DE_L_HOTE>:8000"
   ```
3. Lancez l'agent dans une console PowerShell en tant qu'Administrateur :
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\agent_ps.ps1
   ```
   *(Vous devriez voir l'agent passer en statut actif et interroger le serveur toutes les 2 secondes).*

### 4. Simuler l'attaque de Ransomware
Sur la VM Windows, dans une autre console PowerShell en tant qu'Administrateur, lancez le simulateur d'attaque :
```powershell
.\simulate_ransomware_v2.ps1
```

### 5. Observer la Riposte Active
* Le simulateur va commencer ses actions (création massive de fichiers chiffrés, suppression des Shadow Copies, requêtes DNS suspectes).
* L'API Docker va corréler ces logs (le score heuristique et ML va grimper et dépasser 80 points).
* L'ordre de **KILL** va être généré sur l'API, récupéré par l'agent PowerShell sur la VM en moins de 2 secondes, qui va exterminer automatiquement le processus malveillant du simulateur.
* Vous verrez l'alerte rouge et la trace d'audit nominative apparaître en direct sur le Dashboard SOC à l'adresse `http://localhost:8080`.

---
## 🎯 Le Simulateur V2 (APT)
Le simulateur reproduit fidèlement 3 tactiques MITRE ATT&CK :
- **T1071** — Connexion C2 (via Invoke-WebRequest de test réseau)
- **T1490** — Inhibition de la restauration système (via exécution de vssadmin.exe)
- **T1486** — Chiffrement massif (génération de 500 fichiers à forte entropie .locked)

---

## 📡 Formats JSON des interfaces

### Événement Sysmon normalisé (Parser → Feature Extractor)
```json
{
  "event_id": 11,
  "timestamp": "2026-07-05T14:23:45.123Z",
  "process_name": "unknown.exe",
  "process_id": 4821,
  "process_path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\unknown.exe",
  "parent_process": "explorer.exe",
  "parent_process_id": 1532,
  "target_file": "C:\\Users\\Admin\\Documents\\rapport.docx.encrypted",
  "action": "file_create",
  "network_ip": null,
  "network_port": null
}
```

### Ordre KILL enrichi (API → Agent PowerShell)
```json
{
  "action": "KILL",
  "pid": 6128,
  "process": "powershell.exe",
  "parent": "explorer.exe",
  "parent_pid": 1532,
  "score": 241,
  "confidence": "HIGH",
  "stats": {
    "files_created": 231,
    "files_deleted": 0,
    "network_connections": 1,
    "processes_created": 1,
    "entropy": 5.678
  },
  "reasons": [
    "231 file creations",
    "High entropy (5.678)",
    "Network activity (1 connections)"
  ]
}
```

---

## 📊 Métriques et résultats

### Performance du Modèle Random Forest
| Métrique | Valeur |
|----------|--------|
| Précision (Precision) | 100% |
| Rappel (Recall) | 100% |
| F1-Score | 1.00 |
| Taille du dataset | 14 874 lignes |
| Profils de ransomware | 3 (Chiffrement, Exfiltration, Wiper) |

### Performance du Pipeline End-to-End
| Métrique | Valeur |
|----------|--------|
| Délai de détection | < 12 secondes (fenêtre 10s + polling 2s) |
| Taux de faux positifs (activité normale) | 0% |
| Taux de détection (simulateur V2) | 100% |
| Archivage des preuves | Automatique (JSON) |

---

## 👥 Équipe

| Membre | Domaine | Modules |
|--------|---------|---------|
| Membre 1 (M1) | Pipeline & Connecteur | `agent/`, `parser/`, `baseline/`, `features/`, `scripts/` |
| Membre 2 (M2) | Modèle de détection | `detector/`, `models/`, `notebooks/` |
| Membre 3 (M3) | API, Dashboard, Docker | `api/`, `dashboard/`, `docker-compose.yml` |

---

## 📚 Documentation

La documentation technique détaillée de chaque phase est disponible dans le dossier `docs/` :

| Document | Contenu |
|----------|---------|
| `docs/lab_setup.md` | Guide de configuration du laboratoire (VM, Sysmon, Winlogbeat) |
| `docs/architecture.md` | Architecture technique globale du système |
| `docs/api_reference.md` | Référence complète des endpoints API |
| `docs/phase1_results.md` | Résultats Phase 1 (Environnement) |
| `docs/phase2_results.md` | Résultats Phase 2 (Pipeline & Baseline) |
| `docs/phase3_results.md` | Résultats Phase 3 (Rules Engine) |
| `docs/phase4_results.md` | Résultats Phase 4 (Machine Learning) |
| `docs/phase5_results.md` | Résultats Phase 5 (Response Engine V2.1) |

---

## 📄 Licence

Projet académique de substitution de stage - ECE Paris 2026.  
Usage strictement pédagogique et éducatif.  
Aucune donnée réelle de ransomware n'est utilisée. Les simulations sont inoffensives et confinées dans un environnement de laboratoire isolé.