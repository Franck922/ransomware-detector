# 🔐 Ransomware Detector: MVP EDR Académique

Système de Détection et Réponse (EDR) de classe entreprise, capable d'identifier et d'isoler des comportements de ransomwares en temps réel grâce à l'analyse de signaux système (Sysmon) par des algorithmes ML (Random Forest) et heuristiques.

**ECE Paris Bachelor 3 Réseaux & Cybersécurité Promotion 2026**

---

## 📌 Présentation

Ce projet dépasse le simple cadre de l'IDS (Intrusion Detection System). C'est un **Endpoint Detection and Response (EDR)** complet capable de :

- **Collecter en continu** la télémétrie Windows (Event 1, 3, 11, 23) via Sysmon et Winlogbeat.
- **Extraire des caractéristiques** (Features) agrégées sur une fenêtre de 10s et classées par PID pour établir une chaîne de causalité.
- **Détecter les déviations** mathématiques (Z-Scores) par rapport à un *baseline* du comportement normal.
- **Statuer sur la menace** via un moteur de règles pondéré et un modèle de Machine Learning (Random Forest entraîné sur 14 000+ lignes de dataset).
- **Intervenir chirurgicalement** en tuant automatiquement le Processus malveillant (via son PID) via un Agent de Réponse Active.

---

## 🏗️ Architecture Technique (Phase 5 achevée)

```
[ POSTE CLIENT WINDOWS ]
        Sysmon
          ↓
      Winlogbeat
          │
          │ (JSON sur HTTP :8000)
          ▼
[ SERVEUR BACKEND (Uvicorn / FastAPI) ]
    1. Parser (sysmon_parser.py)
    2. Feature Extractor & Tracker PID (feature_extractor.py)
    3. Baseline Z-Score Engine (baseline_engine.py)
    4. Detector: RulesEngine + Random Forest Model
          │
          │ (Génération de Rapport JSON + File d'Attente)
          ▼
[ AGENT DE RÉPONSE ACTIVE ]
    agent_ps.ps1 (Polling toutes les 2s)
          │
          └─> Stop-Process -Id <PID> (Frappe Chirurgicale)
```

---

## 🚀 Fonctionnalités Clés (État Actuel)

### 1. Extraction Comportementale et Causalité
L'EDR ne se contente pas de surveiller la machine globale. Il suit la trace de chaque processus (PID).
- **12 Features calculées :** Fichiers créés, supprimés, renommés, entropie de Shannon, connexions réseau, processus enfants.
- **Top Suspect :** À chaque fenêtre, le PID ayant le score d'agressivité le plus élevé est retenu. L'arborescence (Parent PID) est tracée.

### 2. Double Moteur de Détection
- **Rules Engine :** Système expert basé sur des anomalies statistiques (Z-Scores).
- **Random Forest :** Entraîné sur un dataset d'injections APT. Modèle exporté via `joblib`.

### 3. Réponse Automatique Proportionnée
Le Backend ne prend pas de décision hâtive :
- **Score < 50** : Ignoré ou loggué.
- **50 ≤ Score < 80** : Alerte Critique (Log).
- **Score ≥ 80** : Déclenchement de l'ordre de meurtre (KILL).

### 4. Traçabilité (SOC)
Chaque meurtre de processus génère un rapport JSON complet (`reports/`) détaillant les statistiques incriminantes, la confiance de l'IA et l'arbre de causalité, prêt à être consommé par un tableau de bord.

---

## 🚀 Installation & Lancement

### Prérequis
- Python 3.11+
- Machine Virtuelle Windows (pour le déploiement Sysmon + Agent)

### 1. Installation du Serveur (Backend)
```bash
git clone https://github.com/TON_USERNAME/ransomware-detector.git
cd ransomware-detector

python -m venv venv
.\venv\Scripts\activate   # Windows
pip install -r requirements.txt --prefer-binary
```

### 2. Démarrage de l'API Centrale
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### 3. Démarrage de l'Agent de Réponse (Sur la VM)
Exécuter avec les droits Administrateur :
```powershell
.\agent\agent_ps.ps1
```

### 4. Simulation d'Attaque (Test End-to-End)
Lancer la simulation d'un ransomware (APT complet avec trafic réseau, purge de backups et création massive de fichiers chiffrés) :
```powershell
.\agent\simulate_ransomware_v2.ps1
```

---

## 📅 Avancement du Projet

| Phase | Objectif                                     | Statut |
|-------|----------------------------------------------|--------|
| 1     | Environnement, VM, Sysmon, Winlogbeat        | ✅ Terminé |
| 2     | Pipeline de données, Baseline, Features      | ✅ Terminé |
| 3     | Moteur de règles heuristiques                | ✅ Terminé |
| 4     | Machine Learning (Random Forest) & Dataset   | ✅ Terminé |
| 5     | API & Response Engine (Frappe Chirurgicale)  | ✅ Terminé |
| 6     | **Dashboard SOC Web & Intégration IA**       | ⏳ À venir |
| 7     | Documentation Finale & Soutenance            | ⏳ À venir |

---

## 📄 Licence
Projet académique (Bachelor Cybersécurité ECE Paris). Usage éducatif.