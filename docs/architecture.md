# Architecture Technique du Système EDR

**Date de rédaction** : Juillet 2026  
**Dernière mise à jour** : 22 juillet 2026  
**Version** : 2.1 (Response Engine avec ciblage PID)

---

## 1. Vue d'ensemble

Le système Ransomware Detector est un EDR (Endpoint Detection and Response) composé de **7 modules** interconnectés, répartis entre un poste Windows surveillé (la VM victime) et un serveur d'analyse centralisé (le PC hôte). L'architecture suit le modèle classique des EDR d'entreprise : collecte sur l'endpoint, analyse dans le cloud, réponse sur l'endpoint.

```
VM Windows (Endpoint)              Serveur Backend (Hôte)
┌────────────────────┐             ┌──────────────────────────────┐
│ Sysmon             │             │                              │
│   ↓                │             │  1. Parser                   │
│ Winlogbeat ────────┼─── HTTP ───→│  2. Feature Extractor        │
│                    │   :8000     │  3. Baseline Engine          │
│ Agent PowerShell ←─┼─── HTTP ───←│  4. Rules Engine             │
│   ↓                │ /commands   │  5. Random Forest / LSTM     │
│ Stop-Process       │             │  6. Response Engine           │
└────────────────────┘             │  7. Dashboard Web (Phase 6)  │
                                   └──────────────────────────────┘
```

---

## 2. Les 7 Modules du Pipeline

### 2.1. Module 1 — Parser Sysmon (`parser/sysmon_parser.py`)

**Entrée** : Événement JSON brut de Winlogbeat (structure Elasticsearch `winlog.event_data`)  
**Sortie** : Dictionnaire Python normalisé

Le Parser est le premier maillon de la chaîne. Il reçoit les événements bruts au format JSON d'Elasticsearch (structure imbriquée avec `winlog.event_data`) et les transforme en un dictionnaire Python plat et exploitable.

#### Filtrage
Seuls 4 Event IDs Sysmon sont conservés (sur les 29 existants) :
- **Event 1** (Process Create) : Création de processus → `action: "process_create"`
- **Event 3** (Network Connection) : Connexion réseau → `action: "network_connection"`
- **Event 11** (File Create) : Création de fichier → `action: "file_create"`
- **Event 23** (File Delete) : Suppression de fichier → `action: "file_delete"`

Tous les autres événements sont silencieusement ignorés pour réduire le bruit (on passe typiquement de 503 événements bruts à ~250 événements pertinents par batch).

#### Normalisation
Chaque événement pertinent est transformé en un dictionnaire contenant :
- `event_id`, `timestamp`, `action` (obligatoires)
- `process_name`, `process_id`, `process_path` (extraits de `Image`)
- `parent_process`, `parent_process_id` (extraits de `ParentImage` et `ParentProcessId`)
- `target_file` (pour les Event 11/23)
- `network_ip`, `network_port` (pour les Event 3)

---

### 2.2. Module 2 — Feature Extractor (`features/feature_extractor.py`)

**Entrée** : Flux d'événements normalisés  
**Sortie** : Vecteur de 12 features numériques + métadonnées du processus suspect

Le Feature Extractor agrège les événements sur des **fenêtres temporelles glissantes** (10 secondes par défaut) et calcule 12 caractéristiques comportementales :

| # | Feature | Type | Description |
|---|---------|------|-------------|
| 1 | `nb_files_created` | int | Compteur de fichiers créés dans la fenêtre |
| 2 | `nb_files_deleted` | int | Compteur de fichiers supprimés |
| 3 | `nb_files_renamed` | int | Compteur de fichiers renommés |
| 4 | `nb_unique_extensions` | int | Nombre d'extensions uniques (.docx, .exe, .encrypted) |
| 5 | `entropy_filenames` | float | Entropie de Shannon des noms de fichiers (0.0 = prévisible, ~8.0 = aléatoire/chiffré) |
| 6 | `nb_processes_created` | int | Nombre de processus créés |
| 7 | `nb_child_processes` | int | Nombre de processus enfants non-système |
| 8 | `process_depth` | int | Profondeur de l'arborescence de processus |
| 9 | `nb_connections` | int | Nombre de connexions réseau |
| 10 | `nb_unique_ips` | int | Nombre d'adresses IP distinctes contactées |
| 11 | `nb_external_connections` | int | Connexions vers des IP publiques (non RFC 1918) |
| 12 | `nb_dns_queries` | int | Requêtes DNS (réservé, Sysmon Event 22) |

#### Tracking par PID (V2.1)
En plus des 12 features globales, le Feature Extractor V2.1 suit chaque processus individuellement via un dictionnaire `process_tracker`. Chaque PID accumule un **score de menace pondéré** :

| Événement | Pondération |
|-----------|:-----------:|
| File Create | +1 |
| File Delete | +2 |
| Process Create | +2 |
| Network Connection | +2 |
| Entropie > 5.0 | +10 |

Le PID ayant le score le plus élevé à la fin de la fenêtre est désigné comme `top_suspect`. Son processus parent (ParentImage, ParentProcessId) est également extrait pour établir la **chaîne de causalité** (Kill Chain).

---

### 2.3. Module 3 — Baseline Engine (`baseline/baseline_engine.py`)

**Entrée** : Vecteurs de features successifs  
**Sortie** : Z-Scores (déviations par rapport au comportement normal)

Le Baseline Engine implémente un algorithme d'**apprentissage statistique non supervisé** en deux phases :

#### Phase d'Apprentissage
Pendant les 10 premières fenêtres (mode lab) ou 90 fenêtres (mode production, soit 15 minutes), le moteur observe l'activité normale de la machine et stocke chaque vecteur de features dans un historique. Lorsque le seuil est atteint, il calcule pour chaque feature :
- **Moyenne (μ)** : Valeur centrale de référence
- **Écart-type (σ)** : Dispersion normale autour de la moyenne

Mesure de protection : L'écart-type est forcé à `max(σ, 1.0)` pour éviter les divisions par zéro lorsqu'une feature est constante (ex: 0 connexions réseau pendant 15 min).

#### Phase de Détection
Pour chaque nouveau vecteur de features, le moteur calcule le **Z-Score** :

$$Z = \frac{X - \mu}{\sigma}$$

Un Z-Score de 63.77 (comme observé lors de nos tests) signifie que la valeur observée est 63.77 écarts-types au-dessus de la normale. C'est une impossibilité statistique qui ne peut s'expliquer que par un comportement anormal (ransomware).

---

### 2.4. Module 4 — Rules Engine (`detector/rules_engine.py`)

**Entrée** : Vecteur de features + Z-Scores  
**Sortie** : Décision binaire (alerte ou non) + score de confiance + règles déclenchées

Le Rules Engine est un **système expert heuristique** qui évalue 4 règles de scoring pondérées :

1. **Création massive de fichiers** : Si `nb_files_created` dépasse un seuil dynamique → +30 points
2. **Entropie suspecte** : Si `entropy_filenames` > 5.0 (noms aléatoires/chiffrés) → +40 points
3. **Processus enfant suspect** : Si un processus enfant non-système est détecté avec activité fichier → +20 points
4. **Connexions réseau externes** : Si des connexions vers des IP publiques sont détectées → +10 points

Le score total est normalisé entre 0.0 et 1.0. Si le score dépasse le seuil configurable (défaut : 0.70), une alerte est déclenchée.

---

### 2.5. Module 5 — Modèles Machine Learning

#### Random Forest (`detector/random_forest.py` + `models/random_forest_model.pkl`)
Modèle de classification supervisé entraîné sur un dataset de 14 874 échantillons (mélange d'activité normale et de 3 profils de ransomware). Les features les plus discriminantes identifiées par l'algorithme sont :
1. `entropy_filenames` (importance ~0.35)
2. `nb_files_created` (importance ~0.25)
3. `nb_external_connections` (importance ~0.15)

Le modèle atteint une précision et un rappel de 100% sur le jeu de test (split 80/20).

#### LSTM (`detector/lstm_model.py` + `models/lstm_model.pth`)
Modèle séquentiel (Long Short-Term Memory) implémenté en PyTorch. Architecture : 2 couches LSTM + Dense + Sigmoid. Entraîné avec Adam + BCELoss. Ce modèle est expérimental et sert de point de comparaison avec le Random Forest.

#### Standardisation (`models/scaler.pkl`)
Les 12 features sont standardisées (moyenne 0, variance 1) via un `StandardScaler` de scikit-learn avant d'être passées au modèle. Le scaler est sérialisé via joblib pour garantir la cohérence entre l'entraînement et l'inférence.

---

### 2.6. Module 6 — Response Engine (intégré dans `api/main.py` + `agent/agent_ps.ps1`)

**Entrée** : Décision du moteur de détection + métadonnées du `top_suspect`  
**Sortie** : Ordre JSON envoyé à l'Agent PowerShell

Le Response Engine est le mécanisme de riposte automatique. Il fonctionne en deux temps :

#### Côté Backend (API)
1. Extraction du `top_suspect` (PID, nom, parent, score)
2. Génération des raisons textuelles (ex: "231 file creations", "High entropy (5.678)")
3. Évaluation du score pour décider de la réponse :
   - **Score < 50** → Journalisation simple (log INFO)
   - **Score 50-79** → Alerte Critique (log WARNING), pas d'action
   - **Score >= 80** → Ordre `KILL` placé dans la file d'attente + rapport JSON archivé dans `reports/`
4. Ajout d'un indicateur de `confidence` (LOW / MEDIUM / HIGH)

#### Côté Endpoint (Agent PowerShell)
L'Agent interroge la route `GET /agent/commands` toutes les 2 secondes (modèle **Pull/Polling**). Lorsqu'un ordre est disponible :
1. Affichage de la console `EDR RESPONSE` avec toutes les preuves
2. Exécution de `Stop-Process -Id <PID> -Force`
3. En cas d'échec du PID (processus déjà mort), fallback sur `Stop-Process -Name <nom>`

#### Choix du modèle Pull (Polling) vs Push (WebSocket)
Le modèle Pull a été choisi car :
- Il traverse naturellement les pare-feux d'entreprise (trafic sortant HTTP standard)
- Il ne nécessite pas d'ouvrir un port d'écoute sur l'endpoint (pas de surface d'attaque)
- Il est simple à implémenter et très résilient (reconnexion automatique)
- Le délai maximal de réponse (polling interval de 2s) est acceptable pour un prototype

---

### 2.7. Module 7 — Dashboard Web SOC (`dashboard/`) — Phase 6

Interface graphique web destinée aux analystes SOC. Prévue en HTML/JS/Chart.js avec les composants suivants :
- **Jauge de risque** en temps réel (score global de la machine)
- **Timeline** chronologique des événements Sysmon
- **Liste des alertes** avec détails (PID, Score, Preuves, Arbre de causalité)
- **Journal des réponses** automatiques (Kill/Isolate) avec horodatage
- **Rafraîchissement automatique** par polling de l'API `/alerts` toutes les 2 secondes

---

## 3. Flux de Données End-to-End

Voici le parcours complet d'un événement, de sa génération à la réponse automatique :

```
T=0s    Un processus malveillant crée 250 fichiers chiffrés sur la VM
          │
T=0.1s  Sysmon (ETW) intercepte chaque création de fichier (Event 11)
          │
T=1s    Winlogbeat collecte les événements du journal Windows
          │
T=2s    Winlogbeat envoie un batch JSON via POST /_bulk à l'API (:8000)
          │
T=2.1s  Le Parser filtre les Event ID pertinents (1, 3, 11, 23)
          │
T=2.2s  Le Feature Extractor agrège les événements sur la fenêtre de 10s
        et calcule le score pondéré par PID
          │
T=10s   La fenêtre se ferme. Le vecteur de 12 features est extrait.
        Le top_suspect est identifié (PID 6128, score 241)
          │
T=10.1s Le Baseline Engine calcule les Z-Scores (création=231.0, entropie=5.68)
          │
T=10.2s Le Rules Engine évalue les règles → Score 0.9 → ALERTE
        Le Random Forest confirme → prediction=1 (Ransomware)
          │
T=10.3s Le Response Engine génère le kill_payload JSON
        Score 241 >= 80 → Ordre KILL pour PID 6128
        Rapport archivé dans reports/2026-07-22_14-41-42_powershell.exe.json
          │
T=12s   L'Agent PowerShell récupère l'ordre via GET /agent/commands
        Affichage de l'EDR RESPONSE (Preuves + Decision + Action)
        Exécution de Stop-Process -Id 6128 -Force
          │
T=12.1s Le processus malveillant est terminé. L'attaque est stoppée.
```

**Temps total de détection et réponse : ~12 secondes** (fenêtre 10s + polling 2s).

---

## 4. Sécurité de l'Architecture

### 4.1. Isolation réseau
Le réseau VMnet1 est Host-Only : aucun accès Internet par défaut. La VM ne peut communiquer qu'avec le PC hôte. Les simulations de ransomware sont donc confinées.

### 4.2. Pas d'agent en écoute
L'Agent PowerShell ne crée aucun serveur HTTP sur l'endpoint. C'est lui qui initie les connexions sortantes (GET). Aucun port n'est ouvert sur la VM, ce qui empêche un attaquant de cibler l'Agent lui-même.

### 4.3. Simulation inoffensive
Le simulateur de ransomware V2 ne chiffre rien réellement. Il crée des fichiers factices dans `%TEMP%` et invoque `vssadmin list shadows` (lecture seule, pas de suppression). Le script est explicitement commenté et documenté pour garantir l'absence de tout effet destructeur.

---

## 5. Conteneurisation Docker (Phase 6)

L'objectif de Docker dans ce projet est de conteneuriser le serveur backend pour simplifier le déploiement. L'architecture Docker prévue :

```yaml
# docker-compose.yml
services:
  api:
    build: .
    ports:
      - "8000:8000"     # API FastAPI
    volumes:
      - ./models:/app/models
      - ./reports:/app/reports

  dashboard:
    image: nginx:alpine
    ports:
      - "8080:80"       # Dashboard Web
    volumes:
      - ./dashboard:/usr/share/nginx/html
```

Avec cette configuration, un seul `docker-compose up` démarre :
1. Le conteneur **API** (Python + FastAPI + modèles ML) sur le port 8000
2. Le conteneur **Dashboard** (Nginx servant les fichiers statiques HTML/JS) sur le port 8080

L'analyste SOC accède au Dashboard via `http://192.168.10.2:8080` depuis n'importe quel navigateur.

---

## 6. Perspectives d'Évolution

- **Intégration LLM** : Connecter un modèle Gemini ou Mistral pour générer des recommandations post-incident à partir des rapports JSON
- **Multi-endpoints** : Gérer plusieurs VMs/endpoints simultanément avec identification par `machine_id`
- **Persistance** : Remplacer les listes Python en mémoire par une base de données (SQLite/PostgreSQL) pour résister aux redémarrages
- **HTTPS/TLS** : Chiffrer les communications API-Agent pour empêcher l'interception des ordres KILL
- **Authentification** : Ajouter un token JWT pour sécuriser les endpoints critiques (`/response/kill`, `/agent/commands`)
