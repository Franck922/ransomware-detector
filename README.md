# Ransomware Detector - MVP EDR Académique

Système de **Détection et Réponse aux Incidents** (EDR) capable d'identifier et de neutraliser en
temps réel des comportements de ransomwares sur des postes Windows, grâce à l'analyse
comportementale des signaux système (Sysmon), un moteur de règles heuristiques adaptatives et un
modèle de Machine Learning (Random Forest).

Le serveur est multi-utilisateurs : plusieurs analystes SOC s'y connectent à distance depuis leur
navigateur, avec des habilitations distinctes, et voient tous les mêmes données au même instant.

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
9. [Vérification automatisée](#-vérification-automatisée)
10. [Guide d'utilisation](#-guide-dutilisation)
11. [Formats JSON des interfaces](#-formats-json-des-interfaces)
12. [Métriques et résultats](#-métriques-et-résultats)
13. [Équipe](#-équipe)
14. [Documentation](#-documentation)
15. [Licence](#-licence)

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
5. **Détecter** les anomalies par un double moteur : règles heuristiques adaptatives (Z-Scores) et Machine Learning (Random Forest).
6. **Répondre** automatiquement en ordonnant la destruction ciblée (par PID) du processus malveillant via un Agent PowerShell.
7. **Tracer** chaque décision dans un rapport JSON archivé pour investigation post-mortem.
8. **Visualiser** les alertes en temps réel dans une console SOC (score de risque, courbe d'activité, journal des alertes et des réponses).
9. **Partager** une vision unique du parc entre plusieurs analystes connectés à distance, avec des comptes cloisonnés par niveau d'habilitation et une traçabilité nominative de chaque action.
10. **Conteneuriser** l'ensemble du serveur (base de données, API, console) via Docker et `docker compose` pour un déploiement en une seule commande.

---

## 🏗️ Architecture globale

```
┌──────────────────────────────┐   ┌──────────────────────────────┐
│   VM WINDOWS surveillée #1   │   │   VM WINDOWS surveillée #2   │
│                              │   │                              │
│  Sysmon ─> Winlogbeat ───────┼───┼──────────┐                   │
│  Agent PowerShell <──────────┼───┼───────┐  │                   │
│    └─> Stop-Process -Id PID  │   │       │  │                   │
└──────────────────────────────┘   └───────┼──┼───────────────────┘
        Token d'agent obligatoire          │  │
                                           │  │ POST /_bulk
                        GET /agent/commands │  │ (NDJSON Sysmon)
┌──────────────────────────────────────────▼──▼───────────────────┐
│                      SERVEUR EDR (Docker)                        │
│                                                                  │
│  nginx :8080 ── origine unique ── /  /api  /ws                   │
│       │                                                          │
│       ├──> Console SOC React (build servi en statique)           │
│       │                                                          │
│       └──> API FastAPI :8000                                     │
│              │                                                   │
│              │  PIPELINE CLOISONNÉ PAR MACHINE                   │
│              │  Parser ─> Features 10s ─> Baseline (Z-Scores)    │
│              │                    │                              │
│              │       ┌────────────▼──────────────┐               │
│              │       │  Règles heuristiques      │               │
│              │       │  + Random Forest          │               │
│              │       │  score borné sur 100      │               │
│              │       └────────────┬──────────────┘               │
│              │                    │                              │
│              │   score >= 70 : alerte    score >= 80 : KILL auto │
│              │                    │                              │
│              ▼                    ▼                              │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                       PostgreSQL                            │  │
│  │  users · sessions · machines · alerts · metrics · commands  │  │
│  │  exclusions · audit_logs · app_settings                     │  │
│  │            SOURCE DE VÉRITÉ UNIQUE ET PARTAGÉE              │  │
│  └────────────────────────────────────────────────────────────┘  │
│              │                                                   │
│              └──> WebSocket /ws : avis d'invalidation par canal   │
└──────────────────────────────────┬───────────────────────────────┘
                                   │  cookie de session HttpOnly
        ┌──────────────────────────┼──────────────────────────┐
        ▼                          ▼                          ▼
   Analyste N1                Analyste N2               SOC Manager N3
   lecture, triage        + kill, isolation        + comptes, exclusions
```

### Pourquoi tous les analystes voient la même chose

PostgreSQL est la seule source de vérité. Aucun indicateur affiché dans la console n'est
calculé dans le navigateur : le score de risque, les compteurs et les points du graphique sont
agrégés par des requêtes SQL, avec des bornes temporelles alignées sur une origine fixe
(`date_bin`). Deux analystes qui ouvrent le dashboard à la même seconde obtiennent donc
rigoureusement les mêmes valeurs.

Le WebSocket ne transporte pas les données métier, seulement des avis d'invalidation
(« le canal `alerts` a changé »). Chaque client relit ensuite l'API. Ce choix évite qu'un message
perdu ou réordonné laisse un poste avec un état divergent, et garantit que les autorisations sont
réévaluées à chaque lecture. Si le WebSocket tombe, l'interface l'indique explicitement et bascule
sur un rafraîchissement périodique, plutôt que d'afficher silencieusement des données figées.

### Rôle de Docker dans le projet

`docker compose up -d --build` démarre les trois services : PostgreSQL, l'API (migrations Alembic
appliquées automatiquement) et nginx qui sert la console compilée. Ni Python ni Node.js ne sont
requis sur le serveur.

L'API tourne avec **un seul worker**, volontairement : les extracteurs de features et les baselines
sont des automates à état en mémoire, propres à chaque processus. Plusieurs workers analyseraient
chacun une partie des événements d'une même machine, ce qui fausserait les fenêtres et les
baselines. La consultation, elle, passe entièrement par PostgreSQL : le nombre de dashboards
connectés n'a donc aucune influence sur la cohérence des données.

---

## 🛠️ Technologies utilisées

| Catégorie | Technologie | Rôle |
|-----------|-------------|------|
| Télémétrie | Sysmon (v15+) | Capture des événements système Windows (ETW) |
| Transport | Winlogbeat (8.18.3) | Expédition des logs JSON vers l'API, authentifiée par token |
| API | FastAPI + Uvicorn | Serveur HTTP asynchrone pour l'ingestion, l'analyse et la console |
| Base de données | PostgreSQL 16 | Source de vérité unique et partagée entre analystes |
| Accès aux données | SQLAlchemy 2 (async) + Alembic | Requêtes typées et schéma versionné |
| Authentification | argon2-cffi | Hachage des mots de passe, sessions serveur en cookie HttpOnly |
| Temps réel | WebSocket (Starlette) | Avis d'invalidation diffusés aux consoles connectées |
| Parsing | Python (json, gzip) | Normalisation des événements Sysmon bruts |
| Features | NumPy, Pandas | Calcul vectoriel des 12 features comportementales |
| ML Classique | scikit-learn (Random Forest) | Classification binaire (Normal vs Ransomware) |
| Sérialisation | joblib | Export/Import des modèles entraînés (.pkl) |
| Console SOC | React 19 + Vite + Recharts | Interface analyste, 11 onglets alimentés par l'API |
| Reverse proxy | nginx | Origine unique pour la console, l'API et le WebSocket |
| Agent | PowerShell natif | Exécution des ordres de réponse sur l'endpoint |
| Vérification | httpx, websockets, Playwright | Suites automatisées API, parcours et rendu navigateur |
| Virtualisation | VMware Workstation Pro | Isolation de l'environnement de test |
| Versioning | Git / GitHub | Collaboration et historique du code |
| Conteneurisation | Docker / Docker Compose | Déploiement complet en une commande |

> PyTorch et XGBoost ont servi, dans le notebook, à comparer un LSTM et un boosting au Random Forest
> finalement retenu. Ils restent déclarés dans `requirements-research.txt` mais sont **exclus de
> l'image du serveur**, qui ne les importe nulle part : ils représentaient plus de 2,5 Go de
> dépendances pour du code jamais exécuté en production, et le build de l'API passe ainsi de plus de
> quinze minutes à une minute.

---

## 📁 Structure du projet

```
ransomware-detector/
├── agent/                          # Déployé sur les VM Windows surveillées
│   ├── agent_ps.ps1                # Agent de réponse (kill / isolate / ack)
│   ├── forwarder.ps1               # Envoi manuel de logs (dépannage)
│   ├── simulate_ransomware.ps1     # Simulateur V1 (création de fichiers)
│   ├── simulate_ransomware_v2.ps1  # Simulateur V2 (APT : C2 + vssadmin + chiffrement)
│   └── winlogbeat.yml              # Configuration Winlogbeat authentifiée
│
├── api/                            # Serveur FastAPI
│   ├── main.py                     # Assemblage, tâches de fond, cycle de vie
│   ├── config.py                   # Réglages typés (.env) + garde-fous production
│   ├── db.py                       # Session SQLAlchemy asynchrone
│   ├── models.py                   # 10 tables (users, sessions, alerts, ...)
│   ├── schemas.py                  # Contrats d'entrée/sortie Pydantic
│   ├── security.py                 # argon2id, sessions, RBAC, token d'agent
│   ├── realtime.py                 # Hub WebSocket et invalidation par canal
│   ├── detection.py                # Pipelines cloisonnés par machine
│   ├── audit_service.py            # Écriture du journal d'audit (serveur seul)
│   ├── bootstrap.py                # Premier compte N3 et réglages par défaut
│   └── routers/                    # auth · alerts · metrics · machines
│                                   # response · exclusions · audit · ingest · settings
│
├── migrations/                     # Alembic (schéma versionné)
│
├── dashboard/                      # Console SOC React
│   ├── src/api/                    # Client HTTP et catalogue d'endpoints
│   ├── src/auth/                   # Contexte de session, connexion, rotation
│   ├── src/realtime/               # Abonnement WebSocket et repli par sondage
│   ├── src/hooks/useResource.js    # Lecture, cache et réactualisation
│   ├── src/components/             # Layout, navigation, composants d'interface
│   ├── src/pages/                  # 11 onglets + fiches alerte et terminal
│   ├── tests/smoke.mjs             # Rendu vérifié dans un vrai navigateur
│   └── Dockerfile                  # Build Node puis service par nginx
│
├── parser/sysmon_parser.py         # Filtre et normalise les Event ID 1/3/11/23
├── features/feature_extractor.py   # Fenêtrage 10 s, 12 features, suivi par PID
├── baseline/baseline_engine.py     # Moyenne, écart-type, Z-Scores
│
├── detector/                       # Moteurs de détection
│   ├── rules_engine.py             # Règles heuristiques pondérées
│   └── random_forest.py            # Entraînement du modèle RF
│
├── models/                         # random_forest_model.pkl · scaler.pkl
│
├── scripts/                        # Outils en ligne de commande
│   ├── manage.py                   # Administration hors bande des comptes
│   ├── migrate_sqlite_to_pg.py     # Reprise de l'ancienne base alerts.db
│   ├── e2e_check.py                # Vérification fonctionnelle complète
│   ├── ui_check.py                 # Parcours de l'interface via le proxy
│   ├── list_routes.py              # Inventaire des routes et de leurs gardes
│   ├── prepare_dataset.py          # Génération du dataset (14 874 lignes)
│   └── train_model.py              # Entraînement automatisé du RF
│
├── data/                           # raw/ · processed/dataset.csv · synthetic/ · external/
├── reports/                        # Rapports d'incidents JSON
├── notebooks/exploration_eda.ipynb # Analyse exploratoire
├── docs/                           # Documentation technique par phase
│
├── deploy/nginx.conf               # Origine unique : /  /api  /ws
├── docker-compose.yml              # db · api · web
├── Dockerfile                      # Image de l'API
├── alembic.ini                     # Configuration des migrations
├── .env.example                    # Modèle de configuration
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
Génération d'un dataset synthétique de 14 874 lignes avec 3 profils de ransomware (A : chiffrement massif, B : exfiltration réseau, C : wiper). Entraînement d'un Random Forest (scikit-learn) avec précision et rappel de 100 % sur le jeu de test. Analyse de la feature importance : la profondeur d'arborescence des processus arrive en tête (20 %), devant le volume de fichiers créés (18 %) — ce n'est donc pas l'intensité du chiffrement qui distingue le mieux une attaque, mais la manière dont le processus a été lancé. Un LSTM (2 couches, PyTorch) a été entraîné et évalué dans le notebook à titre de comparaison, mais n'a pas été retenu pour la production : sur des fenêtres de 10 s déjà agrégées, il n'apportait pas de gain face au Random Forest tout en imposant PyTorch au serveur.

### Phase 5 - API Complète & Response Engine (5–10 août) ✅
Développement du Response Engine V2.1 avec ciblage chirurgical par PID. Implémentation d'un système de score pondéré intra-processus (+1 file create, +2 file delete, +2 process create, +2 network, +10 entropie > 5.0). Réponse proportionnée (Score < 50 : log, 50-79 : alerte, >= 80 : KILL). Extraction de l'arbre généalogique (Parent PID/Name). Archivage JSON automatique dans `reports/`. Création du simulateur V2 (APT complet avec C2, vssadmin, chiffrement massif).

### Phase 6 - Console SOC multi-utilisateurs, Docker & Intégration (11–16 août) ✅
- **Console SOC React** : 11 onglets destinés aux analystes (vue d'ensemble, terminaux, alertes, réponses actives, statistiques ML, moteur heuristique, exclusions, journal d'audit, équipe SOC, configuration, documentation), auxquels s'ajoutent la fiche forensics d'une alerte et la fiche d'un terminal. Aucune donnée fictive : chaque écran lit l'API.
- **Passage à PostgreSQL** : abandon de SQLite et de l'état en mémoire. Neuf tables versionnées par Alembic, avec un script de reprise de l'ancienne base. SQLite verrouillait la base entière à chaque écriture, ce qui interdisait plusieurs analystes simultanés et l'ingestion continue des agents.
- **Comptes et rôles** : authentification argon2id, sessions serveur en cookie `HttpOnly`, trois niveaux d'habilitation appliqués côté serveur, verrouillage après échecs répétés, rotation imposée des mots de passe provisoires.
- **Synchronisation temps réel** : WebSocket authentifié diffusant des avis d'invalidation par canal, avec repli automatique sur un rafraîchissement périodique en cas de coupure.
- **Conteneurisation** : `docker compose up -d --build` démarre PostgreSQL, l'API (migrations appliquées au démarrage) et nginx en origine unique. Aucun prérequis Python ou Node.js sur le serveur.
- **Vérification automatisée** : trois suites (fonctionnelle, parcours d'interface, rendu navigateur) rejouables à volonté pour la démonstration.

### Phase 7 - Documentation, Rapport & Soutenance (17–20 août) ⏳
Documentation technique finale complète, rédaction du rapport académique (contexte, choix techniques justifiés, résultats, perspectives), répétition de la démonstration live (exécution ransomware → détection → réponse automatique visible dans le Dashboard).

---

## 🔥 Fonctionnalités implémentées

### Collecte de Télémétrie
- Capture des événements Sysmon (Event ID 1, 3, 11, 23) via ETW
- Transport JSON via Winlogbeat vers l'API, authentifié par token d'agent
- Simulation de l'API Elasticsearch pour compatibilité native Winlogbeat (pas de script intermédiaire)
- Routage par machine : les événements de chaque poste alimentent son propre pipeline

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

### Réponse Active
- **Tracking par PID** : Chaque processus est suivi individuellement, avec le détail de son activité fichier, réseau et processus.
- **Arbre Généalogique** : Le processus parent (ParentImage, ParentProcessId) est extrait pour tracer la chaîne de causalité.
- **Score borné et explicable** : Le score porté par une alerte est le maximum entre le score heuristique normalisé et la probabilité du modèle, sur une échelle de 0 à 100. Le compteur d'activité brut du processus reste dans la fiche d'alerte comme élément de preuve, mais ne sert pas de niveau de gravité — sinon un serveur de fichiers actif serait classé critique par simple volume.
- **Proportionnalité** : score ≥ 70 → alerte, score ≥ 80 → arrêt automatique du processus (seuils configurables).
- **Frappe Chirurgicale** : `Stop-Process -Id <PID>`, repli par nom uniquement si le PID a disparu.
- **File d'ordres fiable** : chaque commande est persistée, adressée à une machine précise, et doit être acquittée par l'agent. Une commande non acquittée au bout de 15 minutes expire.
- **Dernière fenêtre garantie** : si un rançongiciel neutralise l'agent ou éteint le poste juste après son passage, aucun événement postérieur n'arrive pour fermer la fenêtre d'analyse — c'est pourtant celle-là qui contient la preuve. L'API l'évalue d'elle-même après un court silence.

### Sécurité de la console
- **Mots de passe** hachés en argon2id ; les comptes importés de l'ancienne base SQLite sont réhachés à leur première connexion réussie.
- **Sessions serveur** matérialisées par un cookie `HttpOnly` + `SameSite`, inaccessible au JavaScript : un XSS ne peut pas voler une session. Aucun jeton n'est stocké dans le navigateur.
- **Verrouillage** du compte après 5 échecs consécutifs ; message d'erreur identique pour un compte inexistant et un mot de passe erroné, afin de ne pas révéler quels comptes existent.
- **Rotation imposée** : un mot de passe défini par un administrateur ne donne accès à rien d'autre qu'à son propre changement.
- **RBAC appliqué côté serveur** sur chaque requête. Les boutons masqués dans l'interface ne sont qu'un confort d'affichage : un appel direct à l'API avec un compte N1 reçoit un 403.
- **Agents authentifiés** par token : sans lui, n'importe quelle machine du réseau pourrait injecter de faux événements pour fausser une baseline, ou dépiler l'ordre d'arrêt qui la visait.
- **Audit non falsifiable par un analyste** : les entrées sont écrites exclusivement par le serveur, qui détermine lui-même l'auteur et l'adresse IP source, et aucune route ne permet de les modifier ni de les supprimer. L'ancienne version acceptait ces valeurs du client, ce qui permettait d'écrire une entrée au nom d'un autre. Un accès direct à la base resterait évidemment souverain : la parade correspondante serait un export vers un journal externe en écriture seule.

### Endpoints API

Authentification et comptes :

| Méthode | Route | Rôle requis |
|---------|-------|-------------|
| `POST` | `/auth/login` | public |
| `POST` | `/auth/logout` · `GET /auth/me` · `POST /auth/change-password` | session |
| `GET`/`POST` | `/auth/users` | N3 |
| `PATCH`/`DELETE` | `/auth/users/{id}` | N3 |

Consultation (N1 et au-delà) :

| Méthode | Route | Description |
|---------|-------|-------------|
| `GET` | `/alerts` | Journal filtrable et paginé |
| `GET` | `/alerts/{id}` | Fiche forensics complète |
| `POST` | `/alerts/{id}/assign` · `PATCH /alerts/{id}/status` | Prise en charge et qualification |
| `GET` | `/machines` · `/machines/{machine_id}` | Inventaire des postes surveillés |
| `GET` | `/metrics/overview` | Indicateurs partagés du dashboard |
| `GET` | `/metrics/timeseries` | Série temporelle agrégée en base |
| `GET` | `/metrics/ml-insights` | Caractéristiques réelles du modèle chargé |
| `GET` | `/response/commands` | Journal des réponses actives |
| `GET` | `/audit` · `/audit/actions` | Journal d'audit (lecture seule) |
| `GET` | `/exclusions` · `/settings` | Règles et configuration en vigueur |
| `GET` | `/presence` | Analystes connectés au temps réel |

Actions privilégiées :

| Méthode | Route | Rôle requis |
|---------|-------|-------------|
| `POST` | `/response/kill` · `/response/isolate` · `/response/unisolate` | N2 |
| `POST`/`DELETE` | `/exclusions` · `/exclusions/{id}` | N3 |
| `PATCH` | `/exclusions/{id}/toggle` | N3 |
| `PUT` | `/settings/{key}` | N3 |

Interface agents (token requis) :

| Méthode | Route | Description |
|---------|-------|-------------|
| `POST` | `/_bulk` | Réception native Winlogbeat (NDJSON) |
| `POST` | `/ingest` | Ingestion d'un lot d'événements |
| `GET` | `/agent/commands` | Ordre en attente pour cette machine |
| `POST` | `/agent/commands/ack` | Acquittement d'exécution |

Divers : `GET /status` (sonde publique, ne divulgue aucune donnée métier), `WEBSOCKET /ws`
(canal d'invalidation, authentifié par le cookie de session).

---

## 🚀 Installation et déploiement

### Prérequis
- **Serveur EDR** : Docker Desktop (déploiement) ou Python 3.11+ et Node.js 20+ (développement)
- **VM Windows** : Windows 10/11, Sysmon installé, Winlogbeat, PowerShell 5.1+
- **Réseau** : VMnet1 Host-Only (192.168.10.0/24)

### IP de l'hôte : à lire sur chaque PC (pas une valeur fixe)

Sur VMnet1, l'adresse du **PC qui héberge l'API** n'est **pas la même pour tout le monde**.
Selon la config VMware, elle vaut souvent `192.168.10.1` ou `192.168.10.2`.

Sur le PC hôte :

```powershell
ipconfig
```

Repérer **VMware Network Adapter VMnet1** et noter l'IPv4 — c'est `<IP-HOTE>` dans la suite.
Sur la VM, Winlogbeat et `agent_ps.ps1` doivent pointer vers **cette** adresse, pas celle
d'un autre membre de l'équipe.

Exemple : si `ipconfig` affiche `192.168.10.2`, alors `hosts: ["http://192.168.10.2:8000"]`.

### 1. Cloner et configurer

```bash
git clone https://github.com/Franck922/ransomware-detector.git
cd ransomware-detector
cp .env.example .env
```

Éditer `.env` et remplacer **au minimum** les quatre secrets suivants par des valeurs générées :
`POSTGRES_PASSWORD`, `SESSION_SECRET`, `AGENT_TOKEN`, `BOOTSTRAP_ADMIN_PASSWORD`.

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

`BOOTSTRAP_ADMIN_EMAIL` et `BOOTSTRAP_ADMIN_PASSWORD` créent le premier compte SOC Manager au
démarrage. Ce mot de passe transitant par un fichier, sa rotation est imposée à la première
connexion.

### 1 bis. Vous aviez déjà le projet (mise à jour équipe)

Relancer d'anciens conteneurs **ne suffit pas** : la stack a changé (PostgreSQL, auth, nginx).

```bash
git pull
cp .env.example .env          # seulement si .env n'existe pas encore
# Éditer .env : remplacer les CHANGE_ME (chaque poste a ses propres secrets)
docker compose down
docker compose up -d --build
```

Console : **http://localhost:8080**. Pour reprendre une ancienne `alerts.db` :
`python -m scripts.migrate_sqlite_to_pg`. Puis mettre à jour Winlogbeat sur la VM
(IP hôte + `password` = `AGENT_TOKEN` du nouveau `.env`).

### 2. Déploiement conteneurisé (recommandé)

```bash
docker compose up -d --build
```

Les trois services démarrent : PostgreSQL, l'API (qui applique les migrations Alembic) et nginx.
La console est accessible sur **http://localhost:8080**, et depuis le réseau VMnet1 sur
`http://<IP-HOTE>:8080`. L'API est aussi publiée sur le **port 8000** pour les agents du lab
(`http://<IP-HOTE>:8000`), sans passer par nginx.

```bash
docker compose logs -f api     # suivre le démarrage et les détections
docker compose down            # arrêter (les données restent dans le volume pgdata)
```

### 3. Développement

```bash
python -m venv venv && .\venv\Scripts\activate
pip install -r requirements.txt --prefer-binary

docker compose up -d db        # PostgreSQL seul
alembic upgrade head           # schéma
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Dans un second terminal :

```bash
cd dashboard && npm install && npm run dev
```

La console est sur http://localhost:5173. Vite proxifie `/api` et `/ws` vers l'API, donc le
navigateur ne voit qu'une seule origine — exactement comme derrière nginx en production, ce qui
permet au cookie de session de fonctionner à l'identique dans les deux modes.

### 4. Migrer depuis l'ancienne base SQLite

```bash
python -m scripts.migrate_sqlite_to_pg
```

Comptes, exclusions, journal d'audit et alertes sont reprises. Les mots de passe importés restent
en SHA-256 (marqués `sha256-legacy`), sont réhachés en argon2id à la première connexion réussie, et
leur rotation est exigée immédiatement après.

### 5. Configurer les postes surveillés

1. Sur l'hôte, noter `<IP-HOTE>` (`ipconfig` → VMnet1) et la valeur de `AGENT_TOKEN` dans `.env`
   (ou `docker compose exec -T api printenv AGENT_TOKEN`).
2. Déposer `agent/winlogbeat.yml` dans `C:\Program Files\winlogbeat\` sur la VM, en adaptant :
   - `hosts: ["http://<IP-HOTE>:8000"]`
   - `password: "<AGENT_TOKEN>"` (ce n'est pas une variable nommée AGENT_TOKEN dans le fichier :
     c'est le champ `password` de la sortie Elasticsearch)
3. Puis :

```powershell
Restart-Service winlogbeat
Test-NetConnection <IP-HOTE> -Port 8000

$env:EDR_API_URL     = "http://<IP-HOTE>:8000"
$env:EDR_AGENT_TOKEN = "<AGENT_TOKEN>"
.\agent_ps.ps1                          # agent de réponse (à lancer en administrateur)
```

L'agent exécute les ordres d'arrêt de processus, d'isolation et de levée d'isolation, et acquitte
chaque exécution auprès du serveur.

### 6. Administration hors bande

La création de compte passe normalement par l'onglet **Équipe SOC**. En cas de perte de tous les
accès N3 :

```bash
python -m scripts.manage list-users
python -m scripts.manage create-user --email x@y.local --role N3
python -m scripts.manage reset-password --email x@y.local
python -m scripts.manage unlock --email x@y.local
python -m scripts.manage revoke-sessions --email x@y.local
```

### 7. Avant une exposition réelle

Passer `APP_ENV=production` et `COOKIE_SECURE=true` derrière une terminaison TLS. L'API **refuse de
démarrer** en production si les secrets sont restés à leur valeur de développement.

---

## ✅ Vérification automatisée

Trois suites, à exécuter services démarrés. Chacune accepte l'adresse à viser, ce qui permet de
valider **le déploiement réel derrière nginx** et pas seulement l'environnement de développement :

```bash
# 86 contrôles : API, RBAC, détection, temps réel, audit
python -m scripts.e2e_check                                   # API en direct (dev, port 8000)
python -m scripts.e2e_check --base-url http://localhost:8080/api   # à travers nginx (production)

# 37 contrôles : parcours d'un navigateur, cookie de session compris
python -m scripts.ui_check                                    # proxy Vite (dev, port 5173)
python -m scripts.ui_check --origin http://localhost:8080      # nginx (production)

# Rendu réel dans Chromium, onglet par onglet
python -m scripts.ui_check --origin http://localhost:8080 --keep   # laisse le compte de test
cd dashboard && node tests/smoke.mjs --origin http://localhost:8080
```

`e2e_check` valide notamment que deux analystes obtiennent des chiffres identiques, qu'un N1 ne peut
pas déclencher d'arrêt de processus, que les exclusions sont réellement appliquées par le moteur, et
que la dernière fenêtre d'une attaque est analysée même si l'agent cesse d'émettre.

`smoke.mjs` ouvre chaque onglet dans un vrai navigateur, échoue sur la moindre erreur JavaScript,
vérifie que le cookie de session est invisible de `document.cookie`, ouvre deux sessions pour
confirmer qu'elles affichent le même score, et enregistre des captures dans
`dashboard/tests/screenshots/`. Il a besoin d'un compte existant, d'où le `--keep` ci-dessus.

```bash
python -m scripts.list_routes        # inventaire des routes et de leur protection
```

Ces trois suites ont été exécutées contre le déploiement conteneurisé complet — donc à travers
nginx, avec l'API dans son conteneur — et non seulement en développement.

---

## 📖 Guide d'utilisation

### Scénario de démonstration de bout en bout

1. **Démarrer le serveur** : `docker compose up -d`
2. **Se connecter** sur http://localhost:8080 avec le compte de bootstrap, changer le mot de passe
   imposé, puis créer depuis l'onglet **Équipe SOC** un compte N1 et un compte N2 pour la démonstration.
3. **Lancer l'agent** sur la VM : `.\agent_ps.ps1`. La machine apparaît dans l'onglet
   **Machines** en phase d'apprentissage.
4. **Attendre la calibration** : après 10 fenêtres de 10 s, la machine passe en mode détection.
   L'onglet Machines affiche ce basculement sans rechargement de page.
5. **Déclencher l'attaque** dans un second terminal de la VM : `.\simulate_ransomware_v2.ps1`
6. **Observer**, sur tous les postes connectés simultanément :
   - une alerte apparaît en tête de l'onglet **Alertes** en moins d'une seconde ;
   - l'onglet **Réponses** montre la commande d'arrêt passer de `pending` à `acked` ;
   - le compteur du dashboard et le graphique s'incrémentent à l'identique sur chaque écran ;
   - l'agent affiche le bloc `EDR RESPONSE` puis `SUCCESS : Process terminated` ;
   - un rapport JSON est archivé dans `reports/`.
7. **Vérifier le cloisonnement** : avec le compte N1, le bouton d'arrêt de processus est absent, et un
   appel direct à `POST /api/response/kill` renvoie 403. L'onglet **Journal d'audit** conserve la
   trace nominative de la tentative comme des actions abouties.

### Le simulateur V2 (APT)
Le simulateur reproduit 3 tactiques MITRE ATT&CK :
- **T1071** — Connexion C2 (Invoke-WebRequest)
- **T1490** — Inhibition de la restauration (vssadmin.exe)
- **T1486** — Chiffrement massif (500 fichiers à forte entropie)

Sans machine Windows disponible, `python -m scripts.e2e_check` rejoue la même chaîne en injectant un
lot d'événements Sysmon dans l'API, et vérifie l'alerte, la commande, sa prise en compte par l'agent
et son acquittement.

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
  "command_id": 42,
  "action": "KILL",
  "target": 6128,
  "pid": 6128,
  "machine_id": "WIN10-LAB-01",
  "payload": {
    "action": "KILL",
    "machine_id": "WIN10-LAB-01",
    "pid": 6128,
    "process": "powershell.exe",
    "parent": "explorer.exe",
    "parent_pid": 1532,
    "score": 92,
    "confidence": "HIGH",
    "detection_source": "RulesEngine",
    "rules_score": 92,
    "ml_probability": 0.9993,
    "activity_points": 241,
    "stats": {
      "files_created": 231,
      "files_deleted": 0,
      "network_connections": 1,
      "processes_created": 1,
      "entropy": 5.678
    },
    "reasons": [
      "231 fichiers créés",
      "Entropie élevée des noms de fichiers (5.678)",
      "1 connexions réseau"
    ]
  }
}
```

`score` est la gravité normalisée sur 100 qui déclenche la réponse ; `activity_points` est le
compteur d'activité brut du processus, conservé comme élément de preuve.

### Acquittement (Agent PowerShell → API)
```json
{
  "command_id": 42,
  "success": true,
  "message": "Process 6128 terminated"
}
```

### Avis d'invalidation (API → consoles connectées)
```json
{ "type": "invalidate", "channel": "alerts", "at": "2026-08-11T14:23:52.187Z" }
```

Le message ne transporte aucune donnée métier : chaque console relit l'API sur le canal concerné,
avec ses propres droits.

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
| Délai de détection | < 12 s (fenêtre de 10 s + sondage de l'agent toutes les 2 s) |
| Délai d'affichage dans les consoles | < 1 s après écriture en base (invalidation WebSocket) |
| Fenêtre finale d'une attaque | évaluée dans les 30 s même si l'agent cesse d'émettre |
| Taux de faux positifs (activité normale) | 0 % |
| Taux de détection (simulateur V2) | 100 % |
| Archivage des preuves | Automatique (JSON + fiche d'alerte en base) |

### Robustesse de la plateforme
| Métrique | Valeur |
|----------|--------|
| Contrôles automatisés | 86 (`e2e_check`) + 37 (`ui_check`) + 11 onglets (`smoke.mjs`) |
| Écritures concurrentes | PostgreSQL, plus de verrou global comme avec SQLite |
| Routes exposées sans authentification | 3 (`/status`, `/auth/login`, la console elle-même) |
| Divergence entre deux analystes | nulle : indicateurs agrégés en SQL sur des bornes fixes |

---

## 👥 Équipe

| Membre | Domaine | Modules |
|--------|---------|---------|
| Membre 1 (M1) | Pipeline & Connecteur | `agent/`, `parser/`, `baseline/`, `features/`, `scripts/` |
| Membre 2 (M2) | Modèle de détection | `detector/`, `models/`, `notebooks/` |
| Membre 3 (M3) | API, Dashboard, Docker | `api/`, `dashboard/`, `docker-compose.yml` |

---

## 📚 Documentation

La console embarque son propre onglet **Documentation** : chaîne de traitement, signification des
scores, niveaux d'habilitation et procédure de réponse à incident y sont accessibles à l'analyste
sans quitter l'interface. L'onglet **Moteur heuristique** explique chaque règle avec les seuils
réellement en vigueur, lus depuis la configuration et non recopiés dans le code de la page.

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