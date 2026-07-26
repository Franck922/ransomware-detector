# Phase 6 : Console Web d'Administration SOC & Base de Données

Cette phase documente la transition de la console EDR d'un modèle statique et temporaire vers une plateforme de supervision de niveau industriel, intégrant la persistance des données, la sécurité d'accès et la traçabilité complète des interventions.

---

## 1. Objectifs de la Phase 6
1. **Verrouiller l'accès** à la console d'administration SOC par un écran d'authentification.
2. **Assurer la persistance** de l'historique des alertes au redémarrage de l'API.
3. **Créer un module d'inscription (Sign-up)** pour enrôler dynamiquement de nouveaux analystes dans la base.
4. **Développer un journal d'audit dynamique** pour historiser nominativement toutes les interventions de sécurité (Kills, Isolations, Exclusions).
5. **Gérer de véritables exclusions** de surveillance de fichiers et de dossiers stockées en base de données.

---

## 2. Implémentation du Backend (FastAPI & SQLite)

Nous avons choisi d'intégrer une base de données locale **SQLite** (`alerts.db`) à la racine du backend EDR pour sa légèreté et sa robustesse en mode laboratoire.

### 2.1 Schéma des Tables SQLite
Lors de l'initialisation de l'API (`api/main.py`), quatre tables sont créées automatiquement si elles n'existent pas :
```sql
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    pid INTEGER,
    process TEXT,
    score REAL,
    confidence REAL,
    status TEXT,
    kill_payload TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT,
    permissions TEXT
);

CREATE TABLE IF NOT EXISTS exclusions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,
    path TEXT,
    comment TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    username TEXT,
    action TEXT,
    details TEXT,
    ip_source TEXT
);
```

### 2.2 Utilisateur Administrateur par Défaut
Afin de permettre une connexion immédiate après l'initialisation de la base de données, un profil d'administrateur par défaut est créé et inséré :
* **Username :** `Franck`
* **Password :** `admin123` (Stocké sous forme de hash SHA-256 : `240753773b586c21e51b2a95c95a0680...`)
* **Rôle :** `SOC Manager (N3)` (Permissions : "Contrôle total, Isolation, Exclusions")

---

## 3. Implémentation du Frontend (React & Tailwind CSS)

L'application web React a été enrichie de plusieurs modules clés :

### 3.1 Écran d'Authentification & d'Inscription (Login / Sign-up)
* L'écran de connexion par défaut masque le reste du Dashboard tant que l'analyste n'a pas validé son jeton de session.
* Un lien permet de basculer vers un écran d'inscription pour créer de nouveaux profils avec choix du rôle EDR (N1, N2 ou N3).

### 3.2 Profil Analyste Interactif (Header)
L'avatar utilisateur est cliquable et affiche une bulle de profil déroulante :
* Justifie le nom de l'analyste connecté et son niveau de rôle.
* Affiche ses permissions effectives sous forme de badges.
* Propose un bouton de déconnexion immédiat.

### 3.3 Éditeur d'Exclusions Actives
Connecté directement aux routes `/exclusions` de l'API :
* Permet d'insérer dynamiquement des dossiers (ex: `C:\Program Files\Git\`) ou des exécutables de confiance.
* Offre la possibilité de retirer une exclusion active de la base.

### 3.4 Journal d'Audit SOC
* Historise nominativement toutes les opérations critiques avec heure exacte, action, détail et adresse IP source de la console d'administration.

---

## 4. Déploiement Conteneurisé (Docker & Docker Compose)

Afin d'industrialiser le déploiement et de rendre l'application portable sur n'importe quelle machine (sans nécessiter l'installation de Python, Node.js ou npm localement), nous avons mis en place une conteneurisation complète.

### 4.1 Conteneurisation de l'API (Backend)
Le `Dockerfile` à la racine s'appuie sur une image ultra-légère `python:3.11-slim` :
* Il copie les dépendances (`requirements.txt`).
* Installe les bibliothèques requises (`fastapi`, `uvicorn`, `sqlite3`, etc.).
* Expose le port **`8000`** et démarre le serveur de manière asynchrone avec Uvicorn.

### 4.2 Conteneurisation du Dashboard (Frontend)
Le Dashboard React est déployé dans un serveur web **Nginx** (via l'image officielle `nginx:alpine`) :
* Il sert statiquement le dossier de build de production `./dashboard/dist` sur le port **`8080`** de la machine hôte.

### 4.3 Orchestration avec Docker Compose
Le fichier `docker-compose.yml` orchestre et configure ces deux conteneurs :
```yaml
services:
  api:
    build: .
    container_name: edr-api
    ports:
      - "8000:8000"
    volumes:
      - ./models:/app/models
      - ./reports:/app/reports
      - ./alerts.db:/app/alerts.db
    restart: unless-stopped

  dashboard:
    image: nginx:alpine
    container_name: edr-dashboard
    ports:
      - "8080:80"
    volumes:
      - ./dashboard/dist:/usr/share/nginx/html
    restart: unless-stopped
    depends_on:
      - api
```

#### Points Clés de Sécurité & Fiabilité dans le Compose :
* **Persistance SQLite** : Montage de volume `- ./alerts.db:/app/alerts.db`. Cela garantit que la base de données SQLite physique reste stockée sur la machine hôte. Si les conteneurs sont mis à jour, arrêtés ou recréés, les comptes utilisateurs, les exclusions et les logs d'audit ne sont jamais perdus.
* **Synchronisation** : L'option `depends_on` force le conteneur API à démarrer avant le Dashboard.

---

## 5. Tests et Validation
* **Création de Compte :** Inscription réussie de profils alternatifs et reconnexion avec les droits correspondants.
* **Persistance après Reboot :** Après arrêt et redémarrage du backend FastAPI (ou des conteneurs Docker), l'historique complet des alertes et les exclusions définies sont parfaitement préservés.
* **Journalisation :** Chaque action de blocage manuel (Kill) ou d'isolation réseau initiée depuis le Dashboard écrit instantanément une trace d'audit nominative en base SQLite.
* **Déploiement Docker :** Tout le serveur EDR démarre en une seule ligne de commande (`docker-compose up -d --build`) et est directement accessible sur l'hôte.
