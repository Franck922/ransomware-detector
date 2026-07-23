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

## 4. Tests et Validation
* **Création de Compte :** Inscription réussie de profils alternatifs et reconnexion avec les droits correspondants.
* **Persistance après Reboot :** Après arrêt et redémarrage du backend FastAPI, l'historique complet des alertes et les exclusions définies sont parfaitement préservés.
* **Journalisation :** Chaque action de blocage manuel (Kill) ou d'isolation réseau initiée depuis le Dashboard écrit instantanément une trace d'audit nominative en base SQLite.
