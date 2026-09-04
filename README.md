# Ransomware Detector guide de reproduction

Ce projet est une **console SOC** (centre opérationnel de sécurité) de laboratoire.
Elle détecte des comportements de ransomware sur des postes Windows et permet aux
analystes de réagir depuis un navigateur.

Vous n’avez **pas besoin de connaître le code**. Avec Docker, vous installez le serveur
sur votre PC, vous ouvrez une page web, et vous vous connectez.

**ECE Paris - Bachelor 3 Réseaux & Cybersécurité, FALL 2026**  
Projet pédagogique. Les simulations sont inoffensives et doivent rester dans un lab isolé.

---

## Comment lire ce guide

- Suivez les étapes **dans l’ordre**, de la 0 à la 4. Chaque étape indique **où** taper.
- Les blocs gris sont des **commandes**. Copiez-les telles quelles, puis appuyez sur Entrée.
- `Ctrl+C` arrête un affichage de logs : les programmes Docker **continuent** de tourner.
- Ne commitez **jamais** le fichier `.env` et ne l’envoyez pas à un camarade (mots de passe).

**Deux machines possibles plus tard :**

| Machine | C’est quoi | Commandes à taper |
|---------|------------|-------------------|
| **PC hôte** | Votre ordinateur, celui où tourne Docker | PowerShell Windows |
| **VM Windows** | Un Windows virtuel (VMware), le « poste victime » | PowerShell **dans la VM** |

Jusqu’à l’étape 4, tout se fait **uniquement sur le PC hôte**. La VM est optionnelle.

---

## Table des matières

0. [Installer les prérequis](#0-installer-les-prérequis)
1. [Ouvrir un terminal au bon endroit](#1-ouvrir-un-terminal-au-bon-endroit)
2. [Télécharger le projet](#2-télécharger-le-projet)
3. [Créer le fichier de secrets (`.env`)](#3-créer-le-fichier-de-secrets-env)
4. [Démarrer Docker et ouvrir la console](#4-démarrer-docker-et-ouvrir-la-console)
5. [Première connexion](#5-première-connexion)
6. [Utiliser la plateforme](#6-utiliser-la-plateforme)
7. [Arrêter, relancer, mettre à jour](#7-arrêter-relancer-mettre-à-jour)
8. [Brancher une VM Windows (lab complet)](#8-brancher-une-vm-windows-lab-complet)
9. [Démonstration avec le simulateur](#9-démonstration-avec-le-simulateur)
10. [Si quelque chose ne marche pas](#10-si-quelque-chose-ne-marche-pas)
11. [Pour aller plus loin](#11-pour-aller-plus-loin)
12. [Licence](#12-licence)

---

## 0. Installer les prérequis

Sur le **PC hôte** (votre ordinateur), installez et **laissez ouverts** :

1. **Git** - [https://git-scm.com/download/win](https://git-scm.com/download/win)  
   Cochez les options par défaut. Redémarrez PowerShell après l’installation.
2. **Docker Desktop** — [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)  
   Après l’install, lancez **Docker Desktop** et attendez que l’icône baleine en bas à droite
   soit stable (plus « Starting… »). Sans ça, aucune commande `docker` ne fonctionnera.
3. Environ **4 Go de RAM** libres.

Python et Node.js **ne sont pas nécessaires** pour faire tourner le projet.

Vérification (voir [étape 1](#1-ouvrir-un-terminal-au-bon-endroit) pour ouvrir PowerShell) :

```powershell
git --version
docker --version
docker compose version
```

Vous devez voir un numéro de version pour chaque ligne. Si `docker` est introuvable :
Docker Desktop n’est pas démarré, ou PowerShell a été ouvert **avant** l’installation
(fermez-le et rouvrez-le).

---

## 1. Ouvrir un terminal au bon endroit

**Où :** sur le PC hôte.

1. Appuyez sur la touche **Windows**.
2. Tapez `PowerShell`.
3. Ouvrez **Windows PowerShell** (fond bleu).

Vous voyez une ligne du type `PS C:\Users\VotreNom>`. C’est ici que vous collerez les commandes.

Choisissez un dossier où stocker le projet, par exemple `Documents`. Pour y aller :

```powershell
cd $HOME\Documents
```

(`cd` = « change directory », aller dans un dossier.)

Vous pouvez aussi utiliser un autre chemin, par exemple `cd C:\MAMP\htdocs`.
**Retenez ce dossier** : toutes les commandes `docker compose` devront être tapées
**dedans**, une fois le projet téléchargé.

---

## 2. Télécharger le projet

**Où :** le même PowerShell, toujours dans le dossier choisi à l’étape 1
(ex. `C:\Users\VotreNom\Documents`).

```powershell
git clone https://github.com/Franck922/ransomware-detector.git
cd ransomware-detector
```

**Ce que ça fait :** Git copie le projet, puis `cd` entre **dans** le dossier du projet.

**Vérification :** la ligne de PowerShell doit se terminer par `ransomware-detector>`, par exemple :

```text
PS C:\Users\VotreNom\Documents\ransomware-detector>
```

Si vous fermez PowerShell plus tard, rouvrez-le et revenez dans ce dossier :

```powershell
cd $HOME\Documents\ransomware-detector
```

(Adaptez le chemin si vous avez cloné ailleurs.)

---

## 3. Créer le fichier de secrets (`.env`)

Le fichier `.env` contient les mots de passe du serveur. Chaque personne crée **le sien**.
Ne le commitez pas, ne le partagez pas sur Discord / GitHub.

### 3.1 Copier le modèle

**Où :** PowerShell, **dans** le dossier `ransomware-detector` (étape 2).

```powershell
Copy-Item .env.example .env
```

**Résultat :** un nouveau fichier `.env` apparaît à la racine du projet (à côté de `README.md`).
Windows peut cacher les fichiers qui commencent par un point : dans l’Explorateur, onglet
**Affichage** → cochez **Éléments masqués**.

### 3.2 Générer quatre secrets

Vous avez besoin de **4 chaînes longues et différentes**. Générez-les **une par une**
dans le **même** PowerShell :

```powershell
-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 48 | ForEach-Object { [char]$_ })
```

Appuyez sur Entrée : une ligne du type `kR9mP2…` s’affiche. **Copiez-la** (souris, ou
sélection + `Ctrl+C`), collez-la dans un Bloc-notes temporaire, puis **relancez la même
commande** trois autres fois. Vous obtenez 4 secrets distincts. Notez-les ainsi :

| À coller dans `.env` à la place de `CHANGE_ME` | Votre secret (exemple) |
|------------------------------------------------|------------------------|
| `POSTGRES_PASSWORD` | (secret 1) |
| `SESSION_SECRET` | (secret 2) |
| `AGENT_TOKEN` | (secret 3) |
| `BOOTSTRAP_ADMIN_PASSWORD` | (secret 4, **au moins 12 caractères** — les 48 générés conviennent) |

Gardez surtout `BOOTSTRAP_ADMIN_PASSWORD` et `AGENT_TOKEN` sous la main : login et agents.

### 3.3 Modifier le fichier `.env`

**Où :** l’éditeur de votre choix, **pas** le terminal.

1. Dans l’Explorateur, ouvrez le dossier `ransomware-detector`.
2. Clic droit sur `.env` → **Ouvrir avec** → Bloc-notes (ou Cursor / VS Code).
3. Cherchez le mot `CHANGE_ME` (il apparaît **4 fois**).
4. Remplacez chaque `CHANGE_ME` par le secret correspondant, **sans espaces** autour du `=`.

**Avant :**

```text
POSTGRES_PASSWORD=CHANGE_ME
SESSION_SECRET=CHANGE_ME
AGENT_TOKEN=CHANGE_ME
BOOTSTRAP_ADMIN_PASSWORD=CHANGE_ME
```

**Après (exemple fictif — utilisez les vôtres) :**

```text
POSTGRES_PASSWORD=aB3x……
SESSION_SECRET=kL9p……
AGENT_TOKEN=mN2q……
BOOTSTRAP_ADMIN_PASSWORD=rT8w……
```

Laissez le reste tel quel, notamment :

- `BOOTSTRAP_ADMIN_EMAIL=admin@soc.edr.local` → c’est l’identifiant de connexion
- `APP_ENV=development`
- `COOKIE_SECURE=false`

5. **Enregistrez** le fichier (`Ctrl+S`) et fermez-le.

> Le champ `DATABASE_URL` contient encore `CHANGE_ME` : **ignorez-le** tant que vous
> utilisez Docker. Docker fabrique l’adresse de la base tout seul. Il ne sert que si
> un développeur lance l’API sans Docker (section 11).

---

## 4. Démarrer Docker et ouvrir la console

Vérifiez que **Docker Desktop est bien lancé** (icône baleine).

**Où :** PowerShell, dossier `ransomware-detector`.

### 4.1 Construire et démarrer

```powershell
docker compose up -d --build
```

La **première fois**, cela peut prendre plusieurs minutes (téléchargement des images,
compilation de la console). Laissez tourner jusqu’au retour de la ligne `PS …>`.

`-d` = en arrière-plan. `--build` = reconstruire les images à partir du code actuel.

### 4.2 Vérifier que les 3 services tournent

**Où :** le même PowerShell, toujours dans `ransomware-detector`.

```powershell
docker compose ps
```

Vous devez voir **trois** lignes `Up` (parfois `healthy` pour la base) :

| Nom | Rôle |
|-----|------|
| `edr-postgres` | Base de données |
| `edr-api` | Moteur de détection |
| `edr-web` | Page web (console) |

### 4.3 (Optionnel) Lire les logs de l’API

**Où :** le même PowerShell.

```powershell
docker compose logs -f api
```

Vous devez apercevoir un compte administrateur créé, puis Uvicorn à l’écoute.
Pour **quitter les logs** : `Ctrl+C`. Docker **ne s’arrête pas**.

### 4.4 Ouvrir la console

**Où :** votre navigateur (Chrome, Edge, Firefox), **pas** PowerShell.

Barre d’adresse :

```text
http://localhost:8080
```

Vous devez voir l’écran **Authentification analyste**.

| Adresse | À quoi ça sert |
|---------|----------------|
| http://localhost:8080 | Console (vous, tous les jours) |
| http://localhost:8000 | API pour les agents de la VM (étape 8) |
| http://localhost:8080/api/status | Test : si ça affiche du JSON, le serveur répond |

---

## 5. Première connexion

**Où :** le navigateur, page http://localhost:8080

1. **Adresse professionnelle** : `admin@soc.edr.local`  
   (sauf si vous avez changé `BOOTSTRAP_ADMIN_EMAIL` dans `.env`)
2. **Mot de passe** : la valeur que vous avez mise à `BOOTSTRAP_ADMIN_PASSWORD` dans `.env`
3. Cliquez pour vous connecter.

Le serveur **oblige** à changer ce mot de passe tout de suite (il a été écrit dans un fichier).
Choisissez un nouveau mot de passe d’**au moins 12 caractères**, confirmez, validez.

Ensuite le **Dashboard** s’ouvre. Vous êtes **SOC Manager (N3)** : niveau le plus élevé.

Si le login échoue : revérifiez `.env` (plus aucun `CHANGE_ME` sur les 4 secrets),
enregistrez, puis voir [étape 10](#10-si-quelque-chose-ne-marche-pas).

---

## 6. Utiliser la plateforme

**Où :** toujours le navigateur, http://localhost:8080, une fois connecté.

Le menu est à **gauche**. Sur un petit écran, un bouton **☰** en haut à gauche l’ouvre.

En haut à droite : **Temps réel actif** = la page se met à jour toute seule.
**Mode dégradé** = rafraîchissement automatique un peu moins fluide, les données restent justes.

### Que fait chaque onglet ?

| Menu de gauche | Vous y faites quoi |
|----------------|--------------------|
| **Dashboard** | Vue d’ensemble : compteurs, graphique, file d’alertes à traiter |
| **Terminaux** | Liste des PC Windows qui envoient des logs. Vide tant qu’il n’y a pas de VM (étape 8) |
| **Alertes de sécurité** | Journal des détections. Cliquez une ligne pour la fiche d’enquête |
| **Journal des réponses** | Ordres « arrêter le processus » / « isoler le poste » et leur résultat |
| **Statistiques ML** | Le modèle de machine learning chargé sur le serveur |
| **Moteur heuristique** | Les règles de détection et leurs seuils |
| **Règles d’exclusion** | Ignorer un chemin ou un programme (bruit connu) — réservé N3 |
| **Journal d’audit** | Qui a fait quoi (vous ne pouvez pas l’effacer) |
| **Équipe SOC** | Créer les comptes des autres analystes — réservé N3 |
| **Configuration** | Seuils (alerte, kill automatique) — réservé N3 |
| **Documentation** | Aide intégrée, sans quitter la console |

### Niveaux de compte

| Niveau | Droits |
|--------|--------|
| **N1** Analyste SOC | Lire, prendre une alerte, la clôturer ou la marquer faux positif |
| **N2** Analyste EDR | N1 + arrêter un processus, isoler / désisoler un poste |
| **N3** SOC Manager | N2 + créer des comptes, exclusions, configuration |

Un N1 **ne voit pas** les boutons dangereux. Même s’il essaie l’API à la main, le serveur
répond **interdit (403)**.

### Créer un compte pour un camarade

1. Menu **Équipe SOC**.
2. **Ajouter un analyste**.
3. Adresse, nom, mot de passe initial (**12 caractères minimum**), niveau N1 / N2 / N3.
4. Donnez-lui l’adresse http://localhost:8080 **sur sa machine** seulement si le serveur
   tourne **chez lui**, ou l’IP de **votre** PC si vous partagez **votre** serveur sur le lab.
5. À sa première connexion, **il** devra changer le mot de passe.

**Sans VM Windows**, la console est déjà utilisable (comptes, menus, documentation).
Les terminaux et alertes restent vides jusqu’à l’étape 8.

---

## 7. Arrêter, relancer, mettre à jour

**Où :** PowerShell, dossier `ransomware-detector` (comme à l’étape 2).

### Arrêter le serveur (les données sont conservées)

```powershell
docker compose down
```

Les alertes et comptes restent dans un volume Docker. Pour **tout effacer** (repartir de zéro) :

```powershell
docker compose down -v
```

Après `-v`, il faudra recréer le premier compte au prochain démarrage (le `.env` suffit).

### Relancer sans recompiler

```powershell
docker compose up -d
```

### Relancer après un `git pull` (obligatoire pour avoir le nouveau code)

Les conteneurs déjà créés **n’absorbent pas** tout seuls les modifications Git.
Il faut **reconstruire** :

```powershell
git pull
docker compose down
docker compose up -d --build
```

Ne copiez pas le `.env` d’un camarade. S’il n’existe pas encore chez vous, refaites l’étape 3.

Si vous changez `AGENT_TOKEN` dans `.env`, mettez aussi à jour Winlogbeat et l’agent
sur la VM (étape 8), puis redémarrez Winlogbeat.

### Commandes utiles (même dossier)

```powershell
docker compose ps
docker compose logs -f api
docker compose restart api
```

Pour lister les comptes si plus aucun N3 ne peut se connecter :

```powershell
docker compose exec api python -m scripts.manage list-users
docker compose exec api python -m scripts.manage reset-password --email admin@soc.edr.local
docker compose exec api python -m scripts.manage unlock --email admin@soc.edr.local
```

Ces trois lignes s’exécutent **dans** le conteneur API (Python y est déjà installé).
Tapez-les depuis le PowerShell du **PC hôte**, dossier `ransomware-detector`.

---

## 8. Brancher une VM Windows (lab complet)

Cette étape est pour le **lab VMware** : un Windows virtuel envoie de vrais événements Sysmon.
Détail encore plus fin : fichier [`docs/lab_setup.md`](docs/lab_setup.md).

### 8.1 Réseau : trouver l’IP de **votre** PC hôte

Sur VMware, le réseau **VMnet1 (Host-Only)** isole le lab. L’adresse de l’hôte n’est **pas**
la même chez tout le monde (souvent `192.168.10.1` **ou** `192.168.10.2`).

**Où :** PowerShell du **PC hôte** (pas la VM).

```powershell
ipconfig
```

Cherchez **VMware Network Adapter VMnet1**, ligne **IPv4**. Notez-la : c’est `<IP-HOTE>`.
Dans toute la suite, remplacez `<IP-HOTE>` par ce nombre, par exemple `192.168.10.2`.

**Où :** PowerShell **dans la VM**.

```powershell
ping 192.168.10.2
```

(Mettez **votre** IP, pas celle de l’exemple.) Si ça échoue, le reste de l’étape 8 ne marchera pas.

### 8.2 Récupérer le jeton d’agent

**Où :** PowerShell du **PC hôte**, dossier `ransomware-detector`.

```powershell
docker compose exec -T api printenv AGENT_TOKEN
```

Copiez la ligne affichée. C’est la même valeur que `AGENT_TOKEN` dans `.env`.
Il n’y a **pas** de fichier token à poser sur la VM : on le **colle** dans Winlogbeat
et dans une variable PowerShell.

### 8.3 Sur la VM : Sysmon

PowerShell **Administrateur**, dans la VM.

1. Téléchargez [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
   et la config [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
   (`sysmonconfig-export.xml`).
2. Exemple si les fichiers sont dans `C:\Tools\Sysmon` :

```powershell
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
Get-Service Sysmon64
```

Le service doit être **Running**.

### 8.4 Sur la VM : Winlogbeat

1. Installez [Winlogbeat 8.18.3](https://www.elastic.co/downloads/beats/winlogbeat)
   dans `C:\Program Files\Winlogbeat\`.
2. Copiez le fichier du projet `agent\winlogbeat.yml` (sur le **PC hôte**) vers
   `C:\Program Files\Winlogbeat\winlogbeat.yml` sur la VM.
3. Éditez ce fichier **sur la VM**. Deux lignes seulement :

```yaml
hosts: ["http://<IP-HOTE>:8000"]
password: "<collez ici AGENT_TOKEN>"
```

Exemple si l’hôte est `192.168.10.2` :

```yaml
hosts: ["http://192.168.10.2:8000"]
password: "leMemeSecretQueDansLeEnv"
```

`password` est un champ du fichier YAML, **pas** une variable Windows.

4. PowerShell **Administrateur**, dans la VM :

```powershell
cd "C:\Program Files\Winlogbeat"
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
Test-NetConnection 192.168.10.2 -Port 8000
```

(`TcpTestSucceeded : True` = la VM atteint l’API.)

### 8.5 Sur la VM : agent de réponse

Copiez le dossier `agent` du projet (PC hôte) vers la VM, par exemple sur le Bureau.

PowerShell **Administrateur**, **dans ce dossier** sur la VM :

```powershell
Set-ExecutionPolicy Unrestricted -Force
$env:EDR_API_URL     = "http://192.168.10.2:8000"
$env:EDR_AGENT_TOKEN = "leMemeSecretQueDansLeEnv"
.\agent_ps.ps1
```

Remplacez l’IP et le token. Laissez cette fenêtre **ouverte**.

### 8.6 Snapshot et console

Dans VMware : **VM → Snapshot → Take Snapshot**, nom `Clean_State_Pre_Ransomware`,
**avant** de lancer un simulateur.

Dans la console (navigateur du PC hôte) : onglet **Terminaux**. Le nom du PC de la VM
doit apparaître. Après environ **10 × 10 secondes** d’activité normale, le poste passe
en mode détection.

Si `docker compose logs -f api` (PC hôte) montre `POST /_bulk` en **401** : le `password`
Winlogbeat n’est pas le bon `AGENT_TOKEN`.

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

---

## 9. Démonstration avec le simulateur

**Avant :** étapes 4 et 8 OK, snapshot pris, agent PowerShell **encore ouvert** sur la VM,
vous êtes connecté en **N2 ou N3** sur http://localhost:8080.

**Où :** un **deuxième** PowerShell **dans la VM**, dossier où se trouve `simulate_ransomware_v2.ps1`
(le dossier `agent` copié).

```powershell
.\simulate_ransomware_v2.ps1
```

Le script imite un C2, `vssadmin` et beaucoup de fichiers « chiffrés ». C’est une **simulation**
```

Le script imite un C2, `vssadmin` et beaucoup de fichiers « chiffrés ». C’est une **simulation**
dans le lab isolé.

**Dans le navigateur (PC hôte),** vous devez voir :

- une alerte dans **Alertes de sécurité** ;
- une commande dans **Journal des réponses** qui passe de `pending` à `acked` ;
- dans la fenêtre de l’agent : arrêt du processus.

Puis restaurez le snapshot VMware pour un état propre.

---

## 10. Si quelque chose ne marche pas

Toujours : PowerShell du **PC hôte**, dossier `ransomware-detector`, sauf mention contraire.

| Vous voyez | Cause fréquente | Que faire |
|------------|-----------------|-----------|
| `docker` n’est pas reconnu | Docker Desktop fermé, ou terminal ouvert trop tôt | Lancer Docker Desktop, **fermer et rouvrir** PowerShell |
| `git clone` refuse | Git non installé, ou pas de réseau | Installer Git, réessayer |
| `Copy-Item` : fichier introuvable | Vous n’êtes pas dans `ransomware-detector` | `cd` vers ce dossier, vérifiez avec `dir` que `.env.example` est listé |
| http://localhost:8080 ne charge pas | Build pas fini, ou services down | Attendre ; `docker compose ps` ; relancer `docker compose up -d --build` |
| Ancienne page / écran bizarre | Image web pas reconstruite | `docker compose up -d --build web` |
| Mot de passe refusé | Encore `CHANGE_ME`, ou mauvais secret | Corriger `.env`, enregistrer. Pour repartir de zéro : `docker compose down -v` puis `docker compose up -d --build` |
| Compte verrouillé | 5 essais ratés | Attendre 15 min, ou `docker compose exec api python -m scripts.manage unlock --email admin@soc.edr.local` |
| Terminaux vides | Pas de VM, ou Winlogbeat mal pointé | Étape 8 : IP VMnet1, port **8000**, token |
| `POST /_bulk` **401** dans les logs | Token Winlogbeat ≠ `.env` | Recoller `printenv AGENT_TOKEN` dans `password:` |
| `ping` vers l’hôte échoue (VM) | Mauvaise IP (`.1` vs `.2`) | Refaire `ipconfig` **sur votre** PC hôte |
| Agent : « Token d'agent absent » | Variables non définies dans **cette** fenêtre | Retaper `$env:EDR_API_URL` et `$env:EDR_AGENT_TOKEN` puis `.\agent_ps.ps1` |

---

## 11. Pour aller plus loin

Ces parties s’adressent à quelqu’un qui développe le projet. Elles ne sont **pas**
nécessaires pour reproduire la démo Docker.

### Architecture (idée générale)

```text
Navigateur  →  http://localhost:8080  →  nginx (conteneur web)
                                      →  API FastAPI (conteneur api)  →  PostgreSQL

VM Windows : Sysmon → Winlogbeat → http://<IP-HOTE>:8000
             Agent PowerShell   ← ordres kill / isolate
```

Tout le monde voit les **mêmes** chiffres : ils sont calculés dans PostgreSQL, pas dans
le navigateur.

### Dossiers utiles

| Dossier / fichier | Rôle |
|-------------------|------|
| `agent/` | Scripts à copier sur la VM |
| `api/` | Serveur Python |
| `dashboard/` | Console React |
| `docker-compose.yml` | Les 3 services |
| `.env.example` | Modèle du fichier secrets |

Docs techniques : [`docs/lab_setup.md`](docs/lab_setup.md),
[`docs/architecture.md`](docs/architecture.md),
[`docs/api_reference.md`](docs/api_reference.md).

### Mode développeur (API et console sur l’hôte)

**Où :** PowerShell, dossier `ransomware-detector`. Il faut alors **Python 3.11+** et **Node.js 20+**.

Terminal 1 :

```powershell
docker compose up -d db
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt --prefer-binary
alembic upgrade head
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Dans `.env`, `DATABASE_URL` doit utiliser le **même** mot de passe que `POSTGRES_PASSWORD`,
avec `localhost` (pas `db`).

Terminal 2 :

```powershell
cd $HOME\Documents\ransomware-detector\dashboard
npm install
npm run dev
```

Ouvrez **http://localhost:5173** (plus 8080). C’est le mode rechargement à chaud.

### Tests automatisés

Il faut Python + les paquets de `requirements.txt` **sur l’hôte**, stack Docker déjà up.

**Où :** PowerShell, dossier `ransomware-detector`.

```powershell
python -m scripts.e2e_check --base-url http://localhost:8080/api
python -m scripts.ui_check --origin http://localhost:8080
```

`e2e_check` simule une attaque **sans VM**.

---

## 12. Licence

Projet académique ECE Paris 2026. Usage pédagogique uniquement.
Aucune donnée réelle de ransomware n’est utilisée.
