# Guide de Configuration du Laboratoire (Lab Setup)

**Date de rédaction** : Juillet 2026  
**Dernière mise à jour** : 12 août 2026  
**Public cible** : Tout membre de l'équipe souhaitant reproduire l'environnement de test

---

## 1. Vue d'ensemble du Laboratoire

Le laboratoire est composé de deux machines connectées par un réseau virtuel isolé :

| Machine | Rôle | OS | IP (exemple) |
|---------|------|----|--------------|
| **PC Hôte** | Serveur EDR (API + PostgreSQL + console) | Windows 10/11 | **À lire avec `ipconfig`** — souvent `192.168.10.1` **ou** `192.168.10.2` |
| **VM Windows** | Poste victime (Endpoint protégé) | Windows 10 Pro | souvent `192.168.10.10` |

> **Important pour l'équipe :** l'IP VMnet1 de l'hôte n'est **pas unique pour tout le monde**.
> Chez un membre elle peut être `.1`, chez un autre `.2`. Chaque lab doit utiliser
> **l'IP réelle de son propre PC hôte**, lue avec `ipconfig` (adaptateur VMnet1).
> Dans ce guide, on note cette adresse `<IP-HOTE>`.

Le réseau est un **VMnet1 Host-Only** (192.168.10.0/24) créé par VMware Workstation Pro, ce qui signifie qu'aucune machine n'a accès à Internet (sauf si on ajoute un NAT explicite). Cet isolement garantit que les simulations de ransomware ne peuvent pas se propager vers le réseau réel.

---

## 2. Configuration du PC Hôte (Serveur Backend)

### 2.1. Prérequis logiciels
- **Docker Desktop** : recommandé pour démarrer toute la stack (`db` + `api` + `web`) en une commande.
- **Python 3.11+** et **Git** : utiles en mode développement hors Docker.
- **VMware Workstation Pro** : Version 17+ recommandée.

### 2.2. Cloner (ou mettre à jour) le projet

**Premier clone :**
```bash
git clone https://github.com/Franck922/ransomware-detector.git
cd ransomware-detector
cp .env.example .env
```

**Déjà installé (équipe) :** ne pas se contenter de rouvrir d'anciens conteneurs.
```bash
git pull
cp .env.example .env   # seulement si .env n'existe pas encore
# Éditer .env : POSTGRES_PASSWORD, SESSION_SECRET, AGENT_TOKEN, BOOTSTRAP_ADMIN_PASSWORD
docker compose down
docker compose up -d --build
```

Éditer `.env` et remplacer toutes les valeurs `CHANGE_ME`. Chaque poste génère ses propres secrets
(`python -c "import secrets; print(secrets.token_urlsafe(48))"`).

### 2.3. Vérifier l'adresse IP du réseau VMnet1
Ouvrir un terminal PowerShell **sur le PC hôte** et taper :
```powershell
ipconfig
```
Repérer l'adaptateur **VMware Network Adapter VMnet1** et noter l'IPv4 : c'est `<IP-HOTE>`.
C'est cette valeur (et non celle d'un autre membre) qui doit figurer dans Winlogbeat et
`agent_ps.ps1` sur la VM.

### 2.4. Lancer le serveur
**Recommandé (Docker) :**
```bash
docker compose up -d --build
```
- Console SOC : http://localhost:8080  
- API agents : http://\<IP-HOTE\>:8000  

**Mode développement (API seule) :**
```bash
docker compose up -d db
alembic upgrade head
uvicorn api.main:app --host 0.0.0.0 --port 8000
```
Le serveur écoute sur toutes les interfaces (`0.0.0.0`), ce qui permet à la VM de le joindre via `<IP-HOTE>`.

---

## 3. Configuration de la VM Windows (Endpoint Victime)

### 3.1. Création de la VM
1. Dans VMware Workstation Pro, créer une nouvelle VM :
   - **OS** : Windows 10 Professionnel (64-bit)
   - **RAM** : 4 Go minimum (8 Go recommandé)
   - **Disque** : 60 Go
   - **Réseau** : Adapter 1 en mode **Host-Only (VMnet1)**
2. Installer Windows 10 normalement.
3. Vérifier la connectivité réseau :
   ```powershell
   # Sur la VM — remplacer par l'IP VMnet1 réelle de VOTRE hôte
   ping <IP-HOTE>
   ```
   Si le ping réussit, la communication avec le PC hôte est établie.

### 3.2. Installation de Sysmon

Sysmon (System Monitor) est un outil Microsoft Sysinternals qui intercepte les événements système Windows à très bas niveau (création de processus, connexions réseau, création/suppression de fichiers) et les écrit dans le Journal d'événements Windows au format structuré.

#### Étape 1 : Télécharger Sysmon
Télécharger la dernière version depuis le site officiel :
- **URL** : [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Extraire le fichier ZIP dans `C:\Tools\Sysmon\`

#### Étape 2 : Télécharger la configuration SwiftOnSecurity
La configuration par défaut de Sysmon est trop verbeuse. La communauté utilise la configuration XML de **SwiftOnSecurity**, qui filtre intelligemment le bruit tout en conservant les événements pertinents pour la détection de menaces.

- **URL** : [https://github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- Télécharger le fichier `sysmonconfig-export.xml`
- Le placer dans `C:\Tools\Sysmon\`

#### Étape 3 : Installer Sysmon avec la configuration
Ouvrir un terminal PowerShell **en tant qu'Administrateur** :
```powershell
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

#### Étape 4 : Vérifier l'installation
```powershell
# Vérifier que le service Sysmon est en cours d'exécution
Get-Service Sysmon64

# Vérifier que des événements sont bien générés
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

#### Event IDs surveillés par notre EDR
| Event ID | Nom | Utilité pour la détection |
|----------|-----|--------------------------|
| **1** | Process Create | Détection de processus enfants suspects (vssadmin, cmd, powershell) |
| **3** | Network Connection | Détection de communication C2 (Command & Control) |
| **11** | File Create | Détection de création massive de fichiers (chiffrement) |
| **23** | File Delete | Détection de suppression massive (wiper / ransomware) |

---

### 3.3. Installation de Winlogbeat

Winlogbeat est un agent léger développé par Elastic qui lit les journaux d'événements Windows et les expédie en JSON vers une destination HTTP. Dans notre cas, il envoie directement vers notre API FastAPI (qui simule un serveur Elasticsearch).

#### Étape 1 : Télécharger Winlogbeat
- **URL** : [https://www.elastic.co/downloads/beats/winlogbeat](https://www.elastic.co/downloads/beats/winlogbeat)
- Version utilisée : **8.18.3**
- Extraire dans `C:\Program Files\Winlogbeat\`

#### Étape 2 : Configurer Winlogbeat
Partir du modèle `agent/winlogbeat.yml` du dépôt. **Deux valeurs à adapter sur chaque lab :**

1. `hosts` → `http://<IP-HOTE>:8000` (IP VMnet1 de **votre** PC hôte, lue avec `ipconfig`)
2. `password` → la valeur de `AGENT_TOKEN` du `.env` **du serveur** (à coller dans le champ
   `password` ; ce n'est pas un fichier présent sur la VM)

```yaml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    event_id: 1, 3, 11, 23

output.elasticsearch:
  # Exemples : http://192.168.10.1:8000  OU  http://192.168.10.2:8000
  hosts: ["http://<IP-HOTE>:8000"]
  username: "agent"
  password: "REMPLACER_PAR_AGENT_TOKEN"

setup.ilm.enabled: false
setup.template.enabled: false
```

Sans le bon token, l'API répond **401** et le terminal reste hors ligne dans la console.

> **Point technique :** l'API FastAPI implémente les endpoints Elasticsearch nécessaires
> (`/`, `/_bulk`, `/_license`, `/_xpack`, …) pour que Winlogbeat fonctionne nativement,
> sans script intermédiaire. L'ingestion `/_bulk` exige désormais le token d'agent.

#### Étape 3 : Installer et démarrer Winlogbeat comme service
```powershell
# En PowerShell Administrateur
cd "C:\Program Files\Winlogbeat"

# Installation du service
.\install-service-winlogbeat.ps1

# Démarrage du service
Start-Service winlogbeat

# Vérification
Get-Service winlogbeat
Test-NetConnection <IP-HOTE> -Port 8000
```

#### Étape 4 : Vérifier la réception des logs
Sur le PC hôte (`docker compose logs -f api` ou la console Uvicorn) :
```
INFO: 192.168.10.10:XXXXX - "POST /_bulk?filter_path=..." 200 OK
```
Cela confirme que Winlogbeat envoie bien ses logs à l'API. Un **401** indique un
`password` / `AGENT_TOKEN` incorrect.

---

### 3.4. Installation de l'Agent PowerShell

L'Agent de Réponse Active (`agent_ps.ps1`) est le bras armé de l'EDR sur l'endpoint. Il interroge l'API toutes les 2 secondes pour savoir s'il doit exécuter un ordre (KILL, ISOLATE).

#### Étape 1 : Copier le script sur la VM
Copier le fichier `agent/agent_ps.ps1` du dépôt vers le Bureau de la VM (par exemple `C:\Users\franc\Desktop\agent\agent_ps.ps1`).

#### Étape 2 : Autoriser l'exécution de scripts PowerShell
```powershell
Set-ExecutionPolicy Unrestricted -Force
```

#### Étape 3 : Lancer l'Agent
```powershell
# Remplacer <IP-HOTE> et coller le même AGENT_TOKEN que dans le .env du serveur
$env:EDR_API_URL     = "http://<IP-HOTE>:8000"
$env:EDR_AGENT_TOKEN = "<AGENT_TOKEN>"
.\agent_ps.ps1
```
L'Agent affichera (exemple) :
```
==============================================
  AGENT EDR - DETECTION & REPONSE ACTIVE
==============================================
[*] Demarrage du daemon en arriere-plan...
[*] Connexion a l'API centrale : http://<IP-HOTE>:8000
[+] Pret et en attente d'ordres.
```

---

## 4. Snapshot de Référence

**IMPORTANT** : Avant toute exécution de simulation de ransomware, il est impératif de prendre un **snapshot** de la VM dans VMware. Ce snapshot servira de point de restauration propre.

1. Dans VMware : **VM > Snapshot > Take Snapshot**
2. Nommer le snapshot : `Clean_State_Pre_Ransomware`
3. Après chaque test de simulation, restaurer ce snapshot pour repartir d'un état propre.

---

## 5. Vérification de bout en bout (Checklist)

Avant de lancer un test, vérifier que :

- [ ] Sur l'hôte, `<IP-HOTE>` est connue (`ipconfig` → VMnet1)
- [ ] `.env` est renseigné (plus de `CHANGE_ME`) et la stack tourne (`docker compose up -d` ou Uvicorn)
- [ ] Console accessible sur http://localhost:8080
- [ ] La VM peut pinger l'hôte (`ping <IP-HOTE>`) et joindre le port 8000 (`Test-NetConnection <IP-HOTE> -Port 8000`)
- [ ] Sysmon est installé et le service tourne (`Get-Service Sysmon64`)
- [ ] Winlogbeat a le bon `hosts` + `password` (= `AGENT_TOKEN`) et tourne (`Get-Service winlogbeat`)
- [ ] L'API reçoit des événements (logs `POST /_bulk` en 200, pas 401)
- [ ] La baseline est calibrée (terminal en mode détection dans la console)
- [ ] L'Agent PowerShell est lancé avec `EDR_API_URL` / `EDR_AGENT_TOKEN`
- [ ] Le simulateur de ransomware est prêt (`simulate_ransomware_v2.ps1`)

---

## 6. Dépannage courant

| Problème | Cause probable | Solution |
|----------|---------------|----------|
| Winlogbeat ne démarre pas | Fichier `winlogbeat.yml` mal formaté (YAML sensible aux espaces) | Vérifier l'indentation avec un éditeur YAML |
| `ping <IP-HOTE>` échoue | Mauvaise IP (`.1` chez l'un, `.2` chez l'autre) ou pare-feu hôte | Relire `ipconfig` sur **votre** hôte ; autoriser le trafic VMnet1 |
| Terminal « hors ligne », graphique à 0 | Winlogbeat n'atteint pas l'API (port / IP / token) | Publier le port 8000, corriger `hosts`, coller le bon `AGENT_TOKEN` dans `password`, `Restart-Service winlogbeat` |
| `POST /_bulk` en **401** | `password` Winlogbeat ≠ `AGENT_TOKEN` du `.env` serveur | Recopier le token depuis l'hôte (`docker compose exec -T api printenv AGENT_TOKEN`) |
| L'API affiche `500 Internal Server Error` | Bug Python dans le pipeline | Lire le traceback (`docker compose logs -f api`) |
| L'Agent affiche des erreurs rouges | API arrêtée, mauvaise IP ou token manquant | Vérifier `EDR_API_URL` / `EDR_AGENT_TOKEN` et que le port 8000 répond |
| Emojis cassent PowerShell | Encodage cp1252 de la console Windows | Utiliser uniquement des caractères ASCII dans les scripts .ps1 |
| Le modèle ML ne se charge pas | Fichiers `.pkl` manquants dans `models/` | Vérifier que `models/random_forest_model.pkl` et `scaler.pkl` sont présents (ou relancer `python -m scripts.train_model`) |
