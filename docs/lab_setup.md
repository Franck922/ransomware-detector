# Guide de Configuration du Laboratoire (Lab Setup)

**Date de rédaction** : Juillet 2026  
**Dernière mise à jour** : 22 juillet 2026  
**Public cible** : Tout membre de l'équipe souhaitant reproduire l'environnement de test

---

## 1. Vue d'ensemble du Laboratoire

Le laboratoire est composé de deux machines connectées par un réseau virtuel isolé :

| Machine | Rôle | OS | IP |
|---------|------|----|----|
| **PC Hôte** | Serveur d'analyse (Backend API + ML) | Windows 10/11 | 192.168.10.2 |
| **VM Windows** | Poste victime (Endpoint protégé) | Windows 10 Pro | 192.168.10.10 |

Le réseau est un **VMnet1 Host-Only** (192.168.10.0/24) créé par VMware Workstation Pro, ce qui signifie qu'aucune machine n'a accès à Internet (sauf si on ajoute un NAT explicite). Cet isolement garantit que les simulations de ransomware ne peuvent pas se propager vers le réseau réel.

---

## 2. Configuration du PC Hôte (Serveur Backend)

### 2.1. Prérequis logiciels
- **Python 3.11+** : Télécharger depuis [python.org](https://python.org). Cocher "Add Python to PATH" lors de l'installation.
- **Git** : Télécharger depuis [git-scm.com](https://git-scm.com).
- **VMware Workstation Pro** : Version 17+ recommandée.
- **Docker Desktop** (optionnel, pour le déploiement conteneurisé en Phase 6).

### 2.2. Cloner le projet et installer les dépendances
```bash
git clone https://github.com/Franck922/ransomware-detector.git
cd ransomware-detector

# Création de l'environnement virtuel Python
python -m venv venv
.\venv\Scripts\activate

# Installation des dépendances
pip install -r requirements.txt --prefer-binary
```

### 2.3. Vérifier l'adresse IP du réseau VMnet1
Ouvrir un terminal PowerShell et taper :
```powershell
ipconfig
```
Rechercher l'adaptateur **VMware Network Adapter VMnet1**. L'adresse IP doit être `192.168.10.2` (ou similaire). Si elle est différente, il faudra adapter la configuration de Winlogbeat sur la VM en conséquence.

### 2.4. Lancer le serveur API
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```
Le serveur écoute sur toutes les interfaces réseau (`0.0.0.0`), ce qui permet à la VM de le joindre via l'IP du VMnet1. Le port `8000` est celui configuré dans Winlogbeat et dans l'Agent PowerShell.

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
   # Sur la VM
   ping 192.168.10.2
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
Remplacer le contenu du fichier `winlogbeat.yml` par notre configuration personnalisée (disponible dans `agent/winlogbeat.yml` du dépôt). Les points clés de la configuration :

```yaml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    event_id: 1, 3, 11, 23

output.elasticsearch:
  hosts: ["http://192.168.10.2:8000"]
  # Notre API FastAPI simule un serveur Elasticsearch
  # Winlogbeat pense parler à Elasticsearch, mais c'est notre API

setup.ilm.enabled: false
setup.template.enabled: false
```

> **Point technique important** : Notre API FastAPI implémente les endpoints Elasticsearch nécessaires (`/`, `/_bulk`, `/_license`, `/_xpack`, `/_ilm/policy/*`, `/_index_template/*`, `/_ingest/pipeline/*`) pour que Winlogbeat fonctionne nativement sans aucun script intermédiaire. C'est une innovation technique significative du projet.

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
```

#### Étape 4 : Vérifier la réception des logs
Sur le PC hôte, l'API Uvicorn devrait afficher dans les logs :
```
INFO: 192.168.10.10:XXXXX - "POST /_bulk?filter_path=..." 200 OK
```
Cela confirme que Winlogbeat envoie bien ses logs à notre API.

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
.\agent_ps.ps1
```
L'Agent affichera :
```
==============================================
  AGENT EDR - DETECTION & REPONSE ACTIVE
==============================================
[*] Demarrage du daemon en arriere-plan...
[*] Connexion a l'API centrale : http://192.168.10.2:8000
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

- [ ] Le PC hôte a Python 3.11+ et le venv activé
- [ ] L'API Uvicorn tourne sur le PC hôte (`uvicorn api.main:app --host 0.0.0.0 --port 8000`)
- [ ] La VM peut pinger le PC hôte (`ping 192.168.10.2`)
- [ ] Sysmon est installé et le service tourne (`Get-Service Sysmon64`)
- [ ] Winlogbeat est installé et envoie des logs (`Get-Service winlogbeat`)
- [ ] L'API reçoit des événements (logs `POST /_bulk` visibles dans Uvicorn)
- [ ] La baseline est calibrée (message `Baseline calculée ! Le système passe en mode DÉTECTION`)
- [ ] L'Agent PowerShell est lancé sur la VM (`.\agent_ps.ps1`)
- [ ] Le simulateur de ransomware est prêt (`simulate_ransomware_v2.ps1`)

---

## 6. Dépannage courant

| Problème | Cause probable | Solution |
|----------|---------------|----------|
| Winlogbeat ne démarre pas | Fichier `winlogbeat.yml` mal formaté (YAML sensible aux espaces) | Vérifier l'indentation avec un éditeur YAML |
| `ping 192.168.10.2` échoue | Pare-feu Windows de l'hôte bloque les pings | Désactiver temporairement le pare-feu sur l'hôte |
| L'API affiche `500 Internal Server Error` | Bug Python dans le pipeline | Lire le traceback complet dans le terminal Uvicorn |
| L'Agent affiche des erreurs rouges | L'API n'est pas démarrée ou IP incorrecte | Vérifier que Uvicorn tourne et que l'IP est correcte dans `agent_ps.ps1` |
| Emojis cassent PowerShell | Encodage cp1252 de la console Windows | Utiliser uniquement des caractères ASCII dans les scripts .ps1 |
| Le modèle ML ne se charge pas | Fichiers `.pkl` manquants dans `models/` | Exécuter `python scripts/train_model.py` pour régénérer les modèles |
