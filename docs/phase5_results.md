# Phase 5 : Moteur de Réponse Active (Active Response Engine) et Ingénierie de Déploiement

**Date de réalisation** : 19 juillet 2026  
**Dernière révision majeure (Ciblage PID v2.1 & Architecture Polling)** : 21 juillet 2026  
**Responsable** : Équipe Pipeline (M1) & Détection (M2)

---

## 1. Cadre Conceptuel : L'Architecture 3 Tiers d'un EDR

L'implémentation de la réponse aux incidents (Phase 5) nécessite de bien comprendre la topologie réseau d'un EDR moderne de classe entreprise (tel que CrowdStrike Falcon, SentinelOne ou Microsoft Defender for Endpoint). Un tel système est strictement cloisonné en trois couches logiques, garantissant à la fois la sécurité des échanges et la robustesse de la détection.

### 1.1. Le Capteur Local (Endpoint Agent)
C'est le bras armé du système, déployé physiquement sur les machines des collaborateurs. Contrairement à un antivirus grand public, il s'exécute en mode `SYSTEM` sous forme de service fonctionnant en arrière-plan (Background Daemon). Il ne possède **aucune interface graphique (GUI)** standard. Sa fonction est strictement binaire : 
- Surveiller le système d'exploitation via des hooks du kernel ou des traces ETW (via Sysmon).
- Exécuter aveuglément les ordres punitifs reçus du serveur distant en affichant un log ultra-lisible (Incident Response Console) en cas d'intervention.

### 1.2. Le Cerveau Central (Backend Analytics)
Hébergée sur l'infrastructure Cloud de l'entreprise, c'est notre API Uvicorn codée en FastAPI. C'est ici que se concentre la puissance de calcul. L'API :
- Centralise les centaines de milliers de logs bruts expédiés par l'agent Winlogbeat.
- Exécute l'aggrégation vectorielle en temps réel (fenêtrage 10 secondes) avec **tracking par Process ID (PID)**.
- Fait tourner l'algorithme Random Forest et le Rules Engine pour inférer le niveau de menace.
- Gère une file d'attente d'ordres (Command Queue) pour ordonner la destruction ciblée d'une menace sur un poste distant.
- **Archive** chaque décision dans un dossier `reports/` au format JSON pour traçabilité SOC.

### 1.3. Le Centre des Opérations de Sécurité (Dashboard SOC)
C'est la console de pilotage (qui sera développée en Phase 6). C'est l'unique composante graphique, destinée aux analystes SOC (Niveau 1/2/3). 

---

## 2. Défis de Communication : La Mécanique de Polling Asynchrone

L'un des plus grands défis de l'ingénierie EDR est la communication bidirectionnelle entre l'Endpoint et le Cloud.

### 2.1. L'implémentation du Polling (Pull Request Model)
Nous avons conçu un Agent PowerShell natif (`agent_ps.ps1`) qui inverse ce paradigme. C'est le poste client qui prend l'initiative de demander ses ordres.
Dans une boucle infinie (`while ($true)`), l'Agent interroge l'API distante avec une fréquence de rafraîchissement (polling interval) de **2 secondes**.

---

## 3. La Riposte Chirurgicale (Architecture V2.1)

Lorsque le Backend détecte un comportement de ransomware, il ne tire plus "dans le tas". L'architecture V2.1 introduit une chaîne de causalité irréfutable permettant d'ordonner une frappe chirurgicale.

### 3.1. Calcul de Pondération et Tracking par Processus (PID)
Le `FeatureExtractor` ne se contente plus de compter les événements globaux de la machine. Il suit chaque Process ID (PID) individuellement et lui attribue un score de menace pondéré :
- File Create : +1
- File Delete : +2
- Process Create : +2
- Network Connection : +2
- Entropie cryptographique des noms de fichiers (> 5.0) : +10

À la fin de la fenêtre de 10 secondes, l'API identifie le `top_suspect_pid` (le processus ayant le plus grand score). Elle extrait également le **Processus Parent** via les événements Sysmon (Event 1) pour établir une véritable *Kill Chain*.

### 3.2. Seuils de Décision (Proportionnalité)
La décision de tuer un processus n'est plus binaire, elle dépend du score d'agressivité de ce processus :
- **Score < 50** : Le comportement est suspect mais insuffisant. L'API déclenche une Alerte Simple (Log).
- **50 <= Score < 80** : Alerte Critique et Journalisation avancée (Warning).
- **Score >= 80** : Seuil Létal. L'ordre `KILL` est placé dans la file d'attente pour l'Agent, avec une `confidence` flaggée à HIGH.

### 3.3. Transmission des Preuves et Exécution de la Sentence
Le Backend envoie un payload JSON complet contenant non seulement l'ordre `KILL` et le `PID`, mais aussi les preuves (statistiques exactes et raisons textuelles). 

L'Agent PowerShell récupère cet ordre, affiche une "EDR Incident Response Console" professionnelle dans le terminal (Listant le PID, le Processus, l'Arbre parent, le Score, la Confiance, et les preuves validées), puis exécute un `Stop-Process -Id <PID> -Force`. 
En cas d'échec (ex: PID expiré), il bascule sur le nom de l'exécutable en mode Fallback.

### 3.4. Historisation SOC (JSON Reports)
Chaque ordre létal est couplé à une sauvegarde d'un fichier rapport JSON dans `reports/2026-XX-XX_simulate.exe.json`. Ce fichier horodaté contiendra l'intégralité du contexte nécessaire pour une investigation *Post-Mortem* par un analyste via le futur Dashboard Web.

---

## 4. Le Simulateur de Menaces (Version 2) et Preuve de Concept

### 4.1. Indexation sur la Matrice MITRE ATT&CK
L'exécution du simulateur enchaîne trois opérations distinctes :
1. **T1071 - Application Layer Protocol (Simulation C2) :** Ping réseau.
2. **T1490 - Inhibit System Recovery :** `vssadmin.exe list shadows` (Génère le Parent Process).
3. **T1486 - Data Encrypted for Impact :** Génération de 500 fichiers à entropie massive (Score +10).

### 4.2. Validation du Pipeline End-to-End
L'intégration de la Phase 4 et de la Phase 5 culmine avec cette démonstration de force :
- **T0 :** Exécution manuelle de `simulate_ransomware_v2.ps1` (PID 4216).
- **T+1s :** Sysmon intercepte l'accès à `vssadmin` et les créations de fichiers.
- **T+3s :** Winlogbeat encapsule les logs JSON.
- **T+10s :** L'extracteur fige la fenêtre temporelle. Le PID 4216 affiche un score > 80.
- **T+11s :** Le Rules Engine et le modèle RF confirment l'alerte. L'API archive l'incident dans `reports/` et publie le JSON de condamnation du PID 4216 dans `/agent/commands`.
- **T+12s :** Le Polling asynchrone de `agent_ps.ps1` récupère la consigne. Il affiche les preuves et exécute `Stop-Process -Id 4216`. L'attaque est interrompue.

Ce pipeline complet prouve l'efficacité d'une détection analytique couplée à une réponse chirurgicale quasi-instantanée, digne d'une solution professionnelle moderne.
