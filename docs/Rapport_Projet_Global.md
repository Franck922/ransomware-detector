# Rapport de Projet de Substitution de Stage
**Sujet :** Conception et Développement d'un Détecteur Hybride de Ransomware (Heuristique et Machine Learning)

---

## 1. Introduction et Architecture Globale

### 1.1 Contexte
Les ransomwares (logiciels rançonneurs) constituent aujourd'hui l'une des menaces les plus critiques pour les systèmes d'information. Les solutions antivirales classiques, basées sur des signatures statiques, sont souvent contournées par les nouvelles variantes.
Ce projet propose une approche de **détection comportementale** et **hybride**, analysant à la fois les événements du système d'exploitation et le trafic réseau pour repérer l'activité malveillante en temps réel.

### 1.2 Architecture de la Solution
Notre solution s'articule autour de quatre briques principales :
1. **Agent de Collecte (Machine Surveillée)** : Utilisation de Sysmon et Winlogbeat pour capturer les événements de la machine cible (créations de fichiers, processus, connexions réseau).
2. **API de Réception (Serveur d'Analyse)** : Un serveur FastAPI qui reçoit les logs de l'agent en continu.
3. **Moteur d'Extraction de Features (Feature Engineering)** : Un module qui convertit les logs bruts en vecteurs mathématiques (fenêtres de 10 secondes) décrivant le comportement de la machine.
4. **Moteurs de Détection** :
   - *Couche 1 (Heuristique)* : Un moteur de règles strictes (ex: alerte si le système crée plus de 10 fichiers avec une entropie > 5.0 en moins de 10 secondes).
   - *Couche 2 (Machine Learning)* : Des modèles d'Intelligence Artificielle (Random Forest et LSTM) capables de déceler des motifs complexes (Pattern Recognition) combinant réseau et système.

---

## 2. Le Pipeline de Collecte (Phase 1)

### 2.1 Sysmon (System Monitor)
Sysmon est un outil système Windows qui offre un niveau de journalisation très profond. Pour détecter un ransomware, nous avons configuré Sysmon pour écouter spécifiquement :
- **Event ID 11 (FileCreate)** : Indispensable pour voir le ransomware créer les fichiers chiffrés.
- **Event ID 1 (ProcessCreate)** : Pour analyser la profondeur d'exécution (Process Depth) typique des malwares qui s'injectent dans d'autres processus.
- **Event ID 3 (NetworkConnection)** : Pour tracer les communications vers les serveurs de Commande & Contrôle (C2).

### 2.2 Winlogbeat
Winlogbeat est un agent léger (Shipper) chargé de lire les journaux Windows (dont Sysmon) et de les expédier vers notre serveur d'analyse.

---

## 3. Le Moteur d'Extraction (Feature Engineering - Phase 2)

Les algorithmes de Machine Learning ne comprennent pas le format JSON texte généré par Winlogbeat. Nous avons donc développé un module `feature_extractor.py`.

### 3.1 La Fenêtre Temporelle
Au lieu d'analyser chaque événement un par un, l'extracteur groupe les événements sur une **fenêtre glissante de 10 secondes**. Cela permet d'évaluer la "vitesse" et "l'intensité" de l'activité, critères fondamentaux pour différencier un utilisateur humain d'un script de chiffrement massif.

### 3.2 L'Entropie de Shannon
L'une des 12 dimensions mathématiques calculées est l'Entropie des noms de fichiers. L'entropie mesure le niveau de désordre ou d'aléatoire d'une chaîne de caractères (sur une échelle de 0 à 8). 
- Un fichier normal : `mon_rapport_stage.docx` (Entropie basse : ~3.5).
- Un fichier chiffré par ransomware : `U7x9Pq2.locky` (Entropie haute : ~5.5+).
L'augmentation brutale de l'entropie moyenne sur une fenêtre de 10 secondes est un indicateur fort d'infection.

---

## 4. Les Modèles de Détection (Phases 3 & 4)

### 4.1 La Couche Heuristique (Rules Engine)
Développée en Phase 3, cette couche lève une alerte immédiate si des seuils codés en dur sont franchis (ex: `nb_files_created > 30` ET `entropy > 5.0`). Elle est ultra-rapide et déterministe, mais peut générer des faux positifs lors de mises à jour système légitimes (ex: Windows Update).

### 4.2 La Couche Machine Learning (Défense Avancée)
Pour pallier les limites heuristiques, nous avons entraîné deux modèles de ML sur un dataset hybride (UWF-ZeekData22 pour le réseau normal, Stratosphere IPS pour le réseau malveillant, et données Sysmon).

- **Random Forest (Forêt Aléatoire)** : Avec 100 arbres de décision, ce modèle a identifié que les 3 caractéristiques les plus révélatrices d'une attaque sont le renommage de fichiers (`nb_files_renamed`), la profondeur des processus (`process_depth`), et le volume de fichiers créés.
- **LSTM (Long Short-Term Memory)** : Réseau de neurones profond (Deep Learning) conçu pour traiter des séries temporelles. Contrairement au Random Forest, l'LSTM possède une "mémoire" lui permettant de comprendre la *chronologie* de l'attaque (ex: *D'abord* une connexion réseau suspecte, *Puis* une création de processus, *Ensuite* du chiffrement).

Les deux modèles ont atteint un F1-Score parfait (1.00) sur notre dataset de test, prouvant l'efficacité de notre pipeline d'extraction de *features*.

---

## 5. Moteur de Réponse Active & Forensics (Phase 5)

Afin de passer d'un système de détection simple à une solution de riposte automatisée, nous avons développé en Phase 5 un moteur de réponse active (Response Engine).

### 5.1 L'Agent de Riposte PowerShell
Un agent scripté en PowerShell tourne en boucle infinie (avec un polling HTTP toutes les 2 secondes) sur la machine surveillée.
* **KILL chirurgical par PID** : Dès qu'une menace dépasse un score de 80 points (score heuristique ou de Machine Learning), l'API FastAPI expose un ordre de blocage pour l'agent. Celui-ci extrait le PID (identifiant de processus) responsable du chiffrement suspect et exécute la commande `Stop-Process -Id <PID> -Force` localement.
* **Isolation Réseau** : Si la menace est critique, l'agent reconfigure en temps réel le Pare-feu de Windows pour couper toutes les communications réseau entrantes et sortantes de la VM, à l'exception unique des requêtes vers le serveur API de l'EDR.

### 5.2 Rapports Forensics JSON
À chaque blocage de processus malveillant, un fichier diagnostic structuré en JSON est généré et stocké dans le répertoire `reports/` de l'hôte. Ce fichier contient l'intégralité de la télémétrie capturée dans les 10 secondes ayant précédé l'attaque, facilitant l'analyse post-mortem de l'incident par un analyste SOC.

---

## 6. Console Web d'Administration SOC & Persistance SQLite (Phase 6)

La Phase 6 s'est concentrée sur le développement d'une console d'administration SOC robuste, sécurisée et connectée en temps réel au backend EDR.

### 6.1 Architecture Web (React & Recharts)
Développée avec React, Vite et Tailwind CSS v4, l'interface SOC propose un design moderne et professionnel (style SaaS sombre/ardoise) offrant une navigation fluide à travers ses modules (Dashboard, Terminaux, Forensic, Éditeur d'exclusions, Logs d'audit, etc.).

### 6.2 Persistance des Données (SQLite)
Pour éviter la perte des données de détection lors d'un redémarrage du backend, nous avons migré l'application vers une base de données relationnelle locale **SQLite** (`alerts.db`). Cette base conserve :
* L'historique complet des alertes.
* Les répertoires et processus exclus de la surveillance (Exclusions).
* La traçabilité de toutes les interventions des analystes (Audit logs).

### 6.3 Sécurité, Authentification & Gestion des Analystes
* **Authentification** : L'accès à la console SOC est verrouillé par un écran de connexion. Les mots de passe des analystes sont hachés de manière sécurisée en base de données avec l'algorithme SHA-256.
* **Enrôlement (Sign-up)** : Un écran de création de compte permet de déclarer de nouveaux analystes dans la base en leur attribuant l'un des trois niveaux de droits (N1 : Lecture seule / N2 : Réponse & Isolation / N3 : Contrôle total).
* **Traçabilité Nominative** : Chaque action sensible (kill manuel, isolation, modification des exclusions, création de compte) est liée à l'utilisateur connecté et enregistrée dynamiquement dans la table `audit_logs` de SQLite avec l'adresse IP source de l'analyste.

---

## 7. Guide de Déploiement et d'Utilisation

1. **Démarrer l'API (Serveur) :** 
   Sur la machine d'analyse, lancer `uvicorn api.main:app --host 0.0.0.0 --port 8000`. La base de données SQLite `alerts.db` s'initialise automatiquement avec l'utilisateur administrateur Franck (mot de passe `admin123`).
2. **Démarrer la Console SOC (Frontend) :**
   Dans le dossier `dashboard`, lancer `npm run dev` pour accéder au port `5173` ou compiler pour la production avec `npm run build`.
3. **Lancer la collecte (Agent) :** 
   Sur la machine Windows cible, s'assurer que Sysmon est installé et démarrer l'agent PowerShell `.\agent.ps1` en mode administrateur.
4. **Attaque & Riposte :**
   Exécuter le script `.\simulate_ransomware.ps1` sur la VM cible. Constater l'affichage de l'alerte en direct sur la console web et la terminaison automatique du processus de chiffrement.
5. **Investigation Forensic :** 
   Se connecter sur la console SOC avec Franck pour consulter les graphes temporels d'entropie, extraire les rapports JSON diagnostics de la menace, éditer les règles heuristiques ou ajouter des dossiers de confiance dans l'onglet des exclusions.

---

## 8. Équipe Projet
* **Membres du groupe :** Franck & Groupe de projet ECE Paris
* **Encadreur de projet :** Enseignant de substitution de stage / ECE Paris Fall 2026
