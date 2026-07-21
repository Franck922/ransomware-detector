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

## 5. Guide de Déploiement et d'Utilisation

1. **Démarrer l'API (Serveur) :** 
   Sur la machine d'analyse, lancer `uvicorn api.main:app --host 0.0.0.0 --port 8000`.
2. **Lancer la collecte (Agent) :** 
   Sur la machine Windows cible, s'assurer que Sysmon est installé et lancer `Start-Service winlogbeat`.
3. *(Optionnel : Transfert des logs)* Si Winlogbeat est configuré en mode 'Fichier local' (`output.file`), exécuter un script Python (`log_forwarder.py`) sur la VM pour lire ce fichier `.ndjson` et envoyer des requêtes HTTP POST au serveur FastAPI.
4. **Analyse ML :** 
   Pour ré-entraîner les modèles ou visualiser les graphiques (Matrice de confusion, Feature Importance), ouvrir le notebook `notebooks/exploration_eda.ipynb`.
