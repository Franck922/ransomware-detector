# Phase 4 : Modélisation Algorithmique, Intelligence Artificielle et Dataset Synthétique (Random Forest)

**Date de réalisation** : 16 juillet 2026  
**Dernière révision majeure (Phase 4.5)** : 21 juillet 2026  
**Responsable** : Équipe Modélisation & Data Science (M2)

---

## 1. Introduction et Choix Technologiques

La Phase 4 représente le cœur intellectuel de notre projet EDR. L'objectif est de s'abstraire des seuils heuristiques rigides de la Phase 3 en confiant la prise de décision à un algorithme de Machine Learning.
Nous avons sélectionné l'algorithme **Random Forest (Forêts Aléatoires)** de la librairie *scikit-learn* pour plusieurs raisons critiques en cybersécurité :
1. **Interprétabilité :** Contrairement au Deep Learning (boîte noire), on peut interroger un Random Forest pour connaître l'importance de chaque variable (Feature Importance).
2. **Robustesse au surapprentissage (Overfitting) :** En combinant plusieurs centaines d'arbres de décision générés sur des sous-échantillons aléatoires, l'algorithme annule les biais individuels de chaque arbre (Principe de l'apprentissage ensembliste / *Ensemble Learning*).
3. **Vitesse d'inférence :** L'API doit rendre un verdict en moins d'une seconde. Random Forest est extrêmement rapide en prédiction (`rf_model.predict()`).

---

## 2. Ingénierie des Données : Construction du Dataset

La conception d'un modèle d'IA anti-ransomware se heurte à un problème systémique majeur : **l'absence de données d'entraînement prêtes à l'emploi**. Les jeux de données publics existants (comme *Stratosphere IPS* du CTU de Prague ou *UWF-ZeekData22*) se composent exclusivement de captures réseau (PCAP, NetFlow, Zeek logs). Ils ne contiennent pas les événements internes du disque dur de la victime (Sysmon Event ID 11 ou 23).

### 2.1. L'Algorithme de Synthèse (`prepare_dataset.py`)
Pour résoudre ce paradigme, nous avons développé un générateur de données hybride. L'objectif de ce script Python est de transformer des logs réseau bruts en **Vecteurs Mathématiques de 10 secondes** (les 12 dimensions définies en Phase 3), puis d'y injecter synthétiquement l'empreinte disque d'un ransomware.

1. **Agrégation Temporelle (Resampling) :** Le script lit les CSV contenant des milliers de requêtes IP. En utilisant la fonction `resample('10S')` de *pandas*, il écrase les adresses IP littérales pour les remplacer par des compteurs numériques stricts (ex: `nb_connections=14`, `nb_unique_ips=3`). L'IA est ainsi nourrie exclusivement de statistiques de vélocité.
2. **Injection de Synthèse (Data Augmentation) :** Sur ces fenêtres de trafic malveillant, le script utilise la librairie `numpy.random` pour superposer artificiellement le comportement d'un disque dur attaqué :
```python
# Injection du comportement cryptographique sur une attaque réseau
resampled['nb_files_created'] = np.random.randint(50, 200, size=len(resampled))
resampled['entropy_filenames'] = np.random.uniform(5.0, 7.5, size=len(resampled))
resampled['nb_child_processes'] = np.random.randint(2, 10, size=len(resampled))
```

---

## 3. Évolution du Modèle de Menace (Les 3 Profils de la Phase 4.5)

Lors de nos tests de validation, une faille conceptuelle critique est apparue : le phénomène de la "Règle Stricte".
L'IA a d'abord été entraînée avec un unique profil de malware qui faisait **tout à la fois** (Réseau C2 + Création de fichiers + Suppression des originaux). Ainsi, lorsque nous avons attaqué notre propre EDR avec un simulateur PowerShell furtif qui se contentait uniquement de chiffrer sans rien supprimer et sans aller sur internet, le Random Forest a classifié l'attaque comme normale (Label `0`), considérant qu'il manquait les marqueurs réseau et suppressions pour confirmer la signature.

**La Solution : La Diversification des profils d'entraînement.**
Nous avons restructuré le générateur de Dataset pour inclure trois mutations (profils) de ransomwares, forçant l'IA à apprendre différentes tactiques d'évasion :

- **Profil A (L'attaque APT Complète) :** Le malware se connecte à son serveur C2, spawn des processus (`vssadmin`), chiffre le disque et supprime toutes les traces. Ce profil regroupe les 12 métriques à leur paroxysme.
- **Profil B (Furtif Offline / Air-Gapped) :** Ce profil simule un ransomware conçu pour frapper des systèmes sans internet. L'algorithme force artificiellement `nb_connections = 0`. L'IA apprend ainsi qu'une explosion d'entropie locale suffit à condamner le processus, même en l'absence absolue de communication réseau.
- **Profil C (Évasion de Corbeille / Sans Suppression) :** Conçu pour pallier les défauts de capteurs (Sysmon qui rate l'Event 23), ce profil met `nb_files_deleted = 0`. L'IA apprend que la seule création effrénée de fichiers chiffrés est une preuve suffisante d'infection.

Le dataset final généré compte **14 874 lignes** (dont 555 exemples de ransomwares mutants).

---

## 4. Entraînement et Standardisation (Pipeline ML)

### 4.1. La Standardisation des Données (Z-Score Scaling)
Avant d'être ingérées par l'algorithme, les données subissent une mise à l'échelle via `StandardScaler`. Cette étape transforme toutes les données pour qu'elles aient une moyenne de 0 et un écart-type de 1. C'est fondamental pour éviter que l'IA ne donne une pondération disproportionnée à la variable `nb_files_created` (qui monte à 500) au détriment de l'entropie (qui plafonne à 7.5).

### 4.2. Résultats d'Entraînement (`train_model.py`)
Le script d'entraînement industriel a généré notre cerveau `models/random_forest_model.pkl`. 
Les résultats sur le sous-ensemble de Test (20% du dataset) sont parfaits, avec une précision et un rappel de 1.0 (100%), justifié par la ségrégation forte entre le bruit de fond Windows et l'empreinte massive de notre génération synthétique.

| Classification Report | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: |
| **Normal (0)** | 1.00 | 1.00 | 1.00 |
| **Ransomware (1)** | 1.00 | 1.00 | 1.00 |

---

## 5. Synthèse Architecturale : La Détection Hybride
Le fichier central `api/main.py` de notre EDR implémente le patron de conception (Design Pattern) de la **Détection Hybride**.
L'API consulte simultanément :
1. Le modèle **Machine Learning (Random Forest)**.
2. Le **Moteur Heuristique (Rules Engine)** (défini en Phase 3).

Cette redondance (Fallback) assure une tolérance aux pannes conceptuelles. Si une souche de ransomware utilise une tactique "Zero-Day" non apprise par le Random Forest (résultant en une classification `0`), l'explosion mathématique des Z-Scores captée par le Rules Engine suffira à hisser le score au-delà du seuil de `0.70`, déclenchant immédiatement l'ordre de riposte (KILL).
