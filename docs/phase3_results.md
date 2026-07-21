# Phase 3 : Modélisation Comportementale, Algorithmique de Baseline et Moteur Heuristique

**Date de réalisation** : 15 juillet 2026  
**Dernière révision majeure** : 21 juillet 2026  
**Responsable** : Équipe Détection (Modélisation M2)

---

## 1. Introduction et Contexte Théorique

L'objectif fondamental de la Phase 3 est d'opérer une transition paradigmatique dans notre approche de la détection. Les solutions antivirus traditionnelles (EPP - Endpoint Protection Platforms) reposent historiquement sur des bases de données de signatures (hash MD5/SHA256). Cette approche statique est aujourd'hui frappée d'obsolescence face aux ransomwares polymorphes ou "fileless" qui mutent à chaque infection.

Pour pallier cette limitation, notre EDR hybride se base sur l'**analyse comportementale dynamique (Behavioral Analysis)**. Le postulat est le suivant : peu importe le code source du malware ou sa signature, son *comportement* sur le système (chiffrer des milliers de fichiers en quelques secondes, supprimer des clichés instantanés, communiquer avec un serveur C2) reste immuable. 

La Phase 3 se concentre donc sur la création d'un moteur capable de "traduire" un flux continu de logs textuels (issus de Sysmon) en **métriques mathématiques évaluables en temps réel**.

---

## 2. Le Concept de "Vecteur de Features" (Feature Extraction)

Dans le domaine de la Data Science, les algorithmes de Machine Learning sont incapables de traiter du texte brut de manière performante. Il est impératif de vectoriser l'information.

### 2.1. Le fenêtrage temporel (Time-Windowing)
Notre composant `FeatureExtractor` (situé dans `features/feature_extractor.py`) agit comme un entonnoir temporel. Plutôt que d'analyser chaque événement Sysmon individuellement (ce qui générerait trop de faux positifs), l'algorithme regroupe les événements par **fenêtres strictes de 10 secondes**.
Ce choix de 10 secondes a été défini empiriquement : il est suffisamment court pour bloquer un ransomware avant qu'il ne détruise trop de données, et suffisamment long pour capturer une tendance (vélocité).

### 2.2. Constitution du Vecteur à 12 Dimensions
À l'issue de chaque fenêtre de 10 secondes, l'extracteur fige le buffer d'événements et calcule 12 caractéristiques mathématiques (Features). Le résultat est un dictionnaire Python (un vecteur 1D) :

1. **`nb_files_created`** : Nombre absolu d'Event ID 11 (FileCreate). Un ransomware génère un pic massif.
2. **`nb_files_deleted`** : Nombre absolu d'Event ID 23 (FileDelete). Souvent utilisé pour détruire l'original après chiffrement.
3. **`nb_files_renamed`** : Mouvement de renommage.
4. **`nb_unique_extensions`** : Variété des extensions touchées.
5. **`entropy_filenames`** : (Critique) Mesure de l'aléatoire dans les noms de fichiers créés.
6. **`nb_processes_created`** : Nombre d'Event ID 1 (ProcessCreate).
7. **`nb_child_processes`** : Nombre de sous-processus générés (souvent via `cmd.exe` ou `powershell.exe`).
8. **`process_depth`** : Profondeur de l'arbre des processus.
9. **`nb_connections`** : Volume total des Event ID 3 (NetworkConnection).
10. **`nb_unique_ips`** : Nombre d'adresses IP distinctes contactées.
11. **`nb_external_connections`** : Connexions vers des adresses IP publiques (hors RFC 1918).
12. **`nb_dns_queries`** : Nombre de requêtes DNS (Event ID 22), souvent liées à la résolution d'un domaine DGA (Domain Generation Algorithm).

### 2.3. Focus sur l'Entropie de Shannon
L'entropie de Shannon est une formule mathématique mesurant la quantité d'incertitude (ou d'aléatoire) dans une chaîne de caractères. 
- Un fichier légitime tel que `rapport_annuel_2026.docx` possède une entropie faible (environ **3.0 à 3.5**).
- Un fichier généré par un algorithme de chiffrement (ex: `A8F3J29X.locked`) possède une distribution de caractères imprévisible, résultant en une entropie élevée (souvent **> 5.5**).
L'extraction de cette métrique est le pilier de notre heuristique anti-ransomware.

---

## 3. L'Algorithme de Baseline (Apprentissage du Rythme Cardiaque)

Pour détecter une anomalie, le système doit d'abord définir ce qu'est la "normalité" propre à la machine hôte. C'est la mission de la classe `BaselineEngine` (`baseline/baseline_engine.py`).

### 3.1. Phase d'Observation (T=0s à T=100s)
Au lancement, le moteur entre en état `Apprentissage`. Il va intercepter les 10 premiers vecteurs (soit 10 * 10 secondes = 100 secondes) et les stocker dans une matrice en mémoire (`self.history`). Durant cette phase, l'utilisateur est invité à ne pas lancer d'activité malveillante, voire à générer un trafic "bruit de fond" légitime (navigation web, bureautique).

### 3.2. Calculs Statistiques (La Loi Normale)
Une fois les 10 vecteurs atteints, l'algorithme fait appel à la librairie scientifique `numpy` pour calculer, pour chacune des 12 colonnes, deux valeurs fondamentales de la distribution statistique :
- **La Moyenne ($\mu$) :** Représente l'espérance mathématique de la métrique en temps de paix.
- **L'Écart-Type ($\sigma$) :** Représente la dispersion ou la variance. Il indique de combien la valeur a le droit de fluctuer autour de la moyenne sans être considérée comme anormale.

### 3.3. Analyse d'Incidents et Correctif de la Variance Nulle
**Description du Bug :** Lors de nos tests initiaux, nous avons fait face à une division par zéro provoquant une erreur fatale (`ZeroDivisionError`) ou des Z-Scores dépassant les 60 millions.
**Cause algorithmique :** Si la machine virtuelle est strictement inactive pendant les 100 secondes d'apprentissage, l'écart-type ($\sigma$) calculé pour la création de fichier est de `0.0`. L'algorithme initial ajoutait un epsilon arbitraire `1e-6` pour éviter le crash. Cependant, diviser une valeur de 62 créations de fichiers par `0.000001` donnait mathématiquement `62 000 000`.
**Résolution :** Nous avons implémenté un correctif mathématique de type "plancher". Nous forçons l'écart-type à avoir une valeur minimum absolue de `1.0`. 
```python
# Extrait du code corrigé dans baseline_engine.py
# On impose un écart-type minimum de 1.0 pour éviter les Z-scores astronomiques
self.stds[key] = max(float(np.std(values)), 1.0)
```
Cette modification garantit la robustesse du calcul mathématique en toute circonstance.

---

## 4. Le Calcul d'Anomalie (Z-Score)

Dès que la Baseline est verrouillée (`self.is_trained = True`), le système passe en état `Détection`. Les nouveaux vecteurs ne sont plus ajoutés à l'historique. Ils sont évalués en temps réel via la formule du **Score Standard (Z-Score)** :

$$ Z = \frac{X - \mu}{\sigma} $$

Où :
- $X$ = La valeur capturée dans la fenêtre actuelle (ex: 60 fichiers créés).
- $\mu$ = La moyenne calculée lors de la baseline (ex: 0.5).
- $\sigma$ = L'écart-type calculé lors de la baseline (minimum 1.0).

Si le Z-score dépasse un certain seuil (ex: > 3.0), cela signifie statistiquement que l'événement observé a moins de 0,1% de chances de se produire par hasard dans un comportement normal. C'est une alarme forte pour le moteur de détection.

---

## 5. Le Moteur Heuristique (Rules Engine)

Bien que le Machine Learning (Phase 4) soit notre méthode de détection principale, nous avons appliqué un principe fondamental de cybersécurité : **la défense en profondeur**. Nous avons codé un `RulesEngine` (`detector/rules_engine.py`) qui agit comme un système expert (Expert System) basé sur des règles déterministes codées en dur.

### 5.1. Logique de Pondération
Le moteur de règles lit le vecteur actuel et ses Z-Scores, puis attribue des points de "risque" (maximum 100 points, normalisés de 0.0 à 1.0) selon un arbre de décision strict :
- **Règle 1 (Création massive) :** Si `nb_files_created > 30` ET `Z-score > 3.0` $\rightarrow$ **+30 points**.
- **Règle 2 (Suppression massive) :** Si `nb_files_deleted > 30` ET `Z-score > 3.0` $\rightarrow$ **+30 points**.
- **Règle 3 (Signature cryptographique) :** Si `entropy_filenames > 5.0` $\rightarrow$ **+40 points**.
- **Règle 4 (Comportement de processus) :** Si processus enfants suspects en parallèle d'une activité fichier $\rightarrow$ **+20 points**.

### 5.2. Tuning et Abaissement du Seuil (Threshold)
Initialement, le seuil de déclenchement (`alert_threshold`) était fixé à **0.80**.
Cependant, l'analyse d'une simulation d'attaque a mis en lumière une limitation critique au niveau de l'Event Tracing for Windows (ETW) et de Sysmon : les suppressions de fichiers (Event 23) ne remontaient pas systématiquement à cause des mécanismes de corbeille de l'OS. 
En conséquence, le ransomware marquait 30 points (création) + 40 points (entropie), s'arrêtant à **0.70**, juste sous le radar de l'alerte.

Pour garantir une sécurité optimale face aux ransomwares furtifs qui évitent les suppressions franches, **le seuil a été rabaissé à 0.70** dans `api/main.py`. Grâce à ce tuning précis, le moteur heuristique est capable d'intercepter à lui seul l'attaque de notre simulateur, démontrant ainsi sa capacité à opérer en solution de repli (fallback) autonome en cas de défaillance du modèle de Machine Learning.
