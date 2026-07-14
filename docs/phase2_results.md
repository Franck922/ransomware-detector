# Phase 2 — Résultats : Pipeline de Données & Baseline

**Date** : 12–19 juillet 2026  
**Responsable principal** : M1 (Pipeline & Connecteur)  
**Support** : M3 (API & Infrastructure)

---

## 1. Objectif de la Phase 2

Construire le pipeline complet de traitement des données : de la réception des logs
bruts Winlogbeat jusqu'au calcul d'un profil comportemental "normal" de la machine
surveillée. Ce pipeline constitue le socle technique sur lequel reposent la détection
(Phase 3) et les modèles de Machine Learning (Phase 4).

---

## 2. Architecture du Pipeline

```
  Winlogbeat (VM)
       │
       ▼
  POST /ingest (FastAPI)          ← api/main.py + api/schemas.py
       │
       ▼
  SysmonParser                    ← parser/sysmon_parser.py
  (Filtre EventIDs 1,3,11,23)
  (Normalise en dict Python)
       │
       ▼
  FeatureExtractor (10s et 30s)   ← features/feature_extractor.py
  (Calcule 12 features par fenêtre)
       │
       ▼
  BaselineEngine                  ← baseline/baseline_engine.py
  (Apprend la normale, calcule Z-Scores)
```

---

## 3. Composants développés

### 3.1 Schéma de validation — `api/schemas.py`

**Rôle** : Vérifier que les données envoyées à l'API ont le bon format avant
de les traiter. Si un champ est manquant ou mal formé, la requête est rejetée
immédiatement (code HTTP 422).

**Format attendu** :
```json
{
  "machine_id": "DESKTOP-39R2AEI",
  "batch": [
    { "@timestamp": "...", "winlog": { "event_id": "11", "event_data": {...} } }
  ]
}
```

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| `machine_id` | string | Oui | Identifiant unique de la machine source |
| `batch` | liste de dictionnaires | Oui | Liste des événements Sysmon bruts |

---

### 3.2 Endpoint d'ingestion — `api/main.py`

**Rôle** : Point d'entrée unique du système. Reçoit les lots d'événements via
HTTP POST, les fait passer dans le pipeline (Parser → Features → Baseline → Détection),
et retourne un accusé de réception.

**Endpoint** : `POST /ingest`

**Réponse** :
```json
{
  "status": "success",
  "message": "Batch ingéré et traité par le pipeline complet",
  "processed_events": 15
}
```

**Logging opérationnel** : Chaque étape du pipeline est tracée dans les logs du serveur
avec des icônes visuelles pour faciliter le suivi en temps réel :
- `━━━ Reçu un batch de X événements ━━━`
- `📈 [Fenêtre 10s] Features calculées`
- `📊 Baseline : apprentissage en cours (N/10 vecteurs)`
- `🔍 [Mode Détection] Z-Scores`
- `✅ [Normal]` ou `🚨 ALERTE CRITIQUE`

---

### 3.3 Parser Sysmon — `parser/sysmon_parser.py`

**Rôle** : Filtrer le bruit et normaliser les événements pertinents.

Windows génère des milliers d'événements par minute. La grande majorité ne concerne
pas les ransomwares. Le parser effectue deux opérations :

**Opération 1 — Filtrage** : Seuls 4 types d'événements sont conservés :

| EventID | Nom Sysmon | Action normalisée | Pertinence ransomware |
|---------|-----------|-------------------|----------------------|
| 1 | Process Create | `process_create` | Détecte le lancement du malware et de ses processus enfants |
| 3 | Network Connection | `network_connection` | Détecte la communication avec un serveur de commande (C2) |
| 11 | File Create | `file_create` | Détecte la création des fichiers chiffrés (.encrypted, .locked) |
| 23 | File Delete | `file_delete` | Détecte la suppression des fichiers originaux après chiffrement |

Tous les autres EventIDs (modification de registre, chargement de DLL, etc.)
sont ignorés pour réduire le bruit.

**Opération 2 — Normalisation** : Chaque événement brut Winlogbeat (JSON complexe
avec des dizaines de champs) est transformé en un dictionnaire Python simplifié :

```python
{
    "event_id": 11,
    "timestamp": "2026-07-06T14:06:09.012Z",
    "process_name": "malware.exe",
    "process_id": 4821,
    "process_path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\malware.exe",
    "parent_process": "explorer.exe",
    "target_file": "C:\\Users\\Documents\\rapport.docx.encrypted",
    "action": "file_create",
    "network_ip": None,
    "network_port": None
}
```

---

### 3.4 Feature Extractor — `features/feature_extractor.py`

**Rôle** : Agréger les événements individuels en un "portrait-robot" de l'activité
de la machine sur une fenêtre de temps (10 secondes ou 30 secondes).

Au lieu de regarder chaque événement un par un, le Feature Extractor attend la fin
d'une fenêtre de 10 secondes, puis compte et calcule **12 métriques comportementales** :

| # | Feature | Description | Valeur normale | Valeur ransomware |
|---|---------|-------------|----------------|-------------------|
| 1 | `nb_files_created` | Nombre de fichiers créés | 0–3 | 100–500 |
| 2 | `nb_files_deleted` | Nombre de fichiers supprimés | 0 | 100–500 |
| 3 | `nb_files_renamed` | Nombre de fichiers renommés | 0 | 0 (non collecté dans ce MVP) |
| 4 | `nb_unique_extensions` | Nombre d'extensions différentes | 1–3 | 1 (.encrypted) |
| 5 | `entropy_filenames` | Entropie de Shannon des noms de fichiers | 2.5–3.5 | 5.0–6.0 |
| 6 | `nb_processes_created` | Nombre de processus lancés | 0–1 | 1–5 |
| 7 | `nb_child_processes` | Nombre de processus enfants non-système | 0 | 1–3 |
| 8 | `process_depth` | Profondeur de la chaîne de processus | 0 | 2+ |
| 9 | `nb_connections` | Nombre de connexions réseau | 0–2 | 0–10 |
| 10 | `nb_unique_ips` | Nombre d'IPs distinctes contactées | 0–1 | 1–5 |
| 11 | `nb_external_connections` | Connexions vers des IPs publiques | 0 | 1–3 |
| 12 | `nb_dns_queries` | Requêtes DNS (EventID 22, non collecté) | 0 | 0 |

**Deux extracteurs en parallèle** : Un à 10 secondes (pour la réactivité) et un à
30 secondes (pour la vue d'ensemble). Le détecteur utilise la fenêtre de 10s.

#### L'entropie de Shannon

L'entropie est la métrique la plus discriminante. Elle mesure le "degré d'aléatoire"
d'une chaîne de caractères sur une échelle de 0.0 à 8.0 :

- **0.0** = Parfaitement prévisible (`aaaaaaa`)
- **3.0** = Texte normal (`rapport_2026.docx`)
- **5.5** = Chaîne aléatoire (`xK9mR2pLw4nQ.encrypted`) — signature typique d'un ransomware
- **8.0** = Données binaires pures (maximum théorique)

La formule utilisée est :

$$H = -\sum_{i=1}^{n} p(x_i) \cdot \log_2(p(x_i))$$

Où $p(x_i)$ est la fréquence d'apparition du caractère $x_i$ dans la chaîne.

---

### 3.5 Baseline Engine — `baseline/baseline_engine.py`

**Rôle** : Apprendre ce qui est "normal" pour la machine surveillée, puis mesurer
les écarts (Z-Scores) pour chaque nouvelle fenêtre.

#### Phase d'apprentissage

Le Baseline Engine collecte les vecteurs de features pendant une période d'observation
(configurable : 10 fenêtres en test, 90 en production soit 15 minutes). Pendant cette
période, il ne déclenche aucune alerte.

À la fin de l'apprentissage, il calcule pour chaque feature :
- **La moyenne (μ)** : la valeur typique
- **L'écart-type (σ)** : la variation habituelle

Exemple : si `nb_files_created` = [2, 1, 3, 2, 1, 2, 3, 2, 1, 2], alors μ = 1.9 et σ = 0.7.

#### Phase de détection (Z-Score)

Pour chaque nouvelle fenêtre, le Z-Score mesure combien de fois la valeur dépasse
la variation habituelle :

$$Z = \frac{X - \mu}{\sigma}$$

| Z-Score | Signification | Probabilité que ce soit normal |
|---------|---------------|-------------------------------|
| 0–1 | Dans la normale | 84% |
| 1–2 | Légèrement au-dessus | 16% |
| 2–3 | Significativement au-dessus | 2% |
| > 3 | **Anomalie statistique** | < 0.1% |

Un Z-Score supérieur à 3 signifie que l'activité observée a moins de 0.1% de chances
d'être normale. C'est ce seuil que nos règles utilisent pour décider si une création
ou suppression massive de fichiers est suspecte.

---

## 4. Tests unitaires

### 4.1 Tests du Parser (`parser/tests/test_parser.py`)

| Test | Description | Résultat |
|------|-------------|----------|
| `test_parse_event_1_process_create` | Vérifie qu'un EventID 1 est correctement normalisé | ✅ PASS |
| `test_parse_event_11_file_create` | Vérifie qu'un EventID 11 extrait le `TargetFilename` | ✅ PASS |
| `test_ignore_irrelevant_event` | Vérifie qu'un EventID non pertinent (ex: 7) retourne `None` | ✅ PASS |

### 4.2 Tests du Feature Extractor

Testés manuellement via injection de logs synthétiques. Validé que :
- Les compteurs s'incrémentent correctement pour chaque type d'événement
- L'entropie de Shannon est calculée avec précision
- La fenêtre temporelle se déclenche après 10 secondes d'événements

---

## 5. Fichiers produits lors de la Phase 2

| Fichier | Lignes | Description |
|---------|--------|-------------|
| `api/schemas.py` | 18 | Modèles Pydantic de validation des données |
| `api/main.py` | 91 | Endpoint FastAPI + câblage du pipeline complet |
| `parser/sysmon_parser.py` | 113 | Filtrage et normalisation des logs Sysmon |
| `features/feature_extractor.py` | 143 | Calcul des 12 features + entropie de Shannon |
| `baseline/baseline_engine.py` | 85 | Apprentissage du comportement normal + Z-Scores |
| `parser/tests/test_parser.py` | ~50 | Tests unitaires du parser |
| `docs/phase2_results.md` | Ce document | Documentation des résultats |

---

## 6. Conclusion

Le pipeline de données est entièrement fonctionnel, de la réception des logs bruts
jusqu'au calcul des déviations comportementales. Le système est capable de :

1. **Recevoir** des événements via l'API REST (`POST /ingest`)
2. **Filtrer** le bruit (ne garder que les EventIDs pertinents pour le ransomware)
3. **Normaliser** les données dans un format exploitable
4. **Agréger** les événements par fenêtres de 10 et 30 secondes
5. **Apprendre** le comportement normal de la machine (baseline)
6. **Mesurer** les déviations par rapport à cette normale (Z-Scores)

Ce socle technique est prêt à alimenter le moteur de détection (Phase 3).
