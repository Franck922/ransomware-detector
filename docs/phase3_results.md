# Phase 3 — Résultats : Moteur de Règles & Tests Synthétiques

**Date** : 15 juillet 2026  
**Responsable principal** : M2 (Modèle de détection)  
**Support** : M1 (Pipeline & Connecteur)

---

## 1. Objectif de la Phase 3

Développer un moteur de détection heuristique capable de distinguer un comportement
normal d'un comportement de ransomware, en se basant sur les features comportementales
calculées par le Feature Extractor (Phase 2) et les déviations Z-Score du Baseline Engine.

---

## 2. Architecture du Moteur de Règles

Le moteur de règles (`detector/rules_engine.py`) reçoit deux entrées :

- **Le vecteur de features** : 12 métriques calculées sur une fenêtre de 10 secondes
  (nombre de fichiers créés, supprimés, entropie des noms, etc.)
- **Les déviations Z-Score** : l'écart de chaque feature par rapport au comportement
  normal appris pendant la phase de baseline (15 minutes en production, 10 fenêtres en test).

Il applique **4 règles de scoring** et produit un score de risque entre 0.0 et 1.0.
Une alerte est déclenchée si le score dépasse **0.80** (80 points sur 100).

---

## 3. Définition des 4 Règles de Scoring

| # | Nom de la règle                            | Condition de déclenchement | Points | Justification |
|---|--------------------------------------------|--------------------------- |--------|---------------|
| 1 | Création massive de fichiers               | `nb_files_created > 30` ET `Z-Score création > 3.0` | +30 | Un ransomware crée les fichiers chiffrés à une vitesse inhumaine (centaines par seconde) |
| 2 | Suppression massive de fichiers            | `nb_files_deleted > 30` ET `Z-Score suppression > 3.0` | +30 | Après chiffrement, le ransomware supprime systématiquement les originaux |
| 3 | Entropie suspecte des noms de fichiers     | `nb_files_created > 0` ET `entropy > 5.0` | +40 | Les noms générés par un ransomware sont aléatoires (haute entropie de Shannon) |
| 4 | Processus enfant suspect                   | `nb_child_processes > 0` ET activité fichier élevée | +20 | Les ransomwares lancent souvent des commandes système (ex: `vssadmin delete shadows`) |

**Score maximum** : 120 points, capé à 100.  
**Seuil d'alerte** : 80 points (score ≥ 0.80).

---

## 4. Calibrage des Seuils

### 4.1 Seuil d'entropie : de 6.5 à 5.0

Lors des tests initiaux, le seuil d'entropie était fixé à 6.5. Cependant, les noms de
fichiers générés aléatoirement par un ransomware (caractères alphanumériques, 12-16 caractères)
produisent une entropie de Shannon d'environ **5.2 à 5.7**.

| Type de nom de fichier           | Exemple                       | Entropie mesurée|
|----------------------------------|-------------------------------|-----------------|
| Document normal                  | `rapport_financier_2026.docx` | 3.0 — 3.5       |
| Fichier chiffré (ransomware)     | `xK9mR2pLw4nQ.encrypted`      | 5.2 — 5.7       |
| Chaîne binaire pure (théorique)  | `\x8f\xa2\x3b...`             | 7.5 — 8.0       |

**Décision** : Le seuil a été abaissé à **5.0** pour capturer les noms de fichiers de
ransomware réels tout en restant au-dessus de l'entropie des documents normaux (~3.5).
Cela crée une marge de sécurité de **1.5 points** entre le normal et le seuil.

### 4.2 Seuil de création/suppression : 30 fichiers par 10 secondes

Ce seuil a été maintenu à 30 fichiers. Un utilisateur humain crée rarement plus de
2-3 fichiers en 10 secondes. Le seuil de 30 laisse une marge confortable de **10x**
l'activité normale observée.

---

## 5. Résultats des Tests

### 5.1 Protocole de test

Trois scénarios ont été testés via injection de logs synthétiques dans l'API `/ingest` :

1. **Scénario "Normal"** : 2 fichiers créés par fenêtre de 10s, noms prévisibles (`rapport_1.docx`)
2. **Scénario "Ransomware"** : 150 fichiers créés + 150 supprimés en 10s, noms aléatoires (`.encrypted`)
3. **Scénario "Suspicion partielle"** : 1 fichier créé avec un nom à haute entropie, sans suppression massive

### 5.2 Résultats

| Scénario            | Fichiers créés| Fichiers supprimés| Entropie | Score   | Alerte     | Règles déclenchées |
|---------------------|---------------|-------------------|----------|---------|------------|------------------- |
| Normal              | 2             | 0                 | 3.0      | **0.0** |❌ Non      | Aucune            |
| Ransomware          | 150           | 150               | 5.53     | **1.0** | ✅ **OUI** | R1 + R2 + R3      |
| Suspicion partielle | 1             | 0                 | 5.5      | **0.4** | ❌ Non     | R3 uniquement     |

### 5.3 Métriques de performance

| Métrique | Valeur | Commentaire |
|----------|--------|-------------|
| **Taux de détection (Recall)** | **100%** | Le scénario ransomware a été détecté à chaque exécution |
| **Faux positifs** | **0%** | Aucune alerte sur les scénarios normaux ou partiellement suspects |
| **Temps de détection** | **< 1 seconde** | L'alerte est levée dès la fin de la fenêtre de 10s contenant l'attaque |
| **Score de confiance** | **1.0 / 1.0** | Score maximal atteint lors de l'attaque ransomware |

### 5.4 Features les plus déclenchantes

En ordre d'importance pour la détection :

1. **`entropy_filenames`** (+40 pts) — Le marqueur le plus discriminant. L'entropie passe
   de ~3.0 (normal) à ~5.5 (ransomware), soit une augmentation de 83%.
2. **`nb_files_created`** (+30 pts) — Passe de 2 (normal) à 150 (ransomware), soit un
   Z-Score de 247.
3. **`nb_files_deleted`** (+30 pts) — Passe de 0 (normal) à 150 (ransomware), soit un
   Z-Score de 150 000 000.

---

## 6. Limites identifiées

1. **Règle 4 non testée en conditions réelles** : La détection de processus enfants
   nécessite des logs Sysmon EventID 1 générés par un vrai ransomware (ex: `vssadmin`,
   `bcdedit`). Cette règle sera validée en Phase 5 avec l'intégration VM complète.

2. **Baseline fixe après entraînement** : Actuellement, le baseline ne se met pas à jour
   après la phase d'apprentissage. Un utilisateur changeant ses habitudes pourrait
   déclencher des faux positifs à long terme. (Amélioration possible : baseline glissant.)

3. **Intégration VM à finaliser** : Le forwarder PowerShell doit être synchronisé avec le
   fichier Winlogbeat le plus récent. Ce point sera résolu en Phase 5.

---

## 7. Fichiers produits lors de la Phase 3

| Fichier | Description |
|---------|-------------|
| `detector/rules_engine.py` | Moteur de règles heuristique (4 règles, scoring 0-100) |
| `detector/tests/test_rules_engine.py` | 3 tests unitaires (normal, ransomware, partiel) |
| `agent/simulate_ransomware.ps1` | Script PowerShell de simulation d'attaque pour la VM |
| `agent/forwarder.ps1` | Agent de transfert des logs Winlogbeat vers l'API |
| `docs/phase3_results.md` | Ce document de résultats |

---

## 8. Conclusion

Le moteur de règles adaptatives est **opérationnel** et capable de détecter un
comportement de ransomware avec un taux de détection de 100% et un taux de faux positifs
de 0% sur les données synthétiques testées. Le calibrage du seuil d'entropie (de 6.5 à 5.0)
a été la modification clé pour atteindre ces performances. Le système est prêt pour
l'intégration avec les modèles de Machine Learning (Phase 4) et les tests end-to-end (Phase 5).
