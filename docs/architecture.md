# Architecture Technique du Système EDR

**Date de rédaction** : Juillet 2026  
**Dernière mise à jour** : 11 août 2026  
**Version** : 3.0 (plateforme multi-analystes, base partagée, temps réel)

---

## 1. Vue d'ensemble

Le système Ransomware Detector est un EDR (Endpoint Detection and Response) réparti entre des postes
Windows surveillés et un serveur d'analyse centralisé. Il suit le modèle des EDR d'entreprise :
collecte sur l'endpoint, analyse et décision côté serveur, réponse exécutée sur l'endpoint, et
supervision par une équipe d'analystes.

L'architecture comporte deux couches. La **chaîne de détection** (modules 1 à 6) transforme des
événements système en décisions. La **plateforme de supervision** (modules 7 à 9) rend ces décisions
exploitables par plusieurs analystes simultanément, avec des habilitations distinctes et une
traçabilité opposable.

```
Postes Windows surveillés            Serveur EDR (Docker)
┌────────────────────┐             ┌───────────────────────────────────┐
│ Sysmon             │             │  nginx — origine unique           │
│   ↓                │             │    /  /api  /ws                   │
│ Winlogbeat ────────┼── HTTP ────→│                                   │
│                    │  + token    │  1. Parser                        │
│ Agent PowerShell ←─┼── HTTP ────←│  2. Feature Extractor  ┐          │
│   ↓                │ /commands   │  3. Baseline Engine    │ cloisonné│
│ Stop-Process       │  + ack      │  4. Rules Engine       │ par      │
└────────────────────┘             │  5. Random Forest      ┘ machine  │
                                   │  6. Response Engine               │
                                   │                                   │
                                   │  7. PostgreSQL — vérité partagée  │
                                   │  8. Sessions & habilitations      │
                                   │  9. WebSocket d'invalidation      │
                                   └───────────────┬───────────────────┘
                                                   │ cookie de session
                                     Analystes N1 / N2 / N3 (navigateur)
```

Le cloisonnement par machine est une propriété structurante : chaque poste dispose de son propre
extracteur de features et de sa propre baseline. Sans lui, le comportement normal d'un poste
bureautique et celui d'un serveur de fichiers seraient moyennés dans la même référence statistique,
et l'activité d'un poste pourrait masquer une attaque sur un autre.

---

## 2. Les Modules du Pipeline

### 2.1. Module 1 — Parser Sysmon (`parser/sysmon_parser.py`)

**Entrée** : Événement JSON brut de Winlogbeat (structure Elasticsearch `winlog.event_data`)  
**Sortie** : Dictionnaire Python normalisé

Le Parser est le premier maillon de la chaîne. Il reçoit les événements bruts au format JSON d'Elasticsearch (structure imbriquée avec `winlog.event_data`) et les transforme en un dictionnaire Python plat et exploitable.

#### Filtrage
Seuls 4 Event IDs Sysmon sont conservés (sur les 29 existants) :
- **Event 1** (Process Create) : Création de processus → `action: "process_create"`
- **Event 3** (Network Connection) : Connexion réseau → `action: "network_connection"`
- **Event 11** (File Create) : Création de fichier → `action: "file_create"`
- **Event 23** (File Delete) : Suppression de fichier → `action: "file_delete"`

Tous les autres événements sont silencieusement ignorés pour réduire le bruit (on passe typiquement de 503 événements bruts à ~250 événements pertinents par batch).

#### Normalisation
Chaque événement pertinent est transformé en un dictionnaire contenant :
- `event_id`, `timestamp`, `action` (obligatoires)
- `process_name`, `process_id`, `process_path` (extraits de `Image`)
- `parent_process`, `parent_process_id` (extraits de `ParentImage` et `ParentProcessId`)
- `target_file` (pour les Event 11/23)
- `network_ip`, `network_port` (pour les Event 3)

---

### 2.2. Module 2 — Feature Extractor (`features/feature_extractor.py`)

**Entrée** : Flux d'événements normalisés  
**Sortie** : Vecteur de 12 features numériques + métadonnées du processus suspect

Le Feature Extractor agrège les événements sur des **fenêtres temporelles glissantes** (10 secondes par défaut) et calcule 12 caractéristiques comportementales :

| # | Feature | Type | Description |
|---|---------|------|-------------|
| 1 | `nb_files_created` | int | Compteur de fichiers créés dans la fenêtre |
| 2 | `nb_files_deleted` | int | Compteur de fichiers supprimés |
| 3 | `nb_files_renamed` | int | Compteur de fichiers renommés |
| 4 | `nb_unique_extensions` | int | Nombre d'extensions uniques (.docx, .exe, .encrypted) |
| 5 | `entropy_filenames` | float | Entropie de Shannon des noms de fichiers (0.0 = prévisible, ~8.0 = aléatoire/chiffré) |
| 6 | `nb_processes_created` | int | Nombre de processus créés |
| 7 | `nb_child_processes` | int | Nombre de processus enfants non-système |
| 8 | `process_depth` | int | Profondeur de l'arborescence de processus |
| 9 | `nb_connections` | int | Nombre de connexions réseau |
| 10 | `nb_unique_ips` | int | Nombre d'adresses IP distinctes contactées |
| 11 | `nb_external_connections` | int | Connexions vers des IP publiques (non RFC 1918) |
| 12 | `nb_dns_queries` | int | Requêtes DNS (réservé, Sysmon Event 22) |

#### Tracking par PID (V2.1)
En plus des 12 features globales, le Feature Extractor V2.1 suit chaque processus individuellement via un dictionnaire `process_tracker`. Chaque PID accumule un **score de menace pondéré** :

| Événement | Pondération |
|-----------|:-----------:|
| File Create | +1 |
| File Delete | +2 |
| Process Create | +2 |
| Network Connection | +2 |
| Entropie > 5.0 | +10 |

Le PID ayant le score le plus élevé à la fin de la fenêtre est désigné comme `top_suspect`. Son processus parent (ParentImage, ParentProcessId) est également extrait pour établir la **chaîne de causalité** (Kill Chain).

---

### 2.3. Module 3 — Baseline Engine (`baseline/baseline_engine.py`)

**Entrée** : Vecteurs de features successifs  
**Sortie** : Z-Scores (déviations par rapport au comportement normal)

Le Baseline Engine implémente un algorithme d'**apprentissage statistique non supervisé** en deux phases :

#### Phase d'Apprentissage
Pendant les 10 premières fenêtres (mode lab) ou 90 fenêtres (mode production, soit 15 minutes), le moteur observe l'activité normale de la machine et stocke chaque vecteur de features dans un historique. Lorsque le seuil est atteint, il calcule pour chaque feature :
- **Moyenne (μ)** : Valeur centrale de référence
- **Écart-type (σ)** : Dispersion normale autour de la moyenne

Mesure de protection : L'écart-type est forcé à `max(σ, 1.0)` pour éviter les divisions par zéro lorsqu'une feature est constante (ex: 0 connexions réseau pendant 15 min).

#### Phase de Détection
Pour chaque nouveau vecteur de features, le moteur calcule le **Z-Score** :

$$Z = \frac{X - \mu}{\sigma}$$

Un Z-Score de 63.77 (comme observé lors de nos tests) signifie que la valeur observée est 63.77 écarts-types au-dessus de la normale. C'est une impossibilité statistique qui ne peut s'expliquer que par un comportement anormal (ransomware).

---

### 2.4. Module 4 — Rules Engine (`detector/rules_engine.py`)

**Entrée** : Vecteur de features + Z-Scores  
**Sortie** : Décision binaire (alerte ou non) + score de confiance + règles déclenchées

Le Rules Engine est un **système expert heuristique** qui évalue 4 règles de scoring pondérées :

1. **Création massive de fichiers** : Si `nb_files_created` dépasse un seuil dynamique → +30 points
2. **Entropie suspecte** : Si `entropy_filenames` > 5.0 (noms aléatoires/chiffrés) → +40 points
3. **Processus enfant suspect** : Si un processus enfant non-système est détecté avec activité fichier → +20 points
4. **Connexions réseau externes** : Si des connexions vers des IP publiques sont détectées → +10 points

Le score total est normalisé entre 0.0 et 1.0. Si le score dépasse le seuil configurable (défaut : 0.70), une alerte est déclenchée.

---

### 2.5. Module 5 — Modèles Machine Learning

#### Random Forest (`detector/random_forest.py` + `models/random_forest_model.pkl`)
Modèle de classification supervisé (100 arbres, profondeur maximale 10) entraîné sur un dataset de 14 874 échantillons mêlant activité normale et 3 profils de ransomware. Importance des variables telle qu'elle ressort du modèle effectivement chargé :

| Feature | Importance |
|---------|-----------:|
| `process_depth` | 0.203 |
| `nb_files_created` | 0.177 |
| `nb_unique_extensions` | 0.151 |
| `nb_files_renamed` | 0.151 |
| `entropy_filenames` | 0.150 |
| `nb_processes_created` | 0.082 |
| `nb_child_processes` | 0.057 |
| `nb_files_deleted` | 0.026 |
| `nb_dns_queries` | 0.003 |
| `nb_connections`, `nb_unique_ips`, `nb_external_connections` | 0.000 |

Deux enseignements méritent d'être relevés. D'abord, la profondeur d'arborescence des processus arrive
en tête : ce n'est pas le volume de chiffrement qui distingue le mieux une attaque, mais la manière
dont le processus a été lancé. Ensuite, les trois features réseau ont une importance strictement
nulle : notre dataset synthétique ne comporte pas d'activité réseau discriminante, si bien que le
modèle ne s'en sert pas du tout. Le moteur heuristique, lui, continue de pondérer ces signaux — ce
qui illustre l'intérêt de conserver les deux moteurs plutôt que de s'en remettre au seul modèle.

Le modèle atteint une précision et un rappel de 100 % sur le jeu de test (split 80/20). Ce résultat
parfait doit être lu avec prudence : il traduit surtout la séparabilité d'un dataset synthétique, et
non une garantie de performance sur des rançongiciels réels.

L'onglet **Statistiques ML** de la console affiche ces valeurs telles qu'elles sont lues dans le
modèle chargé, et non des constantes recopiées dans l'interface : si le modèle est ré-entraîné, la
page suit.

#### LSTM (comparatif, `notebooks/exploration_eda.ipynb`)
Modèle séquentiel (Long Short-Term Memory) implémenté en PyTorch : 2 couches LSTM + Dense + Sigmoid, entraîné avec Adam et BCELoss. Il a servi de point de comparaison et n'est pas déployé. Les fenêtres soumises au modèle sont déjà des agrégats de 10 secondes, ce qui aplatit la chronologie fine que le LSTM sait exploiter : à ce niveau d'agrégation, il n'apportait pas de gain mesurable face au Random Forest. Le serveur n'embarque donc pas PyTorch, dépendance de plus de 2,5 Go.

#### Standardisation (`models/scaler.pkl`)
Les 12 features sont standardisées (moyenne 0, variance 1) via un `StandardScaler` de scikit-learn avant d'être passées au modèle. Le scaler est sérialisé via joblib pour garantir la cohérence entre l'entraînement et l'inférence.

---

### 2.6. Module 6 — Response Engine (`api/routers/ingest.py` + `agent/agent_ps.ps1`)

**Entrée** : Décision du moteur de détection + métadonnées du `top_suspect`  
**Sortie** : Alerte persistée et, si nécessaire, ordre adressé à une machine précise

#### Score de gravité borné

Le score porté par une alerte est le **maximum entre le score heuristique normalisé et la
probabilité du modèle**, sur une échelle de 0 à 100. Ce point mérite d'être explicité, car une
version antérieure utilisait directement le compteur d'activité du `top_suspect` comme gravité. Ce
compteur n'a pas de borne supérieure : il produisait des scores de 146 ou 241 sur une échelle
présentée comme /100, et surtout il classait « critique » tout processus simplement très actif — un
serveur de fichiers légitime, par exemple. Le compteur reste dans la fiche d'alerte comme élément de
preuve, mais il est dissocié du niveau de gravité.

#### Côté serveur

1. Extraction du `top_suspect` (PID, nom, parent, activité détaillée)
2. Génération des raisons textuelles (ex : « 231 fichiers créés », « Entropie élevée (5.678) »)
3. Persistance systématique de l'alerte en base, avec sa fiche forensics complète
4. Décision de réponse selon le score normalisé :
   - **< 70** → journalisation
   - **≥ 70** → alerte visible par tous les analystes, avec indicateur de confiance
   - **≥ 80** → ordre `KILL` inscrit dans la file, rapport JSON archivé dans `reports/`
5. Diffusion d'un avis d'invalidation sur les canaux concernés

Les seuils sont configurables depuis la console (table `app_settings`) et non recompilés.

#### File de commandes adressée et acquittée

Chaque ordre est **rattaché à une machine** et conserve son cycle de vie complet :
`pending → sent → acked | failed | expired`. La version précédente utilisait une liste Python et un
`pending_commands.pop(0)` : la première machine à interroger l'API récupérait l'ordre destiné à une
autre, sans trace ni accusé de réception. Une commande non acquittée au bout de 15 minutes expire,
ce qui évite qu'un poste éteint au mauvais moment laisse un ordre en attente indéfiniment.

#### Côté Endpoint (Agent PowerShell)

L'Agent s'authentifie par token et interroge `GET /agent/commands` toutes les 2 secondes en
précisant son identité de machine. Lorsqu'un ordre lui est destiné :

1. Affichage du bloc `EDR RESPONSE` avec l'ensemble des preuves
2. Exécution de `Stop-Process -Id <PID> -Force`, ou de la règle de pare-feu pour une isolation
3. En cas d'échec sur le PID (processus déjà mort), repli sur `Stop-Process -Name <nom>`
4. **Acquittement** auprès du serveur, qui journalise le résultat

#### Choix du modèle Pull (sondage) côté agent

Malgré l'ajout d'un WebSocket pour les consoles, l'agent conserve un modèle de sondage :
- il traverse naturellement les pare-feux (trafic sortant HTTP standard) ;
- il n'exige aucun port en écoute sur le poste surveillé, donc aucune surface d'attaque ajoutée ;
- il se reconnecte de lui-même sans logique d'état ;
- un délai maximal de 2 secondes est négligeable devant la fenêtre d'analyse de 10 secondes.

Le WebSocket est réservé aux consoles d'analystes, où la latence est directement perçue et où la
connexion est déjà authentifiée par un cookie de session.

---

### 2.7. Module 7 — Persistance partagée (`api/models.py`, PostgreSQL)

**Neuf tables** constituent la source de vérité unique : `users`, `sessions`, `machines`, `alerts`,
`metrics`, `commands`, `exclusions`, `audit_logs`, `app_settings`. Le schéma est versionné par
Alembic (`migrations/versions/`), et un script reprend l'ancienne base SQLite sans perte
d'historique.

Trois propriétés justifient PostgreSQL plutôt que SQLite :

- **écritures concurrentes** : SQLite verrouille la base entière à chaque écriture, ce qui rendait
  impossible l'ingestion continue des agents pendant que des analystes consultaient la console ;
- **agrégation déterministe** : `date_bin` découpe le temps sur une origine fixe, donc deux analystes
  obtiennent les mêmes barres de graphique, et non deux découpages calculés chacun depuis son propre
  « maintenant » ;
- **contraintes réelles** : unicité, clés étrangères et transactions garantissent des invariants que
  du code applicatif devait sinon maintenir à la main.

Aucun indicateur affiché n'est calculé dans le navigateur : score de risque, compteurs et points du
graphique proviennent tous de requêtes SQL.

---

### 2.8. Module 8 — Sessions et habilitations (`api/security.py`)

- **argon2id** pour le hachage des mots de passe : coût mémoire et temporel paramétrable, là où
  SHA-256 est volontairement rapide, donc peu adapté à des mots de passe.
- **Session serveur** matérialisée par un cookie `HttpOnly` + `SameSite`, illisible par le
  JavaScript de la page : un XSS ne permet pas de voler une session. Aucun jeton n'est déposé dans
  `localStorage`. La déconnexion supprime la session en base, donc rejouer le cookie échoue.
- **Verrouillage** après 5 échecs, avec un message d'erreur identique pour un compte inexistant et un
  mot de passe erroné, afin de ne pas révéler quels comptes existent.
- **Rotation imposée** : un mot de passe défini par un tiers ne donne accès à rien d'autre qu'à son
  propre changement.
- **Trois niveaux** appliqués par des dépendances FastAPI : N1 consulte et qualifie, N2 arrête et
  isole, N3 administre comptes, exclusions et configuration. L'interface masque les actions
  inaccessibles, mais la protection réelle est le refus du serveur : un appel direct à
  `POST /response/kill` avec un compte N1 reçoit un 403.
- **Audit non falsifiable** : l'auteur et l'adresse IP source sont déterminés par le serveur. La
  version précédente les acceptait du client, ce qui permettait d'écrire une entrée au nom d'un autre
  analyste et ôtait toute valeur probante au registre.
- **Agents authentifiés par token** : sans lui, n'importe quelle machine du réseau pourrait injecter
  de faux événements pour fausser une baseline, ou dépiler l'ordre d'arrêt qui la visait.

---

### 2.9. Module 9 — Synchronisation temps réel (`api/realtime.py`)

Un hub WebSocket diffuse des **avis d'invalidation par canal** (`alerts`, `metrics`, `machines`,
`commands`, `audit`, `exclusions`) :

```json
{ "type": "invalidate", "channel": "alerts", "at": "2026-08-11T14:23:52.187Z" }
```

Le message ne transporte **aucune donnée métier** ; chaque console relit ensuite l'API. Ce choix
évite qu'un message perdu ou réordonné laisse une console avec un état divergent, et garantit que les
habilitations sont réévaluées à chaque lecture. La connexion est authentifiée par le cookie de
session : un WebSocket anonyme est refusé. Si le canal tombe, l'interface le signale et bascule sur
un rafraîchissement périodique, plutôt que de laisser croire à des données à jour.

---

### 2.10. Console SOC (`dashboard/`)

Application React organisée en contextes (session, temps réel), un client d'API unique, un hook de
lecture réutilisable et **onze onglets** : vue d'ensemble, terminaux, alertes, journal des réponses,
statistiques ML, moteur heuristique, exclusions, journal d'audit, équipe SOC, configuration,
documentation. Deux vues de détail s'y ajoutent : la fiche forensics d'une alerte et la fiche d'un
terminal.

Aucune donnée n'est simulée. L'onglet du moteur heuristique lit les seuils réellement en vigueur
depuis la configuration, au lieu de recopier des valeurs dans le code de la page où elles auraient
dérivé silencieusement. Aucune inscription libre n'est proposée : la création de compte relève du
SOC Manager.

---

## 3. Flux de Données End-to-End

Voici le parcours complet d'un événement, de sa génération à la réponse automatique :

```
T=0s    Un processus malveillant crée 250 fichiers chiffrés sur la VM
          │
T=0.1s  Sysmon (ETW) intercepte chaque création de fichier (Event 11)
          │
T=1s    Winlogbeat collecte les événements du journal Windows
          │
T=2s    Winlogbeat envoie un batch NDJSON via POST /_bulk, avec son token d'agent
          │
T=2.1s  Le Parser filtre les Event ID pertinents (1, 3, 11, 23)
          │
T=2.2s  Les événements sont routés vers le pipeline DE CETTE MACHINE.
        Les chemins couverts par une exclusion sont écartés ici.
          │
T=10s   La fenêtre de 10s se ferme. Le vecteur de 12 features est extrait.
        Le top_suspect est identifié (PID 6128, 241 points d'activité)
          │
T=10.1s Le Baseline Engine calcule les Z-Scores (création=231.0, entropie=5.68)
          │
T=10.2s Le Rules Engine évalue les règles → risque 0.92
        Le Random Forest confirme → probabilité 0.9993
        Score de gravité retenu : max(92, 99) borné sur 100 → 92
          │
T=10.3s L'alerte est ÉCRITE EN BASE avec sa fiche forensics complète.
        92 >= 80 → commande KILL créée pour CETTE machine (statut pending)
        Rapport archivé dans reports/2026-08-11_14-23-52_ransom.exe.json
          │
T=10.4s Avis d'invalidation diffusés : alerts, metrics, machines, commands, audit
          │
T=10.9s Toutes les consoles connectées ont relu l'API et affichent l'alerte.
        Deux analystes distants voient le même score et le même graphique.
          │
T=12s   L'Agent récupère l'ordre via GET /agent/commands (statut sent)
        Affichage de l'EDR RESPONSE (preuves, décision, action)
        Exécution de Stop-Process -Id 6128 -Force
          │
T=12.1s Le processus malveillant est terminé. L'attaque est stoppée.
          │
T=12.3s L'Agent acquitte la commande (statut acked). Le journal des réponses
        et le journal d'audit sont mis à jour, et rediffusés aux consoles.
```

**Temps total de détection et réponse : ~12 secondes** (fenêtre 10 s + sondage 2 s).
**Délai d'affichage pour les analystes : moins d'une seconde** après l'écriture en base.

Si l'agent cesse d'émettre — poste éteint, service neutralisé par le rançongiciel — aucun événement
postérieur ne vient fermer la dernière fenêtre, qui est pourtant la plus incriminante. Une tâche de
fond l'évalue donc d'elle-même après un court silence, sans pour autant faire passer le poste
silencieux pour actif.

---

## 4. Sécurité de l'Architecture

### 4.1. Isolation réseau
Le réseau VMnet1 est Host-Only : aucun accès Internet par défaut. La VM ne peut communiquer qu'avec le PC hôte. Les simulations de ransomware sont donc confinées.

### 4.2. Pas d'agent en écoute
L'Agent PowerShell ne crée aucun serveur HTTP sur l'endpoint. C'est lui qui initie les connexions sortantes (GET). Aucun port n'est ouvert sur la VM, ce qui empêche un attaquant de cibler l'Agent lui-même.

### 4.3. Simulation inoffensive
Le simulateur de ransomware V2 ne chiffre rien réellement. Il crée des fichiers factices dans `%TEMP%` et invoque `vssadmin list shadows` (lecture seule, pas de suppression). Le script est explicitement commenté et documenté pour garantir l'absence de tout effet destructeur.

### 4.4. Sécurité de la plateforme de supervision

Le détail des mécanismes figure au module 8. En synthèse : mots de passe en argon2id, sessions
serveur en cookie `HttpOnly` révocables, habilitations appliquées côté serveur sur chaque route,
agents authentifiés par token, journal d'audit alimenté exclusivement par le serveur.

Le serveur **refuse de démarrer** en mode production si un secret est resté à sa valeur de
développement — secret de session, token d'agent, ou cookie non marqué `Secure`. Un déploiement
réellement exposé passe donc obligatoirement par une configuration explicite.

---

## 5. Conteneurisation Docker

`docker compose up -d --build` démarre trois services :

| Service | Image | Rôle |
|---------|-------|------|
| `db` | `postgres:16-alpine` | Source de vérité, données dans un volume nommé, sonde de disponibilité |
| `api` | build local | Applique les migrations Alembic puis démarre FastAPI, en utilisateur non privilégié |
| `web` | build multi-étapes | Compile la console React (Node) puis la sert avec nginx |

Deux décisions ont un effet direct sur le fonctionnement :

**Origine unique.** nginx sert `/` (console), `/api` (API) et `/ws` (WebSocket) sur un seul hôte. Le
navigateur ne voit donc qu'une origine : plus de CORS à ouvrir, et le cookie de session fonctionne
nativement, y compris pour les analystes distants. Le mode développement reproduit ce montage via le
proxy de Vite, afin que le comportement soit identique dans les deux environnements.

**Un seul worker pour l'API, volontairement.** Les extracteurs de features et les baselines sont des
automates à état en mémoire de processus. Avec plusieurs workers, les événements d'une même machine
seraient répartis entre eux, et chacun ne verrait qu'une fraction de l'activité : fenêtres et
baselines en seraient faussées. La consultation, elle, passe entièrement par PostgreSQL, donc le
nombre de consoles connectées n'a aucune incidence sur la cohérence des données.

L'analyste accède à la console via `http://<ip-du-serveur>:8080` depuis n'importe quel navigateur du
réseau ; aucune URL n'est codée en dur côté client.

---

## 6. Vérification

Trois suites automatisées couvrent l'architecture décrite ici, et s'exécutent aussi bien contre
l'environnement de développement que contre le déploiement conteneurisé :

| Suite | Portée |
|-------|--------|
| `scripts/e2e_check.py` | 86 contrôles : authentification, habilitations, CRUD, ingestion, détection, réponse active, temps réel, audit, configuration |
| `scripts/ui_check.py` | 37 contrôles : parcours d'un navigateur à travers le proxy, cookie de session compris |
| `dashboard/tests/smoke.mjs` | Rendu des 11 onglets dans Chromium, échec sur la moindre erreur JavaScript |

`scripts/list_routes.py` produit par ailleurs l'inventaire des routes avec la garde appliquée à
chacune, ce qui permet de vérifier qu'aucun endpoint n'a été ajouté sans protection.

---

## 7. Perspectives d'Évolution

- **HTTPS/TLS** : terminer les connexions en TLS pour chiffrer les échanges API-Agent et permettre
  `COOKIE_SECURE=true`. C'est le prérequis restant avant toute exposition hors laboratoire.
- **Signature des ordres** : signer les commandes envoyées aux agents, afin qu'un token compromis ne
  suffise pas à faire exécuter un arrêt de processus arbitraire.
- **Second facteur** pour les comptes N3, dont les actions sont les plus lourdes de conséquences.
- **Intégration LLM** : générer des recommandations post-incident à partir des fiches forensics.
- **Ré-entraînement continu** : alimenter le modèle avec les alertes qualifiées par les analystes,
  pour transformer le travail de triage en amélioration de la détection.
- **Haute disponibilité** : répartir les pipelines de détection entre plusieurs processus par
  partitionnement des machines, seule voie pour dépasser le worker unique sans casser les fenêtres.
