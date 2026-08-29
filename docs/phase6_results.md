# Phase 6 : Console SOC multi-analystes, base partagée et déploiement

Cette phase fait passer la console EDR d'une maquette mono-poste à une plateforme de supervision
utilisable simultanément par plusieurs analystes distants, sur une base de données partagée et
synchronisée.

---

## 1. Objectifs de la phase

1. **Permettre le travail à plusieurs** : plusieurs analystes connectés à distance depuis leur
   navigateur, avec des comptes et des habilitations distincts.
2. **Partager une vision unique du parc** : deux analystes qui regardent le dashboard au même
   instant doivent voir exactement les mêmes chiffres et le même graphique.
3. **Synchroniser sans rechargement** : une alerte, une réponse ou une exclusion apparaît chez tous
   les analystes connectés en moins d'une seconde.
4. **Rendre les opérations réellement contraintes** : un analyste N1 ne doit pas pouvoir déclencher
   un arrêt de processus, y compris en appelant l'API directement.
5. **Rendre la traçabilité opposable** : le journal d'audit ne doit pas pouvoir être falsifié par
   celui qui y est inscrit.
6. **Déployer en une commande**, sans prérequis Python ni Node.js sur le serveur.

---

## 2. Ce que la première itération ne permettait pas

La version précédente fonctionnait en démonstration sur un seul poste. La confronter à l'exigence
« plusieurs analystes voient les mêmes données » a révélé des limites structurelles, et non de
simples ajustements :

| Constat | Conséquence |
|---------|-------------|
| **SQLite verrouille la base entière** à chaque écriture | Impossible d'ingérer les événements des agents pendant que des analystes consultent la console. Le fournisseur SQLite le documente lui-même : un seul écrivain à la fois. |
| **État de détection en mémoire du processus** (fenêtres, baseline, alertes) | Tout redémarrage effaçait la baseline, et un second processus API aurait vu un état totalement différent. |
| **Authentification décidée par le navigateur** | Le rôle était conservé côté client : il suffisait de le modifier dans le navigateur, ou d'appeler l'API sans passer par l'interface, pour obtenir les droits d'un SOC Manager. |
| **Journal d'audit alimenté par le client** | L'auteur et l'adresse IP d'une action étaient fournis par l'appelant. N'importe qui pouvait donc écrire une entrée au nom d'un autre analyste, ce qui ôtait toute valeur probante au registre. |
| **Compte administrateur en dur** (`Franck` / `admin123`, haché en SHA-256) | Identifiants publiés dans le dépôt et hachage sans sel, inadapté à des mots de passe. |
| **File de commandes en liste Python, sans destinataire** | `pending_commands.pop(0)` : la première machine à interroger l'API récupérait l'ordre d'arrêt destiné à une autre, sans trace ni accusé de réception. |
| **Rafraîchissement par sondage toutes les 2 s** | Latence visible, charge inutile, et surtout aucune garantie que deux consoles soient au même point. |
| **Score de gravité non borné** | Un score de 146 sur une échelle présentée comme /100 : la gravité était en réalité le compteur d'activité du processus, donc un serveur de fichiers actif devenait « critique » par simple volume. |
| **Pas de cloisonnement par machine** | Les événements de tous les postes alimentaient les mêmes fenêtres et la même baseline : l'activité d'un poste pouvait masquer une attaque sur un autre. |

---

## 3. Base de données PostgreSQL

**Neuf tables** décrivent désormais l'ensemble du domaine, versionnées par Alembic
(`migrations/versions/`) :

| Table | Rôle |
|-------|------|
| `users` | Comptes analystes : hachage argon2id, rôle, verrouillage, rotation exigée |
| `sessions` | Sessions serveur, révocables, associées à une empreinte de cookie |
| `machines` | Inventaire des postes : dernier contact, état d'isolation, phase d'apprentissage |
| `alerts` | Alertes avec fiche forensics complète, affectation et statut de traitement |
| `metrics` | Agrégats horodatés par intervalle, qui alimentent le graphique partagé |
| `commands` | File d'ordres adressés à une machine précise, avec statut et accusé de réception |
| `exclusions` | Règles de confiance appliquées par le moteur de détection |
| `audit_logs` | Journal nominatif, écrit exclusivement par le serveur |
| `app_settings` | Configuration modifiable depuis la console (seuils, rétention) |

PostgreSQL a été retenu pour trois raisons précises :

- **écritures concurrentes** : l'ingestion continue des agents et la consultation par les analystes
  ne se bloquent plus mutuellement ;
- **agrégation côté serveur** : `date_bin` permet de découper le temps sur une origine fixe, donc de
  garantir que deux analystes obtiennent des barres identiques, et non deux découpages calculés
  chacun à partir de son « maintenant » ;
- **contraintes réelles** : unicité, clés étrangères et transactions empêchent les incohérences que
  du code applicatif devait sinon prévenir à la main.

Un script de reprise (`scripts/migrate_sqlite_to_pg.py`) importe l'ancienne base : comptes,
exclusions, journal d'audit et alertes sont conservés. Les mots de passe SHA-256 importés sont
marqués comme héritage, réhachés en argon2id à la première connexion réussie, puis leur rotation est
immédiatement exigée.

---

## 4. Comptes, sessions et habilitations

- **Hachage argon2id** (`argon2-cffi`), conçu pour les mots de passe : coût mémoire et temporel
  paramétrable, contrairement à SHA-256 qui est volontairement rapide donc facile à attaquer par
  force brute.
- **Session serveur** matérialisée par un cookie `HttpOnly` + `SameSite`. Le JavaScript de la page
  ne peut pas le lire : un XSS ne permet pas de voler une session. Aucun jeton n'est déposé dans
  `localStorage`, et la réponse de connexion ne contient rien d'exploitable.
- **Révocation effective** : la déconnexion supprime la session en base. Rejouer le cookie ensuite
  renvoie 401, ce qui est vérifié automatiquement.
- **Verrouillage** après 5 échecs consécutifs, avec un message d'erreur identique pour un compte
  inexistant et un mot de passe erroné : la page de connexion ne révèle pas quels comptes existent.
- **Rotation imposée** : un mot de passe défini par un administrateur ne donne accès à rien d'autre
  qu'à son propre changement, ce que le serveur signale par un en-tête dédié.
- **Trois niveaux d'habilitation** appliqués par des dépendances FastAPI sur chaque route :

| Niveau | Peut |
|--------|------|
| **N1 — Analyste** | consulter, prendre en charge et qualifier les alertes |
| **N2 — Analyste confirmé** | en plus : arrêter un processus, isoler et désisoler un poste |
| **N3 — SOC Manager** | en plus : gérer les comptes, les exclusions et la configuration |

L'interface masque les actions inaccessibles, mais ce n'est qu'un confort d'affichage : la
protection réelle est le refus du serveur. Un appel direct à `POST /response/kill` avec un compte N1
reçoit un 403, et la tentative est journalisée.

---

## 5. Synchronisation temps réel

Un hub WebSocket (`api/realtime.py`) diffuse des **avis d'invalidation par canal** : `alerts`,
`metrics`, `machines`, `commands`, `audit`, `exclusions`.

```json
{ "type": "invalidate", "channel": "alerts", "at": "2026-08-11T14:23:52.187Z" }
```

Le message ne transporte volontairement **aucune donnée métier**. Chaque console relit ensuite
l'API sur le canal concerné. Ce choix a trois effets :

1. un message perdu ou réordonné ne peut pas laisser une console avec un état divergent, puisque la
   vérité est toujours relue en base ;
2. les habilitations sont réévaluées à chaque lecture, alors qu'une diffusion de données obligerait
   à filtrer le contenu par destinataire ;
3. le canal reste léger, même pendant une rafale d'ingestion.

La connexion est authentifiée par le cookie de session : un WebSocket anonyme est refusé. En cas de
coupure, l'interface l'affiche explicitement et bascule sur un rafraîchissement périodique, plutôt
que de laisser croire à des données à jour.

---

## 6. Console SOC (React)

L'application monolithique a été découpée en contextes (session, temps réel), en un client d'API
unique, un hook de lecture réutilisable, et **onze onglets** : vue d'ensemble, terminaux, alertes,
journal des réponses, statistiques ML, moteur heuristique, exclusions, journal d'audit, équipe SOC,
configuration et documentation. Deux vues de détail complètent l'ensemble, atteintes en cliquant sur
une ligne : la fiche forensics d'une alerte et la fiche d'un terminal.

Aucune donnée n'est simulée : chaque écran lit l'API. Les points suivants ont été traités
spécifiquement :

- **le score de risque et les compteurs sont calculés par le serveur**, pas dans le navigateur ;
- **l'onglet Moteur heuristique lit les seuils réellement en vigueur** depuis la configuration, au
  lieu de recopier des valeurs dans le code de la page, où elles auraient dérivé silencieusement ;
- **aucune inscription libre** n'est proposée : la création de compte relève du SOC Manager ;
- **la documentation est embarquée** dans la console, pour que l'analyste de garde n'ait pas à
  chercher un fichier ailleurs.

---

## 7. Corrections du moteur de détection

Trois défauts ont été corrigés en plus de la refonte d'architecture :

- **Score borné et explicable.** La gravité est désormais le maximum entre le score heuristique
  normalisé et la probabilité du modèle, sur 0–100. Le compteur d'activité brut du processus reste
  dans la fiche d'alerte comme élément de preuve, mais ne fait plus office de gravité.
- **Cloisonnement par machine.** Chaque poste dispose de son propre extracteur de features et de sa
  propre baseline. Sans cela, le comportement normal d'un poste bureautique et celui d'un serveur de
  fichiers étaient moyennés dans la même référence.
- **Dernière fenêtre garantie.** Une fenêtre d'analyse ne se fermait qu'à l'arrivée d'un événement
  postérieur. Si un rançongiciel neutralise l'agent ou éteint le poste juste après son passage,
  aucun événement n'arrive plus — et c'est précisément cette fenêtre qui contient la preuve. Une
  tâche de fond évalue donc les fenêtres restées inactives, sans pour autant faire passer le poste
  silencieux pour actif.

Les exclusions sont par ailleurs réellement appliquées par le moteur, et non simplement stockées :
un événement portant sur un chemin exclu ne produit plus d'alerte, ce qui est vérifié
automatiquement.

---

## 8. Agents authentifiés

Les routes d'ingestion et la file de commandes exigent un token d'agent. Sans lui, n'importe quelle
machine du réseau pourrait injecter de faux événements pour fausser une baseline, ou dépiler l'ordre
d'arrêt qui la visait.

- `winlogbeat.yml` transmet le token et une identification stable de la machine.
- `agent_ps.ps1` récupère uniquement les commandes destinées à **sa** machine, exécute l'arrêt de
  processus, l'isolation ou la levée d'isolation, puis **acquitte** l'exécution.
- Une commande non acquittée au bout de 15 minutes expire, ce qui évite qu'un poste éteint au mauvais
  moment laisse un ordre en attente indéfiniment.

---

## 9. Déploiement conteneurisé

`docker compose up -d --build` démarre trois services :

| Service | Rôle |
|---------|------|
| `db` | PostgreSQL 16, données dans un volume nommé, sonde de disponibilité |
| `api` | FastAPI ; applique les migrations Alembic puis démarre, en utilisateur non privilégié |
| `web` | Compile la console React puis la sert avec nginx, origine unique pour `/`, `/api` et `/ws` |

Deux points ont un effet direct sur le fonctionnement :

- **Origine unique.** Le navigateur ne voit qu'un seul hôte, donc plus de CORS à ouvrir et le cookie
  de session fonctionne nativement, y compris pour les analystes distants. Le mode développement
  reproduit ce montage via le proxy de Vite, afin que le comportement soit identique.
- **Un seul worker pour l'API, volontairement.** Les extracteurs de features et les baselines sont
  des automates à état en mémoire de processus : répartir les événements d'une même machine sur
  plusieurs workers fausserait fenêtres et baselines. La consultation, elle, passe entièrement par
  PostgreSQL, donc le nombre de consoles connectées n'a aucune incidence sur la cohérence.

Le build de l'image de l'API a par ailleurs été ramené de **plus de quinze minutes à une minute** :
`requirements.txt` déclarait PyTorch, XGBoost et lxml — plus de 2,5 Go — alors qu'aucun fichier du
serveur ne les importe. Ces dépendances d'expérimentation sont désormais isolées dans
`requirements-research.txt`. Un `.dockerignore` empêche en outre `venv/` et `node_modules/` de
partir dans le contexte de build.

---

## 10. Vérification

Trois suites automatisées, exécutées **contre le déploiement conteneurisé complet** (donc à travers
nginx, avec l'API dans son conteneur) et non seulement en développement :

| Suite | Portée | Résultat |
|-------|--------|----------|
| `scripts/e2e_check.py` | 86 contrôles : authentification, habilitations, CRUD, ingestion, détection, réponse active, temps réel, audit, configuration | 86/86 |
| `scripts/ui_check.py` | 37 contrôles : parcours d'un navigateur à travers le proxy, cookie de session compris | 37/37 |
| `dashboard/tests/smoke.mjs` | Rendu des 11 onglets dans Chromium, échec sur la moindre erreur JavaScript | 11/11, console propre |

Contrôles les plus significatifs au regard des objectifs de la phase :

- deux analystes obtiennent des compteurs et des séries temporelles **identiques**, avec les mêmes
  bornes de graphique ;
- un compte N1 se voit refuser l'arrêt de processus, l'isolation, la liste des comptes et la
  création d'exclusion — et le refus est bien lié au rôle, non à un mot de passe en attente ;
- le cookie de session est **invisible de `document.cookie`** dans un vrai navigateur ;
- une écriture depuis l'interface **notifie immédiatement** les autres analystes ;
- l'adresse IP inscrite au journal d'audit est **déterminée par le serveur** ;
- l'historique importé de l'ancienne base SQLite est **retrouvé après migration** ;
- la dernière fenêtre d'une attaque est analysée **même quand l'agent cesse d'émettre**.

Ces suites sont rejouables à volonté, ce qui permet de les exécuter pendant la soutenance plutôt que
de reposer sur des captures d'écran.
