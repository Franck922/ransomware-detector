# Référence de l'API REST (FastAPI)

**Date de rédaction** : Juillet 2026  
**Dernière mise à jour** : 11 août 2026  
**Version de l'API** : 2.0.0

---

## 1. Introduction

L'API EDR centralise la télémétrie des endpoints, calcule les features comportementales, exécute les
moteurs de détection, maintient la file d'ordres destinée aux agents, et sert de source unique à la
console SOC.

En développement, l'API écoute sur `http://localhost:8000` et la documentation interactive est
disponible sur `/docs`. **En production, `/docs`, `/redoc` et `/openapi.json` sont désactivés** : ils
cartographient l'intégralité de la surface exposée, jusqu'aux routes d'agent, ce qui n'a pas à être
offert à un visiteur non authentifié.

Derrière le reverse proxy, toutes les routes sont préfixées par `/api`, et le WebSocket est joignable
sur `/ws` comme sur `/api/ws`.

### 1.1 Les trois modes d'authentification

| Mode | Mécanisme | Concerne |
|------|-----------|----------|
| **Session analyste** | Cookie `HttpOnly` déposé par `POST /auth/login` | Toutes les routes de la console |
| **Token d'agent** | En-tête `X-Agent-Token` (ou authentification basique pour Winlogbeat) | Ingestion et file de commandes |
| **Public** | Aucun | Sonde de santé, connexion, compatibilité Winlogbeat |

Les habilitations sont vérifiées **côté serveur sur chaque requête**. Un appel avec un compte
insuffisamment habilité reçoit `403`, indépendamment de ce que l'interface affiche.

`python -m scripts.list_routes` produit l'inventaire complet des routes avec la garde appliquée à
chacune, et signale toute route publique non justifiée.

### 1.2 Codes de réponse usuels

| Code | Signification |
|------|---------------|
| `401` | Session absente, expirée ou révoquée |
| `403` | Rôle insuffisant, ou rotation de mot de passe en attente (en-tête `X-Password-Change-Required`) |
| `409` | Conflit d'état (machine déjà isolée, exclusion en doublon) |
| `422` | Charge utile invalide (validation Pydantic) |

---

## 2. Authentification et comptes

### 2.1. Connexion (`POST /auth/login`) — public

```json
{ "email": "analyste@soc.edr.local", "password": "..." }
```

La réponse **ne contient aucun jeton** : la session est portée par un cookie `HttpOnly` + `SameSite`,
illisible par le JavaScript de la page. Il n'y a donc rien à voler dans `localStorage`.

```json
{
  "user": {
    "id": 4, "email": "analyste@soc.edr.local",
    "role": "N2", "role_label": "Analyste confirmé (N2)",
    "permissions": ["read", "kill", "isolate"],
    "must_change_password": false, "is_active": true,
    "last_login_at": "2026-08-11T14:02:11Z", "created_at": "2026-08-01T09:00:00Z"
  },
  "expires_at": "2026-08-12T02:02:11Z",
  "connected_analysts": 3
}
```

Après 5 échecs consécutifs, le compte est temporairement verrouillé. Le message d'erreur est
identique pour un compte inexistant et un mot de passe erroné, afin de ne pas révéler quels comptes
existent.

### 2.2. Session courante (`GET /auth/me`) — session

Même structure que ci-dessus. Utilisé au chargement de la console pour rétablir la session sans
stocker quoi que ce soit côté navigateur.

### 2.3. Déconnexion (`POST /auth/logout`) — session

Supprime la session **en base**. Rejouer le cookie ensuite renvoie `401` : la révocation est
effective côté serveur, et non un simple oubli côté client.

### 2.4. Changement de mot de passe (`POST /auth/change-password`) — session

```json
{ "current_password": "...", "new_password": "..." }
```

Tant qu'une rotation est exigée (`must_change_password`), c'est la **seule** route accessible : un
mot de passe défini par un administrateur ne donne accès à rien d'autre qu'à son propre changement.

### 2.5. Gestion des comptes — N3

| Méthode | Route | Effet |
|---------|-------|-------|
| `GET` | `/auth/users` | Liste des analystes |
| `POST` | `/auth/users` | Création (`email`, `password`, `role`, `full_name`) avec rotation imposée |
| `PATCH` | `/auth/users/{id}` | Modification du rôle, de l'activation ou du nom |
| `DELETE` | `/auth/users/{id}` | Désactivation, et révocation de ses sessions |

Il n'existe **aucune route d'inscription libre** : la console SOC n'est pas un service en
libre-service.

---

## 3. Consultation (N1 et au-delà)

### 3.1. Alertes (`GET /alerts`)

Paramètres : `status`, `machine_id`, `severity` (`low`, `medium`, `high`), `open_only`, `limit`
(≤ 500), `offset`.

```json
{
  "items": [
    {
      "id": 812,
      "detected_at": "2026-08-11T14:23:52Z",
      "machine_id": "VM-WIN10-LAB",
      "source": "RulesEngine",
      "severity": "high",
      "score": 92,
      "confidence": "HIGH",
      "pid": 6128, "process_name": "ransom.exe",
      "parent_name": "explorer.exe", "parent_pid": 1532,
      "reasons": ["231 fichiers créés", "Entropie élevée des noms de fichiers (5.678)"],
      "status": "new",
      "assigned_to_email": null,
      "payload": { "...": "fiche forensics complète" }
    }
  ],
  "total": 812, "limit": 50, "offset": 0
}
```

`score` est la gravité **normalisée sur 100** : le maximum entre le score heuristique et la
probabilité du modèle. Le compteur d'activité brut du processus figure dans `payload.activity_points`
comme élément de preuve, mais ne sert pas de niveau de gravité.

- `GET /alerts/{id}` — fiche forensics complète, avec le détail de la fenêtre incriminée.
- `POST /alerts/{id}/assign` — prise en charge par l'analyste courant, visible par toute l'équipe.
- `PATCH /alerts/{id}/status` — qualification (`{"status": "closed", "resolution_note": "..."}`).

### 3.2. Machines (`GET /machines`, `GET /machines/{machine_id}`)

Inventaire des postes : `status`, `is_isolated`, `first_seen_at`, `last_seen_at`, `events_received`,
`open_alerts`. Le dernier contact permet de distinguer un poste silencieux d'un poste sain.

### 3.3. Indicateurs partagés (`GET /metrics/overview`)

```json
{
  "generated_at": "2026-08-11T14:24:00Z",
  "machines_total": 2, "machines_online": 2, "machines_isolated": 0,
  "alerts_total": 812, "alerts_open": 20, "alerts_last_24h": 34,
  "alerts_critical_open": 20, "commands_pending": 4,
  "risk_score": 54, "risk_label": "Élevé",
  "ml_enabled": true, "baseline_trained_machines": 2,
  "events_last_hour": 4348, "connected_analysts": 3
}
```

Tous ces chiffres sont **calculés par le serveur**. C'est ce qui garantit que deux analystes voient
la même chose : rien n'est dérivé dans le navigateur.

### 3.4. Série temporelle (`GET /metrics/timeseries`)

Paramètres : `window_minutes` (défaut 15, ≤ 1440), `bucket_seconds` (défaut 10, ≤ 3600),
`machine_id` optionnel pour isoler un poste.

```json
{
  "window_minutes": 60, "bucket_seconds": 30, "machine_id": null,
  "points": [
    {
      "bucket": "2026-08-11T14:23:30Z",
      "files_created": 231, "files_deleted": 0, "files_renamed": 0,
      "entropy_max": 5.68, "entropy_avg": 4.12,
      "processes_created": 1, "connections": 1, "external_connections": 1,
      "alerts": 1
    }
  ]
}
```

Les bornes sont alignées sur une origine fixe (`date_bin`), et non sur l'instant de la requête : deux
analystes obtiennent donc exactement les mêmes barres, ce qui serait impossible avec un découpage
calculé côté client.

### 3.5. Autres lectures

| Route | Contenu |
|-------|---------|
| `GET /metrics/ml-insights` | Caractéristiques réelles du modèle chargé (importance des variables) |
| `GET /response/commands` | Journal des réponses actives, avec origine et accusés de réception |
| `GET /audit`, `GET /audit/actions` | Journal d'audit paginé (`action`, `actor`, `hours`), en lecture seule |
| `GET /exclusions` | Règles de confiance en vigueur |
| `GET /settings` | Configuration effective (seuils, rétention) |
| `GET /presence` | Analystes actuellement connectés au canal temps réel |
| `GET /status` | Sonde publique : état, version, base, ML, commandes en attente |

---

## 4. Actions privilégiées

### 4.1. Arrêt d'un processus (`POST /response/kill`) — N2

```json
{ "machine_id": "VM-WIN10-LAB", "pid": 6128, "alert_id": 812, "reason": "Chiffrement en cours" }
```

La commande est créée pour **cette machine** et devra être acquittée. La version précédente exposait
`POST /response/kill/{pid}` sans destinataire : l'ordre partait vers la première machine qui
interrogeait l'API, éventuellement la mauvaise.

### 4.2. Isolation et levée (`POST /response/isolate`, `POST /response/unisolate`) — N2

```json
{ "machine_id": "VM-WIN10-LAB", "reason": "Propagation suspectée" }
```

Une double isolation renvoie `409`. L'agent conserve une exception pour joindre l'API, sans quoi le
poste isolé deviendrait impossible à désisoler à distance.

### 4.3. Exclusions — N3

| Méthode | Route | Effet |
|---------|-------|-------|
| `POST` | `/exclusions` | `{"type": "Folder\|Process\|Extension", "path": "...", "comment": "..."}` |
| `PATCH` | `/exclusions/{id}/toggle` | Activation ou désactivation sans suppression |
| `DELETE` | `/exclusions/{id}` | Suppression |

Les exclusions sont **réellement appliquées par le moteur** : un événement portant sur un chemin
exclu ne produit plus d'alerte, ce qui est vérifié automatiquement.

### 4.4. Configuration (`PUT /settings/{key}`) — N3

Modifie une valeur persistée (seuils de détection, rétention, notifications). Une clé inconnue est
rejetée en `400`, afin qu'une faute de frappe ne crée pas un réglage fantôme sans effet.

---

## 5. Interface des agents (token requis)

### 5.1. Ingestion (`POST /ingest`)

```json
{
  "machine_id": "VM-WIN10-LAB",
  "batch": [
    {
      "event_id": 11,
      "timestamp": "2026-08-11T14:23:42.123Z",
      "process_name": "ransom.exe", "process_id": 6128,
      "process_path": "C:\\Users\\franc\\AppData\\Local\\Temp\\ransom.exe",
      "parent_process": "explorer.exe", "parent_process_id": 1532,
      "target_file": "C:\\Users\\franc\\Documents\\rapport.docx.encrypted",
      "action": "file_create",
      "network_ip": null, "network_port": null
    }
  ]
}
```

```json
{ "status": "success", "message": "Batch ingéré et traité", "processed_events": 1 }
```

Les événements sont routés vers le pipeline **de cette machine** : chaque poste dispose de son propre
extracteur de features et de sa propre baseline.

### 5.2. Récupération d'un ordre (`GET /agent/commands?machine_id=...`)

Retourne la commande en attente **la plus ancienne destinée à cette machine**, et la passe en `sent`
sans la détruire : elle reste visible dans le journal des réponses.

```json
{ "action": "NONE" }
```

```json
{
  "command_id": 42,
  "action": "KILL",
  "target": 6128,
  "pid": 6128,
  "machine_id": "VM-WIN10-LAB",
  "payload": {
    "action": "KILL", "machine_id": "VM-WIN10-LAB",
    "pid": 6128, "process": "ransom.exe",
    "parent": "explorer.exe", "parent_pid": 1532,
    "score": 92, "confidence": "HIGH",
    "detection_source": "RulesEngine",
    "rules_score": 92, "ml_probability": 0.9993,
    "activity_points": 241,
    "stats": {
      "files_created": 231, "files_deleted": 0,
      "network_connections": 1, "processes_created": 1, "entropy": 5.678
    },
    "reasons": ["231 fichiers créés", "Entropie élevée des noms de fichiers (5.678)"]
  }
}
```

### 5.3. Acquittement (`POST /agent/commands/ack`)

```json
{ "command_id": 42, "success": true, "message": "Process 6128 terminated" }
```

Le résultat est journalisé et diffusé aux consoles. Une commande non acquittée au bout de 15 minutes
passe en `expired`, afin qu'un poste éteint au mauvais moment ne laisse pas un ordre en attente
indéfiniment.

---

## 6. Canal temps réel (`WEBSOCKET /ws`)

Authentifié par le cookie de session : une connexion anonyme est fermée avant l'acceptation du
handshake (code `1008`). À l'ouverture, le serveur annonce les canaux disponibles :

```json
{ "type": "hello", "channels": ["alerts", "metrics", "machines", "commands", "audit", "exclusions"] }
```

Puis il diffuse des **avis d'invalidation**, sans aucune donnée métier :

```json
{ "type": "invalidate", "channel": "alerts", "at": "2026-08-11T14:23:52.187Z" }
```

Chaque console relit ensuite l'API sur le canal concerné, avec ses propres droits. Ce choix évite
qu'un message perdu ou réordonné laisse un poste avec un état divergent, et garantit que les
habilitations sont réévaluées à chaque lecture. Un heartbeat applicatif circule toutes les 25
secondes ; en cas de coupure, la console le signale et bascule sur un rafraîchissement périodique.

---

## 7. Compatibilité native Elasticsearch (simulation Winlogbeat)

Pour éviter de déployer un traducteur intermédiaire sur les postes surveillés, l'API simule les
endpoints fondamentaux d'Elasticsearch 8, auxquels Winlogbeat s'attend.

### 7.1. Route racine (`GET /`) — public
Simule la réponse d'un cluster opérationnel (`version.number: 8.0.0`, `cluster_name`, etc.).

### 7.2. Licence et X-Pack (`GET /_license`, `GET /_xpack`) — public
Déclarent une licence `basic` active, sans quoi Winlogbeat s'arrête au démarrage.

```json
{ "license": { "status": "active", "type": "basic" } }
```

### 7.3. Ingestion en masse (`POST /_bulk`) — token requis
Point névralgique de la compatibilité. Winlogbeat y pousse des lots NDJSON compressés en GZIP
(décompressés à la volée), alternant une ligne d'action d'indexation et une ligne de document.

```json
{ "errors": false, "items": [ { "create": { "status": 201 } } ] }
```

Contrairement aux routes de compatibilité ci-dessus, celle-ci **exige le token d'agent** : sans lui,
n'importe quelle machine du réseau pourrait injecter de faux événements pour fausser une baseline.

### 7.4. Routes attrape-tout (`ANY /_{path_name}`) — public
Répondent `{"acknowledged": true}` aux vérifications annexes de Winlogbeat (templates ILM, pipelines,
routage). Elles ne consultent ni ne modifient aucune donnée.
