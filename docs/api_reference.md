# Référence de l'API REST (FastAPI)

**Date de rédaction** : Juillet 2026  
**Dernière mise à jour** : 22 juillet 2026  
**Version de l'API** : 1.0.0

---

## 1. Introduction

L'API EDR centralisée est conçue avec **FastAPI**. Elle fait office de "cerveau" pour notre système en centralisant la télémétrie des endpoints, en calculant les features comportementales, en exécutant les modèles de détection, et en maintenant une file d'attente d'ordres pour l'Agent de Réponse Active.

Par défaut, en local, l'API est accessible à l'adresse : `http://localhost:8000`.  
La documentation interactive générée automatiquement (Swagger UI) est disponible à l'adresse : `http://localhost:8000/docs`.

---

## 2. Endpoints Standard de l'API

### 2.1. Ingestion de Télémétrie (`POST /ingest`)
Permet d'envoyer manuellement un lot d'événements Sysmon normalisés à l'API.

- **Requête :**
  ```json
  {
    "machine_id": "VM-WIN10-LAB",
    "batch": [
      {
        "event_id": 11,
        "timestamp": "2026-07-22T14:41:42.123Z",
        "process_name": "powershell.exe",
        "process_id": 6128,
        "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_process": "explorer.exe",
        "parent_process_id": 1532,
        "target_file": "C:\\Users\\franc\\AppData\\Local\\Temp\\Simulation_Ransomware\\random.exe",
        "action": "file_create",
        "network_ip": null,
        "network_port": null
      }
    ]
  }
  ```

- **Réponse (Succès - 200 OK) :**
  ```json
  {
    "status": "success",
    "message": "Batch ingéré et traité par le pipeline complet",
    "processed_events": 1
  }
  ```

---

### 2.2. Analyse de Vecteurs (`POST /analyze`)
Permet de tester directement un vecteur de 12 features pour évaluer la décision du système expert (Rules Engine + Random Forest).

- **Requête :**
  ```json
  {
    "nb_files_created": 250,
    "nb_files_deleted": 0,
    "nb_files_renamed": 0,
    "nb_unique_extensions": 1,
    "entropy_filenames": 5.67,
    "nb_processes_created": 1,
    "nb_child_processes": 1,
    "process_depth": 2,
    "nb_connections": 0,
    "nb_unique_ips": 0,
    "nb_external_connections": 0,
    "nb_dns_queries": 0
  }
  ```

- **Réponse (200 OK) :**
  ```json
  {
    "alert": true,
    "source": "RulesEngine",
    "rules_details": {
      "alert": true,
      "score": 0.9,
      "triggered_rules": [
        "Création massive de fichiers (>250 en 10s) (+30pts)",
        "Entropie suspecte détectée (5.67 > 5.0) (+40pts)",
        "Processus enfant suspect avec activité fichier (+20pts)"
      ]
    }
  }
  ```

---

### 2.3. Récupération des Commandes Agent (`GET /agent/commands`)
Route de type "boîte aux lettres" interrogée par l'Agent PowerShell toutes les 2 secondes (Polling). L'API dépile la commande la plus ancienne de sa file d'attente.

- **Réponse s'il n'y a aucun ordre en attente (200 OK) :**
  ```json
  {
    "action": "NONE"
  }
  ```

- **Réponse s'il y a un ordre de blocage (200 OK) :**
  ```json
  {
    "action": "KILL",
    "pid": 6128,
    "process": "powershell.exe",
    "parent": "explorer.exe",
    "parent_pid": 1532,
    "score": 241,
    "confidence": "HIGH",
    "stats": {
      "files_created": 231,
      "files_deleted": 0,
      "network_connections": 0,
      "processes_created": 1,
      "entropy": 5.678
    },
    "reasons": [
      "231 file creations",
      "High entropy (5.678)"
    ]
  }
  ```

---

### 2.4. Déclenchement d'un Ordre de Mort Manuel (`POST /response/kill/{pid}`)
Permet à un analyste SOC (depuis le futur Dashboard) d'ordonner manuellement le meurtre d'un processus spécifique par son PID.

- **URL Paramètre :** `pid` (int) - Identifiant du processus à stopper.
- **Réponse (200 OK) :**
  ```json
  {
    "message": "Ordre de KILL pour le PID 6128 envoyé à l'agent."
  }
  ```

---

### 2.5. Déclenchement d'une Isolation Manuelle (`POST /response/isolate`)
Permet à un analyste SOC d'ordonner manuellement le confinement réseau de la machine compromise.

- **Réponse (200 OK) :**
  ```json
  {
    "message": "Ordre d'isolation réseau envoyé à l'agent."
  }
  ```

---

### 2.6. Historique des Alertes (`GET /alerts`)
Retourne l'ensemble des alertes détectées depuis le démarrage de l'API.

- **Réponse (200 OK) :**
  ```json
  {
    "alerts": [
      {
        "timestamp": "now",
        "source": "RulesEngine",
        "kill_payload": {
          "action": "KILL",
          "pid": 6128,
          "process": "powershell.exe",
          "parent": "explorer.exe",
          "parent_pid": 1532,
          "score": 241,
          "confidence": "HIGH",
          "stats": {
            "files_created": 231,
            "files_deleted": 0,
            "network_connections": 0,
            "processes_created": 1,
            "entropy": 5.678
          },
          "reasons": [
            "231 file creations",
            "High entropy (5.678)"
          ]
        }
      }
    ]
  }
  ```

---

### 2.7. Statut du Serveur (`GET /status`)
Retourne le statut opérationnel de l'API, si le modèle ML a été importé et si la phase d'apprentissage de la Baseline est terminée.

- **Réponse (200 OK) :**
  ```json
  {
    "status": "online",
    "ml_enabled": true,
    "baseline_trained": true,
    "pending_commands_count": 0
  }
  ```

---

## 3. Compatibilité Native Elasticsearch (Winlogbeat API Simulation)

Pour éviter de devoir déployer un script python intermédiaire sur la VM Windows pour traduire les logs, notre API FastAPI simule en réalité les endpoints fondamentaux de la suite Elastic (Elasticsearch v8).

Winlogbeat envoie des requêtes d'initialisation et d'ingestion massive. L'API y répond avec des structures JSON identiques à celles de la base de données Elasticsearch afin de tromper l'agent Winlogbeat.

### 3.1. Route Racine de Vérification (`GET /`)
Simule la réponse d'un cluster Elasticsearch opérationnel.
- **Réponse (200 OK) :**
  ```json
  {
    "name" : "ransomware-detector",
    "cluster_name" : "ransomware-detector",
    "cluster_uuid" : "123456789",
    "version" : {
      "number" : "8.0.0",
      "build_flavor" : "default",
      "build_type" : "tar",
      "build_hash" : "12345",
      "build_date" : "2026-01-01T00:00:00.000Z",
      "build_snapshot" : false,
      "lucene_version" : "9.0.0",
      "minimum_wire_compatibility_version" : "7.17.0",
      "minimum_index_compatibility_version" : "7.0.0"
    },
    "tagline" : "You Know, for Search"
  }
  ```

### 3.2. Licences et X-Pack (`GET /_license` et `GET /_xpack`)
Permet de valider la présence d'une licence de base active pour éviter que Winlogbeat ne s'arrête.
- **Réponse `/_license` :**
  ```json
  {
    "license": {
      "status": "active",
      "type": "basic"
    }
  }
  ```

### 3.3. Ingestion en Bulk (`POST /_bulk`)
Le point névralgique de la compatibilité. Winlogbeat y pousse des lots d'événements compressés en GZIP (décompressés à la volée par l'API) au format NDJSON (une ligne d'action d'indexation, une ligne de document).

- **Réponse (200 OK) :**
  ```json
  {
    "errors": false,
    "items": [
      {
        "create": {
          "status": 201
        }
      }
    ]
  }
  ```

### 3.4. Routes Attrape-Tout (`ANY /{path_name}`)
Répond positivement (`{"acknowledged": true}`) à toutes les vérifications annexes effectuées par Winlogbeat (Index Lifecycle Management templates, pipelines, routing, etc.) pour éviter les blocages de l'agent.
