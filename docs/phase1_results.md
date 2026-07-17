# Phase 1 — Résultats : Environnement de Laboratoire & Configuration

**Date** : 5–11 juillet 2026  
**Responsable principal** : M1 (Pipeline & Connecteur)  
**Support** : M3 (API & Infrastructure)

---

## 1. Objectif de la Phase 1

Mettre en place l'environnement de travail complet pour le projet : un laboratoire
isolé composé d'une machine virtuelle Windows (la "victime"), des outils de surveillance
système (Sysmon + Winlogbeat), le dépôt de code collaboratif (GitHub), et un snapshot
de référence pour garantir la reproductibilité des tests.

---

## 2. Architecture du Laboratoire

```
┌─────────────────────────────────────┐
│          PC Hôte (Windows)          │
│                                     │
│  ┌───────────────────────────────┐  │
│  │   VMware — VM Windows 10     │  │
│  │                               │  │
│  │   Sysmon (surveillance)       │  │
│  │   Winlogbeat (collecte)       │  │
│  │                               │  │
│  │   Réseau : Host-Only          │  │
│  │   IP VM : 192.168.10.10      │  │
│  └───────────────────────────────┘  │
│                                     │
│   IP Hôte (VMnet1) : 192.168.10.2  │
│   Python 3.11 + venv                │
│   Dépôt Git : ransomware-detector   │
└─────────────────────────────────────┘
```

**Mode réseau Host-Only** : La VM ne peut communiquer qu'avec le PC hôte via le réseau
virtuel VMnet1. Elle n'a pas accès à Internet. Cela simule un environnement isolé
et sécurisé, typique d'un laboratoire de test de malware.

---

## 3. Composants installés

### 3.1 Machine Virtuelle

| Élément | Détail |
|---------|--------|
| Hyperviseur | VMware Workstation |
| Système d'exploitation | Windows 10 |
| Nom de la machine | DESKTOP-39R2AEI |
| Mode réseau | Host-Only (VMnet1) |
| Adresse IP de la VM | 192.168.10.10 |
| Adresse IP de l'hôte | 192.168.10.2 |

### 3.2 Sysmon (System Monitor)

| Élément | Détail |
|---------|--------|
| Éditeur | Microsoft Sysinternals |
| Rôle | Surveiller en temps réel toutes les actions système (création de fichiers, connexions réseau, lancement de processus) |
| Configuration | SwiftOnSecurity (template communautaire optimisé) |
| EventIDs surveillés | 1 (Process Create), 3 (Network Connection), 11 (File Create), 23 (File Delete) |

**Pourquoi Sysmon ?** Windows génère des journaux d'événements basiques, mais ils ne
contiennent pas assez de détails pour détecter un ransomware. Sysmon enrichit chaque
événement avec des informations précieuses : le chemin complet du processus, le hash
du fichier, le processus parent, le nom du fichier cible, etc.

### 3.3 Winlogbeat

| Élément | Détail |
|---------|--------|
| Éditeur | Elastic |
| Version | 8.18.3 |
| Rôle | Lire les événements Sysmon depuis le journal Windows et les écrire au format JSON (NDJSON) dans un fichier local |
| Fichier de sortie | `C:\ProgramData\winlogbeat\logs\winlogbeat-output-YYYYMMDD.ndjson` |
| Configuration | `C:\Program Files\Winlogbeat\winlogbeat.yml` |

**Pourquoi Winlogbeat ?** Sysmon écrit ses logs dans le journal d'événements Windows,
un format binaire difficile à lire par un script Python. Winlogbeat convertit ces
logs en JSON structuré, ce qui permet à notre pipeline d'analyse de les traiter facilement.

### 3.4 Dépôt de code

| Élément | Détail |
|---------|--------|
| Plateforme | GitHub |
| Langage principal | Python 3.11 |
| Framework API | FastAPI |
| Gestionnaire de dépendances | pip + requirements.txt |
| Environnement virtuel | venv |

---

## 4. Structure du projet initialisée

```
ransomware-detector/
├── agent/           # Scripts PowerShell pour la VM (forwarder, simulation)
├── parser/          # Parse et normalise les logs Sysmon
├── baseline/        # Calcule le comportement normal de référence
├── features/        # Extrait les features comportementales
├── detector/        # Moteur de règles + futurs modèles ML
├── api/             # FastAPI — endpoints d'ingestion et d'analyse
├── dashboard/       # Future interface web
├── data/            # Logs bruts, traités et synthétiques
├── docs/            # Documentation technique
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## 5. Snapshot de référence

Un snapshot VMware a été pris à la fin de la Phase 1, après avoir vérifié que :

- ✅ Sysmon est installé et génère des événements (EventID 1, 3, 11, 23)
- ✅ Winlogbeat est installé et écrit les logs au format JSON
- ✅ Le réseau Host-Only fonctionne (ping entre VM et hôte)
- ✅ L'environnement est propre (aucun malware, aucun fichier de test)

**Nom du snapshot** : `Clean-State-Phase1`

Ce snapshot permet de revenir à un état propre à tout moment pour refaire
des tests reproductibles.

---

## 6. Format des données Winlogbeat

Voici un exemple réel d'un événement Sysmon capturé par Winlogbeat (EventID 1 : Process Create) :

```json
{
  "@timestamp": "2026-07-06T14:06:09.012Z",
  "winlog": {
    "event_id": "1",
    "event_data": {
      "Image": "C:\\Program Files\\Winlogbeat\\winlogbeat.exe",
      "ProcessId": "1964",
      "ParentImage": "C:\\Windows\\System32\\services.exe",
      "CommandLine": "\"C:\\Program Files\\Winlogbeat\\winlogbeat.exe\" ...",
      "User": "AUTORITE NT\\Système"
    }
  },
  "host": {
    "name": "DESKTOP-39R2AEI"
  }
}
```

Ce format JSON structuré est le point d'entrée de tout notre pipeline d'analyse
(Phase 2).

---

## 7. Conclusion

L'environnement de laboratoire est entièrement opérationnel. La VM Windows avec
Sysmon et Winlogbeat fournit un flux continu de données système au format JSON,
prêt à être consommé par le pipeline d'analyse développé en Phase 2. 
