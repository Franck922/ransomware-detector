# Rapport de Projet de Substitution de Stage
**Sujet :** Conception et Développement d'un Détecteur Hybride de Ransomware (Heuristique et Machine Learning)

---

## 1. Introduction et Architecture Globale

### 1.1 Contexte
Les ransomwares (logiciels rançonneurs) constituent aujourd'hui l'une des menaces les plus critiques pour les systèmes d'information. Les solutions antivirales classiques, basées sur des signatures statiques, sont souvent contournées par les nouvelles variantes.
Ce projet propose une approche de **détection comportementale** et **hybride**, analysant à la fois les événements du système d'exploitation et le trafic réseau pour repérer l'activité malveillante en temps réel.

### 1.2 Architecture de la Solution
Notre solution s'articule autour de cinq briques principales :
1. **Agent de Collecte (Machine Surveillée)** : Utilisation de Sysmon et Winlogbeat pour capturer les événements de la machine cible (créations de fichiers, processus, connexions réseau).
2. **API de Réception (Serveur d'Analyse)** : Un serveur FastAPI qui reçoit les logs des agents en continu, chaque agent devant s'authentifier par un token.
3. **Moteur d'Extraction de Features (Feature Engineering)** : Un module qui convertit les logs bruts en vecteurs mathématiques (fenêtres de 10 secondes) décrivant le comportement de la machine. Chaque poste surveillé dispose de son propre extracteur et de sa propre référence statistique.
4. **Moteurs de Détection** :
   - *Couche 1 (Heuristique)* : Un moteur de règles strictes (ex: alerte si le système crée plus de 10 fichiers avec une entropie > 5.0 en moins de 10 secondes).
   - *Couche 2 (Machine Learning)* : Un modèle Random Forest capable de déceler des motifs complexes (Pattern Recognition) combinant réseau et système.
5. **Plateforme de Supervision (Console SOC)** : Une base PostgreSQL partagée, une authentification par comptes et niveaux d'habilitation, et une synchronisation temps réel qui permet à plusieurs analystes distants de travailler sur les mêmes données.

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

- **Random Forest (Forêt Aléatoire)** : Avec 100 arbres de décision, ce modèle a identifié que les caractéristiques les plus révélatrices d'une attaque sont la profondeur d'arborescence des processus (`process_depth`, 20 %), le volume de fichiers créés (18 %), puis à égalité la diversité des extensions, le renommage de fichiers et l'entropie des noms (15 % chacun). Il est notable que ce ne soit pas le volume de chiffrement qui distingue le mieux une attaque, mais la manière dont le processus a été lancé. Les trois caractéristiques réseau ressortent en revanche à une importance nulle : notre dataset synthétique ne contient pas d'activité réseau discriminante, et le modèle ne s'en sert donc pas — ce que le moteur heuristique compense en continuant de les pondérer.
- **LSTM (Long Short-Term Memory)** : Réseau de neurones profond (Deep Learning) conçu pour traiter des séries temporelles. Contrairement au Random Forest, le LSTM possède une "mémoire" lui permettant de comprendre la *chronologie* de l'attaque (ex: *D'abord* une connexion réseau suspecte, *Puis* une création de processus, *Ensuite* du chiffrement).

Les deux modèles ont atteint un F1-Score parfait (1.00) sur notre dataset de test, prouvant l'efficacité de notre pipeline d'extraction de *features*.

**Modèle retenu pour la production : le Random Forest.** Ce choix mérite d'être justifié, puisque le LSTM était théoriquement mieux armé pour la chronologie. Dans notre pipeline, le modèle ne reçoit jamais la séquence brute des événements, mais un vecteur de 12 features déjà agrégé sur 10 secondes : la chronologie fine que le LSTM sait exploiter est donc précisément ce que l'agrégation a effacé en amont. À performances égales sur le jeu de test, il imposait en outre PyTorch au serveur, soit plus de 2,5 Go de dépendances. Nous avons préféré une inférence légère et explicable, dont l'importance des variables est directement lisible par un analyste.

---

## 5. Moteur de Réponse Active & Forensics (Phase 5)

Afin de passer d'un système de détection simple à une solution de riposte automatisée, nous avons développé en Phase 5 un moteur de réponse active (Response Engine).

### 5.1 L'Agent de Riposte PowerShell
Un agent scripté en PowerShell tourne en boucle infinie (avec un polling HTTP toutes les 2 secondes) sur la machine surveillée.
* **KILL chirurgical par PID** : Dès qu'une menace dépasse un score de 80 points (score heuristique ou de Machine Learning), l'API FastAPI expose un ordre de blocage pour l'agent. Celui-ci extrait le PID (identifiant de processus) responsable du chiffrement suspect et exécute la commande `Stop-Process -Id <PID> -Force` localement.
* **Isolation Réseau** : Si la menace est critique, l'agent reconfigure en temps réel le Pare-feu de Windows pour couper toutes les communications réseau entrantes et sortantes de la VM, à l'exception unique des requêtes vers le serveur API de l'EDR.

### 5.2 Rapports Forensics JSON
À chaque blocage de processus malveillant, un fichier diagnostic structuré en JSON est généré et stocké dans le répertoire `reports/` de l'hôte. Ce fichier contient l'intégralité de la télémétrie capturée dans les 10 secondes ayant précédé l'attaque, facilitant l'analyse post-mortem de l'incident par un analyste SOC.

---

## 6. Console SOC Multi-Analystes et Base Partagée (Phase 6)

La Phase 6 a transformé la console EDR, initialement conçue pour un poste unique, en une plateforme de supervision utilisable simultanément par plusieurs analystes distants.

### 6.1 L'exigence de départ et ce qu'elle a révélé

L'exigence formulée était simple en apparence : *plusieurs analystes SOC doivent voir les mêmes données au même instant sur le tableau de bord*. La confronter à l'implémentation existante a révélé des limites structurelles, et non de simples réglages :

* **SQLite verrouille la base entière à chaque écriture.** Le moteur ne tolère qu'un seul écrivain à la fois. L'ingestion continue des agents et la consultation par les analystes se bloquaient donc mutuellement.
* **L'état de détection vivait en mémoire du processus** (fenêtres, baseline, file de commandes). Tout redémarrage effaçait l'apprentissage, et deux processus API auraient vu deux réalités différentes.
* **L'authentification était décidée par le navigateur.** Le rôle de l'analyste était conservé côté client : le modifier dans le navigateur, ou appeler l'API sans passer par l'interface, suffisait à obtenir les droits d'un SOC Manager.
* **Le journal d'audit était alimenté par le client.** L'auteur et l'adresse IP d'une action étaient fournis par l'appelant, ce qui permettait d'écrire une entrée au nom d'un autre analyste — et ôtait donc au registre toute valeur probante.
* **Le score de gravité n'était pas borné.** Des alertes affichaient 146 ou 241 sur une échelle présentée comme /100, parce que la gravité était en réalité le compteur d'activité du processus. Un serveur de fichiers légitime devenait ainsi « critique » par simple volume.
* **La file de commandes n'avait pas de destinataire.** La première machine à interroger l'API récupérait l'ordre d'arrêt destiné à une autre, sans trace ni accusé de réception.

### 6.2 Persistance partagée (PostgreSQL)

La base a été migrée vers **PostgreSQL 16**, avec neuf tables versionnées par Alembic : `users`, `sessions`, `machines`, `alerts`, `metrics`, `commands`, `exclusions`, `audit_logs`, `app_settings`. Un script de reprise importe l'ancienne base SQLite sans perte d'historique.

Trois propriétés justifient ce choix :
* les **écritures concurrentes** ne se bloquent plus, ce qui rend l'ingestion continue compatible avec la consultation ;
* l'**agrégation temporelle est déterministe** : les points du graphique sont calculés par le serveur sur des bornes alignées sur une origine fixe (`date_bin`), donc deux analystes obtiennent exactement les mêmes barres, et non deux découpages calculés chacun depuis son propre « maintenant » ;
* les **contraintes d'intégrité** (unicité, clés étrangères, transactions) garantissent des invariants que du code applicatif devait sinon maintenir à la main.

Aucun indicateur affiché n'est calculé dans le navigateur : score de risque, compteurs et séries temporelles proviennent tous de requêtes SQL.

### 6.3 Sécurité, Authentification & Gestion des Analystes

* **Hachage argon2id** (`argon2-cffi`), algorithme conçu pour les mots de passe, à coût mémoire et temporel paramétrable. SHA-256, utilisé précédemment, est volontairement rapide : cette rapidité même le rend inadapté, car elle profite à l'attaquant qui teste des milliards de combinaisons.
* **Session serveur en cookie `HttpOnly`** : le JavaScript de la page ne peut pas lire le cookie, donc une faille de type XSS ne permet pas de voler la session d'un analyste. Aucun jeton n'est déposé dans `localStorage`. La déconnexion supprime la session en base, si bien que rejouer le cookie ensuite échoue.
* **Protection contre le bruteforce** : verrouillage après 5 échecs consécutifs, avec un message d'erreur identique pour un compte inexistant et un mot de passe erroné — la page de connexion ne révèle donc pas quels comptes existent.
* **Enrôlement contrôlé** : l'inscription libre a été supprimée. La création de compte relève du SOC Manager, et le mot de passe qu'il définit ne donne accès à rien d'autre qu'à son propre changement.
* **Habilitations appliquées côté serveur** sur chaque route (N1 : consultation et qualification / N2 : arrêt de processus et isolation / N3 : comptes, exclusions, configuration). L'interface masque les actions inaccessibles, mais la protection réelle est le refus du serveur : un appel direct à `POST /response/kill` avec un compte N1 reçoit un 403.
* **Traçabilité opposable** : l'auteur et l'adresse IP source de chaque action sont déterminés par le serveur, jamais acceptés de l'appelant. Les réponses actives déclenchées automatiquement par le moteur sont auditées comme des actions d'analyste.
* **Agents authentifiés par token** : sans lui, n'importe quelle machine du réseau pourrait injecter de faux événements pour fausser une référence statistique, ou dépiler l'ordre d'arrêt qui la visait.

### 6.4 Synchronisation temps réel

Le sondage périodique a été remplacé par un **WebSocket authentifié** qui diffuse des avis d'invalidation par canal (`alerts`, `metrics`, `machines`, `commands`, `audit`, `exclusions`). Le message ne transporte aucune donnée métier : il signale qu'un canal a changé, et chaque console relit l'API.

Ce choix est délibéré. Diffuser les données elles-mêmes aurait exposé à deux problèmes : un message perdu ou réordonné aurait laissé une console avec un état divergent, et il aurait fallu filtrer le contenu selon les droits de chaque destinataire. En ne diffusant qu'un avis, la vérité reste toujours relue en base et les habilitations sont réévaluées à chaque lecture. Si le canal tombe, l'interface le signale explicitement et bascule sur un rafraîchissement périodique, plutôt que d'afficher silencieusement des données figées.

### 6.5 Architecture Web (React & Recharts)

Développée avec React, Vite et Tailwind CSS, l'interface SOC propose un design professionnel et une navigation fluide à travers **onze onglets** : vue d'ensemble, terminaux, alertes, journal des réponses, statistiques ML, moteur heuristique, exclusions, journal d'audit, équipe SOC, configuration et documentation embarquée. S'y ajoutent deux vues de détail, atteintes en cliquant sur une ligne : la fiche forensics d'une alerte et la fiche d'un terminal.

L'application monolithique initiale a été découpée en contextes (session, temps réel), un client d'API unique et un hook de lecture réutilisable. Aucune donnée n'est simulée, et l'onglet du moteur heuristique lit les seuils réellement en vigueur depuis la configuration, au lieu de recopier des valeurs dans le code de la page où elles auraient dérivé silencieusement.

### 6.6 Corrections apportées au moteur de détection

* **Score borné et explicable** : la gravité est le maximum entre le score heuristique normalisé et la probabilité du modèle, sur 0–100. Le compteur d'activité brut reste dans la fiche d'alerte comme élément de preuve, dissocié du niveau de gravité.
* **Cloisonnement par machine** : chaque poste possède son extracteur de features et sa référence statistique, sans quoi le comportement d'un poste bureautique et celui d'un serveur de fichiers étaient moyennés dans la même référence.
* **Dernière fenêtre garantie** : une fenêtre ne se fermait qu'à l'arrivée d'un événement postérieur. Si un rançongiciel neutralise l'agent ou éteint le poste juste après son passage, aucun événement n'arrive plus — et c'est précisément cette fenêtre qui contient la preuve. Une tâche de fond évalue donc les fenêtres restées inactives.
* **Exclusions réellement appliquées** par le moteur, et non simplement stockées en base.

### 6.7 Vérification automatisée

Trois suites de contrôles ont été développées et exécutées **contre le déploiement conteneurisé complet**, donc à travers le reverse proxy et non seulement en environnement de développement :

| Suite | Portée | Résultat |
|-------|--------|----------|
| `scripts/e2e_check.py` | 86 contrôles : authentification, habilitations, CRUD, ingestion, détection, réponse active, temps réel, audit, configuration | 86/86 |
| `scripts/ui_check.py` | 37 contrôles : parcours d'un navigateur à travers le proxy, cookie de session compris | 37/37 |
| `dashboard/tests/smoke.mjs` | Rendu des 11 onglets dans Chromium, échec sur la moindre erreur JavaScript | 11/11 |

Ces suites vérifient notamment que deux analystes obtiennent des chiffres identiques, qu'un compte N1 ne peut pas déclencher d'arrêt de processus, que le cookie de session est invisible du JavaScript dans un vrai navigateur, et que la dernière fenêtre d'une attaque est analysée même lorsque l'agent cesse d'émettre. Étant rejouables, elles peuvent être exécutées en direct pendant la soutenance.

---

## 7. Guide de Déploiement et d'Utilisation

1. **Configurer les secrets :**
   Copier `.env.example` en `.env`, puis remplacer les valeurs `CHANGE_ME` : mot de passe PostgreSQL, secret de session, token d'agent et mot de passe du compte d'amorçage. Ce dernier crée le premier SOC Manager, et sa rotation est imposée à la première connexion puisqu'il a transité par un fichier.
2. **Démarrer le serveur EDR :**
   `docker compose up -d --build` lance PostgreSQL, l'API (qui applique elle-même les migrations) et le reverse proxy. La console est accessible sur `http://<ip-du-serveur>:8080` depuis n'importe quel poste du réseau, sans installer Python ni Node.js sur le serveur.
3. **Créer les comptes analystes :**
   Se connecter avec le compte d'amorçage, changer le mot de passe imposé, puis déclarer les analystes depuis l'onglet **Équipe SOC** en leur attribuant le niveau adéquat (N1, N2 ou N3).
4. **Lancer la collecte (Agent) :**
   Sur chaque machine Windows surveillée, s'assurer que Sysmon est installé, renseigner le token d'agent dans `winlogbeat.yml`, puis démarrer `.\agent_ps.ps1` en administrateur. Le poste apparaît dans l'onglet **Terminaux** en phase d'apprentissage, puis bascule en mode détection après une centaine de secondes d'observation.
5. **Attaque & Riposte :**
   Exécuter `.\simulate_ransomware_v2.ps1` sur la VM cible. L'alerte apparaît en moins d'une seconde sur **toutes** les consoles connectées, la commande d'arrêt passe de `pending` à `acked` dans le journal des réponses, et le processus de chiffrement est terminé.
6. **Investigation Forensic :**
   Ouvrir la fiche d'une alerte pour consulter le détail de la fenêtre incriminée, l'arbre de causalité du processus et le rapport JSON archivé. Les onglets **Exclusions** et **Configuration** permettent d'ajuster les dossiers de confiance et les seuils de déclenchement ; chaque modification est tracée nominativement dans le journal d'audit.
7. **En cas de perte des accès administrateur :**
   Le script `python -m scripts.manage` permet, depuis le serveur, de lister les comptes, d'en créer un, de réinitialiser un mot de passe, de déverrouiller un compte ou de révoquer ses sessions.

> **Avant toute exposition hors laboratoire**, passer `APP_ENV=production` et `COOKIE_SECURE=true` derrière une terminaison TLS. L'API refuse de démarrer en production si un secret est resté à sa valeur de développement.

---

## 8. Équipe Projet
* **Membres du groupe :** Franck & Groupe de projet ECE Paris
* **Encadreur de projet :** Enseignant de substitution de stage / ECE Paris Fall 2026
