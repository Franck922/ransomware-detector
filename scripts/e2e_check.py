"""
Vérification de bout en bout de la plateforme EDR.

Couvre les garanties qui manquaient à l'implémentation précédente :
  1. authentification réelle (mauvais mot de passe refusé, verrouillage) ;
  2. rotation de mot de passe imposée aux comptes importés ;
  3. RBAC appliqué côté serveur (un N1 ne peut pas déclencher un KILL) ;
  4. endpoints d'ingestion fermés sans token d'agent ;
  5. détection -> alerte -> commande, entièrement persistée ;
  6. graphique alimenté par la base et identique pour deux analystes ;
  7. diffusion temps réel reçue par un dashboard connecté ;
  8. audit écrit par le serveur, non falsifiable par le client.

Usage : python -m scripts.e2e_check [--base-url http://127.0.0.1:8000]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import string
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import httpx
import websockets

PASSED: List[str] = []
FAILED: List[str] = []

E2E_ADMIN_EMAIL = "e2e.admin@soc.edr.local"
E2E_LEGACY_PASSWORD = "admin123"


def provision_test_admin() -> None:
    """
    (Ré)initialise un compte N3 dédié au test, avec un hachage SHA-256 « legacy »
    et une rotation de mot de passe en attente. Le test est ainsi rejouable et
    couvre le chemin de migration des comptes importés de SQLite.
    """
    import hashlib

    from sqlalchemy import create_engine, delete, func, select
    from sqlalchemy.orm import Session as OrmSession

    from api.config import settings
    from api.models import Role, Session as SessionModel, User

    engine = create_engine(settings.sync_database_url)
    with OrmSession(engine) as db:
        user = db.scalar(select(User).where(func.lower(User.email) == E2E_ADMIN_EMAIL))
        if user is None:
            user = User(email=E2E_ADMIN_EMAIL)
            db.add(user)

        user.password_hash = hashlib.sha256(E2E_LEGACY_PASSWORD.encode()).hexdigest()
        user.hash_algo = "sha256-legacy"
        user.role = Role.N3.value
        user.full_name = "Compte de vérification e2e"
        user.is_active = True
        user.must_change_password = True
        user.failed_login_count = 0
        user.locked_until = None
        db.flush()

        db.execute(delete(SessionModel).where(SessionModel.user_id == user.id))
        db.commit()


def read_hash_algo(email: str) -> str:
    from sqlalchemy import create_engine, func, select
    from sqlalchemy.orm import Session as OrmSession

    from api.config import settings
    from api.models import User

    with OrmSession(create_engine(settings.sync_database_url)) as db:
        return (
            db.scalar(select(User.hash_algo).where(func.lower(User.email) == email.lower())) or "?"
        )


def cleanup_test_accounts(emails: List[str]) -> None:
    from sqlalchemy import create_engine, func, select
    from sqlalchemy.orm import Session as OrmSession

    from api.config import settings
    from api.models import User

    with OrmSession(create_engine(settings.sync_database_url)) as db:
        for email in emails:
            user = db.scalar(select(User).where(func.lower(User.email) == email.lower()))
            if user is not None:
                db.delete(user)
        db.commit()


def check(label: str, condition: bool, detail: str = "") -> bool:
    if condition:
        PASSED.append(label)
        print(f"  [OK]   {label}")
    else:
        FAILED.append(f"{label} — {detail}")
        print(f"  [FAIL] {label}" + (f" -> {detail}" if detail else ""))
    return condition


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def build_sysmon_event(
    event_id: int,
    machine: str,
    pid: int,
    process: str,
    when: datetime,
    target_file: str | None = None,
    parent: str = "explorer.exe",
    parent_pid: int = 1000,
    dest_ip: str | None = None,
) -> Dict[str, Any]:
    event_data: Dict[str, Any] = {
        "Image": f"C:\\Windows\\Temp\\{process}",
        "ProcessId": str(pid),
        "ParentImage": f"C:\\Windows\\explorer\\{parent}",
        "ParentProcessId": str(parent_pid),
    }
    if target_file:
        event_data["TargetFilename"] = target_file
    if dest_ip:
        event_data["DestinationIp"] = dest_ip
        event_data["DestinationPort"] = "443"

    return {
        "@timestamp": when.isoformat().replace("+00:00", "Z"),
        "host": {"name": machine, "ip": ["192.168.10.10"], "os": {"name": "Windows 10 Pro"}},
        "agent": {"version": "8.13.0"},
        "winlog": {"event_id": str(event_id), "computer_name": machine, "event_data": event_data},
    }


def random_filename() -> str:
    stem = "".join(random.choices(string.ascii_letters + string.digits, k=18))
    return f"C:\\Users\\victim\\Documents\\{stem}.LOCKED"


def benign_batch(machine: str, start: datetime, windows: int) -> List[Dict[str, Any]]:
    """活動 normale : sert à entraîner la baseline (peu de fichiers, noms lisibles)."""
    events = []
    cursor = start
    for index in range(windows):
        for step in range(2):
            events.append(
                build_sysmon_event(
                    11,
                    machine,
                    2200,
                    "notepad.exe",
                    cursor + timedelta(seconds=step),
                    target_file=f"C:\\Users\\victim\\Documents\\rapport_{index}_{step}.docx",
                )
            )
        # Événement qui déborde la fenêtre de 10 s et la fait fermer.
        cursor += timedelta(seconds=11)
        events.append(
            build_sysmon_event(
                11,
                machine,
                2200,
                "notepad.exe",
                cursor,
                target_file=f"C:\\Users\\victim\\Documents\\suivi_{index}.docx",
            )
        )
    return events


def ransomware_batch(machine: str, start: datetime) -> List[Dict[str, Any]]:
    """Rafale de chiffrement : création massive + entropie élevée + réseau."""
    events = []
    cursor = start
    for index in range(120):
        events.append(
            build_sysmon_event(
                11, machine, 6112, "ransom.exe", cursor, target_file=random_filename()
            )
        )
        if index % 20 == 0:
            events.append(
                build_sysmon_event(
                    23,
                    machine,
                    6112,
                    "ransom.exe",
                    cursor,
                    target_file=f"C:\\Users\\victim\\Documents\\original_{index}.docx",
                )
            )
        if index == 40:
            events.append(
                build_sysmon_event(
                    3, machine, 6112, "ransom.exe", cursor, dest_ip="185.199.110.153"
                )
            )
        if index == 60:
            events.append(
                build_sysmon_event(
                    1, machine, 7000, "vssadmin.exe", cursor, parent="ransom.exe", parent_pid=6112
                )
            )
        cursor += timedelta(milliseconds=60)

    # Ferme la fenêtre pour forcer l'évaluation.
    events.append(
        build_sysmon_event(
            11, machine, 6112, "ransom.exe", start + timedelta(seconds=12),
            target_file=random_filename(),
        )
    )
    return events


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    ws_url = base.replace("http://", "ws://").replace("https://", "wss://") + "/ws"

    sys.path.insert(0, ".")
    from api.config import settings

    agent_headers = {"X-Agent-Token": settings.agent_token}
    machine = "VM-WIN10-LAB"
    suffix = "".join(random.choices(string.ascii_lowercase, k=6))
    n1_email = f"analyste.{suffix}@soc.edr.local"
    n1_password = "AnalysteN1-2026!"
    n1_rotated_password = f"N1-{suffix}-Rotate1!"
    admin_email = E2E_ADMIN_EMAIL
    legacy_password = E2E_LEGACY_PASSWORD
    new_admin_password = f"SocManager-{suffix}-2026!"

    # Compte de test remis à zéro à chaque exécution : le scénario reste
    # reproductible sans toucher aux comptes réels du SOC.
    provision_test_admin()

    async with httpx.AsyncClient(base_url=base, timeout=30.0) as anon:
        section("1. Sonde publique")
        resp = await anon.get("/status")
        body = resp.json() if resp.status_code == 200 else {}
        check("GET /status répond 200", resp.status_code == 200, resp.text[:120])
        check("PostgreSQL joignable", body.get("database") == "up", json.dumps(body))

        section("2. Endpoints métier fermés sans session")
        for path in ("/alerts", "/metrics/overview", "/machines", "/audit", "/exclusions"):
            r = await anon.get(path)
            check(f"GET {path} refusé sans session (401)", r.status_code == 401, f"reçu {r.status_code}")

        r = await anon.post("/response/kill", json={"machine_id": machine, "pid": 4242})
        check(
            "POST /response/kill refusé sans session (401)",
            r.status_code == 401,
            f"reçu {r.status_code}",
        )

        section("3. Ingestion fermée sans token d'agent")
        r = await anon.post("/ingest", json={"machine_id": machine, "batch": []})
        check("POST /ingest refusé sans token (401)", r.status_code == 401, f"reçu {r.status_code}")
        r = await anon.get("/agent/commands")
        check(
            "GET /agent/commands refusé sans token (401)",
            r.status_code == 401,
            f"reçu {r.status_code}",
        )
        r = await anon.post("/ingest", json={"machine_id": machine, "batch": []},
                            headers={"X-Agent-Token": "mauvais-token"})
        check("Token d'agent invalide refusé", r.status_code == 401, f"reçu {r.status_code}")

        section("4. Authentification")
        r = await anon.post("/auth/login", json={"email": admin_email, "password": "wrong-pass"})
        check("Mot de passe erroné refusé (401)", r.status_code == 401, f"reçu {r.status_code}")
        check(
            "Message d'erreur non énumérant",
            "Identifiants invalides" in r.text,
            r.text[:120],
        )
        r = await anon.post(
            "/auth/login", json={"email": "inconnu@nowhere.local", "password": "x" * 12}
        )
        check(
            "Compte inexistant renvoie le même message",
            r.status_code == 401 and "Identifiants invalides" in r.text,
            r.text[:120],
        )

    # ── Session administrateur (compte importé de SQLite) ────────────
    async with httpx.AsyncClient(base_url=base, timeout=30.0) as admin:
        check(
            "Hachage legacy en base avant connexion",
            read_hash_algo(admin_email) == "sha256-legacy",
            read_hash_algo(admin_email),
        )

        r = await admin.post("/auth/login", json={"email": admin_email, "password": legacy_password})
        logged = check(
            "Login du compte importé avec son ancien mot de passe SHA-256",
            r.status_code == 200,
            r.text[:200],
        )
        if not logged:
            print("\n[!] Impossible de se connecter au compte de test, arrêt.")
            return 1

        payload = r.json()
        check("Cookie de session posé par le serveur", "edr_session" in dict(admin.cookies))
        check(
            "Hachage migré vers argon2id à la connexion",
            read_hash_algo(admin_email) == "argon2",
            read_hash_algo(admin_email),
        )
        check(
            "Rotation de mot de passe imposée au compte importé",
            payload.get("user", {}).get("must_change_password") is True,
            json.dumps(payload)[:200],
        )

        r = await admin.get("/alerts")
        check(
            "Accès aux données bloqué avant rotation (403)",
            r.status_code == 403,
            f"reçu {r.status_code}",
        )

        r = await admin.post(
            "/auth/change-password",
            json={"current_password": legacy_password, "new_password": "court"},
        )
        check("Mot de passe trop faible refusé (422)", r.status_code == 422, f"reçu {r.status_code}")

        r = await admin.post(
            "/auth/change-password",
            json={"current_password": legacy_password, "new_password": legacy_password},
        )
        check(
            "Réutilisation du même mot de passe refusée (422)",
            r.status_code == 422,
            f"reçu {r.status_code}",
        )

        r = await admin.post(
            "/auth/change-password",
            json={"current_password": legacy_password, "new_password": new_admin_password},
        )
        check("Changement de mot de passe accepté", r.status_code == 200, r.text[:200])

        r = await admin.get("/alerts")
        check("Accès aux alertes après rotation", r.status_code == 200, r.text[:200])

        r = await admin.get("/auth/me")
        me = r.json() if r.status_code == 200 else {}
        check(
            "Rôle N3 correctement restitué",
            me.get("user", {}).get("role") == "N3",
            json.dumps(me)[:200],
        )

        section("5. RBAC — création d'un analyste N1 et vérification des refus")
        r = await admin.post(
            "/auth/users",
            json={"email": n1_email, "password": n1_password, "role": "N1", "full_name": "Analyste Test"},
        )
        created = check("Création d'un compte N1 par le N3", r.status_code == 201, r.text[:200])

        # Le rôle n'est plus choisi par le demandeur : plus d'auto-inscription.
        async with httpx.AsyncClient(base_url=base, timeout=30.0) as rogue:
            r = await rogue.post(
                "/auth/users",
                json={"email": f"pirate.{suffix}@soc.local", "password": "Pirate-2026!x", "role": "N3"},
            )
            check(
                "Auto-inscription en N3 impossible sans session N3 (401)",
                r.status_code == 401,
                f"reçu {r.status_code}",
            )

        if created:
            async with httpx.AsyncClient(base_url=base, timeout=30.0) as n1:
                r = await n1.post("/auth/login", json={"email": n1_email, "password": n1_password})
                check("Login du compte N1", r.status_code == 200, r.text[:200])
                r = await n1.post(
                    "/auth/change-password",
                    json={"current_password": n1_password, "new_password": n1_rotated_password},
                )
                check("Rotation initiale du compte N1", r.status_code == 200, r.text[:200])

                r = await n1.get("/alerts")
                check("N1 peut lire les alertes", r.status_code == 200, f"reçu {r.status_code}")

                r = await n1.post(
                    "/response/kill", json={"machine_id": machine, "pid": 6112}
                )
                check(
                    "N1 ne peut PAS déclencher un KILL (403)",
                    r.status_code == 403,
                    f"reçu {r.status_code} {r.text[:120]}",
                )

                r = await n1.post(
                    "/exclusions", json={"type": "Folder", "path": "C:\\Temp\\", "comment": "test"}
                )
                check(
                    "N1 ne peut PAS créer d'exclusion (403)",
                    r.status_code == 403,
                    f"reçu {r.status_code}",
                )

                r = await n1.get("/auth/users")
                check(
                    "N1 ne peut PAS lister les comptes (403)",
                    r.status_code == 403,
                    f"reçu {r.status_code}",
                )

        section("6. Détection : ingestion -> alerte -> commande")
        alerts_before = (await admin.get("/alerts")).json().get("total", 0)

        async with httpx.AsyncClient(base_url=base, timeout=60.0) as agent:
            now = datetime.now(timezone.utc)
            baseline_events = benign_batch(machine, now - timedelta(minutes=5), windows=12)
            r = await agent.post(
                "/ingest",
                json={"machine_id": machine, "batch": baseline_events},
                headers=agent_headers,
            )
            check("Ingestion avec token valide acceptée", r.status_code == 200, r.text[:200])

            burst = ransomware_batch(machine, now)
            r = await agent.post(
                "/ingest", json={"machine_id": machine, "batch": burst}, headers=agent_headers
            )
            check("Ingestion de la rafale de chiffrement", r.status_code == 200, r.text[:200])

        r = await admin.get("/machines")
        machines = r.json() if r.status_code == 200 else []
        target = next((m for m in machines if m["machine_id"] == machine), None)
        check("Machine enregistrée en base", target is not None, json.dumps(machines)[:200])
        if target:
            check(
                "Métadonnées d'inventaire récupérées depuis les événements",
                target.get("ip_address") == "192.168.10.10" and bool(target.get("os_name")),
                json.dumps(target)[:200],
            )

        r = await admin.get("/alerts")
        alerts_body = r.json()
        alerts_after = alerts_body.get("total", 0)
        alert_created = check(
            "Au moins une alerte créée par le moteur",
            alerts_after > alerts_before,
            f"avant={alerts_before} après={alerts_after}",
        )

        alert = None
        if alert_created and alerts_body.get("items"):
            alert = alerts_body["items"][0]
            check(
                "Alerte rattachée à la machine",
                alert.get("machine_id") == machine,
                json.dumps(alert)[:200],
            )
            check(
                "Alerte enrichie (score, motifs, processus)",
                alert.get("score", 0) > 0
                and bool(alert.get("reasons"))
                and bool(alert.get("process_name")),
                json.dumps(alert)[:300],
            )
            # Le score alimente la gravité, le seuil d'arrêt automatique et
            # l'affichage « /100 » : hors de cette borne, les trois deviennent
            # faux. Le compteur d'activité brut, lui, reste non borné et doit
            # rester dans la charge utile à titre de preuve.
            score = alert.get("score", 0)
            check(
                "Score d'alerte borné sur 100",
                0 < score <= 100,
                f"score={score}, activité brute={alert.get('payload', {}).get('activity_points')}",
            )
            check(
                "Gravité cohérente avec le score",
                (score >= 80 and alert.get("severity") == "high")
                or (50 <= score < 80 and alert.get("severity") == "medium")
                or (score < 50 and alert.get("severity") == "low"),
                f"score={score}, gravité={alert.get('severity')}",
            )

        section("6 bis. Dernière fenêtre analysée même si l'agent se taît")

        # Scénario réel : le rançongiciel neutralise l'agent ou éteint le poste
        # juste après son passage. Aucun événement postérieur n'arrive donc pour
        # fermer la fenêtre d'analyse, et c'est précisément celle-là qui contient
        # la preuve. L'API doit l'évaluer d'elle-même après un court silence.
        silent_machine = f"{machine}-SILENT"
        alerts_before_flush = (await admin.get("/alerts")).json().get("total", 0)

        async with httpx.AsyncClient(base_url=base, timeout=60.0) as agent:
            now = datetime.now(timezone.utc)
            await agent.post(
                "/ingest",
                json={
                    "machine_id": silent_machine,
                    "batch": benign_batch(silent_machine, now - timedelta(minutes=5), windows=12),
                },
                headers=agent_headers,
            )
            # Rafale tronquée : on retire l'événement final qui, dans le test
            # précédent, servait justement à forcer la fermeture de la fenêtre.
            truncated = ransomware_batch(silent_machine, now)[:-1]
            r = await agent.post(
                "/ingest",
                json={"machine_id": silent_machine, "batch": truncated},
                headers=agent_headers,
            )
            check("Rafale ingérée sans événement de clôture", r.status_code == 200, r.text[:150])

        immediate = (await admin.get("/alerts")).json().get("total", 0)
        seen_before_flush = (
            (await admin.get(f"/machines/{silent_machine}")).json().get("last_seen_at")
        )
        detected = False
        for _ in range(12):
            await asyncio.sleep(3)
            total_now = (await admin.get("/alerts")).json().get("total", 0)
            if total_now > immediate:
                detected = True
                break

        check(
            "La fenêtre inactive est évaluée par le serveur",
            detected,
            f"alertes : {alerts_before_flush} avant, {immediate} après ingestion, "
            f"{'nouvelle alerte levée' if detected else 'aucune alerte après attente'}",
        )

        if detected:
            r = await admin.get("/alerts", params={"machine_id": silent_machine, "limit": 5})
            silent_alerts = r.json().get("items", [])
            check(
                "L'alerte est rattachée au poste devenu silencieux",
                bool(silent_alerts) and silent_alerts[0]["machine_id"] == silent_machine,
                json.dumps(silent_alerts[:1])[:200],
            )
            # L'évaluation vient du serveur, pas d'un signe de vie de l'agent :
            # elle ne doit donc pas rafraîchir la dernière activité du poste,
            # sous peine d'afficher « en ligne » une machine éteinte.
            r = await admin.get(f"/machines/{silent_machine}")
            machine_state = r.json() if r.status_code == 200 else {}
            check(
                "L'évaluation serveur ne fait pas passer le poste pour actif",
                machine_state.get("last_seen_at") == seen_before_flush,
                f"dernière activité inchangée : {seen_before_flush}",
            )

        section("7. Graphique alimenté par la base")
        r = await admin.get("/metrics/timeseries", params={"window_minutes": 15, "bucket_seconds": 10})
        series = r.json() if r.status_code == 200 else {}
        points = series.get("points", [])
        check("GET /metrics/timeseries répond", r.status_code == 200, r.text[:150])
        check("Série temporelle non vide", len(points) > 0, f"{len(points)} points")
        total_files = sum(p["files_created"] for p in points)
        check(
            "Le graphique contient l'activité réellement ingérée",
            total_files > 0,
            f"fichiers créés cumulés = {total_files}",
        )

        r = await admin.get("/metrics/overview")
        overview = r.json() if r.status_code == 200 else {}
        check("GET /metrics/overview répond", r.status_code == 200, r.text[:150])
        check(
            "Compteurs calculés côté serveur",
            overview.get("machines_total", 0) >= 1 and overview.get("alerts_total", 0) >= 1,
            json.dumps(overview)[:250],
        )
        check(
            "Score de risque dérivé des alertes réelles",
            isinstance(overview.get("risk_score"), int) and overview.get("risk_label"),
            json.dumps(overview)[:250],
        )

        section("8. Deux analystes voient les mêmes données")
        if created:
            async with httpx.AsyncClient(base_url=base, timeout=30.0) as n1:
                await n1.post(
                    "/auth/login", json={"email": n1_email, "password": n1_rotated_password}
                )
                a = (await admin.get("/metrics/overview")).json()
                b = (await n1.get("/metrics/overview")).json()
                comparable = {k: v for k, v in a.items() if k not in ("generated_at", "connected_analysts")}
                comparable_b = {k: v for k, v in b.items() if k not in ("generated_at", "connected_analysts")}
                check(
                    "Vue d'ensemble identique pour le N3 et le N1",
                    comparable == comparable_b,
                    f"{json.dumps(comparable)[:150]} != {json.dumps(comparable_b)[:150]}",
                )

                sa = (await admin.get("/metrics/timeseries", params={"window_minutes": 15})).json()
                sb = (await n1.get("/metrics/timeseries", params={"window_minutes": 15})).json()
                check(
                    "Séries temporelles identiques (mêmes bornes, mêmes valeurs)",
                    [p["files_created"] for p in sa["points"]]
                    == [p["files_created"] for p in sb["points"]],
                    "divergence entre les deux analystes",
                )

        section("9. Synchronisation temps réel (WebSocket)")
        cookie_value = dict(admin.cookies).get("edr_session")
        if not cookie_value:
            check("Cookie disponible pour le WebSocket", False, "cookie absent")
        else:
            try:
                async with websockets.connect(
                    ws_url, extra_headers={"Cookie": f"edr_session={cookie_value}"}
                ) as ws:
                    hello = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
                    check("Handshake WebSocket authentifié", hello.get("type") == "hello", str(hello))

                    await ws.send("ping")
                    pong = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
                    check("Heartbeat applicatif fonctionnel", pong.get("type") == "pong", str(pong))

                    # Une écriture par un autre canal doit réveiller ce client.
                    async with httpx.AsyncClient(base_url=base, timeout=60.0) as agent:
                        await agent.post(
                            "/ingest",
                            json={
                                "machine_id": machine,
                                "batch": ransomware_batch(
                                    machine, datetime.now(timezone.utc) + timedelta(seconds=30)
                                ),
                            },
                            headers=agent_headers,
                        )

                    received = []
                    try:
                        while len(received) < 4:
                            message = json.loads(await asyncio.wait_for(ws.recv(), timeout=15))
                            received.append(message)
                            if message.get("channel") == "alerts":
                                break
                    except asyncio.TimeoutError:
                        pass

                    channels = {m.get("channel") for m in received}
                    check(
                        "Invalidation temps réel reçue sans rechargement",
                        bool(channels & {"alerts", "metrics", "machines"}),
                        f"canaux reçus = {channels}",
                    )
            except Exception as exc:
                check("Connexion WebSocket", False, str(exc)[:200])

            # Un client non authentifié doit être rejeté.
            try:
                async with websockets.connect(ws_url) as ws:
                    await asyncio.wait_for(ws.recv(), timeout=5)
                    check("WebSocket anonyme refusé", False, "connexion acceptée")
            except Exception:
                check("WebSocket anonyme refusé", True)

        section("10. Réponse active tracée (N2+) et file de commandes")

        # La file est un FIFO par machine : on la vide d'abord, sinon une
        # exécution précédente laisse des ordres en attente et l'agent récupère
        # ceux-là au lieu du KILL créé ci-dessous.
        async with httpx.AsyncClient(base_url=base, timeout=30.0) as agent:
            for _ in range(50):
                r = await agent.get(
                    "/agent/commands", params={"machine_id": machine}, headers=agent_headers
                )
                leftover = r.json() if r.status_code == 200 else {}
                if not leftover.get("command_id"):
                    break
                await agent.post(
                    "/agent/commands/ack",
                    json={
                        "command_id": leftover["command_id"],
                        "success": True,
                        "message": "Purge avant test",
                    },
                    headers=agent_headers,
                )

        r = await admin.post(
            "/response/kill",
            json={"machine_id": machine, "pid": 6112, "reason": "Test e2e"},
        )
        kill_ok = check("N3 peut déclencher un KILL", r.status_code in (200, 201), r.text[:200])
        command_id = r.json().get("id") if kill_ok else None

        async with httpx.AsyncClient(base_url=base, timeout=30.0) as agent:
            r = await agent.get("/agent/commands", params={"machine_id": machine},
                                headers=agent_headers)
            cmd = r.json() if r.status_code == 200 else {}
            check(
                "L'agent récupère exactement la commande créée",
                cmd.get("action") == "KILL" and cmd.get("command_id") == command_id,
                json.dumps(cmd)[:200],
            )
            if cmd.get("command_id"):
                r = await agent.post(
                    "/agent/commands/ack",
                    json={"command_id": cmd["command_id"], "success": True, "message": "PID terminé"},
                    headers=agent_headers,
                )
                check("Acquittement de la commande par l'agent", r.status_code == 200, r.text[:150])

        r = await admin.get("/response/commands")
        commands = r.json() if r.status_code == 200 else []
        check("Journal des réponses persisté", len(commands) > 0, f"{len(commands)} commande(s)")
        check(
            "Origine automatique tracée pour les KILL du moteur",
            any(c["origin"] == "auto" for c in commands),
            json.dumps(commands[:2])[:250],
        )

        section("11. Isolation réseau et état de la machine")
        r = await admin.post("/response/isolate", json={"machine_id": machine, "reason": "Test e2e"})
        check("Isolation acceptée", r.status_code in (200, 201), r.text[:200])
        r = await admin.get(f"/machines/{machine}")
        check(
            "Machine marquée isolée",
            r.status_code == 200 and r.json().get("is_isolated") is True,
            r.text[:150],
        )
        r = await admin.post("/response/isolate", json={"machine_id": machine})
        check("Double isolation refusée (409)", r.status_code == 409, f"reçu {r.status_code}")
        r = await admin.post("/response/unisolate", json={"machine_id": machine})
        check("Levée d'isolation acceptée", r.status_code in (200, 201), r.text[:200])

        section("12. Cycle de vie collaboratif des alertes")
        if alert:
            r = await admin.post(f"/alerts/{alert['id']}/assign")
            check("Prise en charge d'une alerte", r.status_code == 200, r.text[:200])
            assigned = r.json() if r.status_code == 200 else {}
            check(
                "Affectation visible par tous",
                assigned.get("assigned_to_email") == admin_email
                and assigned.get("status") == "in_progress",
                json.dumps(assigned)[:200],
            )
            r = await admin.patch(
                f"/alerts/{alert['id']}/status",
                json={"status": "closed", "resolution_note": "Test e2e : incident confirmé"},
            )
            check("Clôture d'une alerte", r.status_code == 200, r.text[:200])

        section("13. Exclusions (N3) et effet réel sur le moteur")
        excl_path = f"C:\\Exclu-{suffix}\\"
        r = await admin.post(
            "/exclusions", json={"type": "Folder", "path": excl_path, "comment": "Test e2e"}
        )
        excl_created = check("Création d'exclusion par le N3", r.status_code == 201, r.text[:200])
        excl_id = r.json().get("id") if excl_created else None
        r = await admin.post("/exclusions", json={"type": "Folder", "path": excl_path})
        check("Doublon d'exclusion refusé (409)", r.status_code == 409, f"reçu {r.status_code}")

        # L'exclusion doit réellement filtrer les événements du pipeline.
        await asyncio.sleep(11)  # dépassement du TTL du cache d'exclusions
        async with httpx.AsyncClient(base_url=base, timeout=60.0) as agent:
            excluded_events = [
                build_sysmon_event(
                    11,
                    machine,
                    9100,
                    "ignored.exe",
                    datetime.now(timezone.utc) + timedelta(seconds=60 + i),
                    target_file=f"{excl_path}fichier_{i}.tmp",
                )
                for i in range(30)
            ]
            r = await agent.post(
                "/ingest",
                json={"machine_id": machine, "batch": excluded_events},
                headers=agent_headers,
            )
            processed = r.json().get("processed_events", -1) if r.status_code == 200 else -1
            check(
                "Les événements exclus sont réellement filtrés par le moteur",
                processed == 0,
                f"processed_events = {processed} (attendu 0)",
            )

        if excl_id:
            r = await admin.delete(f"/exclusions/{excl_id}")
            check("Suppression d'exclusion", r.status_code == 200, r.text[:150])

        section("14. Audit écrit par le serveur")
        r = await admin.get("/audit", params={"limit": 200})
        audit_body = r.json() if r.status_code == 200 else {}
        entries = audit_body.get("items", [])
        actions = {e["action"] for e in entries}
        check("Journal d'audit lisible", r.status_code == 200, r.text[:150])
        check(
            "Connexions et échecs tracés",
            {"auth.login", "auth.login_failed"} <= actions,
            f"actions = {sorted(actions)}",
        )
        check(
            "Réponse active tracée nominativement",
            any(
                e["action"] == "response.kill" and e["actor_label"] == admin_email
                for e in entries
            ),
            "aucune entrée response.kill trouvée",
        )
        check(
            "KILL automatique du moteur audité",
            any(e["action"] == "engine.auto_kill" for e in entries),
            "aucune entrée engine.auto_kill",
        )
        # Les entrées importées sont les plus anciennes : chaque exécution du
        # test en ajoute de nouvelles qui les repoussent hors de la première
        # page. On interroge donc explicitement la fin du journal.
        total_audit = audit_body.get("total", 0)
        r = await admin.get(
            "/audit", params={"limit": 100, "offset": max(0, total_audit - 100)}
        )
        oldest = r.json().get("items", []) if r.status_code == 200 else []
        check(
            "Historique SQLite préservé après migration",
            any((e.get("details") or {}).get("imported_from") == "sqlite" for e in oldest),
            f"{total_audit} entrées au total, aucune importée dans les plus anciennes",
        )
        real_ips = {e["ip_source"] for e in entries if e["action"] == "auth.login"}
        check(
            "IP source déterminée par le serveur (plus de valeur codée en dur)",
            "192.168.10.2" not in real_ips,
            f"ips = {real_ips}",
        )

        section("15. Configuration persistée")
        r = await admin.get("/settings")
        check("Lecture de la configuration", r.status_code == 200, r.text[:150])
        r = await admin.put(
            "/settings/detection",
            json={"value": {"auto_kill_score_threshold": 85, "rules_alert_threshold": 0.7,
                            "baseline_min_vectors": 10}},
        )
        check("Écriture de la configuration par le N3", r.status_code == 200, r.text[:200])
        r = await admin.get("/settings")
        saved = next((s for s in r.json() if s["key"] == "detection"), {})
        check(
            "Configuration réellement persistée",
            saved.get("value", {}).get("auto_kill_score_threshold") == 85,
            json.dumps(saved)[:200],
        )
        r = await admin.put("/settings/inexistant", json={"value": {}})
        check("Clé de configuration inconnue rejetée (400)", r.status_code == 400, f"reçu {r.status_code}")

        section("16. Fin de session")
        r = await admin.post("/auth/logout")
        check("Déconnexion", r.status_code == 200, r.text[:150])
        r = await admin.get("/alerts")
        check(
            "Session révoquée côté serveur après logout (401)",
            r.status_code == 401,
            f"reçu {r.status_code}",
        )

    cleanup_test_accounts([admin_email, n1_email])

    print("\n" + "=" * 72)
    print(f"RÉSULTAT : {len(PASSED)} vérification(s) réussie(s), {len(FAILED)} échec(s)")
    if FAILED:
        print("\nÉchecs :")
        for item in FAILED:
            print(f"  - {item}")
        return 1
    print("Toutes les vérifications sont passées.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
