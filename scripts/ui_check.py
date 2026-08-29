"""
Vérification du parcours navigateur.

`scripts/e2e_check.py` valide l'API en l'attaquant directement sur son port.
Ce script valide la couche que traverse réellement un analyste : le reverse
proxy (nginx en production, Vite en développement) sert à la fois le dashboard,
l'API sous /api et le WebSocket sous /ws.

C'est cette couche qui rend la console utilisable à distance : sans elle, le
navigateur voit deux origines différentes et refuse d'envoyer le cookie de
session, symptôme classique d'un « ça marche sur ma machine mais pas sur la
tienne ».

    python -m scripts.ui_check                        # dev, port 5173
    python -m scripts.ui_check --origin http://srv:8080  # production nginx
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import websockets
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session as OrmSession

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.config import settings  # noqa: E402
from api.models import Role, Session as SessionModel, User  # noqa: E402
from api.security import hash_password  # noqa: E402

UI_ACCOUNT = "ui-check@soc.edr.local"
UI_PASSWORD = "UiCheck!2026#Soc"

OK, KO, WARN = "[OK]", "[KO]", "[! ]"


class Report:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def check(self, label: str, condition: bool, detail: str = "") -> bool:
        if condition:
            print(f"  {OK} {label}" + (f" — {detail}" if detail else ""))
        else:
            print(f"  {KO} {label}" + (f" — {detail}" if detail else ""))
            self.failures.append(label)
        return condition

    def note(self, label: str) -> None:
        print(f"  {WARN} {label}")

    def section(self, title: str) -> None:
        print(f"\n{title}")
        print("-" * len(title))


def provision_account() -> None:
    """
    Compte dédié recréé à chaque exécution : le test reste rejouable même si un
    lancement précédent a modifié le mot de passe ou verrouillé le compte.
    """
    with OrmSession(create_engine(settings.sync_database_url)) as db:
        user = db.scalar(select(User).where(func.lower(User.email) == UI_ACCOUNT))
        if user is None:
            user = User(email=UI_ACCOUNT, full_name="Vérification interface")
            db.add(user)

        user.password_hash = hash_password(UI_PASSWORD)
        user.hash_algo = "argon2id"
        user.role = Role.N3.value
        user.is_active = True
        user.must_change_password = False
        user.failed_login_count = 0
        user.locked_until = None
        db.commit()


def cleanup_account() -> None:
    with OrmSession(create_engine(settings.sync_database_url)) as db:
        user = db.scalar(select(User).where(func.lower(User.email) == UI_ACCOUNT))
        if user is not None:
            db.query(SessionModel).filter(SessionModel.user_id == user.id).delete()
            db.delete(user)
            db.commit()


async def run(origin: str, report: Report) -> None:
    api = f"{origin}/api"

    async with httpx.AsyncClient(base_url=origin, timeout=20.0, follow_redirects=True) as client:
        report.section("1. Le proxy sert bien le dashboard et l'API sur une seule origine")

        page = await client.get("/")
        report.check(
            "La racine renvoie l'application",
            page.status_code == 200 and "<div id=\"root\">" in page.text,
            f"HTTP {page.status_code}",
        )

        status = await client.get(f"{api}/status")
        body = status.json() if status.status_code == 200 else {}
        report.check(
            "L'API répond sous /api",
            status.status_code == 200 and body.get("database") == "up",
            f"base {body.get('database')}, ML {body.get('ml_enabled')}",
        )

        anonymous = await client.get(f"{api}/metrics/overview")
        report.check(
            "Un visiteur non authentifié est rejeté",
            anonymous.status_code == 401,
            f"HTTP {anonymous.status_code}",
        )

        report.section("2. Session par cookie HttpOnly, comme le fait le navigateur")

        login = await client.post(
            f"{api}/auth/login", json={"email": UI_ACCOUNT, "password": UI_PASSWORD}
        )
        report.check("Connexion acceptée", login.status_code == 200, f"HTTP {login.status_code}")

        cookie_header = login.headers.get("set-cookie", "")
        report.check(
            "Le cookie de session est HttpOnly",
            "httponly" in cookie_header.lower(),
            "inaccessible à document.cookie, donc au XSS",
        )
        report.check(
            "Le cookie est en SameSite",
            "samesite" in cookie_header.lower(),
            cookie_header.split("SameSite=")[-1].split(";")[0] if "SameSite=" in cookie_header else "absent",
        )
        report.check(
            "Aucun jeton n'est renvoyé dans le corps de la réponse",
            "token" not in login.text.lower(),
            "rien à voler dans localStorage",
        )

        me = await client.get(f"{api}/auth/me")
        identity = (me.json() or {}).get("user", {}) if me.status_code == 200 else {}
        report.check(
            "La session est reconnue au rechargement de page",
            me.status_code == 200 and identity.get("email") == UI_ACCOUNT,
            f"{identity.get('email')} / {identity.get('role_label')}",
        )

        report.section("3. Chaque onglet de la console obtient ses données")

        pages = {
            "Vue d'ensemble": f"{api}/metrics/overview",
            "Graphique d'activité": f"{api}/metrics/timeseries?window_minutes=60&bucket_seconds=30",
            "Alertes": f"{api}/alerts?limit=20",
            "Terminaux": f"{api}/machines",
            "Réponses actives": f"{api}/response/commands?limit=20",
            "Moteur ML": f"{api}/metrics/ml-insights",
            "Exclusions": f"{api}/exclusions",
            "Journal d'audit": f"{api}/audit?limit=20",
            "Équipe SOC": f"{api}/auth/users",
            "Configuration": f"{api}/settings",
        }
        payloads = {}
        for label, url in pages.items():
            resp = await client.get(url)
            payloads[label] = resp.json() if resp.status_code == 200 else None
            report.check(f"Onglet « {label} »", resp.status_code == 200, f"HTTP {resp.status_code}")

        report.section("4. Les indicateurs partagés viennent du serveur, pas du navigateur")

        overview = payloads.get("Vue d'ensemble") or {}
        series = payloads.get("Graphique d'activité") or {}
        points = series.get("points", [])

        report.check(
            "Le score de risque est calculé par l'API",
            isinstance(overview.get("risk_score"), int),
            f"{overview.get('risk_score')}/100",
        )
        expected_keys = (
            "machines_total",
            "machines_online",
            "machines_isolated",
            "alerts_open",
            "alerts_critical_open",
            "alerts_last_24h",
            "commands_pending",
            "baseline_trained_machines",
            "events_last_hour",
            "connected_analysts",
        )
        missing = [key for key in expected_keys if key not in overview]
        report.check(
            "Tous les compteurs affichés par le dashboard existent",
            not missing,
            f"{overview.get('machines_total')} terminaux, "
            f"{overview.get('alerts_open')} alertes ouvertes"
            + (f" — champs absents : {missing}" if missing else ""),
        )
        report.check(
            "Le graphique est alimenté par des points datés en base",
            isinstance(points, list) and len(points) > 0 and "bucket" in (points[0] or {}),
            f"{len(points)} points sur 1 h",
        )

        # Deux lectures successives doivent donner des bornes temporelles
        # identiques : c'est ce qui garantit que deux analystes superposent le
        # même graphique au lieu de chacun le sien.
        second = await client.get(f"{api}/metrics/timeseries?window_minutes=60&bucket_seconds=30")
        second_points = second.json().get("points", []) if second.status_code == 200 else []
        aligned = (
            len(points) == len(second_points)
            and bool(points)
            and points[0]["bucket"] == second_points[0]["bucket"]
        )
        report.check(
            "Les bornes du graphique sont déterministes",
            aligned,
            "deux analystes voient exactement les mêmes barres",
        )

        report.section("5. Canal temps réel à travers le proxy")

        cookie_name = settings.session_cookie_name
        session_cookie = client.cookies.get(cookie_name)
        ws_url = origin.replace("http://", "ws://").replace("https://", "wss://") + "/ws"

        try:
            async with websockets.connect(
                ws_url,
                extra_headers={"Cookie": f"{cookie_name}={session_cookie}"},
                open_timeout=10,
            ) as socket:
                hello = json.loads(await asyncio.wait_for(socket.recv(), timeout=10))
                report.check(
                    "Le WebSocket est accepté et authentifié par le cookie",
                    hello.get("type") == "hello",
                    f"canaux : {', '.join(hello.get('channels', []))}",
                )

                # Une action d'analyste doit provoquer une invalidation chez les
                # autres postes : c'est le mécanisme qui remplace le polling.
                created = await client.post(
                    f"{api}/exclusions",
                    json={
                        "type": "Folder",
                        "path": f"C:\\Temp\\ui-check-{datetime.now(timezone.utc).timestamp()}",
                        "comment": "Créée par la vérification d'interface",
                    },
                )
                report.check(
                    "Écriture depuis l'interface acceptée",
                    created.status_code in (200, 201),
                    f"HTTP {created.status_code}",
                )

                # Le serveur ne pousse pas la donnée mais un avis de péremption
                # par canal ; le client relit ensuite l'endpoint REST.
                received: list[str] = []
                loop = asyncio.get_running_loop()
                deadline = loop.time() + 8
                while loop.time() < deadline and "exclusions" not in received:
                    try:
                        message = json.loads(
                            await asyncio.wait_for(
                                socket.recv(), timeout=max(0.5, deadline - loop.time())
                            )
                        )
                    except asyncio.TimeoutError:
                        break
                    if message.get("type") == "invalidate":
                        received.append(message.get("channel"))

                report.check(
                    "Les autres analystes sont notifiés immédiatement",
                    "exclusions" in received,
                    f"canaux invalidés : {', '.join(c for c in received if c) or 'aucun'}",
                )

                if created.status_code in (200, 201):
                    await client.delete(f"{api}/exclusions/{created.json()['id']}")

        except Exception as exc:  # noqa: BLE001
            report.check("Canal temps réel", False, f"{type(exc).__name__}: {exc}")

        report.section("6. Les restrictions de rôle tiennent aussi derrière le proxy")

        # Un compte N1 créé à la volée : les boutons masqués dans l'interface ne
        # doivent pas être la seule protection.
        n1_email = "ui-check-n1@soc.edr.local"
        provisional = "UiCheckN1!2026#"
        rotated = "UiCheckN1!2026#Rotated"

        existing = await client.get(f"{api}/auth/users")
        for entry in existing.json() if existing.status_code == 200 else []:
            if entry["email"] == n1_email:
                await client.delete(f"{api}/auth/users/{entry['id']}")

        creation = await client.post(
            f"{api}/auth/users",
            json={
                "email": n1_email,
                "password": provisional,
                "role": "N1",
                "full_name": "Analyste de contrôle",
            },
        )
        report.check("Création de compte par un N3", creation.status_code in (200, 201))

        if creation.status_code in (200, 201):
            async with httpx.AsyncClient(base_url=origin, timeout=20.0) as n1_client:
                first_login = await n1_client.post(
                    f"{api}/auth/login", json={"email": n1_email, "password": provisional}
                )
                report.check(
                    "Connexion avec le mot de passe provisoire",
                    first_login.status_code == 200,
                    f"HTTP {first_login.status_code}",
                )
                report.check(
                    "Rotation du mot de passe exigée dès la création",
                    (first_login.json() or {}).get("user", {}).get("must_change_password") is True,
                    "un mot de passe défini par un tiers ne donne pas d'accès direct",
                )

                # Tant que la rotation n'est pas faite, tout est refusé avec un
                # en-tête dédié : sans lui, l'interface ne pourrait pas
                # distinguer ce blocage d'un simple manque de privilège.
                blocked = await n1_client.get(f"{api}/alerts?limit=5")
                report.check(
                    "Compte en attente de rotation : accès bloqué",
                    blocked.status_code == 403
                    and blocked.headers.get("X-Password-Change-Required") == "1",
                    f"HTTP {blocked.status_code}, en-tête "
                    f"{blocked.headers.get('X-Password-Change-Required')}",
                )

                rotation = await n1_client.post(
                    f"{api}/auth/change-password",
                    json={"current_password": provisional, "new_password": rotated},
                )
                report.check(
                    "Rotation acceptée", rotation.status_code == 200, f"HTTP {rotation.status_code}"
                )

                # La rotation révoque les autres sessions : il faut se
                # reconnecter avec le nouveau mot de passe.
                await n1_client.post(
                    f"{api}/auth/login", json={"email": n1_email, "password": rotated}
                )

                allowed = await n1_client.get(f"{api}/alerts?limit=5")
                report.check(
                    "Un N1 consulte bien les alertes",
                    allowed.status_code == 200,
                    f"HTTP {allowed.status_code}",
                )

                forbidden = await n1_client.post(
                    f"{api}/response/kill",
                    json={"machine_id": "peu-importe", "pid": 4242, "reason": "test"},
                )
                report.check(
                    "Un N1 ne peut pas arrêter un processus",
                    forbidden.status_code == 403
                    and forbidden.headers.get("X-Password-Change-Required") is None,
                    f"HTTP {forbidden.status_code} — refus lié au rôle, pas au mot de passe",
                )

                isolation = await n1_client.post(
                    f"{api}/response/isolate",
                    json={"machine_id": "peu-importe", "reason": "test"},
                )
                report.check(
                    "Un N1 ne peut pas isoler un terminal",
                    isolation.status_code == 403,
                    f"HTTP {isolation.status_code}",
                )

                denied = await n1_client.get(f"{api}/auth/users")
                report.check(
                    "Un N1 ne peut pas lister les comptes",
                    denied.status_code == 403,
                    f"HTTP {denied.status_code}",
                )

                no_exclusion = await n1_client.post(
                    f"{api}/exclusions", json={"type": "Folder", "path": "C:\\Interdit"}
                )
                report.check(
                    "Un N1 ne peut pas créer d'exclusion",
                    no_exclusion.status_code == 403,
                    f"HTTP {no_exclusion.status_code}",
                )

            await client.delete(f"{api}/auth/users/{creation.json()['id']}")

        report.section("7. Fermeture de session")

        logout = await client.post(f"{api}/auth/logout")
        report.check("Déconnexion acceptée", logout.status_code == 200)

        after = await client.get(f"{api}/auth/me")
        report.check(
            "La session est invalidée côté serveur",
            after.status_code == 401,
            "le cookie seul ne suffit plus, la session est révoquée en base",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Vérifie la console SOC via son reverse proxy")
    parser.add_argument(
        "--origin",
        default="http://127.0.0.1:5173",
        help="Origine servant le dashboard (défaut : serveur Vite de développement)",
    )
    parser.add_argument("--keep", action="store_true", help="Conserver le compte de test")
    args = parser.parse_args()

    print("=" * 74)
    print(f"  VÉRIFICATION DE LA CONSOLE SOC — {args.origin}")
    print("=" * 74)

    report = Report()
    provision_account()
    try:
        asyncio.run(run(args.origin.rstrip("/"), report))
    finally:
        if not args.keep:
            cleanup_account()

    print("\n" + "=" * 74)
    if report.failures:
        print(f"  {len(report.failures)} CONTRÔLE(S) EN ÉCHEC")
        for failure in report.failures:
            print(f"    - {failure}")
        print("=" * 74)
        return 1

    print("  TOUS LES CONTRÔLES PASSENT")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
