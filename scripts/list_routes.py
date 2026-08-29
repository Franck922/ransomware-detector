"""
Inventaire des routes exposées par l'API et de la garde appliquée à chacune.

Sert à vérifier d'un coup d'œil qu'aucun endpoint n'a été ajouté sans protection :
la liste des routes réellement publiques est affichée séparément en fin de sortie,
afin qu'un oubli saute aux yeux au lieu de se perdre dans le tableau.

    python -m scripts.list_routes
"""

import inspect
import sys
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.main import app  # noqa: E402

# Routes publiques par conception, avec la raison qui le justifie. Toute route
# publique absente de ce dictionnaire est signalée comme à revoir.
EXPECTED_PUBLIC = {
    "/": "compatibilité Winlogbeat (réponse de cluster factice)",
    "/_license": "compatibilité Winlogbeat",
    "/_xpack": "compatibilité Winlogbeat",
    "/_{path_name:path}": "compatibilité Winlogbeat (vérifications annexes)",
    "/status": "sonde de santé, ne divulgue aucune donnée métier",
    "/auth/login": "point d'entrée de l'authentification",
    "/docs": "documentation interactive (désactivée en production)",
    "/docs/oauth2-redirect": "documentation interactive",
    "/redoc": "documentation interactive (désactivée en production)",
    "/openapi.json": "schéma de l'API (désactivé en production)",
}

GUARD_LABELS = {
    "_guard": "session+rôle",
    "require_agent_token": "token agent",
    "get_current_user": "session",
}


def guards_of(route) -> str:
    """Déduit la protection d'une route de ses dépendances déclarées."""
    endpoint = getattr(route, "endpoint", None)
    if endpoint is None:
        return "?"

    try:
        parameters = inspect.signature(endpoint).parameters
    except (TypeError, ValueError):
        return "?"

    labels: List[str] = []
    for parameter in parameters.values():
        dependency = getattr(parameter.default, "dependency", None)
        label = GUARD_LABELS.get(getattr(dependency, "__name__", ""))
        if label:
            labels.append(label)

    if labels:
        return ", ".join(dict.fromkeys(labels))

    # Un WebSocket ne peut pas être protégé par une dépendance qui lève une
    # HTTPException : le handshake doit d'abord être refusé proprement. La
    # session est donc vérifiée dans le corps du handler, avant acceptation.
    if getattr(route, "methods", None) is None and "session" in inspect.getsource(endpoint):
        return "session (vérifiée dans le handler)"

    return "public"


def main() -> int:
    rows: List[Tuple[str, str, str]] = []
    for route in app.routes:
        path = getattr(route, "path", None)
        if path is None:
            continue
        methods = getattr(route, "methods", None)
        verb = ",".join(sorted(methods - {"HEAD", "OPTIONS"})) if methods else "WEBSOCKET"
        rows.append((path, verb, guards_of(route)))

    print(f"{'MÉTHODE':<22} {'CHEMIN':<42} PROTECTION")
    print("-" * 92)
    for path, verb, protection in sorted(rows):
        print(f"{verb:<22} {path:<42} {protection}")

    unexpected = [
        (path, verb)
        for path, verb, protection in sorted(rows)
        if protection == "public" and path not in EXPECTED_PUBLIC
    ]

    print()
    if unexpected:
        print(f"{len(unexpected)} route(s) publique(s) NON justifiée(s) — à revoir :")
        for path, verb in unexpected:
            print(f"  {verb} {path}")
        return 1

    print("Aucune route publique inattendue. Routes publiques par conception :")
    for path, reason in sorted(EXPECTED_PUBLIC.items()):
        print(f"  {path:<28} {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
