/** Référence intégrée : architecture, rôles, procédures et déploiement. */

import { Panel } from '../components/ui';

function Section({ title, children }) {
  return (
    <Panel title={title}>
      <div className="text-xs text-slate-700 leading-relaxed space-y-3">{children}</div>
    </Panel>
  );
}

export default function Docs() {
  return (
    <div className="space-y-6">
      <Section title="Chaîne de traitement">
        <p>
          Sysmon écrit les événements 1 (création de processus), 3 (connexion réseau), 11 (création
          de fichier) et 23 (suppression de fichier). Winlogbeat les transmet à l'API sur{' '}
          <span className="code-text">POST /_bulk</span> ou <span className="code-text">POST /ingest</span>,
          authentifié par le token d'agent.
        </p>
        <p>
          L'API normalise les événements, les agrège en fenêtres de 10 secondes{' '}
          <strong>propres à chaque terminal</strong>, compare le résultat à la baseline de ce
          terminal, puis applique le moteur heuristique et le modèle Random Forest. Chaque fenêtre
          fermée est écrite dans la table <span className="code-text">metrics</span> ; chaque
          détection dans <span className="code-text">alerts</span>.
        </p>
        <p>
          Au-delà du seuil configuré, une commande d'arrêt de processus est déposée dans la table{' '}
          <span className="code-text">commands</span>. L'agent la récupère sur{' '}
          <span className="code-text">GET /agent/commands</span> et l'acquitte sur{' '}
          <span className="code-text">POST /agent/commands/ack</span>.
        </p>
      </Section>

      <Section title="Pourquoi tous les analystes voient la même chose">
        <p>
          PostgreSQL est la seule source de vérité. Aucun indicateur affiché dans cette console n'est
          calculé dans le navigateur : le score de risque, les compteurs et les points du graphique
          sont agrégés par des requêtes SQL, avec des bornes temporelles alignées sur une origine
          fixe (<span className="code-text">date_bin</span>). Deux analystes qui ouvrent le dashboard
          à la même seconde obtiennent donc rigoureusement les mêmes valeurs.
        </p>
        <p>
          Le WebSocket ne transporte pas les données métier, seulement des notifications
          d'invalidation du type « le canal alerts a changé ». Chaque client relit ensuite l'API. Ce
          choix évite qu'un message perdu ou réordonné ne laisse un poste avec un état divergent, et
          garantit que les autorisations sont réévaluées à chaque lecture.
        </p>
        <p>
          Si le WebSocket tombe, l'interface le signale explicitement (« mode dégradé ») et bascule
          sur un rafraîchissement périodique, plutôt que d'afficher silencieusement des données
          figées.
        </p>
      </Section>

      <Section title="Niveaux de privilège">
        <div className="table-container">
          <table className="custom-table">
            <thead>
              <tr>
                <th>Niveau</th>
                <th>Peut faire</th>
                <th>Ne peut pas faire</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="font-semibold">N1 — Analyste SOC</td>
                <td>
                  Consulter alertes, terminaux, métriques et audit ; prendre en charge et qualifier
                  une alerte
                </td>
                <td>Arrêter un processus, isoler un poste, gérer exclusions ou comptes</td>
              </tr>
              <tr>
                <td className="font-semibold">N2 — Analyste EDR</td>
                <td>Tout N1, plus l'arrêt de processus et l'isolation réseau</td>
                <td>Gérer les exclusions, les comptes et la configuration</td>
              </tr>
              <tr>
                <td className="font-semibold">N3 — SOC Manager</td>
                <td>Administration complète : comptes, exclusions, configuration système</td>
                <td>—</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p>
          Ces restrictions sont appliquées par l'API à chaque requête. Les boutons masqués dans
          l'interface ne sont qu'un confort d'affichage : un appel direct à l'API avec un compte N1
          reçoit une réponse 403.
        </p>
      </Section>

      <Section title="Procédure : suspicion de rançongiciel">
        <ol className="list-decimal list-inside space-y-1.5">
          <li>
            Depuis le <strong>Dashboard</strong>, ouvrir la <strong>file de triage</strong> (alertes
            ouvertes non assignées, triées par score) et sélectionner l'incident le plus critique.
          </li>
          <li>
            Sur la fiche d'alerte, lire la <strong>chronologie</strong> (parent → réseau → chiffrement
            → détection) et les alertes <strong>corrélées</strong> sur le même terminal.
          </li>
          <li>
            En N2+, cliquer sur <strong>Confinement complet</strong> : prise en charge + arrêt du
            PID + isolation réseau en une seule action tracée. Sinon, prendre en charge puis escalader
            à un N2.
          </li>
          <li>Suivre le playbook à droite jusqu'à ce que toutes les étapes soient cochées.</li>
          <li>
            Vérifier l'acquittement dans le journal des réponses, puis qualifier l'alerte (clôturée
            ou faux positif) avec une note de résolution.
          </li>
        </ol>
      </Section>

      <Section title="Déploiement">
        <p>
          <strong>Développement.</strong> Base :{' '}
          <span className="code-text">docker compose up -d db</span>. Migrations :{' '}
          <span className="code-text">alembic upgrade head</span>. API :{' '}
          <span className="code-text">uvicorn api.main:app --port 8000</span>. Dashboard :{' '}
          <span className="code-text">npm run dev</span> dans <span className="code-text">dashboard/</span>.
          Vite proxifie <span className="code-text">/api</span> et <span className="code-text">/ws</span>,
          donc le navigateur ne voit qu'une seule origine.
        </p>
        <p>
          <strong>Accès distant.</strong>{' '}
          <span className="code-text">npm run build</span> puis{' '}
          <span className="code-text">docker compose up -d</span>. Nginx sert le dashboard et
          proxifie l'API et le WebSocket sur le port 8080. Les analystes se connectent depuis
          n'importe quel poste du réseau : aucune URL n'est codée en dur côté client.
        </p>
        <p>
          <strong>Avant une exposition réelle.</strong> Passer{' '}
          <span className="code-text">APP_ENV=production</span> et{' '}
          <span className="code-text">COOKIE_SECURE=true</span> derrière un terminaison TLS. L'API
          refuse de démarrer en production si les secrets sont restés à leur valeur de
          développement.
        </p>
      </Section>

      <Section title="Administration hors bande">
        <p>
          La création de compte passe normalement par l'onglet Équipe SOC. En cas de perte de tous
          les accès N3, les opérations suivantes restent possibles sur le serveur :
        </p>
        <ul className="list-disc list-inside space-y-1 font-mono text-[11px]">
          <li>python -m scripts.manage list-users</li>
          <li>python -m scripts.manage create-user --email x@y.local --role N3</li>
          <li>python -m scripts.manage reset-password --email x@y.local</li>
          <li>python -m scripts.manage unlock --email x@y.local</li>
          <li>python -m scripts.manage revoke-sessions --email x@y.local</li>
        </ul>
      </Section>
    </div>
  );
}
