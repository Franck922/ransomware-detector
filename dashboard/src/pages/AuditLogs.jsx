/**
 * Journal d'audit.
 *
 * Le dashboard écrivait auparavant dans ce journal via POST /audit, en
 * fournissant lui-même le nom de l'utilisateur ET une IP source codée en dur
 * (192.168.10.2) : le registre était donc entièrement falsifiable. L'écriture
 * est maintenant exclusivement serveur ; cet écran est en lecture seule.
 */

import { useState } from 'react';
import { FileCheck } from 'lucide-react';
import { audit as auditApi } from '../api/endpoints';
import { useResource } from '../hooks/useResource';
import { AsyncSection, EmptyState, Panel, formatDateTime } from '../components/ui';

const PAGE_SIZE = 50;

const PERIODS = [
  { value: 24, label: '24 h' },
  { value: 24 * 7, label: '7 jours' },
  { value: 24 * 30, label: '30 jours' },
  { value: 0, label: 'Tout' },
];

const ACTION_LABELS = {
  'auth.login': 'Connexion',
  'auth.login_failed': 'Échec de connexion',
  'auth.logout': 'Déconnexion',
  'auth.password_changed': 'Changement de mot de passe',
  'user.created': 'Création de compte',
  'user.updated': 'Modification de compte',
  'user.deleted': 'Suppression de compte',
  'alert.status_changed': "Changement de statut d'alerte",
  'alert.assigned': 'Affectation d\'alerte',
  'response.kill': 'Arrêt de processus',
  'response.isolate': 'Isolation réseau',
  'response.unisolate': "Levée d'isolation",
  'response.command_acked': 'Acquittement agent',
  'exclusion.created': 'Ajout d\'exclusion',
  'exclusion.deleted': 'Retrait d\'exclusion',
  'exclusion.toggled': 'Bascule d\'exclusion',
  'settings.updated': 'Modification de configuration',
  'engine.auto_kill': 'Arrêt automatique (moteur)',
  'engine.alert_raised': 'Alerte levée (moteur)',
};

function describe(entry) {
  const details = entry.details || {};
  if (details.message) return details.message;

  const parts = Object.entries(details)
    .filter(([, value]) => value !== null && value !== undefined && value !== '')
    .map(([key, value]) => {
      if (value && typeof value === 'object' && 'from' in value && 'to' in value) {
        return `${key} : ${value.from} → ${value.to}`;
      }
      if (typeof value === 'object') return `${key} : ${JSON.stringify(value)}`;
      return `${key} : ${value}`;
    });

  return parts.length > 0 ? parts.join(' · ') : '—';
}

export default function AuditLogs() {
  const [action, setAction] = useState('');
  const [actor, setActor] = useState('');
  const [hours, setHours] = useState(24 * 7);
  const [page, setPage] = useState(0);

  const actions = useResource((signal) => auditApi.actions(signal), { channels: ['audit'] });

  const { data, loading, error, reload } = useResource(
    (signal) =>
      auditApi.list(
        {
          action: action || undefined,
          actor: actor || undefined,
          hours: hours || undefined,
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
        },
        signal,
      ),
    { channels: ['audit'], deps: [action, actor, hours, page] },
  );

  const items = data?.items || [];
  const total = data?.total || 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <Panel
      title={`${total} entrée(s) d'audit`}
      subtitle="Journal en lecture seule, alimenté exclusivement par le serveur"
      actions={
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={actor}
            onChange={(event) => {
              setActor(event.target.value);
              setPage(0);
            }}
            placeholder="Filtrer par acteur"
            className="px-2.5 py-1.5 rounded-lg border border-border text-[11px] w-40 focus:outline-none focus:ring-2 focus:ring-brand-primary/20"
          />
          <select
            value={action}
            onChange={(event) => {
              setAction(event.target.value);
              setPage(0);
            }}
            className="px-2.5 py-1.5 rounded-lg border border-border text-[11px] bg-white focus:outline-none max-w-52"
          >
            <option value="">Toutes les actions</option>
            {(actions.data || []).map((value) => (
              <option key={value} value={value}>
                {ACTION_LABELS[value] || value}
              </option>
            ))}
          </select>
          <div className="flex items-center gap-1 bg-gray-50 rounded-lg p-1 border border-border">
            {PERIODS.map((period) => (
              <button
                key={period.label}
                type="button"
                onClick={() => {
                  setHours(period.value);
                  setPage(0);
                }}
                className={`px-2.5 py-1 rounded-md text-[10px] font-semibold transition-all ${
                  hours === period.value
                    ? 'bg-white text-brand-primary shadow-sm'
                    : 'text-text-muted hover:text-text-main'
                }`}
              >
                {period.label}
              </button>
            ))}
          </div>
        </div>
      }
    >
      <AsyncSection
        loading={loading}
        error={error}
        onRetry={reload}
        isEmpty={items.length === 0}
        empty={
          <EmptyState
            icon={FileCheck}
            title="Aucune entrée pour ces critères"
            description="Les connexions, réponses actives et modifications de configuration sont tracées automatiquement."
          />
        }
      >
        <>
          <div className="table-container">
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Horodatage</th>
                  <th>Acteur</th>
                  <th>Action</th>
                  <th>Cible</th>
                  <th>Détails</th>
                  <th>IP source</th>
                  <th>Résultat</th>
                </tr>
              </thead>
              <tbody>
                {items.map((entry) => (
                  <tr key={entry.id}>
                    <td className="whitespace-nowrap">{formatDateTime(entry.occurred_at)}</td>
                    <td className="font-medium">{entry.actor_label}</td>
                    <td>{ACTION_LABELS[entry.action] || entry.action}</td>
                    <td className="text-text-muted">
                      {entry.target ? <span className="code-text">{entry.target}</span> : '—'}
                    </td>
                    <td className="text-text-muted max-w-md truncate" title={describe(entry)}>
                      {describe(entry)}
                    </td>
                    <td>
                      <span className="code-text">{entry.ip_source || '—'}</span>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          entry.result === 'success' ? 'badge-success' : 'badge-danger'
                        }`}
                      >
                        {entry.result === 'success' ? 'Succès' : 'Échec'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {pageCount > 1 ? (
            <div className="flex items-center justify-between mt-5 pt-4 border-t border-border">
              <span className="text-[10px] text-text-muted">
                Page {page + 1} sur {pageCount}
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={page === 0}
                  onClick={() => setPage((value) => Math.max(0, value - 1))}
                  className="btn btn-outline disabled:opacity-40"
                >
                  Précédent
                </button>
                <button
                  type="button"
                  disabled={page + 1 >= pageCount}
                  onClick={() => setPage((value) => value + 1)}
                  className="btn btn-outline disabled:opacity-40"
                >
                  Suivant
                </button>
              </div>
            </div>
          ) : null}
        </>
      </AsyncSection>
    </Panel>
  );
}
