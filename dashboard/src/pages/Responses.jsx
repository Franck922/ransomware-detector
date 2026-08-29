/**
 * Journal des réponses actives.
 *
 * Auparavant les commandes vivaient dans une liste Python en mémoire et étaient
 * détruites dès qu'un agent les consommait : impossible de savoir a posteriori
 * qui avait tué quoi, ni si l'ordre avait abouti. Chaque commande est maintenant
 * persistée avec son auteur, son origine et son acquittement.
 */

import { ShieldAlert } from 'lucide-react';
import { response as responseApi } from '../api/endpoints';
import { useResource } from '../hooks/useResource';
import {
  AsyncSection,
  CommandStatusBadge,
  EmptyState,
  Panel,
  formatDateTime,
} from '../components/ui';

const ORIGIN_LABELS = {
  auto: 'Moteur de détection',
  manual: 'Analyste',
};

export default function Responses() {
  const { data, loading, error, reload } = useResource(
    (signal) => responseApi.commands({ limit: 200 }, signal),
    { channels: ['commands'] },
  );

  const items = data || [];
  const pending = items.filter((item) => ['pending', 'sent'].includes(item.status)).length;

  return (
    <Panel
      title={`${items.length} réponse(s) active(s)`}
      subtitle={
        pending
          ? `${pending} commande(s) en attente d'acquittement par un agent`
          : 'Toutes les commandes ont été traitées'
      }
    >
      <AsyncSection
        loading={loading}
        error={error}
        onRetry={reload}
        isEmpty={items.length === 0}
        empty={
          <EmptyState
            icon={ShieldAlert}
            title="Aucune réponse active enregistrée"
            description="Les arrêts de processus et isolations réseau apparaîtront ici, qu'ils soient automatiques ou déclenchés par un analyste."
          />
        }
      >
        <div className="table-container">
          <table className="custom-table">
            <thead>
              <tr>
                <th>Horodatage</th>
                <th>Terminal</th>
                <th>Action</th>
                <th>Cible</th>
                <th>Origine</th>
                <th>Déclencheur</th>
                <th>Statut</th>
                <th>Acquittement</th>
              </tr>
            </thead>
            <tbody>
              {items.map((command) => (
                <tr key={command.id}>
                  <td className="whitespace-nowrap">{formatDateTime(command.created_at)}</td>
                  <td className="font-medium">{command.machine_id || '—'}</td>
                  <td className="font-semibold">{command.action}</td>
                  <td>
                    {command.target_pid ? (
                      <span className="code-text">PID {command.target_pid}</span>
                    ) : (
                      <span className="text-text-muted">Réseau</span>
                    )}
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        command.origin === 'auto'
                          ? 'badge-warning'
                          : 'bg-brand-primaryGlow text-brand-primary border border-border'
                      }`}
                    >
                      {ORIGIN_LABELS[command.origin] || command.origin}
                    </span>
                  </td>
                  <td className="text-text-muted">
                    {command.created_by_email || 'Automatique'}
                  </td>
                  <td>
                    <CommandStatusBadge status={command.status} />
                  </td>
                  <td className="text-text-muted">
                    {command.result?.message || (command.acked_at ? 'Confirmé' : '—')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </AsyncSection>
    </Panel>
  );
}
