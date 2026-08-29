/**
 * Inventaire des terminaux surveillés.
 *
 * L'ancien onglet affichait un unique poste « VM-WIN10-LAB » écrit en dur, avec
 * une IP et un pourcentage de CPU inventés. La liste provient maintenant de la
 * table `machines`, alimentée à chaque lot d'événements reçu.
 */

import { Terminal } from 'lucide-react';
import { machines as machinesApi } from '../api/endpoints';
import { useResource } from '../hooks/useResource';
import {
  AsyncSection,
  EmptyState,
  MachineStatusBadge,
  Panel,
  formatDateTime,
  formatRelative,
} from '../components/ui';

export default function Machines({ onOpenMachine }) {
  const { data, loading, error, reload } = useResource((signal) => machinesApi.list(signal), {
    channels: ['machines', 'alerts'],
  });

  const items = data || [];

  return (
    <Panel
      title={`${items.length} terminal(aux)`}
      subtitle="Un poste apparaît dès que son agent transmet son premier lot d'événements"
    >
      <AsyncSection
        loading={loading}
        error={error}
        onRetry={reload}
        isEmpty={items.length === 0}
        empty={
          <EmptyState
            icon={Terminal}
            title="Aucun terminal enregistré"
            description="Démarrez Winlogbeat sur une VM surveillée avec le token d'agent configuré dans .env, puis rechargez cette page."
          />
        }
      >
        <div className="table-container">
          <table className="custom-table">
            <thead>
              <tr>
                <th>Terminal</th>
                <th>Adresse IP</th>
                <th>Système</th>
                <th>Agent</th>
                <th>Statut</th>
                <th>Alertes ouvertes</th>
                <th>Événements reçus</th>
                <th>Dernière activité</th>
              </tr>
            </thead>
            <tbody>
              {items.map((machine) => (
                <tr
                  key={machine.id}
                  onClick={() => onOpenMachine(machine.machine_id)}
                  className="cursor-pointer"
                >
                  <td className="font-semibold">{machine.machine_id}</td>
                  <td>
                    <span className="code-text">{machine.ip_address || '—'}</span>
                  </td>
                  <td className="text-text-muted">{machine.os_name || '—'}</td>
                  <td className="text-text-muted">{machine.agent_version || '—'}</td>
                  <td>
                    <MachineStatusBadge status={machine.status} />
                  </td>
                  <td>
                    {machine.open_alerts > 0 ? (
                      <span className="badge badge-danger">{machine.open_alerts}</span>
                    ) : (
                      <span className="text-text-muted">0</span>
                    )}
                  </td>
                  <td className="font-mono">{machine.events_received.toLocaleString('fr-FR')}</td>
                  <td className="text-text-muted" title={formatDateTime(machine.last_seen_at)}>
                    {formatRelative(machine.last_seen_at)}
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
