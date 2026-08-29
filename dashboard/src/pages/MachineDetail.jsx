/** Fiche d'un terminal : activité mesurée, alertes et réponses le concernant. */

import { useState } from 'react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { ArrowLeft, ShieldOff, Undo2 } from 'lucide-react';
import {
  alerts as alertsApi,
  machines as machinesApi,
  metrics as metricsApi,
  response as responseApi,
} from '../api/endpoints';
import { useResource } from '../hooks/useResource';
import { useAuth } from '../auth/AuthContext';
import { useRealtime } from '../realtime/RealtimeProvider';
import {
  AsyncSection,
  CommandStatusBadge,
  EmptyState,
  MachineStatusBadge,
  Panel,
  SeverityBadge,
  StatCard,
  StatusBadge,
  formatDateTime,
  formatRelative,
  formatTime,
} from '../components/ui';

export default function MachineDetail({ machineId, onBack, onOpenAlert, onToast }) {
  const { hasRole } = useAuth();
  const { invalidate } = useRealtime();
  const [busy, setBusy] = useState(false);

  const machine = useResource((signal) => machinesApi.get(machineId, signal), {
    channels: ['machines', 'alerts', 'commands'],
    deps: [machineId],
  });

  const series = useResource(
    (signal) =>
      metricsApi.timeseries(
        { window_minutes: 60, bucket_seconds: 30, machine_id: machineId },
        signal,
      ),
    { channels: ['metrics'], deps: [machineId] },
  );

  const machineAlerts = useResource(
    (signal) => alertsApi.list({ machine_id: machineId, limit: 20 }, signal),
    { channels: ['alerts'], deps: [machineId] },
  );

  const commands = useResource(
    (signal) => responseApi.commands({ machine_id: machineId, limit: 20 }, signal),
    { channels: ['commands'], deps: [machineId] },
  );

  const toggleIsolation = async () => {
    setBusy(true);
    try {
      if (machine.data?.is_isolated) {
        await responseApi.unisolate(machineId, 'Levée de confinement depuis la console');
        onToast({ tone: 'success', message: `${machineId} reconnectée au réseau.` });
      } else {
        await responseApi.isolate(machineId, 'Confinement depuis la console');
        onToast({ tone: 'success', message: `${machineId} isolée du réseau.` });
      }
      invalidate(['machines', 'commands', 'audit']);
      machine.reload();
    } catch (error) {
      onToast({ tone: 'error', message: error.message });
    } finally {
      setBusy(false);
    }
  };

  const chartData = (series.data?.points || []).map((point) => ({
    time: formatTime(point.bucket),
    fichiers: point.files_created,
    supprimes: point.files_deleted,
    processus: point.processes_created,
  }));

  const info = machine.data;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <button type="button" onClick={onBack} className="btn btn-outline">
          <ArrowLeft className="w-3.5 h-3.5" />
          Retour aux terminaux
        </button>

        {hasRole('N2') && info ? (
          <button
            type="button"
            onClick={toggleIsolation}
            disabled={busy}
            className={`btn ${info.is_isolated ? 'btn-outline' : 'btn-danger'} disabled:opacity-50`}
          >
            {info.is_isolated ? (
              <>
                <Undo2 className="w-3.5 h-3.5" />
                Lever l'isolation
              </>
            ) : (
              <>
                <ShieldOff className="w-3.5 h-3.5" />
                Isoler du réseau
              </>
            )}
          </button>
        ) : null}
      </div>

      <AsyncSection
        loading={machine.loading}
        error={machine.error}
        onRetry={machine.reload}
        isEmpty={!info}
      >
        {info ? (
          <div className="space-y-6">
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 sm:gap-5">
              <StatCard
                label="Terminal"
                value={info.machine_id}
                hint={info.os_name || 'Système non renseigné'}
              />
              <StatCard
                label="Adresse IP"
                value={info.ip_address || '—'}
                hint={`Agent ${info.agent_version || 'inconnu'}`}
              />
              <StatCard
                label="Alertes ouvertes"
                value={info.open_alerts}
                hint={info.open_alerts ? 'Traitement requis' : 'Aucune alerte à traiter'}
                tone={info.open_alerts ? 'danger' : 'success'}
              />
              <StatCard
                label="Événements reçus"
                value={info.events_received.toLocaleString('fr-FR')}
                hint={`Vu ${formatRelative(info.last_seen_at)}`}
              />
            </div>

            <Panel
              title="Activité de la dernière heure"
              subtitle="Agrégation serveur par intervalle de 30 secondes"
              actions={<MachineStatusBadge status={info.status} />}
            >
              <AsyncSection
                loading={series.loading}
                error={series.error}
                onRetry={series.reload}
                isEmpty={chartData.length === 0}
                empty={<EmptyState title="Aucune métrique sur la dernière heure" />}
              >
                <ResponsiveContainer width="100%" height={220}>
                  <AreaChart data={chartData} margin={{ top: 5, right: 8, left: -20, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} />
                    <XAxis
                      dataKey="time"
                      tick={{ fontSize: 10, fill: '#64748b' }}
                      stroke="#e5e7eb"
                      minTickGap={28}
                    />
                    <YAxis
                      tick={{ fontSize: 10, fill: '#64748b' }}
                      stroke="#e5e7eb"
                      allowDecimals={false}
                    />
                    <Tooltip contentStyle={{ fontSize: 11, borderRadius: 10 }} />
                    <Area
                      type="monotone"
                      dataKey="fichiers"
                      name="Fichiers créés"
                      stroke="#0f172a"
                      fill="#0f172a"
                      fillOpacity={0.12}
                    />
                    <Area
                      type="monotone"
                      dataKey="supprimes"
                      name="Fichiers supprimés"
                      stroke="#d97706"
                      fill="#d97706"
                      fillOpacity={0.12}
                    />
                    <Area
                      type="monotone"
                      dataKey="processus"
                      name="Processus créés"
                      stroke="#16a34a"
                      fill="#16a34a"
                      fillOpacity={0.12}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </AsyncSection>
            </Panel>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
              <Panel title="Alertes du terminal">
                <AsyncSection
                  loading={machineAlerts.loading}
                  error={machineAlerts.error}
                  onRetry={machineAlerts.reload}
                  isEmpty={(machineAlerts.data?.items || []).length === 0}
                  empty={<EmptyState title="Aucune alerte sur ce poste" />}
                >
                  <div className="table-container">
                    <table className="custom-table">
                      <thead>
                        <tr>
                          <th>Date</th>
                          <th>Processus</th>
                          <th>Gravité</th>
                          <th>Statut</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(machineAlerts.data?.items || []).map((alert) => (
                          <tr
                            key={alert.id}
                            onClick={() => onOpenAlert(alert.id)}
                            className="cursor-pointer"
                          >
                            <td className="whitespace-nowrap">{formatDateTime(alert.detected_at)}</td>
                            <td>
                              <span className="code-text">{alert.process_name || '—'}</span>
                            </td>
                            <td>
                              <SeverityBadge severity={alert.severity} />
                            </td>
                            <td>
                              <StatusBadge status={alert.status} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </AsyncSection>
              </Panel>

              <Panel title="Réponses actives sur ce poste">
                <AsyncSection
                  loading={commands.loading}
                  error={commands.error}
                  onRetry={commands.reload}
                  isEmpty={(commands.data || []).length === 0}
                  empty={<EmptyState title="Aucune réponse déclenchée" />}
                >
                  <div className="table-container">
                    <table className="custom-table">
                      <thead>
                        <tr>
                          <th>Date</th>
                          <th>Action</th>
                          <th>Cible</th>
                          <th>Statut</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(commands.data || []).map((command) => (
                          <tr key={command.id}>
                            <td className="whitespace-nowrap">{formatDateTime(command.created_at)}</td>
                            <td className="font-semibold">{command.action}</td>
                            <td>
                              {command.target_pid ? (
                                <span className="code-text">PID {command.target_pid}</span>
                              ) : (
                                'Réseau'
                              )}
                            </td>
                            <td>
                              <CommandStatusBadge status={command.status} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </AsyncSection>
              </Panel>
            </div>
          </div>
        ) : null}
      </AsyncSection>
    </div>
  );
}
