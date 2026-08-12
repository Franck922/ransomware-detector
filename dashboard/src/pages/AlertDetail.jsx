/**
 * Analyse forensics d'une alerte, avec actions de réponse.
 *
 * Deux corrections par rapport à l'ancienne version :
 *   - le bouton « Terminer le processus » appelait `triggerKill(...)`, une
 *     fonction jamais définie : cliquer levait une ReferenceError et ne faisait
 *     donc rien du tout ;
 *   - le KILL était envoyé sans identifiant de machine, donc à n'importe quel
 *     agent qui interrogeait la file en premier.
 */

import { useState } from 'react';
import { ArrowLeft, Ban, Crosshair, ShieldOff } from 'lucide-react';
import { alerts as alertsApi, response as responseApi } from '../api/endpoints';
import { useResource } from '../hooks/useResource';
import { useAuth } from '../auth/AuthContext';
import { useRealtime } from '../realtime/RealtimeProvider';
import {
  AsyncSection,
  Panel,
  SeverityBadge,
  StatusBadge,
  STATUS_LABELS,
  formatDateTime,
} from '../components/ui';

const NEXT_STATUSES = ['new', 'in_progress', 'closed', 'false_positive'];

export default function AlertDetail({ alertId, onBack, onToast }) {
  const { hasRole, user } = useAuth();
  const { invalidate } = useRealtime();
  const [busy, setBusy] = useState(null);
  const [note, setNote] = useState('');

  const { data: alert, loading, error, reload } = useResource(
    (signal) => alertsApi.get(alertId, signal),
    { channels: ['alerts', 'commands'], deps: [alertId] },
  );

  const run = async (label, action, channels) => {
    setBusy(label);
    try {
      await action();
      invalidate(channels);
      reload();
    } catch (err) {
      onToast({ tone: 'error', message: err.message });
    } finally {
      setBusy(null);
    }
  };

  const handleKill = () =>
    run(
      'kill',
      async () => {
        await responseApi.kill(
          alert.machine_id,
          alert.pid,
          alert.id,
          `Réponse manuelle sur alerte #${alert.id}`,
        );
        onToast({
          tone: 'success',
          message: `Ordre d'arrêt du PID ${alert.pid} transmis à ${alert.machine_id}.`,
        });
      },
      ['commands', 'audit'],
    );

  const handleIsolate = () =>
    run(
      'isolate',
      async () => {
        await responseApi.isolate(alert.machine_id, `Confinement suite à l'alerte #${alert.id}`);
        onToast({ tone: 'success', message: `${alert.machine_id} isolée du réseau.` });
      },
      ['commands', 'machines', 'audit'],
    );

  const handleAssign = () =>
    run(
      'assign',
      async () => {
        await alertsApi.assign(alert.id);
        onToast({ tone: 'success', message: 'Alerte prise en charge.' });
      },
      ['alerts', 'audit'],
    );

  const handleStatus = (status) =>
    run(
      status,
      async () => {
        await alertsApi.setStatus(alert.id, status, note || undefined);
        onToast({ tone: 'success', message: `Statut mis à jour : ${STATUS_LABELS[status]}.` });
      },
      ['alerts', 'audit'],
    );

  return (
    <div className="space-y-6">
      <button type="button" onClick={onBack} className="btn btn-outline">
        <ArrowLeft className="w-3.5 h-3.5" />
        Retour au journal
      </button>

      <AsyncSection loading={loading} error={error} onRetry={reload} isEmpty={!alert}>
        {alert ? (
          <div className="space-y-6">
            <Panel>
              <div className="flex items-start justify-between gap-6">
                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    <h2 className="text-lg font-bold tracking-tight">
                      Alerte #{alert.id} — {alert.process_name || 'processus inconnu'}
                    </h2>
                    <SeverityBadge severity={alert.severity} />
                    <StatusBadge status={alert.status} />
                  </div>
                  <p className="text-xs text-text-muted">
                    Détectée le {formatDateTime(alert.detected_at)} sur{' '}
                    <strong>{alert.machine_id || 'terminal inconnu'}</strong> par le moteur{' '}
                    <strong>{alert.source}</strong>
                    {alert.assigned_to_email ? ` · prise en charge par ${alert.assigned_to_email}` : ''}
                  </p>
                </div>

                <div className="text-right shrink-0">
                  <div className="stat-label">Score de suspicion</div>
                  <div className="text-3xl font-bold tracking-tight">{alert.score}</div>
                  <div className="text-[10px] text-text-muted">Confiance {alert.confidence}</div>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 mt-6 pt-5 border-t border-border">
                {!alert.assigned_to || alert.assigned_to !== user?.id ? (
                  <button
                    type="button"
                    onClick={handleAssign}
                    disabled={busy !== null}
                    className="btn btn-primary disabled:opacity-50"
                  >
                    <Crosshair className="w-3.5 h-3.5" />
                    Prendre en charge
                  </button>
                ) : null}

                {hasRole('N2') ? (
                  <>
                    <button
                      type="button"
                      onClick={handleKill}
                      disabled={busy !== null || !alert.pid || !alert.machine_id}
                      className="btn btn-danger disabled:opacity-50"
                      title={
                        alert.pid
                          ? `Arrêter le PID ${alert.pid} sur ${alert.machine_id}`
                          : 'Aucun PID identifié pour cette alerte'
                      }
                    >
                      <Ban className="w-3.5 h-3.5" />
                      {busy === 'kill' ? 'Envoi…' : `Terminer le PID ${alert.pid ?? '—'}`}
                    </button>
                    <button
                      type="button"
                      onClick={handleIsolate}
                      disabled={busy !== null || !alert.machine_id}
                      className="btn btn-outline disabled:opacity-50"
                    >
                      <ShieldOff className="w-3.5 h-3.5" />
                      {busy === 'isolate' ? 'Envoi…' : 'Isoler le terminal'}
                    </button>
                  </>
                ) : (
                  <span className="text-[10px] text-text-muted">
                    La réponse active (arrêt de processus, isolation) requiert le niveau N2.
                  </span>
                )}
              </div>
            </Panel>

            <div className="grid grid-cols-3 gap-6">
              <Panel className="col-span-2" title="Justification de la détection">
                {(alert.reasons || []).length > 0 ? (
                  <ul className="space-y-2">
                    {alert.reasons.map((reason, index) => (
                      <li
                        key={`${index}-${reason}`}
                        className="flex items-start gap-2.5 text-xs text-slate-700"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-brand-danger mt-1.5 shrink-0" />
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-text-muted">Aucun motif détaillé enregistré.</p>
                )}

                <div className="mt-6 pt-5 border-t border-border">
                  <h3 className="stat-label mb-3">Chaîne de processus</h3>
                  <div className="flex items-center gap-3 text-xs flex-wrap">
                    <span className="code-text">{alert.parent_name || 'parent inconnu'}</span>
                    {alert.parent_pid ? (
                      <span className="text-text-muted">PID {alert.parent_pid}</span>
                    ) : null}
                    <span className="text-text-muted">→</span>
                    <span className="code-text bg-brand-dangerGlow border-red-100 text-brand-danger">
                      {alert.process_name || 'processus inconnu'}
                    </span>
                    {alert.pid ? <span className="text-text-muted">PID {alert.pid}</span> : null}
                  </div>
                </div>

                {alert.payload?.stats ? (
                  <div className="mt-6 pt-5 border-t border-border">
                    <h3 className="stat-label mb-3">Activité du processus sur la fenêtre</h3>
                    <div className="grid grid-cols-2 gap-x-8 gap-y-2">
                      {Object.entries(alert.payload.stats).map(([key, value]) => (
                        <div key={key} className="flex justify-between text-xs">
                          <span className="text-text-muted">{STAT_LABELS[key] || key}</span>
                          <span className="font-semibold">{String(value)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </Panel>

              <div className="space-y-6">
                <Panel title="Qualification">
                  <div className="space-y-3">
                    <textarea
                      value={note}
                      onChange={(event) => setNote(event.target.value)}
                      rows={4}
                      placeholder="Note de résolution partagée avec l'équipe…"
                      className="w-full px-3 py-2 rounded-lg border border-border text-xs focus:outline-none focus:ring-2 focus:ring-brand-primary/20"
                    />
                    <div className="grid grid-cols-2 gap-2">
                      {NEXT_STATUSES.filter((value) => value !== alert.status).map((value) => (
                        <button
                          key={value}
                          type="button"
                          onClick={() => handleStatus(value)}
                          disabled={busy !== null}
                          className="btn btn-outline disabled:opacity-50"
                        >
                          {STATUS_LABELS[value]}
                        </button>
                      ))}
                    </div>
                    {alert.resolution_note ? (
                      <div className="text-[10px] text-text-muted border-t border-border pt-3">
                        <span className="font-semibold block mb-0.5">Note enregistrée</span>
                        {alert.resolution_note}
                      </div>
                    ) : null}
                  </div>
                </Panel>

                <Panel title="Vecteur de features">
                  {alert.payload?.window_features ? (
                    <dl className="space-y-1.5">
                      {Object.entries(alert.payload.window_features).map(([key, value]) => (
                        <div key={key} className="flex justify-between text-[11px]">
                          <dt className="text-text-muted">{key}</dt>
                          <dd className="font-mono font-semibold">{String(value)}</dd>
                        </div>
                      ))}
                    </dl>
                  ) : (
                    <p className="text-xs text-text-muted">Non disponible pour cette alerte.</p>
                  )}
                </Panel>
              </div>
            </div>
          </div>
        ) : null}
      </AsyncSection>
    </div>
  );
}

const STAT_LABELS = {
  files_created: 'Fichiers créés',
  files_deleted: 'Fichiers supprimés',
  network_connections: 'Connexions réseau',
  processes_created: 'Processus créés',
  entropy: 'Entropie des noms',
};
