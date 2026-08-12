/**
 * Analyse forensics d'une alerte, avec chronologie, corrélation et containment.
 *
 * Améliorations SOC :
 *   - timeline reconstruite côté serveur (parent → réseau → chiffrement → alerte → réponses) ;
 *   - alertes corrélées sur le même terminal / processus dans une fenêtre de 15 min ;
 *   - playbook de réponse guidé ;
 *   - pack « Confinement » N2 (prise en charge + kill + isolation en une action).
 */

import { useState } from 'react';
import {
  ArrowLeft,
  Ban,
  CheckCircle2,
  Circle,
  Crosshair,
  ShieldAlert,
  ShieldOff,
  Siren,
} from 'lucide-react';
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
  formatRelative,
} from '../components/ui';

const NEXT_STATUSES = ['new', 'in_progress', 'closed', 'false_positive'];

const TONE_DOT = {
  muted: 'bg-slate-300',
  info: 'bg-sky-500',
  warning: 'bg-amber-500',
  danger: 'bg-brand-danger',
  success: 'bg-brand-success',
};

export default function AlertDetail({ alertId, onBack, onOpenAlert, onToast }) {
  const { hasRole, user } = useAuth();
  const { invalidate } = useRealtime();
  const [busy, setBusy] = useState(null);
  const [note, setNote] = useState('');

  const { data: dossier, loading, error, reload } = useResource(
    (signal) => alertsApi.investigation(alertId, signal),
    { channels: ['alerts', 'commands', 'machines'], deps: [alertId] },
  );

  const alert = dossier?.alert;
  const timeline = dossier?.timeline || [];
  const related = dossier?.related || [];
  const playbook = dossier?.playbook || [];

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

  const handleContain = () =>
    run(
      'contain',
      async () => {
        const result = await alertsApi.contain(alert.id, {
          kill: Boolean(alert.pid),
          isolate: true,
          note: note || undefined,
        });
        onToast({ tone: 'success', message: result.message });
      },
      ['alerts', 'commands', 'machines', 'audit'],
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
              <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 sm:gap-6">
                <div className="space-y-2 min-w-0">
                  <div className="flex items-center gap-3 flex-wrap">
                    <h2 className="text-base sm:text-lg font-bold tracking-tight break-words">
                      Alerte #{alert.id} — {alert.process_name || 'processus inconnu'}
                    </h2>
                    <SeverityBadge severity={alert.severity} />
                    <StatusBadge status={alert.status} />
                  </div>
                  <p className="text-xs text-text-muted">
                    Détectée le {formatDateTime(alert.detected_at)} (
                    {formatRelative(alert.detected_at)}) sur{' '}
                    <strong>{alert.machine_id || 'terminal inconnu'}</strong> par le moteur{' '}
                    <strong>{alert.source}</strong>
                    {alert.assigned_to_email
                      ? ` · prise en charge par ${alert.assigned_to_email}`
                      : ' · non assignée'}
                  </p>
                </div>

                <div className="text-left sm:text-right shrink-0">
                  <div className="stat-label">Score de suspicion</div>
                  <div className="text-3xl font-bold tracking-tight">{alert.score}</div>
                  <div className="text-[10px] text-text-muted">Confiance {alert.confidence}</div>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 mt-6 pt-5 border-t border-border">
                {hasRole('N2') ? (
                  <button
                    type="button"
                    onClick={handleContain}
                    disabled={busy !== null || !alert.machine_id}
                    className="btn btn-danger disabled:opacity-50"
                    title="Prise en charge + arrêt du PID + isolation réseau"
                  >
                    <Siren className="w-3.5 h-3.5" />
                    {busy === 'contain' ? 'Confinement…' : 'Confinement complet'}
                  </button>
                ) : null}

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
                      className="btn btn-outline disabled:opacity-50"
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
                    La réponse active (arrêt de processus, isolation, confinement) requiert le
                    niveau N2.
                  </span>
                )}
              </div>
            </Panel>

            <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 sm:gap-6">
              <div className="xl:col-span-2 space-y-6">
                <Panel
                  title="Chronologie de l'attaque"
                  subtitle={`Reconstruite sur ${dossier.correlation_window_minutes} min autour de la détection`}
                >
                  {timeline.length > 0 ? (
                    <ol className="relative space-y-0 border-l border-border ml-2">
                      {timeline.map((event, index) => (
                        <li key={`${event.kind}-${index}-${event.at}`} className="relative pl-5 pb-5 last:pb-0">
                          <span
                            className={`absolute -left-[5px] top-1.5 w-2.5 h-2.5 rounded-full ring-2 ring-white ${
                              TONE_DOT[event.tone] || TONE_DOT.muted
                            }`}
                          />
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <p className="text-xs font-semibold text-text-main">{event.title}</p>
                              {event.detail ? (
                                <p className="text-[11px] text-text-muted mt-0.5">{event.detail}</p>
                              ) : null}
                              {event.alert_id && event.alert_id !== alert.id && onOpenAlert ? (
                                <button
                                  type="button"
                                  onClick={() => onOpenAlert(event.alert_id)}
                                  className="text-[10px] font-semibold text-brand-primary mt-1 hover:underline"
                                >
                                  Ouvrir l'alerte #{event.alert_id}
                                </button>
                              ) : null}
                            </div>
                            <time className="text-[10px] text-text-muted whitespace-nowrap shrink-0">
                              {formatDateTime(event.at)}
                            </time>
                          </div>
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <p className="text-xs text-text-muted">Chronologie indisponible.</p>
                  )}
                </Panel>

                <Panel title="Justification de la détection">
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
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-2">
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

                {related.length > 0 ? (
                  <Panel
                    title={`${related.length} alerte(s) corrélée(s)`}
                    subtitle="Même terminal et même processus / PID dans la fenêtre de corrélation"
                  >
                    <div className="table-container">
                      <table className="custom-table">
                        <thead>
                          <tr>
                            <th>Horodatage</th>
                            <th>Processus</th>
                            <th>Score</th>
                            <th>Statut</th>
                          </tr>
                        </thead>
                        <tbody>
                          {related.map((item) => (
                            <tr
                              key={item.id}
                              className="cursor-pointer"
                              onClick={() => onOpenAlert?.(item.id)}
                            >
                              <td className="whitespace-nowrap">{formatDateTime(item.detected_at)}</td>
                              <td>
                                <span className="code-text">{item.process_name || 'inconnu'}</span>
                                {item.pid ? (
                                  <span className="text-text-muted ml-1.5">PID {item.pid}</span>
                                ) : null}
                              </td>
                              <td className="font-bold">{item.score}</td>
                              <td>
                                <StatusBadge status={item.status} />
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </Panel>
                ) : null}
              </div>

              <div className="space-y-6">
                <Panel title="Playbook de réponse" subtitle="Checklist SOC pour cet incident">
                  <ul className="space-y-3">
                    {playbook.map((step) => (
                      <li key={step.id} className="flex items-start gap-2.5">
                        {step.done ? (
                          <CheckCircle2 className="w-4 h-4 text-brand-success shrink-0 mt-0.5" />
                        ) : (
                          <Circle className="w-4 h-4 text-slate-300 shrink-0 mt-0.5" />
                        )}
                        <div>
                          <p
                            className={`text-xs font-semibold ${
                              step.done ? 'text-text-muted line-through' : 'text-text-main'
                            }`}
                          >
                            {step.label}
                            {step.required_role ? (
                              <span className="ml-1.5 text-[10px] font-medium text-text-muted">
                                ({step.required_role})
                              </span>
                            ) : null}
                          </p>
                          {step.hint ? (
                            <p className="text-[10px] text-text-muted mt-0.5">{step.hint}</p>
                          ) : null}
                        </div>
                      </li>
                    ))}
                  </ul>
                  {!hasRole('N2') ? (
                    <p className="text-[10px] text-text-muted mt-4 pt-3 border-t border-border flex items-start gap-2">
                      <ShieldAlert className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                      Escaladez à un N2 pour le confinement (kill / isolation).
                    </p>
                  ) : null}
                </Panel>

                <Panel title="Qualification">
                  <div className="space-y-3">
                    <textarea
                      value={note}
                      onChange={(event) => setNote(event.target.value)}
                      rows={4}
                      placeholder="Note de résolution partagée avec l'équipe…"
                      className="w-full px-3 py-2 rounded-lg border border-border text-xs focus:outline-none focus:ring-2 focus:ring-brand-primary/20"
                    />
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
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
