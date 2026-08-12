/**
 * Vue d'ensemble du SOC.
 *
 * Tout ce qui est affiché ici provient de l'API :
 *   - le graphique lit /metrics/timeseries (l'ancienne version contenait un
 *     tableau `chartData` écrit en dur dans le JSX, avec un pic factice à 231
 *     fichiers dès qu'une alerte existait) ;
 *   - les compteurs et le score de risque viennent de /metrics/overview, calculés
 *     en base (l'ancienne jauge affichait 92 % de façon forfaitaire).
 *
 * Conséquence : deux analystes connectés voient les mêmes valeurs parce qu'elles
 * sont issues de la même requête sur la même base, et non parce qu'elles sont
 * constantes.
 */

import { useState } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Activity, ShieldAlert, Users } from 'lucide-react';
import { alerts as alertsApi, metrics as metricsApi } from '../api/endpoints';
import { useResource } from '../hooks/useResource';
import {
  AsyncSection,
  EmptyState,
  Panel,
  SeverityBadge,
  StatCard,
  StatusBadge,
  formatDateTime,
  formatTime,
} from '../components/ui';

const WINDOWS = [
  { label: '15 min', minutes: 15, bucket: 10 },
  { label: '1 h', minutes: 60, bucket: 30 },
  { label: '6 h', minutes: 360, bucket: 180 },
  { label: '24 h', minutes: 1440, bucket: 600 },
];

const RISK_TONES = {
  Faible: { text: 'text-brand-success', bar: 'bg-brand-success' },
  Modéré: { text: 'text-brand-warning', bar: 'bg-brand-warning' },
  Élevé: { text: 'text-brand-warning', bar: 'bg-brand-warning' },
  Critique: { text: 'text-brand-danger', bar: 'bg-brand-danger' },
};

export default function Overview({ onOpenAlert }) {
  const [windowIndex, setWindowIndex] = useState(0);
  const selected = WINDOWS[windowIndex];

  const overview = useResource((signal) => metricsApi.overview(signal), {
    channels: ['alerts', 'metrics', 'machines', 'commands'],
  });

  const series = useResource(
    (signal) =>
      metricsApi.timeseries(
        { window_minutes: selected.minutes, bucket_seconds: selected.bucket },
        signal,
      ),
    { channels: ['metrics', 'alerts'], deps: [selected.minutes, selected.bucket] },
  );

  const recent = useResource(
    (signal) => alertsApi.list({ limit: 8 }, signal),
    { channels: ['alerts'] },
  );

  const data = overview.data;
  const riskTone = RISK_TONES[data?.risk_label] || RISK_TONES.Faible;

  const chartData = (series.data?.points || []).map((point) => ({
    time: formatTime(point.bucket),
    fichiers: point.files_created,
    supprimes: point.files_deleted,
    entropie: point.entropy_max,
    alertes: point.alerts,
  }));

  const hasActivity = chartData.some(
    (point) => point.fichiers > 0 || point.supprimes > 0 || point.alertes > 0,
  );

  return (
    <div className="space-y-8">
      <div className="grid grid-cols-4 gap-5">
        <StatCard
          label="Terminaux surveillés"
          value={data ? data.machines_total : '—'}
          hint={
            data
              ? `${data.machines_online} en ligne${
                  data.machines_isolated ? ` · ${data.machines_isolated} isolé(s)` : ''
                }`
              : 'Chargement…'
          }
          tone={data?.machines_isolated ? 'danger' : 'success'}
        />
        <StatCard
          label="Alertes ouvertes"
          value={data ? data.alerts_open : '—'}
          hint={data ? `${data.alerts_critical_open} critique(s) non traitée(s)` : 'Chargement…'}
          tone={data?.alerts_critical_open ? 'danger' : 'success'}
        />
        <StatCard
          label="Réponses en attente"
          value={data ? data.commands_pending : '—'}
          hint={data ? `${data.alerts_last_24h} alerte(s) sur 24 h` : 'Chargement…'}
          tone={data?.commands_pending ? 'warning' : 'muted'}
        />
        <StatCard
          label="Moteur de détection"
          value={data ? (data.ml_enabled ? 'Heuristique + ML' : 'Heuristique') : '—'}
          hint={
            data
              ? `${data.baseline_trained_machines} baseline(s) entraînée(s) · ${data.events_last_hour} évts/h`
              : 'Chargement…'
          }
          tone={data?.ml_enabled ? 'success' : 'warning'}
        />
      </div>

      <div className="grid grid-cols-3 gap-6">
        <Panel
          className="col-span-2"
          title="Activité fichiers et entropie"
          subtitle={
            series.data
              ? `Agrégation serveur par intervalle de ${series.data.bucket_seconds} s`
              : 'Chargement de la série temporelle'
          }
          actions={
            <div className="flex items-center gap-1 bg-gray-50 rounded-lg p-1 border border-border">
              {WINDOWS.map((option, index) => (
                <button
                  key={option.label}
                  type="button"
                  onClick={() => setWindowIndex(index)}
                  className={`px-2.5 py-1 rounded-md text-[10px] font-semibold transition-all ${
                    index === windowIndex
                      ? 'bg-white text-brand-primary shadow-sm'
                      : 'text-text-muted hover:text-text-main'
                  }`}
                >
                  {option.label}
                </button>
              ))}
            </div>
          }
        >
          <AsyncSection
            loading={series.loading}
            error={series.error}
            onRetry={series.reload}
            isEmpty={chartData.length === 0}
            empty={
              <EmptyState
                title="Aucune donnée sur la période"
                description="Le graphique se remplira dès que l'agent Winlogbeat enverra des événements Sysmon."
                icon={Activity}
              />
            }
          >
            <>
              <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={chartData} margin={{ top: 5, right: 8, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="filesGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#0f172a" stopOpacity={0.25} />
                      <stop offset="100%" stopColor="#0f172a" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="deletedGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#d97706" stopOpacity={0.25} />
                      <stop offset="100%" stopColor="#d97706" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} />
                  <XAxis
                    dataKey="time"
                    tick={{ fontSize: 10, fill: '#64748b' }}
                    stroke="#e5e7eb"
                    minTickGap={28}
                  />
                  <YAxis
                    yAxisId="left"
                    tick={{ fontSize: 10, fill: '#64748b' }}
                    stroke="#e5e7eb"
                    allowDecimals={false}
                  />
                  <YAxis
                    yAxisId="right"
                    orientation="right"
                    domain={[0, 8]}
                    tick={{ fontSize: 10, fill: '#64748b' }}
                    stroke="#e5e7eb"
                  />
                  <Tooltip
                    contentStyle={{
                      fontSize: 11,
                      borderRadius: 10,
                      border: '1px solid #e5e7eb',
                      boxShadow: '0 4px 12px rgba(15,23,42,0.08)',
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: 10 }} />
                  <Area
                    yAxisId="left"
                    type="monotone"
                    dataKey="fichiers"
                    name="Fichiers créés"
                    stroke="#0f172a"
                    strokeWidth={2}
                    fill="url(#filesGradient)"
                  />
                  <Area
                    yAxisId="left"
                    type="monotone"
                    dataKey="supprimes"
                    name="Fichiers supprimés"
                    stroke="#d97706"
                    strokeWidth={2}
                    fill="url(#deletedGradient)"
                  />
                  <Line
                    yAxisId="right"
                    type="monotone"
                    dataKey="entropie"
                    name="Entropie max (Shannon)"
                    stroke="#dc2626"
                    strokeWidth={2}
                    dot={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
              {!hasActivity ? (
                <p className="text-[10px] text-text-muted mt-2">
                  Aucune activité mesurée sur la fenêtre sélectionnée : la courbe est à zéro, ce
                  n'est pas une absence de données.
                </p>
              ) : null}
            </>
          </AsyncSection>
        </Panel>

        <div className="space-y-6">
          <Panel title="Score de risque du parc">
            {data ? (
              <div className="space-y-4">
                <div className="flex items-end justify-between">
                  <span className={`text-4xl font-bold tracking-tight ${riskTone.text}`}>
                    {data.risk_score}
                    <span className="text-lg">/100</span>
                  </span>
                  <span className={`text-xs font-bold ${riskTone.text}`}>{data.risk_label}</span>
                </div>
                <div className="w-full h-2 bg-gray-100 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${riskTone.bar}`}
                    style={{ width: `${data.risk_score}%` }}
                  />
                </div>
                <dl className="text-[10px] text-text-muted space-y-1 border-t border-border pt-3">
                  <div className="flex justify-between">
                    <dt>Alertes critiques ouvertes</dt>
                    <dd className="font-semibold text-text-main">{data.alerts_critical_open}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt>Machines isolées</dt>
                    <dd className="font-semibold text-text-main">{data.machines_isolated}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt>Commandes en attente</dt>
                    <dd className="font-semibold text-text-main">{data.commands_pending}</dd>
                  </div>
                </dl>
                <p className="text-[10px] text-text-muted leading-relaxed">
                  Calculé côté serveur à partir des alertes ouvertes, de l'état d'isolation et de la
                  file de réponses. Identique pour tous les analystes.
                </p>
              </div>
            ) : (
              <p className="text-xs text-text-muted">Chargement…</p>
            )}
          </Panel>

          <Panel title="Analystes connectés">
            <div className="flex items-center gap-3">
              <Users className="w-5 h-5 text-text-muted" />
              <span className="text-2xl font-bold">{data?.connected_analysts ?? '—'}</span>
              <span className="text-xs text-text-muted">session(s) temps réel</span>
            </div>
            <p className="text-[10px] text-text-muted mt-3">
              Dernière agrégation : {formatDateTime(data?.generated_at)}
            </p>
          </Panel>
        </div>
      </div>

      <Panel
        title="Dernières alertes"
        subtitle="Cliquez sur une ligne pour ouvrir l'analyse forensics"
      >
        <AsyncSection
          loading={recent.loading}
          error={recent.error}
          onRetry={recent.reload}
          isEmpty={(recent.data?.items || []).length === 0}
          empty={
            <EmptyState
              title="Aucune alerte enregistrée"
              description="Le moteur n'a détecté aucun comportement suspect depuis le démarrage."
              icon={ShieldAlert}
            />
          }
        >
          <div className="table-container">
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Horodatage</th>
                  <th>Terminal</th>
                  <th>Processus</th>
                  <th>Score</th>
                  <th>Gravité</th>
                  <th>Statut</th>
                  <th>Prise en charge</th>
                </tr>
              </thead>
              <tbody>
                {(recent.data?.items || []).map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => onOpenAlert(alert.id)}
                    className="cursor-pointer"
                  >
                    <td className="whitespace-nowrap">{formatDateTime(alert.detected_at)}</td>
                    <td className="font-medium">{alert.machine_id || '—'}</td>
                    <td>
                      <span className="code-text">{alert.process_name || 'inconnu'}</span>
                      {alert.pid ? (
                        <span className="text-text-muted ml-1.5">PID {alert.pid}</span>
                      ) : null}
                    </td>
                    <td className="font-bold">{alert.score}</td>
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td>
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="text-text-muted">{alert.assigned_to_email || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </AsyncSection>
      </Panel>
    </div>
  );
}
