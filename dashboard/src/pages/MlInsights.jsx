/**
 * Statistiques du moteur ML.
 *
 * L'ancien onglet affichait un score F1 de 0.94, une précision de 96 % et une
 * liste d'importances de features entièrement écrite dans le JSX, sans aucun
 * lien avec le modèle réellement chargé. Ces valeurs sont maintenant lues sur
 * l'objet `RandomForestClassifier` en mémoire côté API.
 */

import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Brain } from 'lucide-react';
import { metrics as metricsApi } from '../api/endpoints';
import { useResource } from '../hooks/useResource';
import { AsyncSection, EmptyState, Panel, StatCard } from '../components/ui';

const FEATURE_LABELS = {
  nb_files_created: 'Fichiers créés',
  nb_files_deleted: 'Fichiers supprimés',
  nb_files_renamed: 'Fichiers renommés',
  nb_unique_extensions: 'Extensions distinctes',
  entropy_filenames: 'Entropie des noms',
  nb_processes_created: 'Processus créés',
  nb_child_processes: 'Processus enfants',
  process_depth: 'Profondeur de processus',
  nb_connections: 'Connexions réseau',
  nb_unique_ips: 'IP distinctes',
  nb_external_connections: 'Connexions externes',
  nb_dns_queries: 'Requêtes DNS',
};

export default function MlInsights() {
  const { data, loading, error, reload } = useResource(
    (signal) => metricsApi.mlInsights(signal),
    { channels: ['alerts'] },
  );

  const model = data?.model || {};
  const importances = (data?.feature_importances || []).map((item) => ({
    name: FEATURE_LABELS[item.feature] || item.feature,
    importance: Number((item.importance * 100).toFixed(2)),
  }));
  const baselines = Object.entries(data?.baseline_progress || {});

  return (
    <AsyncSection loading={loading} error={error} onRetry={reload} isEmpty={!data}>
      <div className="space-y-6">
        <div className="grid grid-cols-4 gap-5">
          <StatCard
            label="Modèle chargé"
            value={model.enabled ? model.algorithm : 'Aucun'}
            hint={model.enabled ? 'Inférence active à chaque fenêtre' : 'Détection heuristique seule'}
            tone={model.enabled ? 'success' : 'warning'}
          />
          <StatCard
            label="Arbres de décision"
            value={model.n_estimators ?? '—'}
            hint={model.max_depth ? `Profondeur max ${model.max_depth}` : 'Profondeur illimitée'}
          />
          <StatCard
            label="Features en entrée"
            value={model.n_features ?? '—'}
            hint="Vecteur comportemental sur 10 secondes"
          />
          <StatCard
            label="Baselines entraînées"
            value={`${baselines.filter(([, value]) => value.trained).length}/${baselines.length || 0}`}
            hint="Une baseline par terminal surveillé"
            tone={baselines.some(([, value]) => !value.trained) ? 'warning' : 'success'}
          />
        </div>

        <Panel
          title="Importance réelle des features"
          subtitle="Extraite du modèle Random Forest entraîné, pas d'une constante d'interface"
        >
          {importances.length > 0 ? (
            <ResponsiveContainer width="100%" height={Math.max(260, importances.length * 26)}>
              <BarChart
                data={importances}
                layout="vertical"
                margin={{ top: 5, right: 24, left: 130, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" horizontal={false} />
                <XAxis
                  type="number"
                  unit="%"
                  tick={{ fontSize: 10, fill: '#64748b' }}
                  stroke="#e5e7eb"
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={130}
                  tick={{ fontSize: 10, fill: '#64748b' }}
                  stroke="#e5e7eb"
                />
                <Tooltip
                  formatter={(value) => [`${value} %`, 'Poids dans la décision']}
                  contentStyle={{ fontSize: 11, borderRadius: 10 }}
                />
                <Bar dataKey="importance" radius={[0, 4, 4, 0]}>
                  {importances.map((entry, index) => (
                    <Cell key={entry.name} fill={index === 0 ? '#dc2626' : '#0f172a'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState
              icon={Brain}
              title="Modèle ML non chargé"
              description="Placez random_forest_model.pkl et scaler.pkl dans le dossier models/, puis redémarrez l'API."
            />
          )}
        </Panel>

        <div className="grid grid-cols-2 gap-6">
          <Panel
            title="Origine des détections"
            subtitle="Répartition des alertes réellement enregistrées en base"
          >
            {(data?.detections_by_source || []).length > 0 ? (
              <div className="table-container">
                <table className="custom-table">
                  <thead>
                    <tr>
                      <th>Moteur</th>
                      <th>Alertes levées</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.detections_by_source.map((row) => (
                      <tr key={row.source}>
                        <td className="font-semibold">{row.source}</td>
                        <td>{row.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState title="Aucune détection à ce jour" />
            )}
          </Panel>

          <Panel
            title="Apprentissage des baselines"
            subtitle="Chaque terminal apprend son propre comportement normal"
          >
            {baselines.length > 0 ? (
              <div className="space-y-4">
                {baselines.map(([machineId, progress]) => {
                  const ratio = progress.required
                    ? Math.min(100, Math.round((progress.vectors / progress.required) * 100))
                    : 0;
                  return (
                    <div key={machineId}>
                      <div className="flex items-center justify-between text-xs mb-1.5">
                        <span className="font-semibold">{machineId}</span>
                        <span className={progress.trained ? 'text-brand-success' : 'text-brand-warning'}>
                          {progress.trained
                            ? 'Mode détection'
                            : `Apprentissage ${progress.vectors}/${progress.required}`}
                        </span>
                      </div>
                      <div className="w-full h-1.5 bg-gray-100 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            progress.trained ? 'bg-brand-success' : 'bg-brand-warning'
                          }`}
                          style={{ width: `${progress.trained ? 100 : ratio}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
                <p className="text-[10px] text-text-muted border-t border-border pt-3">
                  Tant qu'une baseline n'est pas calculée, le moteur observe sans lever d'alerte :
                  c'est ce qui évite les faux positifs au démarrage.
                </p>
              </div>
            ) : (
              <EmptyState
                title="Aucun pipeline actif"
                description="Les baselines se créent au premier lot d'événements reçu de chaque terminal."
              />
            )}
          </Panel>
        </div>
      </div>
    </AsyncSection>
  );
}
