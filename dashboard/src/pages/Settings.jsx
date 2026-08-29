/**
 * Configuration système.
 *
 * L'ancien onglet se contentait d'un `alert('Configuration sauvegardée')` : rien
 * n'était transmis au serveur. Les valeurs sont maintenant persistées dans la
 * table `app_settings`, donc partagées par toute l'équipe et conservées après
 * redémarrage.
 */

import { useEffect, useState } from 'react';
import { Save } from 'lucide-react';
import { settings as settingsApi } from '../api/endpoints';
import { useResource } from '../hooks/useResource';
import { useAuth } from '../auth/AuthContext';
import { AsyncSection, Panel, formatDateTime } from '../components/ui';

const FIELDS = {
  detection: [
    {
      key: 'auto_kill_score_threshold',
      label: 'Seuil de score déclenchant un arrêt automatique',
      type: 'number',
      min: 0,
      max: 100,
      hint: 'Au-delà de ce score, le moteur envoie un ordre KILL sans intervention humaine.',
    },
    {
      key: 'rules_alert_threshold',
      label: "Seuil de risque du moteur heuristique",
      type: 'number',
      min: 0,
      max: 1,
      step: 0.05,
      hint: 'Score normalisé (0 à 1) à partir duquel une fenêtre devient une alerte.',
    },
    {
      key: 'baseline_min_vectors',
      label: 'Fenêtres nécessaires pour entraîner une baseline',
      type: 'number',
      min: 1,
      max: 1000,
      hint: 'Nombre de fenêtres de 10 s observées avant de passer en mode détection.',
    },
  ],
  retention: [
    { key: 'metrics_days', label: 'Rétention des métriques (jours)', type: 'number', min: 1, max: 365 },
    { key: 'alerts_days', label: 'Rétention des alertes (jours)', type: 'number', min: 1, max: 3650 },
  ],
  notifications: [
    { key: 'email_enabled', label: 'Notifications par courriel', type: 'boolean' },
    { key: 'webhook_url', label: 'URL de webhook', type: 'text' },
  ],
};

const SECTION_TITLES = {
  detection: 'Moteur de détection',
  retention: 'Rétention des données',
  notifications: 'Notifications',
};

const SECTION_NOTES = {
  detection:
    "Ces seuils sont partagés par tous les analystes. Les valeurs appliquées au démarrage viennent du fichier .env ; celles définies ici les documentent et servent de référence d'équipe.",
  retention: 'La purge des métriques est exécutée par la tâche de maintenance de l\'API.',
  notifications: 'Réservé aux intégrations externes (SIEM, messagerie d\'équipe).',
};

export default function Settings({ onToast }) {
  const { hasRole } = useAuth();
  const canEdit = hasRole('N3');

  const { data, loading, error, reload } = useResource((signal) => settingsApi.list(signal), {
    channels: [],
  });

  const [draft, setDraft] = useState({});
  const [saving, setSaving] = useState(null);

  useEffect(() => {
    if (!data) return;
    setDraft(
      data.reduce((acc, entry) => ({ ...acc, [entry.key]: { ...entry.value } }), {}),
    );
  }, [data]);

  const update = (sectionKey, fieldKey, value) => {
    setDraft((previous) => ({
      ...previous,
      [sectionKey]: { ...(previous[sectionKey] || {}), [fieldKey]: value },
    }));
  };

  const save = async (sectionKey) => {
    setSaving(sectionKey);
    try {
      await settingsApi.update(sectionKey, draft[sectionKey]);
      onToast({ tone: 'success', message: `${SECTION_TITLES[sectionKey]} enregistré.` });
      reload();
    } catch (err) {
      onToast({ tone: 'error', message: err.message });
    } finally {
      setSaving(null);
    }
  };

  return (
    <AsyncSection loading={loading} error={error} onRetry={reload} isEmpty={!data}>
      <div className="space-y-6">
        {!canEdit ? (
          <div className="panel bg-brand-warningGlow border-yellow-200">
            <p className="text-xs text-brand-warning font-medium">
              La configuration système est modifiable uniquement par un SOC Manager (N3). Les
              valeurs en vigueur sont affichées en lecture seule.
            </p>
          </div>
        ) : null}

        {(data || []).map((entry) => {
          const fields = FIELDS[entry.key] || [];
          const values = draft[entry.key] || entry.value;

          return (
            <Panel
              key={entry.key}
              title={SECTION_TITLES[entry.key] || entry.key}
              subtitle={SECTION_NOTES[entry.key]}
              actions={
                canEdit ? (
                  <button
                    type="button"
                    onClick={() => save(entry.key)}
                    disabled={saving === entry.key}
                    className="btn btn-primary disabled:opacity-50"
                  >
                    <Save className="w-3.5 h-3.5" />
                    {saving === entry.key ? 'Enregistrement…' : 'Enregistrer'}
                  </button>
                ) : null
              }
            >
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-5">
                {fields.map((field) => (
                  <div key={field.key}>
                    <label htmlFor={`${entry.key}-${field.key}`} className="stat-label block mb-1.5">
                      {field.label}
                    </label>

                    {field.type === 'boolean' ? (
                      <button
                        type="button"
                        disabled={!canEdit}
                        onClick={() => update(entry.key, field.key, !values?.[field.key])}
                        className={`badge ${values?.[field.key] ? 'badge-success' : 'bg-gray-100 text-text-muted border border-border'}`}
                      >
                        {values?.[field.key] ? 'Activé' : 'Désactivé'}
                      </button>
                    ) : (
                      <input
                        id={`${entry.key}-${field.key}`}
                        type={field.type}
                        min={field.min}
                        max={field.max}
                        step={field.step}
                        disabled={!canEdit}
                        value={values?.[field.key] ?? ''}
                        onChange={(event) =>
                          update(
                            entry.key,
                            field.key,
                            field.type === 'number'
                              ? Number(event.target.value)
                              : event.target.value,
                          )
                        }
                        className="w-full px-3 py-2 rounded-lg border border-border text-xs disabled:bg-gray-50 disabled:text-text-muted focus:outline-none focus:ring-2 focus:ring-brand-primary/20"
                      />
                    )}

                    {field.hint ? (
                      <p className="text-[10px] text-text-muted mt-1.5 leading-relaxed">
                        {field.hint}
                      </p>
                    ) : null}
                  </div>
                ))}
              </div>

              <p className="text-[10px] text-text-muted mt-5 pt-3 border-t border-border">
                Dernière modification : {formatDateTime(entry.updated_at)}
                {entry.updated_by_email ? ` par ${entry.updated_by_email}` : ''}
              </p>
            </Panel>
          );
        })}
      </div>
    </AsyncSection>
  );
}
