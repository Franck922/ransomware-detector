/**
 * Règles d'exclusion.
 *
 * Deux différences majeures : ces règles sont désormais réellement appliquées
 * par le moteur de détection (elles étaient auparavant stockées et affichées
 * sans aucun effet), et leur modification est réservée au niveau N3 puisqu'elle
 * réduit la couverture de surveillance.
 */

import { useState } from 'react';
import { CheckCircle, Plus, Trash2 } from 'lucide-react';
import { exclusions as exclusionsApi } from '../api/endpoints';
import { useResource } from '../hooks/useResource';
import { useAuth } from '../auth/AuthContext';
import { useRealtime } from '../realtime/RealtimeProvider';
import { AsyncSection, EmptyState, Panel, formatDateTime } from '../components/ui';

const TYPES = [
  { value: 'Folder', label: 'Dossier', placeholder: 'C:\\Program Files\\Git\\' },
  { value: 'Process', label: 'Processus', placeholder: 'C:\\Windows\\System32\\svchost.exe' },
  { value: 'Extension', label: 'Extension', placeholder: '.tmp' },
];

export default function Exclusions({ onToast }) {
  const { hasRole } = useAuth();
  const { invalidate } = useRealtime();
  const canManage = hasRole('N3');

  const [type, setType] = useState('Folder');
  const [path, setPath] = useState('');
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState(false);

  const { data, loading, error, reload } = useResource((signal) => exclusionsApi.list(signal), {
    channels: ['exclusions'],
  });

  const items = data || [];
  const currentType = TYPES.find((option) => option.value === type);

  const handleCreate = async (event) => {
    event.preventDefault();
    if (!path.trim() || busy) return;
    setBusy(true);
    try {
      await exclusionsApi.create({ type, path: path.trim(), comment: comment.trim() });
      setPath('');
      setComment('');
      invalidate(['exclusions', 'audit']);
      onToast({
        tone: 'success',
        message: 'Exclusion enregistrée : le moteur la prend en compte sous 10 secondes.',
      });
    } catch (err) {
      onToast({ tone: 'error', message: err.message });
    } finally {
      setBusy(false);
    }
  };

  const handleToggle = async (exclusion) => {
    try {
      await exclusionsApi.toggle(exclusion.id);
      invalidate(['exclusions', 'audit']);
    } catch (err) {
      onToast({ tone: 'error', message: err.message });
    }
  };

  const handleDelete = async (exclusion) => {
    try {
      await exclusionsApi.remove(exclusion.id);
      invalidate(['exclusions', 'audit']);
      onToast({ tone: 'success', message: 'Exclusion retirée.' });
    } catch (err) {
      onToast({ tone: 'error', message: err.message });
    }
  };

  return (
    <div className="space-y-6">
      {canManage ? (
        <Panel
          title="Nouvelle exclusion"
          subtitle="Un chemin exclu ne génère plus aucune détection : à utiliser avec parcimonie"
        >
          <form onSubmit={handleCreate} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-3 items-end">
            <div className="lg:col-span-2">
              <label htmlFor="type" className="stat-label block mb-1.5">
                Type
              </label>
              <select
                id="type"
                value={type}
                onChange={(event) => setType(event.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-border text-xs bg-white focus:outline-none"
              >
                {TYPES.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="sm:col-span-2 lg:col-span-5">
              <label htmlFor="path" className="stat-label block mb-1.5">
                Chemin ou motif
              </label>
              <input
                id="path"
                type="text"
                required
                value={path}
                onChange={(event) => setPath(event.target.value)}
                placeholder={currentType?.placeholder}
                className="w-full px-3 py-2 rounded-lg border border-border text-xs font-mono focus:outline-none focus:ring-2 focus:ring-brand-primary/20"
              />
            </div>
            <div className="lg:col-span-3">
              <label htmlFor="comment" className="stat-label block mb-1.5">
                Justification
              </label>
              <input
                id="comment"
                type="text"
                value={comment}
                onChange={(event) => setComment(event.target.value)}
                placeholder="Bruit de renommage connu"
                className="w-full px-3 py-2 rounded-lg border border-border text-xs focus:outline-none focus:ring-2 focus:ring-brand-primary/20"
              />
            </div>
            <div className="lg:col-span-2">
              <button type="submit" disabled={busy} className="btn btn-primary w-full disabled:opacity-50">
                <Plus className="w-3.5 h-3.5" />
                Ajouter
              </button>
            </div>
          </form>
        </Panel>
      ) : (
        <div className="panel bg-brand-warningGlow border-yellow-200">
          <p className="text-xs text-brand-warning font-medium">
            La gestion des exclusions est réservée au SOC Manager (N3). Vous pouvez consulter les
            règles en vigueur ci-dessous.
          </p>
        </div>
      )}

      <Panel title={`${items.length} règle(s) d'exclusion`}>
        <AsyncSection
          loading={loading}
          error={error}
          onRetry={reload}
          isEmpty={items.length === 0}
          empty={
            <EmptyState
              icon={CheckCircle}
              title="Aucune exclusion configurée"
              description="La totalité de l'activité des terminaux est analysée par le moteur."
            />
          }
        >
          <div className="table-container">
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Chemin</th>
                  <th>Justification</th>
                  <th>État</th>
                  <th>Créée par</th>
                  <th>Date</th>
                  {canManage ? <th className="text-right">Actions</th> : null}
                </tr>
              </thead>
              <tbody>
                {items.map((exclusion) => (
                  <tr key={exclusion.id}>
                    <td className="font-semibold">{exclusion.type}</td>
                    <td>
                      <span className="code-text">{exclusion.path}</span>
                    </td>
                    <td className="text-text-muted">{exclusion.comment || '—'}</td>
                    <td>
                      <span className={`badge ${exclusion.enabled ? 'badge-success' : 'bg-gray-100 text-text-muted border border-border'}`}>
                        {exclusion.enabled ? 'Active' : 'Désactivée'}
                      </span>
                    </td>
                    <td className="text-text-muted">{exclusion.created_by_email || 'Import initial'}</td>
                    <td className="text-text-muted whitespace-nowrap">
                      {formatDateTime(exclusion.created_at)}
                    </td>
                    {canManage ? (
                      <td className="text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={() => handleToggle(exclusion)}
                          className="btn btn-outline mr-2"
                        >
                          {exclusion.enabled ? 'Désactiver' : 'Activer'}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDelete(exclusion)}
                          className="btn btn-outline text-brand-danger hover:bg-red-50"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    ) : null}
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
