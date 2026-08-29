/**
 * Journal des alertes avec filtres et pagination.
 *
 * L'ancien onglet affichait l'intégralité de l'historique en une requête, sans
 * filtre ni notion de statut : deux analystes ne pouvaient pas se répartir le
 * travail. Le cycle de vie (nouvelle / en cours / clôturée) et l'affectation
 * sont maintenant partagés en base et diffusés en temps réel.
 */

import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { alerts as alertsApi } from '../api/endpoints';
import { useResource } from '../hooks/useResource';
import {
  AsyncSection,
  EmptyState,
  Panel,
  SeverityBadge,
  StatusBadge,
  STATUS_LABELS,
  formatDateTime,
} from '../components/ui';

const PAGE_SIZE = 25;

const STATUS_FILTERS = [
  { value: '', label: 'Toutes' },
  { value: 'new', label: 'Nouvelles' },
  { value: 'in_progress', label: 'En cours' },
  { value: 'closed', label: 'Clôturées' },
  { value: 'false_positive', label: 'Faux positifs' },
];

const SEVERITY_FILTERS = [
  { value: '', label: 'Toutes gravités' },
  { value: 'high', label: 'Critique' },
  { value: 'medium', label: 'Modérée' },
  { value: 'low', label: 'Faible' },
];

export default function Alerts({ onOpenAlert }) {
  const [status, setStatus] = useState('');
  const [severity, setSeverity] = useState('');
  const [machineId, setMachineId] = useState('');
  const [unassignedOnly, setUnassignedOnly] = useState(false);
  const [sort, setSort] = useState('detected_at');
  const [page, setPage] = useState(0);

  const { data, loading, error, reload } = useResource(
    (signal) =>
      alertsApi.list(
        {
          status: status || undefined,
          severity: severity || undefined,
          machine_id: machineId || undefined,
          open_only: unassignedOnly || undefined,
          unassigned_only: unassignedOnly || undefined,
          sort,
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
        },
        signal,
      ),
    { channels: ['alerts'], deps: [status, severity, machineId, unassignedOnly, sort, page] },
  );

  const items = data?.items || [];
  const total = data?.total || 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const resetTo = (setter) => (value) => {
    setter(value);
    setPage(0);
  };

  return (
    <Panel
      title={`${total} alerte(s)`}
      subtitle={
        unassignedOnly
          ? 'File de triage : ouvertes, non assignées'
          : 'Filtrage et pagination appliqués côté serveur'
      }
      actions={
        <div className="flex items-center gap-2 flex-wrap justify-end">
          <button
            type="button"
            onClick={() => {
              setUnassignedOnly((value) => !value);
              setPage(0);
              if (!unassignedOnly) {
                setStatus('');
                setSort('score');
              }
            }}
            className={`btn ${unassignedOnly ? 'btn-primary' : 'btn-outline'}`}
          >
            File de triage
          </button>
          <select
            value={sort}
            onChange={(event) => resetTo(setSort)(event.target.value)}
            className="px-2.5 py-1.5 rounded-lg border border-border text-[11px] bg-white focus:outline-none"
            title="Ordre de tri"
          >
            <option value="detected_at">Plus récentes</option>
            <option value="score">Score décroissant</option>
          </select>
          <input
            type="text"
            value={machineId}
            onChange={(event) => resetTo(setMachineId)(event.target.value)}
            placeholder="Filtrer par terminal"
            className="px-2.5 py-1.5 rounded-lg border border-border text-[11px] w-full sm:w-40 focus:outline-none focus:ring-2 focus:ring-brand-primary/20"
          />
          <select
            value={severity}
            onChange={(event) => resetTo(setSeverity)(event.target.value)}
            className="px-2.5 py-1.5 rounded-lg border border-border text-[11px] bg-white focus:outline-none"
          >
            {SEVERITY_FILTERS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          <div className="flex items-center gap-1 bg-gray-50 rounded-lg p-1 border border-border overflow-x-auto max-w-full">
            {STATUS_FILTERS.map((option) => (
              <button
                key={option.value}
                type="button"
                onClick={() => resetTo(setStatus)(option.value)}
                disabled={unassignedOnly}
                className={`px-2.5 py-1 rounded-md text-[10px] font-semibold transition-all whitespace-nowrap disabled:opacity-40 ${
                  status === option.value
                    ? 'bg-white text-brand-primary shadow-sm'
                    : 'text-text-muted hover:text-text-main'
                }`}
              >
                {option.label}
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
            title="Aucune alerte pour ces critères"
            description={
              status || severity || machineId
                ? 'Élargissez les filtres pour voir davantage de résultats.'
                : "Le moteur n'a rien détecté de suspect pour l'instant."
            }
            icon={ShieldCheck}
          />
        }
      >
        <>
          <div className="table-container">
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Horodatage</th>
                  <th>Terminal</th>
                  <th>Processus suspect</th>
                  <th>Parent</th>
                  <th>Score</th>
                  <th>Source</th>
                  <th>Gravité</th>
                  <th>Statut</th>
                  <th>Analyste</th>
                </tr>
              </thead>
              <tbody>
                {items.map((alert) => (
                  <tr key={alert.id} onClick={() => onOpenAlert(alert.id)} className="cursor-pointer">
                    <td className="whitespace-nowrap">{formatDateTime(alert.detected_at)}</td>
                    <td className="font-medium">{alert.machine_id || '—'}</td>
                    <td>
                      <span className="code-text">{alert.process_name || 'inconnu'}</span>
                      {alert.pid ? (
                        <span className="text-text-muted ml-1.5">PID {alert.pid}</span>
                      ) : null}
                    </td>
                    <td className="text-text-muted">{alert.parent_name || '—'}</td>
                    <td className="font-bold">{alert.score}</td>
                    <td className="text-text-muted">{alert.source}</td>
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

          {pageCount > 1 ? (
            <div className="flex items-center justify-between mt-5 pt-4 border-t border-border">
              <span className="text-[10px] text-text-muted">
                Page {page + 1} sur {pageCount} · {total} résultat(s)
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

export { STATUS_LABELS };
