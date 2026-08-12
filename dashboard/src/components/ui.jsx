/** Briques d'interface partagées, alignées sur les classes définies dans index.css. */

import { AlertCircle, Inbox, Loader2 } from 'lucide-react';

export function StatCard({ label, value, hint, tone = 'muted' }) {
  const tones = {
    muted: 'text-text-muted',
    success: 'text-brand-success',
    warning: 'text-brand-warning',
    danger: 'text-brand-danger',
  };
  return (
    <div className="card-stat">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {hint ? <span className={`stat-desc ${tones[tone] || tones.muted}`}>{hint}</span> : null}
    </div>
  );
}

export function Panel({ title, subtitle, actions, children, className = '' }) {
  return (
    <div className={`panel ${className}`}>
      {(title || actions) && (
        <div className="flex items-start justify-between mb-5">
          <div>
            {title ? <h2 className="panel-title">{title}</h2> : null}
            {subtitle ? <p className="text-xs text-text-muted mt-1">{subtitle}</p> : null}
          </div>
          {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
        </div>
      )}
      {children}
    </div>
  );
}

const SEVERITY_STYLES = {
  high: 'badge-danger',
  medium: 'badge-warning',
  low: 'badge-success',
};

const SEVERITY_LABELS = { high: 'Critique', medium: 'Modérée', low: 'Faible' };

export function SeverityBadge({ severity }) {
  return (
    <span className={`badge ${SEVERITY_STYLES[severity] || 'badge-success'}`}>
      {SEVERITY_LABELS[severity] || severity}
    </span>
  );
}

const STATUS_STYLES = {
  new: 'badge-danger',
  acknowledged: 'badge-warning',
  in_progress: 'badge-warning',
  closed: 'badge-success',
  false_positive: 'bg-gray-100 text-text-muted border border-border',
};

export const STATUS_LABELS = {
  new: 'Nouvelle',
  acknowledged: 'Prise en compte',
  in_progress: 'En cours',
  closed: 'Clôturée',
  false_positive: 'Faux positif',
};

export function StatusBadge({ status }) {
  return (
    <span className={`badge ${STATUS_STYLES[status] || 'badge-success'}`}>
      {STATUS_LABELS[status] || status}
    </span>
  );
}

const COMMAND_STATUS_STYLES = {
  pending: 'badge-warning',
  sent: 'badge-warning',
  acked: 'badge-success',
  failed: 'badge-danger',
  expired: 'bg-gray-100 text-text-muted border border-border',
};

const COMMAND_STATUS_LABELS = {
  pending: 'En attente',
  sent: 'Transmise',
  acked: 'Exécutée',
  failed: 'Échec',
  expired: 'Expirée',
};

export function CommandStatusBadge({ status }) {
  return (
    <span className={`badge ${COMMAND_STATUS_STYLES[status] || 'badge-success'}`}>
      {COMMAND_STATUS_LABELS[status] || status}
    </span>
  );
}

export function MachineStatusBadge({ status }) {
  const map = {
    online: { className: 'badge-success', label: 'En ligne' },
    offline: { className: 'bg-gray-100 text-text-muted border border-border', label: 'Hors ligne' },
    isolated: { className: 'badge-danger', label: 'Isolée' },
  };
  const entry = map[status] || map.offline;
  return <span className={`badge ${entry.className}`}>{entry.label}</span>;
}

export function RoleBadge({ role }) {
  const labels = { N1: 'Analyste SOC (N1)', N2: 'Analyste EDR (N2)', N3: 'SOC Manager (N3)' };
  return (
    <span className="badge bg-brand-primaryGlow text-brand-primary border border-border">
      {labels[role] || role}
    </span>
  );
}

export function Spinner({ label = 'Chargement…' }) {
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-xs text-text-muted">
      <Loader2 className="w-4 h-4 animate-spin" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({ title, description, icon: Icon = Inbox }) {
  return (
    <div className="flex flex-col items-center justify-center py-14 text-center">
      <Icon className="w-8 h-8 text-text-muted mb-3" />
      <p className="text-sm font-semibold text-text-main">{title}</p>
      {description ? (
        <p className="text-xs text-text-muted mt-1 max-w-md">{description}</p>
      ) : null}
    </div>
  );
}

export function ErrorState({ error, onRetry }) {
  return (
    <div className="flex flex-col items-center justify-center py-14 text-center">
      <AlertCircle className="w-8 h-8 text-brand-danger mb-3" />
      <p className="text-sm font-semibold text-text-main">Impossible de charger ces données</p>
      <p className="text-xs text-text-muted mt-1 max-w-lg">{error?.message}</p>
      {onRetry ? (
        <button type="button" onClick={onRetry} className="btn btn-outline mt-4">
          Réessayer
        </button>
      ) : null}
    </div>
  );
}

/** Enveloppe standard : squelette, erreur, vide, contenu. */
export function AsyncSection({ loading, error, isEmpty, empty, onRetry, children }) {
  if (loading) return <Spinner />;
  if (error) return <ErrorState error={error} onRetry={onRetry} />;
  if (isEmpty) return empty ?? <EmptyState title="Aucune donnée" />;
  return children;
}

export function Toast({ toast, onClose }) {
  if (!toast) return null;
  const tones = {
    success: 'bg-brand-successGlow border-green-200 text-brand-success',
    error: 'bg-brand-dangerGlow border-red-200 text-brand-danger',
    info: 'bg-brand-primaryGlow border-border text-brand-primary',
  };
  return (
    <div className="fixed bottom-6 right-6 z-50">
      <div
        className={`flex items-start gap-3 px-4 py-3 rounded-xl border shadow-lg text-xs font-medium max-w-md ${
          tones[toast.tone] || tones.info
        }`}
      >
        <span className="flex-1">{toast.message}</span>
        <button type="button" onClick={onClose} className="opacity-60 hover:opacity-100">
          ✕
        </button>
      </div>
    </div>
  );
}

export function formatDateTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString('fr-FR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatRelative(value) {
  if (!value) return '—';
  const seconds = Math.floor((Date.now() - new Date(value).getTime()) / 1000);
  if (Number.isNaN(seconds)) return '—';
  if (seconds < 10) return "à l'instant";
  if (seconds < 60) return `il y a ${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `il y a ${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `il y a ${hours} h`;
  return `il y a ${Math.floor(hours / 24)} j`;
}
