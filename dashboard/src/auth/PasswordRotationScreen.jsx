/**
 * Rotation de mot de passe obligatoire.
 *
 * Affiché quand le serveur signale `must_change_password`. Ce n'est pas
 * seulement une contrainte d'interface : tant que la rotation n'est pas
 * effectuée, l'API refuse tout accès aux données (403), y compris pour un
 * client qui contournerait le dashboard.
 */

import { useMemo, useState } from 'react';
import { KeyRound, Loader2 } from 'lucide-react';
import { useAuth } from './AuthContext';

const MIN_LENGTH = 12;

function evaluate(password) {
  return [
    { label: `${MIN_LENGTH} caractères minimum`, ok: password.length >= MIN_LENGTH },
    { label: 'Une minuscule', ok: /[a-z]/.test(password) },
    { label: 'Une majuscule', ok: /[A-Z]/.test(password) },
    { label: 'Un chiffre', ok: /\d/.test(password) },
  ];
}

export default function PasswordRotationScreen() {
  const { user, changePassword, logout } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const rules = useMemo(() => evaluate(newPassword), [newPassword]);
  const mismatch = confirmation.length > 0 && confirmation !== newPassword;
  const ready = rules.every((rule) => rule.ok) && !mismatch && confirmation.length > 0;

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!ready || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await changePassword(currentPassword, newPassword);
    } catch (err) {
      setError(err.message);
      setCurrentPassword('');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-main px-4">
      <div className="w-full max-w-md">
        <div className="panel">
          <div className="flex items-center gap-2 mb-1">
            <KeyRound className="w-4 h-4 text-brand-warning" />
            <h1 className="text-sm font-bold tracking-tight">Renouvellement obligatoire</h1>
          </div>
          <p className="text-xs text-text-muted mb-6">
            Le compte <strong>{user?.email}</strong> utilise un mot de passe provisoire ou hérité de
            l'ancienne base. Il doit être remplacé avant tout accès aux données du SOC.
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="current" className="stat-label block mb-1.5">
                Mot de passe actuel
              </label>
              <input
                id="current"
                type="password"
                autoComplete="current-password"
                required
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
                className="w-full px-3 py-2.5 rounded-lg border border-border text-xs focus:outline-none focus:ring-2 focus:ring-brand-primary/20"
              />
            </div>

            <div>
              <label htmlFor="new" className="stat-label block mb-1.5">
                Nouveau mot de passe
              </label>
              <input
                id="new"
                type="password"
                autoComplete="new-password"
                required
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                className="w-full px-3 py-2.5 rounded-lg border border-border text-xs focus:outline-none focus:ring-2 focus:ring-brand-primary/20"
              />
            </div>

            <div>
              <label htmlFor="confirm" className="stat-label block mb-1.5">
                Confirmation
              </label>
              <input
                id="confirm"
                type="password"
                autoComplete="new-password"
                required
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
                className={`w-full px-3 py-2.5 rounded-lg border text-xs focus:outline-none focus:ring-2 ${
                  mismatch
                    ? 'border-brand-danger focus:ring-red-100'
                    : 'border-border focus:ring-brand-primary/20'
                }`}
              />
              {mismatch ? (
                <p className="text-[10px] text-brand-danger mt-1">
                  Les deux saisies ne correspondent pas.
                </p>
              ) : null}
            </div>

            <ul className="space-y-1 bg-gray-50 rounded-lg p-3 border border-border">
              {rules.map((rule) => (
                <li
                  key={rule.label}
                  className={`text-[10px] flex items-center gap-2 ${
                    rule.ok ? 'text-brand-success' : 'text-text-muted'
                  }`}
                >
                  <span>{rule.ok ? '✓' : '○'}</span>
                  {rule.label}
                </li>
              ))}
            </ul>

            {error ? (
              <div className="px-3 py-2.5 rounded-lg bg-brand-dangerGlow border border-red-100 text-brand-danger text-xs font-medium">
                {error}
              </div>
            ) : null}

            <button
              type="submit"
              disabled={!ready || submitting}
              className="btn btn-primary w-full py-2.5 disabled:opacity-50"
            >
              {submitting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null}
              Enregistrer et continuer
            </button>
          </form>

          <p className="text-[10px] text-text-muted mt-4 leading-relaxed">
            Les autres sessions ouvertes sur ce compte seront révoquées.
          </p>

          <button
            type="button"
            onClick={logout}
            className="btn btn-outline w-full mt-3"
          >
            Se déconnecter
          </button>
        </div>
      </div>
    </div>
  );
}
