/**
 * Écran de connexion.
 *
 * L'inscription libre a été retirée : elle permettait à n'importe qui de créer
 * un compte en choisissant lui-même le rôle « SOC Manager (N3) ». Les comptes
 * sont désormais créés par un SOC Manager depuis l'onglet Équipe SOC, ou en
 * ligne de commande avec `python -m scripts.manage create-user`.
 */

import { useState } from 'react';
import { Loader2, Lock, ShieldCheck } from 'lucide-react';
import { useAuth } from './AuthContext';

export default function LoginScreen() {
  const { login, error, clearError } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    try {
      await login(email.trim(), password);
    } catch {
      setPassword('');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-main px-4">
      <div className="w-full max-w-md">
        <div className="flex items-center justify-center gap-3 mb-8">
          <div className="w-10 h-10 bg-brand-primary rounded-lg flex items-center justify-center font-bold text-white text-sm">
            EDR
          </div>
          <div>
            <div className="font-semibold text-lg tracking-tight leading-none">SOC Console</div>
            <div className="text-[10px] text-text-muted mt-1">
              Détection et réponse aux ransomwares
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="flex items-center gap-2 mb-1">
            <Lock className="w-4 h-4 text-text-muted" />
            <h1 className="text-sm font-bold tracking-tight">Authentification analyste</h1>
          </div>
          <p className="text-xs text-text-muted mb-6">
            Accès restreint aux analystes du centre opérationnel de sécurité.
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="stat-label block mb-1.5">
                Adresse professionnelle
              </label>
              <input
                id="email"
                type="text"
                autoComplete="username"
                required
                value={email}
                onChange={(event) => {
                  setEmail(event.target.value);
                  if (error) clearError();
                }}
                placeholder="analyste@soc.edr.local"
                className="w-full px-3 py-2.5 rounded-lg border border-border text-xs focus:outline-none focus:ring-2 focus:ring-brand-primary/20 focus:border-brand-primary"
              />
            </div>

            <div>
              <label htmlFor="password" className="stat-label block mb-1.5">
                Mot de passe
              </label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(event) => {
                  setPassword(event.target.value);
                  if (error) clearError();
                }}
                placeholder="••••••••••••"
                className="w-full px-3 py-2.5 rounded-lg border border-border text-xs focus:outline-none focus:ring-2 focus:ring-brand-primary/20 focus:border-brand-primary"
              />
            </div>

            {error ? (
              <div className="px-3 py-2.5 rounded-lg bg-brand-dangerGlow border border-red-100 text-brand-danger text-xs font-medium">
                {error}
              </div>
            ) : null}

            <button
              type="submit"
              disabled={submitting}
              className="btn btn-primary w-full py-2.5 disabled:opacity-60"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  Vérification…
                </>
              ) : (
                <>
                  <ShieldCheck className="w-3.5 h-3.5" />
                  Ouvrir la session
                </>
              )}
            </button>
          </form>

          <p className="text-[10px] text-text-muted mt-6 leading-relaxed border-t border-border pt-4">
            Les tentatives de connexion sont journalisées. Après{' '}
            <strong>5 échecs consécutifs</strong>, le compte est verrouillé
            temporairement. La création de compte relève du SOC Manager.
          </p>
        </div>
      </div>
    </div>
  );
}
