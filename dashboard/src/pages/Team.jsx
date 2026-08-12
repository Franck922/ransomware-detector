/**
 * Gestion de l'équipe SOC.
 *
 * L'ancien onglet affichait trois analystes fictifs codés en dur. La liste
 * provient maintenant de la table `users`, et la création de compte se fait ici,
 * par un SOC Manager, avec un rôle qu'il attribue lui-même — l'inscription libre
 * permettait à n'importe qui de se déclarer N3.
 */

import { useState } from 'react';
import { Plus, Trash2, Users } from 'lucide-react';
import { auth as authApi } from '../api/endpoints';
import { useResource } from '../hooks/useResource';
import { useAuth } from '../auth/AuthContext';
import {
  AsyncSection,
  EmptyState,
  Panel,
  RoleBadge,
  formatDateTime,
  formatRelative,
} from '../components/ui';

const ROLES = [
  { value: 'N1', label: 'Analyste SOC (N1) — lecture et qualification' },
  { value: 'N2', label: 'Analyste EDR (N2) — réponse active' },
  { value: 'N3', label: 'SOC Manager (N3) — administration' },
];

export default function Team({ onToast }) {
  const { hasRole, user: currentUser } = useAuth();
  const canManage = hasRole('N3');

  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('N1');
  const [busy, setBusy] = useState(false);
  const [showForm, setShowForm] = useState(false);

  const { data, loading, error, reload } = useResource(
    (signal) => (canManage ? authApi.listUsers(signal) : Promise.resolve([])),
    { channels: ['audit'], deps: [canManage] },
  );

  const users = data || [];

  const handleCreate = async (event) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    try {
      await authApi.createUser({
        email: email.trim(),
        password,
        role,
        full_name: fullName.trim() || null,
      });
      onToast({
        tone: 'success',
        message: `Compte ${email.trim()} créé. L'analyste devra changer son mot de passe à la première connexion.`,
      });
      setEmail('');
      setFullName('');
      setPassword('');
      setRole('N1');
      setShowForm(false);
      reload();
    } catch (err) {
      onToast({ tone: 'error', message: err.message });
    } finally {
      setBusy(false);
    }
  };

  const handleRoleChange = async (target, nextRole) => {
    try {
      await authApi.updateUser(target.id, { role: nextRole });
      onToast({ tone: 'success', message: `Rôle de ${target.email} mis à jour.` });
      reload();
    } catch (err) {
      onToast({ tone: 'error', message: err.message });
      reload();
    }
  };

  const handleToggleActive = async (target) => {
    try {
      await authApi.updateUser(target.id, { is_active: !target.is_active });
      onToast({
        tone: 'success',
        message: `${target.email} ${target.is_active ? 'désactivé' : 'réactivé'}.`,
      });
      reload();
    } catch (err) {
      onToast({ tone: 'error', message: err.message });
    }
  };

  const handleDelete = async (target) => {
    try {
      await authApi.deleteUser(target.id);
      onToast({ tone: 'success', message: `Compte ${target.email} supprimé.` });
      reload();
    } catch (err) {
      onToast({ tone: 'error', message: err.message });
    }
  };

  if (!canManage) {
    return (
      <Panel title="Votre profil">
        <div className="space-y-4">
          <div>
            <span className="stat-label block mb-1">Compte</span>
            <span className="text-sm font-semibold">{currentUser?.email}</span>
          </div>
          <div>
            <span className="stat-label block mb-1.5">Niveau</span>
            <RoleBadge role={currentUser?.role} />
          </div>
          <div>
            <span className="stat-label block mb-1.5">Permissions</span>
            <div className="flex flex-wrap gap-1.5">
              {(currentUser?.permissions || []).map((permission) => (
                <span
                  key={permission}
                  className="px-2 py-0.5 text-[10px] rounded-full bg-brand-primaryGlow text-brand-primary font-medium"
                >
                  {permission}
                </span>
              ))}
            </div>
          </div>
          <p className="text-xs text-text-muted border-t border-border pt-4">
            La liste des comptes et leur gestion sont réservées au SOC Manager (N3).
          </p>
        </div>
      </Panel>
    );
  }

  return (
    <div className="space-y-6">
      {showForm ? (
        <Panel
          title="Nouveau compte analyste"
          subtitle="Le mot de passe initial devra être renouvelé à la première connexion"
          actions={
            <button type="button" onClick={() => setShowForm(false)} className="btn btn-outline">
              Annuler
            </button>
          }
        >
          <form onSubmit={handleCreate} className="grid grid-cols-12 gap-3 items-end">
            <div className="col-span-3">
              <label htmlFor="new-email" className="stat-label block mb-1.5">
                Adresse
              </label>
              <input
                id="new-email"
                type="text"
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="analyste@soc.edr.local"
                className="w-full px-3 py-2 rounded-lg border border-border text-xs focus:outline-none focus:ring-2 focus:ring-brand-primary/20"
              />
            </div>
            <div className="col-span-2">
              <label htmlFor="new-name" className="stat-label block mb-1.5">
                Nom complet
              </label>
              <input
                id="new-name"
                type="text"
                value={fullName}
                onChange={(event) => setFullName(event.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-border text-xs focus:outline-none focus:ring-2 focus:ring-brand-primary/20"
              />
            </div>
            <div className="col-span-3">
              <label htmlFor="new-password" className="stat-label block mb-1.5">
                Mot de passe initial (12 caractères min.)
              </label>
              <input
                id="new-password"
                type="text"
                required
                minLength={12}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-border text-xs font-mono focus:outline-none focus:ring-2 focus:ring-brand-primary/20"
              />
            </div>
            <div className="col-span-3">
              <label htmlFor="new-role" className="stat-label block mb-1.5">
                Niveau
              </label>
              <select
                id="new-role"
                value={role}
                onChange={(event) => setRole(event.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-border text-xs bg-white focus:outline-none"
              >
                {ROLES.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="col-span-1">
              <button type="submit" disabled={busy} className="btn btn-primary w-full disabled:opacity-50">
                Créer
              </button>
            </div>
          </form>
        </Panel>
      ) : null}

      <Panel
        title={`${users.length} compte(s) analyste`}
        subtitle="Les niveaux sont appliqués côté API sur chaque requête"
        actions={
          !showForm ? (
            <button type="button" onClick={() => setShowForm(true)} className="btn btn-primary">
              <Plus className="w-3.5 h-3.5" />
              Ajouter un analyste
            </button>
          ) : null
        }
      >
        <AsyncSection
          loading={loading}
          error={error}
          onRetry={reload}
          isEmpty={users.length === 0}
          empty={<EmptyState icon={Users} title="Aucun compte" />}
        >
          <div className="table-container">
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Analyste</th>
                  <th>Niveau</th>
                  <th>État</th>
                  <th>Mot de passe</th>
                  <th>Dernière connexion</th>
                  <th>Création</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((member) => {
                  const isSelf = member.id === currentUser?.id;
                  return (
                    <tr key={member.id}>
                      <td>
                        <div className="font-semibold">{member.email}</div>
                        {member.full_name ? (
                          <div className="text-[10px] text-text-muted">{member.full_name}</div>
                        ) : null}
                        {isSelf ? (
                          <div className="text-[10px] text-brand-primary font-semibold">
                            Votre compte
                          </div>
                        ) : null}
                      </td>
                      <td>
                        <select
                          value={member.role}
                          onChange={(event) => handleRoleChange(member, event.target.value)}
                          disabled={isSelf}
                          className="px-2 py-1 rounded-md border border-border text-[11px] bg-white disabled:bg-gray-50 disabled:text-text-muted"
                        >
                          {ROLES.map((option) => (
                            <option key={option.value} value={option.value}>
                              {option.value}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <span className={`badge ${member.is_active ? 'badge-success' : 'badge-danger'}`}>
                          {member.is_active ? 'Actif' : 'Désactivé'}
                        </span>
                      </td>
                      <td>
                        {member.must_change_password ? (
                          <span className="badge badge-warning">Rotation requise</span>
                        ) : (
                          <span className="text-text-muted">À jour</span>
                        )}
                      </td>
                      <td className="text-text-muted" title={formatDateTime(member.last_login_at)}>
                        {member.last_login_at ? formatRelative(member.last_login_at) : 'Jamais'}
                      </td>
                      <td className="text-text-muted whitespace-nowrap">
                        {formatDateTime(member.created_at)}
                      </td>
                      <td className="text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={() => handleToggleActive(member)}
                          disabled={isSelf}
                          className="btn btn-outline mr-2 disabled:opacity-40"
                        >
                          {member.is_active ? 'Désactiver' : 'Réactiver'}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDelete(member)}
                          disabled={isSelf}
                          className="btn btn-outline text-brand-danger hover:bg-red-50 disabled:opacity-40"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <p className="text-[10px] text-text-muted mt-4 pt-3 border-t border-border">
            Un mot de passe oublié se réinitialise hors bande :
            <span className="code-text ml-1">python -m scripts.manage reset-password --email …</span>
          </p>
        </AsyncSection>
      </Panel>
    </div>
  );
}
