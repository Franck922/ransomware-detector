/**
 * État d'authentification de la console.
 *
 * Changement de fond : il n'y a plus de `localStorage.setItem('edr_authenticated',
 * 'true')`. La session est un cookie HttpOnly que le JavaScript ne peut pas
 * lire, et l'état d'authentification est déterminé en interrogeant le serveur
 * (`GET /auth/me`). Modifier quoi que ce soit dans le navigateur ne donne donc
 * plus accès à l'application.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { onAuthFailure } from '../api/client';
import { auth as authApi } from '../api/endpoints';

const AuthContext = createContext(null);

const ROLE_RANK = { N1: 1, N2: 2, N3: 3 };

export function AuthProvider({ children }) {
  const [session, setSession] = useState(null);
  const [checking, setChecking] = useState(true);
  const [error, setError] = useState(null);

  const refresh = useCallback(async (signal) => {
    try {
      const data = await authApi.me(signal);
      setSession(data);
      return data;
    } catch (err) {
      if (err.name === 'AbortError') return null;
      setSession(null);
      return null;
    } finally {
      if (!signal?.aborted) setChecking(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    refresh(controller.signal);
    return () => controller.abort();
  }, [refresh]);

  // Une 401 émise par n'importe quel appel purge la session locale : plus
  // d'interface qui reste affichée en boucle d'erreur après expiration.
  useEffect(
    () =>
      onAuthFailure((failure) => {
        if (failure.isUnauthorized) {
          setSession(null);
        } else if (failure.requiresPasswordChange) {
          setSession((previous) =>
            previous
              ? { ...previous, user: { ...previous.user, must_change_password: true } }
              : previous,
          );
        }
      }),
    [],
  );

  const login = useCallback(async (email, password) => {
    setError(null);
    try {
      const data = await authApi.login(email, password);
      setSession(data);
      return data;
    } catch (err) {
      setError(err.message);
      throw err;
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch {
      /* la session est peut-être déjà expirée côté serveur */
    }
    setSession(null);
  }, []);

  const changePassword = useCallback(
    async (currentPassword, newPassword) => {
      await authApi.changePassword(currentPassword, newPassword);
      return refresh();
    },
    [refresh],
  );

  const user = session?.user ?? null;

  const value = useMemo(
    () => ({
      session,
      user,
      checking,
      error,
      isAuthenticated: Boolean(user),
      mustChangePassword: Boolean(user?.must_change_password),
      login,
      logout,
      changePassword,
      refresh,
      clearError: () => setError(null),
      /**
       * Confort d'affichage uniquement : l'autorisation réelle est appliquée par
       * l'API. Masquer un bouton n'est pas un contrôle d'accès.
       */
      hasRole: (minimum) => (ROLE_RANK[user?.role] || 0) >= (ROLE_RANK[minimum] || 99),
    }),
    [session, user, checking, error, login, logout, changePassword, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth doit être utilisé dans un AuthProvider');
  return context;
}
