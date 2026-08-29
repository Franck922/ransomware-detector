/**
 * Client HTTP unique de l'application.
 *
 * Remplace les 17 appels `fetch('http://localhost:8000/...')` codés en dur dans
 * l'ancien App.jsx, qui rendaient le dashboard inutilisable depuis un autre
 * poste que celui hébergeant l'API.
 *
 * - même origine par défaut (/api proxifié par Vite en dev, par nginx en prod) ;
 * - `credentials: 'include'` pour transmettre le cookie de session HttpOnly ;
 * - gestion centralisée du 401 (session expirée) et du 403 « rotation requise ».
 */

const BASE = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');
const PREFIX = `${BASE}/api`;

export class ApiError extends Error {
  constructor(message, { status, code, payload } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.payload = payload;
  }

  get isUnauthorized() {
    return this.status === 401;
  }

  get isForbidden() {
    return this.status === 403;
  }

  get requiresPasswordChange() {
    return this.code === 'password_change_required';
  }
}

const listeners = new Set();

/** Permet à AuthContext de réagir globalement à une session invalidée. */
export function onAuthFailure(callback) {
  listeners.add(callback);
  return () => listeners.delete(callback);
}

function notifyAuthFailure(error) {
  listeners.forEach((callback) => {
    try {
      callback(error);
    } catch {
      /* un listener défaillant ne doit pas interrompre les autres */
    }
  });
}

function buildUrl(path, params) {
  const query = new URLSearchParams();
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.append(key, String(value));
    }
  });
  const search = query.toString();
  return `${PREFIX}${path}${search ? `?${search}` : ''}`;
}

async function parseBody(response) {
  const type = response.headers.get('content-type') || '';
  if (!type.includes('application/json')) {
    const text = await response.text();
    return text || null;
  }
  try {
    return await response.json();
  } catch {
    return null;
  }
}

/** Aplati les erreurs de validation Pydantic en un message lisible. */
function extractMessage(payload, response) {
  if (!payload) return `Erreur ${response.status}`;
  if (typeof payload === 'string') return payload;

  const detail = payload.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        const field = Array.isArray(item.loc) ? item.loc[item.loc.length - 1] : '';
        return field ? `${field} : ${item.msg}` : item.msg;
      })
      .join(' — ');
  }
  return `Erreur ${response.status}`;
}

async function request(path, { method = 'GET', body, params, signal } = {}) {
  let response;
  try {
    response = await fetch(buildUrl(path, params), {
      method,
      signal,
      credentials: 'include',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    throw new ApiError(
      "Liaison avec l'API EDR impossible. Vérifiez que le service est démarré.",
      { status: 0, code: 'network_error' },
    );
  }

  if (response.status === 204) return null;

  const payload = await parseBody(response);

  if (response.ok) return payload;

  const passwordChange =
    response.status === 403 && response.headers.get('X-Password-Change-Required') === '1';

  const error = new ApiError(extractMessage(payload, response), {
    status: response.status,
    code: passwordChange ? 'password_change_required' : undefined,
    payload,
  });

  // Une session expirée ou un compte en attente de rotation doit remonter à
  // l'échelle de l'application, pas seulement à l'écran qui a émis l'appel.
  if (error.isUnauthorized || passwordChange) {
    notifyAuthFailure(error);
  }

  throw error;
}

export const api = {
  get: (path, params, signal) => request(path, { method: 'GET', params, signal }),
  post: (path, body, params) => request(path, { method: 'POST', body, params }),
  patch: (path, body, params) => request(path, { method: 'PATCH', body, params }),
  put: (path, body, params) => request(path, { method: 'PUT', body, params }),
  delete: (path, params) => request(path, { method: 'DELETE', params }),
};

/** URL absolue du canal temps réel, dérivée de l'origine courante. */
export function websocketUrl() {
  if (BASE) {
    return `${BASE.replace(/^http/, 'ws')}/ws`;
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/ws`;
}
