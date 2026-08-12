/** Surface d'API de la console SOC, regroupée par domaine. */

import { api } from './client';

export const auth = {
  login: (email, password) => api.post('/auth/login', { email, password }),
  logout: () => api.post('/auth/logout'),
  me: (signal) => api.get('/auth/me', undefined, signal),
  changePassword: (currentPassword, newPassword) =>
    api.post('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    }),
  listUsers: (signal) => api.get('/auth/users', undefined, signal),
  createUser: (payload) => api.post('/auth/users', payload),
  updateUser: (id, payload) => api.patch(`/auth/users/${id}`, payload),
  deleteUser: (id) => api.delete(`/auth/users/${id}`),
};

export const alerts = {
  list: (params, signal) => api.get('/alerts', params, signal),
  get: (id, signal) => api.get(`/alerts/${id}`, undefined, signal),
  assign: (id, userId) => api.post(`/alerts/${id}/assign`, undefined, userId ? { user_id: userId } : undefined),
  setStatus: (id, status, resolutionNote) =>
    api.patch(`/alerts/${id}/status`, { status, resolution_note: resolutionNote ?? null }),
};

export const metrics = {
  timeseries: (params, signal) => api.get('/metrics/timeseries', params, signal),
  overview: (signal) => api.get('/metrics/overview', undefined, signal),
  mlInsights: (signal) => api.get('/metrics/ml-insights', undefined, signal),
};

export const machines = {
  list: (signal) => api.get('/machines', undefined, signal),
  get: (machineId, signal) => api.get(`/machines/${encodeURIComponent(machineId)}`, undefined, signal),
};

export const response = {
  kill: (machineId, pid, alertId, reason) =>
    api.post('/response/kill', { machine_id: machineId, pid, alert_id: alertId ?? null, reason }),
  isolate: (machineId, reason) => api.post('/response/isolate', { machine_id: machineId, reason }),
  unisolate: (machineId, reason) => api.post('/response/unisolate', { machine_id: machineId, reason }),
  commands: (params, signal) => api.get('/response/commands', params, signal),
};

export const exclusions = {
  list: (signal) => api.get('/exclusions', undefined, signal),
  create: (payload) => api.post('/exclusions', payload),
  toggle: (id) => api.patch(`/exclusions/${id}/toggle`),
  remove: (id) => api.delete(`/exclusions/${id}`),
};

export const audit = {
  list: (params, signal) => api.get('/audit', params, signal),
  actions: (signal) => api.get('/audit/actions', undefined, signal),
};

export const settings = {
  list: (signal) => api.get('/settings', undefined, signal),
  update: (key, value) => api.put(`/settings/${key}`, { value }),
};

export const system = {
  status: (signal) => api.get('/status', undefined, signal),
  presence: (signal) => api.get('/presence', undefined, signal),
};
