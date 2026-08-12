/**
 * Canal temps réel côté client.
 *
 * L'ancien dashboard re-téléchargeait la totalité des données toutes les 3
 * secondes. Ici, le serveur pousse une notification d'invalidation par canal ;
 * seules les vues concernées se rafraîchissent, et la latence tombe sous la
 * seconde.
 *
 * Un repli en polling est conservé : si le WebSocket est coupé (proxy,
 * redémarrage de l'API, réseau instable), l'interface continue de se mettre à
 * jour, plus lentement, au lieu d'afficher des données figées sans le dire.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { websocketUrl } from '../api/client';

const CHANNELS = ['alerts', 'metrics', 'machines', 'commands', 'audit', 'exclusions'];
const HEARTBEAT_MS = 25000;
const FALLBACK_POLL_MS = 5000;
const MAX_RECONNECT_DELAY_MS = 15000;

const RealtimeContext = createContext(null);

function initialVersions() {
  return CHANNELS.reduce((acc, channel) => ({ ...acc, [channel]: 0 }), {});
}

export function RealtimeProvider({ enabled, children }) {
  const [versions, setVersions] = useState(initialVersions);
  const [connected, setConnected] = useState(false);
  const [lastEventAt, setLastEventAt] = useState(null);

  const socketRef = useRef(null);
  const heartbeatRef = useRef(null);
  const reconnectRef = useRef(null);
  const pollRef = useRef(null);
  const attemptRef = useRef(0);
  const closedByUsRef = useRef(false);

  const bump = useCallback((channels) => {
    setVersions((previous) => {
      const next = { ...previous };
      channels.forEach((channel) => {
        next[channel] = (next[channel] || 0) + 1;
      });
      return next;
    });
  }, []);

  /** Force le rafraîchissement de toutes les vues (bouton « Rafraîchir »). */
  const refreshAll = useCallback(() => bump(CHANNELS), [bump]);

  const clearTimers = useCallback(() => {
    if (heartbeatRef.current) clearInterval(heartbeatRef.current);
    if (reconnectRef.current) clearTimeout(reconnectRef.current);
    if (pollRef.current) clearInterval(pollRef.current);
    heartbeatRef.current = null;
    reconnectRef.current = null;
    pollRef.current = null;
  }, []);

  const startFallbackPolling = useCallback(() => {
    if (pollRef.current) return;
    pollRef.current = setInterval(() => bump(CHANNELS), FALLBACK_POLL_MS);
  }, [bump]);

  const stopFallbackPolling = useCallback(() => {
    if (!pollRef.current) return;
    clearInterval(pollRef.current);
    pollRef.current = null;
  }, []);

  const connect = useCallback(() => {
    if (!enabled) return;

    let socket;
    try {
      socket = new WebSocket(websocketUrl());
    } catch {
      startFallbackPolling();
      return;
    }
    socketRef.current = socket;

    socket.onopen = () => {
      attemptRef.current = 0;
      setConnected(true);
      stopFallbackPolling();
      // Resynchronisation immédiate : on peut avoir manqué des événements
      // pendant la coupure.
      bump(CHANNELS);
      heartbeatRef.current = setInterval(() => {
        if (socket.readyState === WebSocket.OPEN) socket.send('ping');
      }, HEARTBEAT_MS);
    };

    socket.onmessage = (event) => {
      let message;
      try {
        message = JSON.parse(event.data);
      } catch {
        return;
      }
      if (message.type === 'invalidate' && message.channel) {
        bump([message.channel]);
        setLastEventAt(new Date());
      }
    };

    socket.onclose = () => {
      setConnected(false);
      if (heartbeatRef.current) {
        clearInterval(heartbeatRef.current);
        heartbeatRef.current = null;
      }
      if (closedByUsRef.current) return;

      startFallbackPolling();

      // Reconnexion avec back-off : évite de marteler une API redémarrée.
      attemptRef.current += 1;
      const delay = Math.min(1000 * 2 ** (attemptRef.current - 1), MAX_RECONNECT_DELAY_MS);
      reconnectRef.current = setTimeout(connect, delay);
    };

    socket.onerror = () => {
      // onclose suit systématiquement : la reconnexion y est gérée.
    };
  }, [enabled, bump, startFallbackPolling, stopFallbackPolling]);

  useEffect(() => {
    if (!enabled) {
      closedByUsRef.current = true;
      clearTimers();
      if (socketRef.current) socketRef.current.close();
      socketRef.current = null;
      setConnected(false);
      return undefined;
    }

    closedByUsRef.current = false;
    connect();

    return () => {
      closedByUsRef.current = true;
      clearTimers();
      if (socketRef.current) socketRef.current.close();
      socketRef.current = null;
    };
  }, [enabled, connect, clearTimers]);

  const value = useMemo(
    () => ({ versions, connected, lastEventAt, refreshAll, invalidate: bump }),
    [versions, connected, lastEventAt, refreshAll, bump],
  );

  return <RealtimeContext.Provider value={value}>{children}</RealtimeContext.Provider>;
}

export function useRealtime() {
  const context = useContext(RealtimeContext);
  if (!context) {
    throw new Error('useRealtime doit être utilisé dans un RealtimeProvider');
  }
  return context;
}

export { CHANNELS };
