/**
 * Chargement de données piloté par les invalidations temps réel.
 *
 * Une vue déclare de quels canaux elle dépend ; elle se recharge quand le
 * serveur signale un changement sur l'un d'eux, et non plus toutes les 3
 * secondes quoi qu'il arrive.
 *
 * Les données précédentes restent affichées pendant le rechargement, ce qui
 * évite le clignotement de l'interface à chaque nouvelle alerte.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { useRealtime } from '../realtime/RealtimeProvider';

export function useResource(fetcher, { channels = [], deps = [], enabled = true } = {}) {
  const { versions } = useRealtime();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(enabled);
  const [refreshing, setRefreshing] = useState(false);

  const hasDataRef = useRef(false);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const channelVersion = channels.map((channel) => versions[channel] || 0).join('.');

  const load = useCallback(
    async (signal) => {
      if (hasDataRef.current) setRefreshing(true);
      else setLoading(true);

      try {
        const result = await fetcherRef.current(signal);
        if (signal?.aborted) return;
        setData(result);
        setError(null);
        hasDataRef.current = true;
      } catch (err) {
        if (err.name === 'AbortError' || signal?.aborted) return;
        setError(err);
      } finally {
        if (!signal?.aborted) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    },
    [],
  );

  useEffect(() => {
    if (!enabled) {
      setLoading(false);
      return undefined;
    }
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, channelVersion, load, ...deps]);

  const reload = useCallback(() => {
    const controller = new AbortController();
    load(controller.signal);
  }, [load]);

  return { data, error, loading, refreshing, reload };
}
