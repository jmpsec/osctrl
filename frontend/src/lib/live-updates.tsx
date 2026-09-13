import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { ApiError, AuthError, setCsrfToken } from '$/api/client';
import { readEvents, type EventTopic, type StreamEvent } from '$/api/events';
import { getFeatures } from '$/api/features';

type ResourceTopic = 'queries' | 'carves';
type SessionTopic = 'console' | 'file_explorer';
type AlertChangeKind = 'rules' | 'channels' | 'history';
type Register = (topic: ResourceTopic) => () => void;
type LiveStatus = {
  register: Register;
  live: Record<ResourceTopic, boolean>;
};
const LiveUpdatesContext = createContext<LiveStatus | null>(null);
const fallbackRefetchInterval = 15_000;
const liveReconcileInterval = 60_000;
type ChangeKind = 'metadata' | 'results' | 'files';
type PendingInvalidation = { topic: ResourceTopic; name?: string; change?: ChangeKind };
export type SessionResourceChange = { resourceId: number; change?: ChangeKind };

function invalidationKeys(topic: ResourceTopic, change?: ChangeKind) {
  if (topic === 'queries') {
    if (change === 'metadata') return ['queries', 'query'];
    if (change === 'results') return ['query-results'];
    return ['queries', 'query', 'query-results'];
  }
  if (change === 'metadata') return ['carves', 'carve'];
  if (change === 'files') return ['carve', 'carves'];
  return ['carves', 'carve'];
}

// Coalesces invalidations and performs a trailing refetch if an event arrives
// while a snapshot is in flight. It never patches authoritative result rows.
export function createInvalidator(client: QueryClient, env: string) {
  const pending = new Map<string, PendingInvalidation>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let active = true;
  let running = false;
  const schedule = () => {
    if (active && !running && !timer) timer = setTimeout(() => { void flush(); }, 250);
  };
  const flush = async () => {
    timer = undefined;
    if (!active || running) return;
    running = true;
    const batch = [...pending.values()];
    pending.clear();
    try {
      const requests = batch.flatMap(({ topic, name, change }) => {
        const keys = invalidationKeys(topic, change);
        return keys.map(async key => {
          const filters = { queryKey: name && key !== topic ? [key, env, name] : [key, env] };
          const wasFetching = client.isFetching(filters) > 0;
          await client.invalidateQueries(filters, { cancelRefetch: false });
          if (active && wasFetching) await client.invalidateQueries(filters, { cancelRefetch: false });
        });
      });
      await Promise.allSettled(requests);
    } finally {
      running = false;
      if (pending.size) schedule();
    }
  };
  return {
    add(topic: ResourceTopic, name?: string, change?: ChangeKind) {
      if (!active) return;
      if (!name || pending.size >= 64) {
        for (const [key, item] of pending) if (item.topic === topic) pending.delete(key);
        pending.set(topic, { topic });
      } else if (!pending.has(topic)) pending.set(`${topic}:${change || 'all'}:${name}`, { topic, name, change });
      schedule();
    },
    close() { active = false; pending.clear(); if (timer) clearTimeout(timer); },
  };
}

export function LiveUpdatesProvider({ env, children }: { env: string; children: ReactNode }) {
  const client = useQueryClient();
  const [counts, setCounts] = useState<Record<ResourceTopic, number>>({ queries: 0, carves: 0 });
  const [live, setLive] = useState<Record<ResourceTopic, boolean>>({ queries: false, carves: false });
  const register = useCallback<Register>((topic) => {
    setCounts(current => ({ ...current, [topic]: current[topic] + 1 }));
    return () => setCounts(current => ({ ...current, [topic]: Math.max(0, current[topic] - 1) }));
  }, []);
  const { data: features } = useQuery({ queryKey: ['features'], queryFn: getFeatures });
  const selection = (Object.keys(counts) as ResourceTopic[])
    .filter(topic => counts[topic] > 0 && features?.event_topics?.includes(topic)).sort().join(',');

  useEffect(() => {
    if (!features?.events || !selection) return;
    const topics = selection.split(',') as ResourceTopic[];
    const invalidator = createInvalidator(client, env);
    const setTopicsLive = (value: boolean) => {
      setLive(current => {
        const next = { ...current };
        for (const topic of topics) next[topic] = value;
        return next;
      });
    };
    let active = true;
    let forbidden = false;
    let attempts = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;
    let environmentUUID: string | undefined;
    const receive = ({ event, data }: StreamEvent) => {
      if (!active || !data || typeof data !== 'object') return;
      const value = data as Record<string, unknown>;
      if (event === 'auth.expired') {
        forbidden = true;
        controller?.abort();
        // Permissions can change while the login is still valid. Refresh the
        // current view through REST so its existing 401/403 behavior applies.
        for (const topic of topics) invalidator.add(topic);
      } else if (event === 'stream.ready' && typeof value.environment_uuid === 'string') {
        environmentUUID = value.environment_uuid;
        attempts = 0;
        setTopicsLive(true);
        for (const topic of topics) invalidator.add(topic);
      } else if (event === 'resource.changed' && value.schema_version === 1 &&
        environmentUUID && value.environment_uuid === environmentUUID &&
        topics.includes(value.topic as ResourceTopic) && typeof value.name === 'string' && value.name.length <= 256) {
        const change = value.change === 'metadata' || value.change === 'results' || value.change === 'files' ? value.change : undefined;
        invalidator.add(value.topic as ResourceTopic, value.name, change);
      }
    };
    const connect = async () => {
      if (!active || forbidden) return;
      environmentUUID = undefined;
      controller = new AbortController();
      try { await readEvents(env, topics, controller.signal, receive); }
      catch (error) {
        if (!active) return;
        if (error instanceof AuthError) {
          setCsrfToken(null);
          forbidden = true;
          for (const topic of topics) invalidator.add(topic);
        } else if (error instanceof ApiError && [400, 403, 404].includes(error.status)) forbidden = true;
      }
      if (active) setTopicsLive(false);
      if (active && !forbidden) {
        const delay = Math.min(30_000, 1000 * 2 ** Math.min(attempts++, 5)) * (0.8 + Math.random() * 0.4);
        timer = setTimeout(() => { void connect(); }, delay);
      }
    };
    void connect();
    return () => { active = false; controller?.abort(); if (timer) clearTimeout(timer); invalidator.close(); setTopicsLive(false); };
  }, [client, env, features?.events, selection]);

  const value = useMemo(() => ({ register, live }), [register, live]);
  return <LiveUpdatesContext.Provider value={value}>{children}</LiveUpdatesContext.Provider>;
}

export function resourceRefetchInterval(
  live: boolean,
  resource?: { active?: boolean; completed?: boolean; expired?: boolean; deleted?: boolean },
) {
  if (resource && (!resource.active || resource.completed || resource.expired || resource.deleted)) {
    return false;
  }
  return live ? liveReconcileInterval : fallbackRefetchInterval;
}

export function useSessionResourceUpdates(
  env: string,
  topic: SessionTopic,
  sessionId: number | undefined,
  receiveChanged: (change: SessionResourceChange) => void,
) {
  const { data: features } = useQuery({ queryKey: ['features'], queryFn: getFeatures });
  const [live, setLive] = useState(false);
  useEffect(() => {
    if (!sessionId || !features?.events || !features.event_topics?.includes(topic)) {
      setLive(false);
      return undefined;
    }
    let active = true;
    let forbidden = false;
    let attempts = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;
    let environmentUUID: string | undefined;
    const receive = ({ event, data }: StreamEvent) => {
      if (!active || !data || typeof data !== 'object') return;
      const value = data as Record<string, unknown>;
      if (event === 'auth.expired') {
        forbidden = true;
        controller?.abort();
      } else if (event === 'stream.ready' && typeof value.environment_uuid === 'string') {
        environmentUUID = value.environment_uuid;
        attempts = 0;
        setLive(true);
      } else if (event === 'resource.changed' && value.schema_version === 1 &&
        environmentUUID && value.environment_uuid === environmentUUID &&
        value.topic === topic && value.session_id === sessionId && typeof value.resource_id === 'number') {
        const change = value.change === 'metadata' || value.change === 'results' || value.change === 'files' ? value.change : undefined;
        receiveChanged({ resourceId: value.resource_id, change });
      }
    };
    const connect = async () => {
      if (!active || forbidden) return;
      environmentUUID = undefined;
      controller = new AbortController();
      const options = topic === 'console' ? { consoleSessionId: sessionId } : { fileExplorerSessionId: sessionId };
      try { await readEvents(env, [topic], controller.signal, receive, options); }
      catch (error) {
        if (!active) return;
        if (error instanceof AuthError) {
          setCsrfToken(null);
          forbidden = true;
        } else if (error instanceof ApiError && [400, 403, 404].includes(error.status)) forbidden = true;
      }
      if (active) setLive(false);
      if (active && !forbidden) {
        const delay = Math.min(30_000, 1000 * 2 ** Math.min(attempts++, 5)) * (0.8 + Math.random() * 0.4);
        timer = setTimeout(() => { void connect(); }, delay);
      }
    };
    void connect();
    return () => { active = false; controller?.abort(); if (timer) clearTimeout(timer); setLive(false); };
  }, [env, features?.events, features?.event_topics, receiveChanged, sessionId, topic]);
  return live;
}


export function useAlertUpdates(env: string | undefined) {
  const client = useQueryClient();
  const { data: features } = useQuery({ queryKey: ['features'], queryFn: getFeatures });
  const [live, setLive] = useState(false);
  useEffect(() => {
    if (!env || !features?.events || !features.event_topics?.includes('alerts')) {
      setLive(false);
      return undefined;
    }
    let active = true;
    let forbidden = false;
    let attempts = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;
    let environmentUUID: string | undefined;
    const invalidate = (change?: AlertChangeKind) => {
      const keys = change === 'rules' ? ['alert-rules']
        : change === 'channels' ? ['alert-channels']
          : change === 'history' ? ['alert-history']
            : ['alert-rules', 'alert-channels', 'alert-history'];
      for (const key of keys) void client.invalidateQueries({ queryKey: [key] });
    };
    const receive = ({ event, data }: StreamEvent) => {
      if (!active || !data || typeof data !== 'object') return;
      const value = data as Record<string, unknown>;
      if (event === 'auth.expired') {
        forbidden = true;
        controller?.abort();
        invalidate();
      } else if (event === 'stream.ready' && typeof value.environment_uuid === 'string') {
        environmentUUID = value.environment_uuid;
        attempts = 0;
        setLive(true);
        invalidate();
      } else if (event === 'resource.changed' && value.schema_version === 1 &&
        environmentUUID && value.environment_uuid === environmentUUID && value.topic === 'alerts') {
        const change = value.change === 'rules' || value.change === 'channels' || value.change === 'history' ? value.change : undefined;
        invalidate(change);
      }
    };
    const connect = async () => {
      if (!active || forbidden) return;
      environmentUUID = undefined;
      controller = new AbortController();
      try { await readEvents(env, ['alerts'], controller.signal, receive); }
      catch (error) {
        if (!active) return;
        if (error instanceof AuthError) {
          setCsrfToken(null);
          forbidden = true;
          invalidate();
        } else if (error instanceof ApiError && [400, 403, 404].includes(error.status)) forbidden = true;
      }
      if (active) setLive(false);
      if (active && !forbidden) {
        const delay = Math.min(30_000, 1000 * 2 ** Math.min(attempts++, 5)) * (0.8 + Math.random() * 0.4);
        timer = setTimeout(() => { void connect(); }, delay);
      }
    };
    void connect();
    return () => { active = false; controller?.abort(); if (timer) clearTimeout(timer); setLive(false); };
  }, [client, env, features?.events, features?.event_topics]);
  return live;
}

export function useServiceCommandUpdates(commandID: string | undefined, onChange: () => void) {
  const { data: features } = useQuery({ queryKey: ['features'], queryFn: getFeatures });
  const [live, setLive] = useState(false);
  useEffect(() => {
    if (!commandID || !features?.events || !features.event_topics?.includes('service_commands')) {
      setLive(false);
      return undefined;
    }
    let active = true;
    let forbidden = false;
    let attempts = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;
    let ready = false;
    const receive = ({ event, data }: StreamEvent) => {
      if (!active || !data || typeof data !== 'object') return;
      const value = data as Record<string, unknown>;
      if (event === 'auth.expired') {
        forbidden = true;
        controller?.abort();
        onChange();
      } else if (event === 'stream.ready' && value.environment_uuid === 'all') {
        ready = true;
        attempts = 0;
        setLive(true);
        onChange();
      } else if (event === 'resource.changed' && ready && value.schema_version === 1 &&
        value.environment_uuid === 'all' && value.topic === 'service_commands' && value.name === commandID) {
        onChange();
      }
    };
    const connect = async () => {
      if (!active || forbidden) return;
      ready = false;
      controller = new AbortController();
      try { await readEvents('all', ['service_commands'], controller.signal, receive); }
      catch (error) {
        if (!active) return;
        if (error instanceof AuthError) {
          setCsrfToken(null);
          forbidden = true;
          onChange();
        } else if (error instanceof ApiError && [400, 403, 404].includes(error.status)) forbidden = true;
      }
      if (active) setLive(false);
      if (active && !forbidden) {
        const delay = Math.min(30_000, 1000 * 2 ** Math.min(attempts++, 5)) * (0.8 + Math.random() * 0.4);
        timer = setTimeout(() => { void connect(); }, delay);
      }
    };
    void connect();
    return () => { active = false; controller?.abort(); if (timer) clearTimeout(timer); setLive(false); };
  }, [commandID, features?.events, features?.event_topics, onChange]);
  return live;
}

export function useFleetUpdates() {
  const client = useQueryClient();
  const { data: features } = useQuery({ queryKey: ['features'], queryFn: getFeatures });
  const [live, setLive] = useState(false);
  useEffect(() => {
    if (!features?.events || !features.event_topics?.includes('fleet')) {
      setLive(false);
      return undefined;
    }
    let active = true;
    let forbidden = false;
    let attempts = 0;
    let pending = false;
    let flushTimer: ReturnType<typeof setTimeout> | undefined;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;
    const invalidate = () => {
      pending = false;
      for (const key of [
        'stats',
        'dashboard-recently-seen',
        'dashboard-env-list',
        'dashboard-env-tiles',
        'dashboard-osquery-versions',
        'dashboard-error-nodes',
        'nodes',
        'node-tiles-batch',
      ]) void client.invalidateQueries({ queryKey: [key] });
    };
    const schedule = () => {
      if (pending || flushTimer) return;
      pending = true;
      flushTimer = setTimeout(() => {
        flushTimer = undefined;
        if (active) invalidate();
      }, 5000);
    };
    const receive = ({ event, data }: StreamEvent) => {
      if (!active || !data || typeof data !== 'object') return;
      const value = data as Record<string, unknown>;
      if (event === 'auth.expired') {
        forbidden = true;
        controller?.abort();
        invalidate();
      } else if (event === 'stream.ready' && value.environment_uuid === 'all') {
        attempts = 0;
        setLive(true);
      } else if (event === 'resource.changed' && value.schema_version === 1 &&
        value.environment_uuid === 'all' && value.topic === 'fleet' && value.change === 'activity') {
        schedule();
      }
    };
    const connect = async () => {
      if (!active || forbidden) return;
      controller = new AbortController();
      try { await readEvents('all', ['fleet'], controller.signal, receive); }
      catch (error) {
        if (!active) return;
        if (error instanceof AuthError) {
          setCsrfToken(null);
          forbidden = true;
          invalidate();
        } else if (error instanceof ApiError && [400, 403, 404].includes(error.status)) forbidden = true;
      }
      if (active) setLive(false);
      if (active && !forbidden) {
        const delay = Math.min(30_000, 1000 * 2 ** Math.min(attempts++, 5)) * (0.8 + Math.random() * 0.4);
        retryTimer = setTimeout(() => { retryTimer = undefined; void connect(); }, delay);
      }
    };
    void connect();
    return () => {
      active = false;
      controller?.abort();
      if (flushTimer) clearTimeout(flushTimer);
      if (retryTimer) clearTimeout(retryTimer);
      setLive(false);
    };
  }, [client, features?.events, features?.event_topics]);
  return live;
}

export function useResourceUpdates(topic: EventTopic) {
  const status = useContext(LiveUpdatesContext);
  const resourceTopic = topic === 'queries' || topic === 'carves' ? topic : null;
  useEffect(() => {
    if (!resourceTopic) return undefined;
    return status?.register(resourceTopic);
  }, [status?.register, resourceTopic]);
  return resourceTopic ? status?.live[resourceTopic] ?? false : false;
}
