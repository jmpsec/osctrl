import { useEffect } from 'react';
import { useParams } from '@tanstack/react-router';

/**
 * usePageTitle keeps the browser tab title in sync with the current page and
 * environment.
 *
 * Env-scoped routes (those with an `env` path param, e.g. /_app/env/dev/nodes)
 * render "<page>: <env>" — e.g. "Nodes: dev". Routes without an environment
 * render "<page> · osctrl". This replaces the static "osctrl" title so each
 * open tab identifies the page you're actually looking at.
 */
export function usePageTitle(page: string): void {
  const params = useParams({ strict: false });
  const env = (params as { env?: string }).env;
  useEffect(() => {
    document.title = env ? `${page}: ${env}` : `${page} \u00b7 osctrl`;
  }, [page, env]);
}
