/**
 * /santa/request/$env — where the Santa block dialog sends a blocked user.
 * It sits outside the app shell: a requester is an account with no
 * permissions, and this page is all it needs.
 */
import { createRoute, redirect } from '@tanstack/react-router';
import { rootRoute } from './__root';
import { isAuthenticated } from '$/api/client';
import { RequestPage } from '$/features/santa/RequestPage';

const RETURN_KEY = 'osctrl.santaRequest';

interface RequestTarget {
  env: string;
  sha256: string;
  machine_id: string;
}

const text = (v: unknown): string => (typeof v === 'string' || typeof v === 'number' ? String(v) : '');

/**
 * The request link a signed-out user opened, kept across the login round trip
 * (SSO included) and returned once. Only the three values are stored, never a
 * URL, so this cannot be turned into a redirect to somewhere else.
 */
export function takeSantaRequestTarget(): RequestTarget | null {
  try {
    const raw = sessionStorage.getItem(RETURN_KEY);
    sessionStorage.removeItem(RETURN_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw) as Record<string, unknown>;
    const target = { env: text(v.env), sha256: text(v.sha256), machine_id: text(v.machine_id) };
    return target.env ? target : null;
  } catch {
    return null;
  }
}

export const santaRequestRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/santa/request/$env',
  validateSearch: (s: Record<string, unknown>) => ({ sha256: text(s.sha256), machine_id: text(s.machine_id) }),
  beforeLoad({ params, search }) {
    if (!isAuthenticated()) {
      try {
        sessionStorage.setItem(RETURN_KEY, JSON.stringify({ env: params.env, ...search }));
      } catch {
        // No storage: the user signs in and opens the link again.
      }
      throw redirect({ to: '/login' });
    }
  },
  component: function SantaRequestRoute() {
    const { env } = santaRequestRoute.useParams();
    const { sha256, machine_id } = santaRequestRoute.useSearch();
    return <RequestPage env={env} sha256={sha256} machineId={machine_id} />;
  },
});
