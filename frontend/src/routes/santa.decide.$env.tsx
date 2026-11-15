/**
 * /santa/decide/$env?request=ID&action=approve|deny#TOKEN — where the approve
 * and deny links of an approval notification land. The token is the URL
 * fragment, so it is not sent to the server with the page request.
 */
import { createRoute, redirect } from '@tanstack/react-router';
import { rootRoute } from './__root';
import { isAuthenticated } from '$/api/client';
import { DecideLinkPage } from '$/features/santa/DecideLinkPage';

const RETURN_KEY = 'osctrl.santaDecide';

interface DecideTarget {
  env: string;
  request: number;
  action: 'approve' | 'deny';
  token: string;
}

const text = (v: unknown): string => (typeof v === 'string' || typeof v === 'number' ? String(v) : '');
const action = (v: unknown): 'approve' | 'deny' => (v === 'approve' ? 'approve' : 'deny');
const requestId = (v: unknown): number => {
  const n = Number(text(v));
  return Number.isInteger(n) && n > 0 ? n : 0;
};

/**
 * The link a signed-out approver opened, kept across the login round trip and
 * returned once. Only its four values are stored, never a URL. The token is
 * useless without an environment admin session and works once.
 */
export function takeSantaDecideTarget(): DecideTarget | null {
  try {
    const raw = sessionStorage.getItem(RETURN_KEY);
    sessionStorage.removeItem(RETURN_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw) as Record<string, unknown>;
    const target = { env: text(v.env), request: requestId(v.request), action: action(v.action), token: text(v.token) };
    return target.env && target.request && target.token ? target : null;
  } catch {
    return null;
  }
}

export const santaDecideRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/santa/decide/$env',
  validateSearch: (s: Record<string, unknown>) => ({ request: requestId(s.request), action: action(s.action) }),
  beforeLoad({ params, search, location }) {
    if (!isAuthenticated()) {
      try {
        sessionStorage.setItem(RETURN_KEY, JSON.stringify({ env: params.env, ...search, token: location.hash.replace(/^#/, '') }));
      } catch {
        // No storage: the approver signs in and opens the link again.
      }
      throw redirect({ to: '/login' });
    }
  },
  component: function SantaDecideRoute() {
    const { env } = santaDecideRoute.useParams();
    const { request, action } = santaDecideRoute.useSearch();
    // Read from the address bar: the fragment is not part of the route's search.
    const token = window.location.hash.replace(/^#/, '');
    return <DecideLinkPage env={env} requestId={request} approve={action === 'approve'} token={token} />;
  },
});
