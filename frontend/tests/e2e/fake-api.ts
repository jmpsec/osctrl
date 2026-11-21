import type { BrowserContext, Page, Route } from '@playwright/test';

/**
 * A small in-memory osctrl-api for browser workflows: just the routes the
 * Santa pages call, with state shared by every page of the browser context.
 * Unknown routes answer 404 and are recorded, so a spec can assert it hit
 * none.
 */
export const ENV = 'dev';

export interface FakeRequest {
  id: number;
  file_sha256: string;
  machine_id: string;
  justification: string;
  requester: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  reason: string;
  decided_by: string;
  rule_id: number;
  created_at: string;
}

export interface FakeRule {
  id: number;
  identifier: string;
  rule_type: string;
  policy: string;
  scope: string;
  scope_value: string;
  created_by: string;
}

export class FakeApi {
  user = 'admin';
  requests: FakeRequest[] = [];
  rules: FakeRule[] = [];
  decisions: unknown[] = [];
  unknown: string[] = [];
  /** Notification link tokens, by request ID. */
  links = new Map<string, number>();

  async install(context: BrowserContext) {
    // osctrl_csrf is how the SPA knows it is signed in.
    await context.addCookies([{ name: 'osctrl_csrf', value: 'e2e-csrf', url: 'http://localhost:5173' }]);
    await context.route('**/api/v1/**', (route) => this.handle(route));
  }

  /** Signs the browser in as another user. */
  as(user: string) {
    this.user = user;
  }

  private json(route: Route, body: unknown, status = 200) {
    return route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  }

  private request(r: FakeRequest) {
    return {
      ...r, kind: '', monitor_hours: 0, file_name: 'Tool.app', file_path: '/Applications/Tool.app/Contents/MacOS/Tool',
      signing_id: '', team_id: '', executing_user: r.requester, decided_at: null, risk_override: false, event_id: 0,
      environment_id: 1,
    };
  }

  private async handle(route: Route) {
    const req = route.request();
    const url = new URL(req.url());
    const path = url.pathname.replace(/^\/api\/v1/, '');
    const method = req.method();
    const santa = `/santa/${ENV}`;

    if (method === 'GET' && path === '/users/me') {
      return this.json(route, { username: this.user, admin: this.user === 'admin', permissions: {}, environments: [] });
    }
    if (method === 'GET' && path === '/features') return this.json(route, { santa: true });
    if (method === 'GET' && path === '/environments') {
      return this.json(route, [{ id: 1, name: ENV, uuid: 'ENV-UUID', hostname: 'tls.example.com' }]);
    }
    if (method === 'GET' && path === `${santa}/access`) return this.json(route, { admin: this.user === 'admin', approver: false });
    if (method === 'GET' && path === `${santa}/machines`) return this.json(route, []);
    if (method === 'GET' && path === `${santa}/votes`) {
      return this.json(route, { votes: 0, local_threshold: 0, global_threshold: 0, voted: false, allowed: '' });
    }
    if (method === 'GET' && path === `${santa}/requests/mine`) {
      return this.json(route, this.requests.filter((r) => r.requester === this.user).map((r) => this.request(r)));
    }
    if (method === 'POST' && path === `${santa}/requests`) {
      const body = req.postDataJSON() as { sha256: string; machine_id: string; justification: string };
      const r: FakeRequest = {
        id: this.requests.length + 1, file_sha256: body.sha256, machine_id: body.machine_id, justification: body.justification,
        requester: this.user, status: 'pending', reason: '', decided_by: '', rule_id: 0, created_at: new Date().toISOString(),
      };
      this.requests.push(r);
      return this.json(route, this.request(r), 201);
    }
    if (method === 'GET' && path === `${santa}/requests`) {
      const status = url.searchParams.get('status');
      return this.json(route, this.requests.filter((r) => !status || r.status === status).map((r) => this.request(r)));
    }
    const one = path.match(new RegExp(`^${santa}/requests/(\\d+)$`));
    if (method === 'GET' && one) {
      const r = this.requests.find((x) => x.id === Number(one[1]));
      return r ? this.json(route, this.request(r)) : this.json(route, { error: 'request not found' }, 404);
    }
    // A notification link: the token names the request, and works once.
    const byLink = method === 'POST' && path === `${santa}/requests/link`;
    const decision = byLink ? null : path.match(new RegExp(`^${santa}/requests/(\\d+)/decision$`));
    if (byLink || (method === 'POST' && decision)) {
      const { token, ...body } = req.postDataJSON() as {
        token?: string; decision: 'approve' | 'deny'; reason?: string; scope?: string; scope_value?: string; rule_type?: string;
      };
      const id = byLink ? this.links.get(token ?? '') : Number(decision![1]);
      if (byLink) this.links.delete(token ?? '');
      if (id === undefined) return this.json(route, { error: 'link used or expired' }, 410);
      const r = this.requests.find((x) => x.id === id);
      if (!r) return this.json(route, { error: 'request not found' }, 404);
      this.decisions.push(body);
      const approve = body.decision === 'approve';
      r.status = approve ? 'approved' : 'denied';
      r.decided_by = this.user;
      r.reason = body.reason ?? '';
      if (approve) {
        const scope = body.scope || 'node';
        const rule: FakeRule = {
          id: this.rules.length + 1, identifier: r.file_sha256, rule_type: body.rule_type || 'BINARY', policy: 'ALLOWLIST',
          scope, scope_value: scope === 'node' ? r.machine_id : body.scope_value ?? '', created_by: this.user,
        };
        this.rules.push(rule);
        r.rule_id = rule.id;
      }
      return this.json(route, this.request(r));
    }
    if (method === 'GET' && path === `${santa}/rules`) {
      return this.json(route, this.rules.map((x) => ({ ...x, cel_expr: '', custom_msg: '', custom_url: '', environment_id: 1, created_at: new Date().toISOString() })));
    }

    this.unknown.push(`${method} ${path}`);
    return this.json(route, { error: 'not in the e2e fake API' }, 404);
  }
}

/** Opens a page and fails the spec on any page error. */
export async function openPage(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  page.on('pageerror', (err) => {
    throw err;
  });
  return page;
}
