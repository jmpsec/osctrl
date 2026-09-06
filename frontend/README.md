# osctrl Frontend

The operator interface is a React 19, TypeScript, and Vite SPA under `frontend/`. It communicates only with `osctrl-api`; there is no separate frontend Go service.

The UI covers environments, nodes, activity and posture, queries, saved queries, carves, console and file exploration, tags, enrollment packages, users and MFA, alerts, log sinks, authentication providers, audit records, settings, and service configuration.

## Requirements

- Node.js 22 or newer
- npm with the committed `package-lock.json`
- A reachable `osctrl-api` for interactive use

Install dependencies from the repository root:

```bash
make frontend-install
```

## Development

Start an API instance on `http://localhost:8081`, then run:

```bash
make frontend-dev
```

Vite serves the SPA at `http://localhost:5173` and proxies `/api/*` to `http://localhost:8081`. The same-origin proxy is important for JWT and CSRF cookies.

The Docker development stack instead exposes the SPA and proxied API at `https://localhost:8444`:

```bash
make docker_dev_build
make docker_dev_up
```

## Validation

```bash
make frontend-test
make frontend-build
```

`frontend-test` runs Vitest and TypeScript checking. Run the browser workflow suite when navigation, authentication, or an end-to-end operator flow changes:

```bash
cd frontend
npm run test:e2e
```

Useful npm scripts:

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start Vite on port 5173 |
| `npm run check` | Run TypeScript checking |
| `npm test` | Run Vitest once |
| `npm run test:watch` | Run Vitest in watch mode |
| `npm run test:e2e` | Run Playwright |
| `npm run build` | Type-check and create `frontend/dist/` |
| `npm run preview` | Preview the production bundle |

The `predev` and `prebuild` hooks copy Monaco Editor assets into the local static tree so the editor does not depend on a CDN.

## Project Layout

```text
frontend/
├── src/
│   ├── api/          Typed API modules and generated types
│   ├── components/   Shared UI primitives and composed controls
│   ├── features/     Operator feature modules
│   ├── lib/          Utilities and reusable hooks
│   ├── routes/       TanStack Router pages
│   ├── styles/       Tailwind and design-token styles
│   ├── main.tsx      Application entry point
│   └── router.tsx    Router configuration
├── tests/e2e/        Playwright workflows
└── scripts/          Build helpers, including Monaco asset staging
```

The main frontend stack is React Query, TanStack Router, TanStack Table, Radix UI, Tailwind CSS, React Hook Form, Zod, Monaco Editor, Visx, Motion, and Lucide icons.

## API and Authorization

Frontend permission checks improve navigation but are not security controls. Every protected operation must remain authenticated and authorized in `osctrl-api`.

API modules live in `src/api/` and use relative `/api/v1/*` paths. Cookie-authenticated mutations include CSRF handling through the shared API client. Do not bypass that client for ad hoc requests without reproducing its authentication and error behavior.

When public REST contracts change, update the Go handlers and generated OpenAPI output before adapting frontend types.

## Production

`make frontend-build` writes static files to `frontend/dist/`.

The tagged release pipeline builds that bundle before GoReleaser creates the frontend container from [deploy/cicd/docker/Dockerfile-osctrl-frontend](../deploy/cicd/docker/Dockerfile-osctrl-frontend). The image serves the SPA with nginx and proxies `/api/*` to `osctrl-api:9002`.

By default the release image listens on HTTP port 80 for use behind a TLS terminator. Set `OSCTRL_FRONTEND_TLS=1` to enable its TLS configuration, then mount:

- `/etc/ssl/osctrl/tls.crt`
- `/etc/ssl/osctrl/tls.key`

The matching nginx configurations live under `deploy/cicd/nginx/`.
