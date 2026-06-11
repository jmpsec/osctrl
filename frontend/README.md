# osctrl frontend

React + TypeScript + Vite SPA for the osctrl admin UI.

Talks exclusively to `osctrl-api` (port 8081 by default). Served as static files — no Node.js server in production.

> [!IMPORTANT]
> The frontend is the primary operator UI going forward. The legacy server-rendered `osctrl-admin` HTML interface is being kept for transition purposes and will be deprecated.

## 🤔 What is the frontend?

The **osctrl frontend** is the modern operator UI for managing environments,
nodes, queries, carves, tags, users, and settings through `osctrl-api`.

### 🚀 Why it exists

The frontend is where new operator-facing UX improvements are landing. It
replaces the legacy server-rendered `osctrl-admin` experience with a React SPA
that talks directly to the API layer.

## 🗂 Directory

```
frontend/
├── src/
│   ├── main.tsx          React 19 entry point
│   ├── router.tsx        TanStack Router instance
│   ├── routes/           Page components (TanStack Router)
│   ├── components/       Reusable UI components (primitives, atoms, data, chrome, forms, feedback)
│   ├── features/         Feature modules (one folder per page: nodes, queries, carves, ...)
│   ├── api/              Typed API client + generated types
│   ├── lib/              Utilities, custom hooks, time formatting
│   └── styles/           Tailwind base + design token CSS
└── tests/
    └── e2e/              Playwright end-to-end tests
```

## 🧰 npm scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Start Vite dev server on port 5173, proxying `/api` to `:8081` |
| `npm run build` | Type-check then produce `dist/` |
| `npm run preview` | Preview the production build locally |
| `npm run check` | Run `tsc --noEmit` (type-check only) |
| `npm run lint` | Alias for `check` (linting config added in a later track) |
| `npm test` | Run Vitest once |
| `npm run test:watch` | Run Vitest in watch mode |
| `npm run test:e2e` | Run Playwright e2e tests |

## 🛠 Development

### 💻 Local frontend workflow

```bash
# Terminal 1 — osctrl API (Go)
make api-dev   # starts osctrl-api on :8081

# Terminal 2 — React SPA
cd frontend
npm run dev    # starts Vite on :5173, proxies /api/* to :8081
```

Open `http://localhost:5173` in the browser. Vite's dev proxy forwards all `/api/*` requests to the running Go API, so auth cookies work as same-origin.

### 🐳 Docker dev stack

The repository's `docker-compose-dev.yml` exposes the frontend through
`osctrl-nginx` at:

- `https://localhost:8444` for the frontend SPA
- `https://localhost:8443` for the legacy `osctrl-admin` HTML interface

In that setup, `osctrl-frontend` stays internal-only on the Docker network and
`osctrl-nginx` performs TLS termination before proxying requests to it.

## 🏗 Production build

```bash
make frontend    # runs npm ci + npm run build in frontend/
```

Output: `frontend/dist/`. Deploy options:

1. **nginx** — serve `dist/` as the document root, reverse-proxy `/api/*` to `osctrl-api`. See `deploy/nginx/frontend.conf.example`.
2. **Static hosting + CDN** — upload `dist/` to S3/Cloudfront/etc. Configure CORS on the API.
3. **Docker** — build the multi-stage image at `deploy/docker/dockerfiles/Dockerfile-osctrl-frontend` (`node:22-alpine` → `nginx:alpine`). Single image, no separate Go binary.

## ⚙️ Tech stack

- React 19 + TypeScript 5 (strict)
- Vite 7
- TanStack Router (typed routing)
- TanStack Query 5 (server state)
- TanStack Table 8 (headless table)
- Tailwind CSS v4 via `@tailwindcss/vite`
- Radix UI primitives (à la carte)
- react-hook-form 7 + zod 3
- Vitest + @testing-library/react + jsdom
- Playwright (e2e)
