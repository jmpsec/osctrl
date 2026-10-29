# Docker Development Environment

The root [docker-compose-dev.yml](../../docker-compose-dev.yml) runs the local `osctrl` stack:

- nginx TLS termination
- `osctrl-tls`
- `osctrl-api`
- the React frontend
- PostgreSQL and Redis
- `osctrl-cli` bootstrap
- three sample osquery clients
- an optional catch-all HTTP sink

This stack is for development and testing. Its sample credentials and self-signed certificate are not production defaults.

## Prerequisites

Install Docker with the Compose v2 plugin and OpenSSL.

Create the local environment file:

```bash
cp .env.example .env
```

Review at least `JWT_SECRET`, `OSCTRL_USER`, `OSCTRL_PASS`, image versions, and database credentials. Generate a long JWT secret, for example:

```bash
openssl rand -hex 32
```

Do not commit `.env`.

## TLS Certificate

Generate the development certificate and private key from `deploy/docker/conf/tls/openssl.cnf`:

```bash
make docker_dev_certs
```

The generated `osctrl.crt` and `osctrl.key` are local development material and must not be committed. To customize names or subject alternative names, copy and edit `openssl.cnf.example` before generating the certificate.

## Build and Start

From the repository root:

```bash
make docker_dev_build
make docker_dev_up
```

Or run both through the combined target:

```bash
make docker_dev
```

The first CLI bootstrap creates the `dev` environment and the administrator configured by `OSCTRL_USER` and `OSCTRL_PASS`.

## Endpoints

| Surface | URL | Purpose |
| --- | --- | --- |
| Operator frontend | `https://localhost:8444` | React SPA and proxied `/api/*` requests |
| osquery TLS endpoint | `https://localhost:8443` | Enroll, config, log, distributed query, and carve traffic |
| Direct API | `http://localhost:9002` | Local API debugging |
| Direct TLS service | `http://localhost:9000` | Local TLS-handler debugging |
| PostgreSQL | `localhost:5432` | Development database |
| Redis | `localhost:6379` | Development cache and shared runtime state |
| Catch-all sink | `http://localhost:8088` | External log/alert sink testing |

The browser will warn about the self-signed certificate unless the development CA or certificate is trusted locally.

## Common Commands

```bash
make docker_dev_logs_tls
make docker_dev_logs_api
make docker_dev_logs_frontend

make docker_dev_shell_tls
make docker_dev_shell_api
make docker_dev_shell_frontend
make docker_dev_shell_cli

make docker_dev_rebuild_tls
make docker_dev_rebuild_api
make docker_dev_rebuild_frontend

make docker_dev_down
```

`make docker_dev_clean` removes matching development images and volumes, including PostgreSQL and Redis data. Use it only when a full local reset is intended.

## Troubleshooting

- **Missing `.env`**: run `cp .env.example .env`.
- **Missing certificate or key**: run `make docker_dev_certs`.
- **Frontend login loops**: use `https://localhost:8444` so the SPA and API cookies remain same-origin.
- **Services cannot reach PostgreSQL or Redis**: inspect container health and the shared `osctrl-dev-backend` network.
- **osquery clients do not enroll**: confirm the CLI bootstrap completed and the certificate mounted into the clients matches nginx.

## Staging (published release)

The root `docker-compose-staging.yml` assembles the four published Docker Hub images (`osctrl-tls`, `osctrl-api`, `osctrl-cli`, and `osctrl-frontend`). It does not compile local source or mount the source tree. Configuration files and the bootstrap script are mounted read-only. Use a release that publishes all four images with the current API/frontend split, such as `0.6.2`.

### Configure and start

From the repository root:

```bash
cp .env.staging.example .env.staging
```

Edit `.env.staging`:

- Set `OSCTRL_VERSION` to the Docker Hub release tag, without a leading `v`. All four images use this tag; prerelease tags are supported.
- Set independent, random `JWT_SECRET`, `POSTGRES_DB_PASSWORD`, and `OSCTRL_PASS` values. Generate each with `openssl rand -hex 32`. The JWT secret must be at least 32 bytes.
- Set `OSCTRL_USER` to the initial administrator's username.
- Keep `OSCTRL_IMAGE_NAMESPACE=jmpsec` for the official images, or select your own Docker Hub namespace.

Empty required values fail before Compose starts the stack. `.env.staging` is ignored by Git and is separate from development's `.env`.

For local testing, generate the staging certificate, then start:

```bash
make docker_staging_certs
make docker_staging
```

The certificate command refuses to overwrite existing staging certificates. It creates a self-signed certificate for `localhost`, `127.0.0.1`, and the internal proxy name. The browser will need to trust this certificate or accept its warning.

By default all published ports are bound to loopback:

| Surface | URL |
| --- | --- |
| Operator frontend and `/api/*` | `https://localhost:9444` |
| osquery TLS endpoint | `https://localhost:9443` |
| PostgreSQL | `localhost:15432` |
| Redis | `localhost:16379` |

PostgreSQL and Redis use non-standard host ports to avoid development conflicts. Configure them with `STAGING_POSTGRES_PORT` and `STAGING_REDIS_PORT` in `.env.staging`; both always bind to `127.0.0.1`, even if HTTPS is exposed remotely. Containers still connect to PostgreSQL on `5432` and Redis on `6379` through the staging network. The API and backend TLS listener remain internal. The Compose project is named `osctrl-staging`, with project-scoped volumes and networking; development can run alongside it.

Bootstrap waits for PostgreSQL, creates the `staging` environment and administrator if absent, then exits. Backend services start only after bootstrap succeeds and Redis is healthy. Subsequent starts preserve the environment, administrator password, and persisted data. Changing `OSCTRL_PASS` in the file does not reset an existing user's password.

For a remote staging host, set `STAGING_BIND_ADDRESS` to the intended interface, set `STAGING_TLS_HOST` and `STAGING_FRONTEND_HOST` to reachable `hostname:port` values, and provide a matching certificate using `STAGING_TLS_CERT` and `STAGING_TLS_KEY`. Keep those hosts consistent with `STAGING_TLS_PORT` and `STAGING_FRONTEND_PORT`. The local certificate generator is for localhost only. Set the external hostname and certificate before the first bootstrap; existing environment settings are preserved on later starts.

### Commands and release changes

```bash
make docker_staging_pull   # Download the selected images without starting them
make docker_staging_build  # Alias for pull; no local build
make docker_staging_up     # Pull and start the selected stack in the background
make docker_staging_logs
make docker_staging_down   # Stop the stack; retain database/cache volumes
make docker_staging_check  # Deployment contract tests; no daemon needed
```

The start command recreates all staging containers together so nginx resolves the current upstream container addresses. This briefly interrupts staging; named volumes are retained.

To select another release, back up the staging database, edit `OSCTRL_VERSION` in `.env.staging`, and run `make docker_staging`. An unpublished tag fails during image pulling. Backend startup performs database schema migration; switching to an older image tag is not a database rollback. Restore a compatible backup or use a separate fresh Compose project for downgrade testing. Keep the PostgreSQL major version unchanged for an existing database volume.

For an isolated test project, override the project name and host ports explicitly:

```bash
STAGING_POSTGRES_PORT=25432 STAGING_REDIS_PORT=26379 \
STAGING_TLS_PORT=10443 STAGING_FRONTEND_PORT=10444 \
STAGING_TLS_HOST=localhost:10443 STAGING_FRONTEND_HOST=localhost:10444 \
docker compose -p osctrl-staging-test --env-file .env.staging \
  -f docker-compose-staging.yml up -d --no-build
```

Use that same project name when stopping it. Avoid `down -v` unless you intend to delete that project's staging database and cache. The existing `docker_dev_clean` target broadly matches osctrl images/volumes and must not be used while preserving staging data.
