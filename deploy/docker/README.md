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
