# fake_news_go

`fake_news_go` is a console-native load harness for `osctrl-tls` and `osctrl-api`.

It keeps the terminal workflow of the original `fake_news.py`, but adds a structured package layout, testable transport and synthetic query simulation, a `termui` dashboard, and sweep mode for finding a practical limit.

## 🚦 Modes

- `steady`: fixed node count, continuous traffic, exit with `Ctrl+C`, `q`, or `Q`
- `sweep`: staged ramp-up, automatic stop when thresholds are crossed, JSON report on completion, exit early with `Ctrl+C`, `q`, or `Q`

## 🎯 Targets

- `osctrl-tls`: enroll, log, config, distributed read, distributed write
- `osctrl-api`: auth discovery, login environment list, login, `users/me`, environment reads, paged node reads, node detail, settings reads

## 🛠️ Useful flags

- `--tls-url` or legacy `--url`: base URL for `osctrl-tls`
- `--api-url`: base URL for `osctrl-api`
- `--api-username`, `--api-password`: credentials for authenticated API scenarios
- `--discover-envs`: log into `osctrl-api`, resolve every accessible environment UUID plus enroll secret, and start the harness automatically
- `--env`: environment UUID
- `--secret`: enroll secret for `osctrl-tls`
- `--mode`: `steady` or `sweep`
- `--display-mode`: `quiet`, `summary`, `verbose`, `dashboard`, or `json`
- `--error-threshold`: stop sweep when error rate exceeds this ratio
- `--p95-threshold`: stop sweep when p95 exceeds this duration
- `--sweep-start-nodes`, `--sweep-step-nodes`, `--sweep-stages`
- `--settle`, `--sample`
- `--state`: persisted node state file

The harness now simulates distributed query results internally and does not require a local `osqueryi` binary for query-write traffic.

Default runtime files:

- node state: `fake_news_state.json`
- final report: `fake_news_report.json`

## 🚀 Examples

Helper targets from this directory:

```bash
make dashboard ENV_UUID=YOUR_ENV_UUID SECRET=YOUR_SECRET

make dashboard \
  DISCOVER_ENVS=1 \
  API_URL=http://localhost:9002 \
  API_USERNAME=admin \
  API_PASSWORD=admin

make sweep ENV_UUID=YOUR_ENV_UUID SECRET=YOUR_SECRET

make clean

make sweep \
  ENV_UUID=YOUR_ENV_UUID \
  SECRET=YOUR_SECRET \
  API_URL=http://localhost:9002 \
  API_USERNAME=admin \
  API_PASSWORD=admin
```

Useful helper variables:

- `TLS_URL`
- `API_URL`
- `API_USERNAME`
- `API_PASSWORD`
- `NODES`
- `STATE`
- `REPORT`
- `SWEEP_START_NODES`
- `SWEEP_STEP_NODES`
- `SWEEP_STAGES`

Steady TLS load with dashboard output:

```bash
go run ./tools/fake_news_go \
  --tls-url http://localhost:9000 \
  --env YOUR_ENV_UUID \
  --secret YOUR_SECRET \
  --nodes 50 \
  --display-mode dashboard
```

Automatic environment discovery from `osctrl-api` and immediate startup across every accessible environment:

```bash
go run ./tools/fake_news_go \
  --tls-url http://localhost:9000 \
  --api-url http://localhost:9002 \
  --api-username admin \
  --api-password admin \
  --discover-envs \
  --nodes 50 \
  --display-mode dashboard
```

Mixed TLS + API sweep with automatic stop and JSON report:

```bash
go run ./tools/fake_news_go \
  --tls-url http://localhost:9000 \
  --api-url http://localhost:9002 \
  --api-username admin \
  --api-password admin \
  --env YOUR_ENV_UUID \
  --secret YOUR_SECRET \
  --mode sweep \
  --display-mode dashboard \
  --sweep-start-nodes 25 \
  --sweep-step-nodes 25 \
  --sweep-stages 8 \
  --error-threshold 0.02 \
  --p95-threshold 1s \
  --settle 10s \
  --sample 20s
```

## ✅ Verification

Focused package verification:

```bash
go test ./tools/fake_news_go/...
```

Dashboard mode uses `termui` and shows:

- global totals and latency percentiles
- per-operation metrics for enroll, status, result, config, query-read, and query-write
- per-endpoint breakdown
- sweep stage and threshold state in sweep mode

The harness writes `fake_news_report.json` in the current working directory and persists node state to `fake_news_state.json` by default.

When `--discover-envs` finds more than one environment, state is split per environment automatically, for example `fake_news_state_<env-uuid>.json`.
