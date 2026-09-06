# Monitoring fake_news_go

`fake_news_go` records request counts, failures, error rate, and min/average/max/P95/P99 latency globally, per operation, and per endpoint. Use it to observe a steady workload or find a practical failure threshold with a staged sweep.

See [README.md](./README.md) for connection, discovery, posture, and traffic-generation options.

## Scenario and Display Modes

The two mode flags control different things:

- `--mode steady|sweep` selects the workload scenario.
- `--display-mode quiet|summary|verbose|dashboard|json` selects output formatting.
- `--output-mode` is an alias for `--display-mode`.

Do not use `--mode dashboard` or `--mode json`; those are display modes.

| Display mode | Use |
| --- | --- |
| `quiet` | Minimal terminal output for high-volume runs |
| `summary` | Periodic text summaries; the default |
| `verbose` | Per-request diagnostics for small debugging runs |
| `dashboard` | Interactive terminal dashboard; quit with `q` or `Ctrl+C` |
| `json` | Periodic machine-readable snapshots |

Set the summary or JSON cadence with `--summary-interval <seconds>`.

## Steady Monitoring

Run a fixed workload until interrupted:

```bash
go run ./tools/fake_news_go \
  --tls-url http://localhost:9000 \
  --env YOUR_ENV_UUID \
  --secret YOUR_SECRET \
  --nodes 100 \
  --display-mode dashboard
```

For lower terminal overhead:

```bash
go run ./tools/fake_news_go \
  --tls-url http://localhost:9000 \
  --env YOUR_ENV_UUID \
  --secret YOUR_SECRET \
  --nodes 2000 \
  --display-mode summary \
  --summary-interval 60
```

Use `quiet` when an external profiler or service dashboard is the primary observer.

## Sweep Monitoring

Sweep mode increases the node count in stages and stops at the first configured threshold breach:

```bash
go run ./tools/fake_news_go \
  --tls-url http://localhost:9000 \
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

The threshold values are:

- `--error-threshold`: failure ratio from 0 to 1
- `--p95-threshold`: maximum acceptable P95 duration
- `--settle`: warm-up duration before evaluating a stage
- `--sample`: measurement duration for a stage

A completed or interrupted run writes `fake_news_report.json` by default. The report records the highest stable stage, first failing stage, failure reason, totals, and generation time.

## JSON Output

JSON display mode emits periodic snapshots suitable for collection or post-processing:

```bash
go run ./tools/fake_news_go \
  --tls-url http://localhost:9000 \
  --env YOUR_ENV_UUID \
  --secret YOUR_SECRET \
  --nodes 500 \
  --display-mode json \
  --summary-interval 30
```

Keep credentials out of shell history and collected output. Prefer `--discover-envs` only in an isolated test environment because it authenticates to `osctrl-api` and retrieves enroll secrets for every accessible environment.

## Interpreting Results

- Compare P95 and error rate together; low median latency does not compensate for a failing tail.
- Allow a settling period after enrollment before evaluating recurring traffic.
- Increase node counts gradually to separate capacity limits from enrollment bursts.
- Use `--enroll-delay` when the TLS enrollment rate limiter is the behavior under test only indirectly.
- Keep API, TLS, PostgreSQL, Redis, and host metrics alongside the harness report.
- Repeat a sweep before treating its first failing stage as a stable capacity limit.

The harness simulates distributed query results internally. `--osquery-binary` remains available for compatibility, but normal query-write traffic does not require a local `osqueryi` process.

## Verification

Run the focused test suite after changing the harness or its metrics:

```bash
go test ./tools/fake_news_go/...
```
