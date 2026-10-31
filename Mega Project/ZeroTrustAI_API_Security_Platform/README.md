# ZeroTrustAI — API Security Platform

A working, local-first academic prototype: a defensive API gateway that combines explicit
authentication and authorization, behavioral rules, optional Isolation Forest scoring,
temporary identity quarantine, and a live SecOps dashboard.

**This is a research build, not a production WAF or a certified Zero Trust solution.**
The source presentation's accuracy, latency, throughput, and zero-day claims are not
validated results. This implementation makes no such claims.

## What's implemented

- Asynchronous FastAPI reverse proxy with a fixed upstream (not an open proxy).
- JWT signature, expiry, issuer, and audience validation on every protected request.
- Demo API with Alice/Bob object ownership and a separate operator role.
- 18 versioned features, rolling 60-second history, and atomic rate counters.
- Redis shared state or bounded single-process memory state for local development.
- Configurable throttling, temporary quarantine, and audited administrator releases.
- SQLite locally / PostgreSQL in Docker; 7-day default event retention.
- Password/token/query redaction: telemetry stores numeric features, not raw payloads.
- A trainable Isolation Forest, held-out calibration/test split, evaluation JSON.
- Administrator-only dashboard with live SSE summaries, event filters, and quarantines.
- Local-only traffic scenarios and automated integration tests.

**Not implemented yet:** autoencoder/ensemble, actual step-up MFA, geo-velocity, gRPC,
SIEM forwarding, production identity-provider integration, or verified OWASP-wide detection.
The dashboard explicitly identifies these limits. The frontend is vanilla JavaScript/CSS,
not React, to keep this release runnable without a Node.js toolchain.

## Quick start — recommended Docker setup

Requirements: Docker with Compose, Python 3.12+, and optionally [uv](https://docs.astral.sh/uv/)
for training/tests. No paid services are required.

```bash
cd "Mega Project/ZeroTrustAI_API_Security_Platform"
python3 scripts/init_env.py
docker compose up -d --build
```

Open **http://127.0.0.1:8000**. Sign in as `admin` using `ZT_ADMIN_PASSWORD` from
the generated `.env` file. Open that file locally; do not share or commit it.

Docker runs the gateway, demo API, Redis, and PostgreSQL. **Only the gateway is
published**, on the host's loopback interface. The demo backend cannot be accessed
directly from the host in this configuration. Services require a healthy dependency
before the gateway starts. PostgreSQL events survive container restarts.

Useful commands:

```bash
docker compose ps
docker compose logs --tail=60 gateway
docker compose down
```

`down` preserves the database volume. Do not use `down -v` unless you intend to delete
all stored events. Quarantines/counters are ephemeral in this research configuration.

### Enable the ML baseline

```bash
uv sync --python 3.13
uv run python -m ml.train
docker compose restart gateway
```

The model is loaded **only at gateway startup**. The host artifact directory is mounted
read-only inside the gateway. If no artifact exists, the gateway explicitly runs
**rules-only**. An incompatible/corrupt artifact prevents startup; it is not silently
ignored. Only load your own trusted artifacts: joblib/pickle files can execute code.

Default training data is **synthetic and deliberately limited**. Its scores are a pipeline
sanity check, not an estimate of real-world detection. In particular, Isolation Forest
need not identify every out-of-range vector; rate rules are an independent control.
See `reports/model_evaluation.json` after training.

## Local development without Docker

```bash
python3 scripts/init_env.py
uv sync --python 3.13
uv run python -m ml.train
```

Start these in **two terminals**, from the project directory:

```bash
uv run uvicorn demo_api.main:app --host 127.0.0.1 --port 8001 --no-proxy-headers
```

```bash
uv run uvicorn gateway.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Empty `ZT_REDIS_URL` selects memory state. **Use exactly one gateway worker** in this
mode. The backend's loopback port is reachable locally in development; Docker is the
recommended demo when showing gateway isolation.

## Generate demo traffic

Run while the gateway is active:

```bash
uv run python -m traffic_simulator.run normal
uv run python -m traffic_simulator.run bola
uv run python -m traffic_simulator.run role
uv run python -m traffic_simulator.run invalid-token
uv run python -m traffic_simulator.run burst
```

The simulator is restricted to local HTTP targets and has bounded request counts.
Expected outcomes: normal requests `200`, Alice accessing Bob's order `403`, Alice
accessing administrator users `403`, invalid token `401`, bursts eventually `429`.
Run `burst` last; previous counters persist for 60 seconds. Severe sustained traffic
can trigger a 120-second quarantine. Releasing a quarantine does **not** reset its
rate window; wait for the window to expire.

Demo users `alice`, `bob`, and `operator` share `ZT_DEMO_PASSWORD` in this sandbox.
`operator` is a **demo backend administrator**, not a dashboard administrator.
Dashboard tokens and demo API tokens have separate audiences and cannot substitute
for one another. Both expire after 15 minutes; there are no refresh tokens.

## API reference

| Endpoint | Access / purpose |
| --- | --- |
| `GET /` | Dashboard shell, no telemetry until authenticated |
| `GET /health` | Gateway liveness |
| `POST /api/admin/login` | Dashboard username/password → administrator JWT |
| `GET /api/summary` | Admin; last-hour outcomes and engine status |
| `GET /api/events?limit=100` | Admin; latest redacted events, max 500 |
| `GET /api/stream` | Admin; SSE summaries, closes at token expiry |
| `GET /api/quarantines` | Admin; active identity restrictions |
| `POST /api/quarantines/release` | Admin; `{"identity":"user:alice"}` |
| `POST /proxy/auth/login` | Demo username/password → demo JWT |
| `GET /proxy/products` | Authenticated demo catalog |
| `GET /proxy/orders` | Own orders; operator can view all |
| `GET /proxy/orders/{id}` | Ownership/role checked by backend |
| `GET /proxy/admin/users` | Demo operator role only |

Bearer tokens go in `Authorization: Bearer <token>`, including SSE. Tokens are never
put in query strings or browser persistent storage. Interactive gateway API docs:
`http://127.0.0.1:8000/docs`.

## Detection and enforcement

Hard authentication/authorization failures are denied independent of anomaly score.
Authenticated rate windows use the verified subject, **not token ID or caller-supplied
forwarded IP**, so refreshing a token or spoofing `X-Forwarded-For` does not reset them.
Unauthenticated traffic is keyed by actual socket peer; login has a stricter limit.

ML contributes at most 35 points. Rate abuse, enumeration, query shape, and historical
authentication failures contribute deterministic signals. Above 70, the gateway blocks
and temporarily quarantines the identity. Medium risk can tighten rate limits but does
**not** trigger fake MFA. A score is a research heuristic, not a calibrated probability.

Ownership denials are backend decisions logged as `backend_authorization_denied`.
This is not a claim that ML detects BOLA. SQLi/XSS payload classification and OWASP-wide
coverage are not implemented. Oversize bodies are rejected, not classified as attacks.

### Features (schema v1)

`path_length`, `path_depth`, `query_length`, `parameter_count`, `body_bytes`,
`body_entropy`, `header_count`, `header_bytes`, `is_post`, `is_write`, `requests_60s`,
`unique_paths_60s`, `interarrival_ms`, `recent_error_ratio`, `recent_auth_failures`,
`token_age_seconds`, `is_json`, `special_char_ratio`.

Current response status is excluded from the current decision, avoiding future-data
leakage. Historical status is recorded after the response. Timing uses wall clock for
windows and monotonic performance counters for elapsed measurements.

### Curated training data

Use only reviewed benign records; do not automatically retrain on live, potentially
malicious requests. Input is JSONL with `label: "benign"` and an ordered `features`
array of 18 finite numbers. Keep sessions/users separated across temporal train,
validation, and test boundaries when collecting data.

```bash
uv run python -m ml.train --input data/curated_benign.jsonl
```

The first 70% is training, next 15% threshold calibration, final 15% held-out benign
testing. The generated evaluation includes an explicitly synthetic modified-vector
sanity check. A genuine attack-labeled evaluation dataset is still required.

## Verification

```bash
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
```

Tests cover authentication/audience isolation, expired/forged tokens, BOLA and roles,
atomic concurrent limits, quarantine/release audit, redaction, body/path validation,
upstream/state failure, private secret initialization, features, and training round-trip.

`inspection_ms` is pre-forward checks (including async scheduling), excludes backend
execution and final event persistence. `total_ms` includes backend time, but excludes
final database persistence and network delivery. **Neither is a controlled overhead
benchmark.** Use direct-backend versus proxied load tests on an isolated environment,
recording hardware, concurrency, failures, and p50/p95/p99. No target figures are assumed.

## Configuration

Run initialization once; it refuses to overwrite an existing `.env`, generates random
secrets, and sets file permissions to `0600`. `.env`, data, and model artifacts are ignored
by Git. `ZT_` environment variables override the file. Key defaults:

| Variable | Default |
| --- | --- |
| `ZT_REQUESTS_PER_MINUTE` | 60 per subject/peer rolling minute |
| `ZT_QUARANTINE_SECONDS` | 120 |
| `ZT_MAX_BODY_BYTES` | 65,536 |
| `ZT_EVENT_RETENTION_DAYS` | 7 |
| `ZT_REDIS_URL` | Empty: single-process memory |
| `ZT_DATABASE_URL` | Local SQLite; Compose overrides to PostgreSQL |
| `ZT_MODEL_PATH` | `ml/artifacts/isolation_forest.joblib` |

Responses are buffered and limited to 2 MiB. This is a bounded JSON/REST prototype,
not a transparent proxy for uploads, cookies, WebSockets, streaming, or gRPC.

## Next milestones

1. Gather representative benign sessions and independent labeled abuse scenarios.
2. Add a PyTorch `18 → 12 → 6 → 12 → 18` autoencoder; compare rules/IF/AE/ensemble.
3. Implement real TOTP step-up with enrollment, replay prevention, and route-bound grants.
4. Add workload benchmarks, policy-versioned evaluation, and model drift reporting.
5. Verify presentation references; update the academic report with measured results.

See [`docs/SECURITY.md`](docs/SECURITY.md) for the threat model and deployment limits.
