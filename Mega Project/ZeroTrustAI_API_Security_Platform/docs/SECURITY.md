# Threat model and known limits

## Intended environment

An isolated local college demonstration with synthetic identities and records. Run test
traffic only against your own sandbox. Do not put real customer data into this prototype.

## Trust boundaries

1. **Client → gateway:** untrusted headers, paths, body, and tokens. JWT claims become
   usable only after verification. `X-Forwarded-*` and `Forwarded` are not trusted.
2. **Gateway → backend:** fixed configured origin, no redirects followed, path components
   encoded, dot/backslash paths rejected. Docker does not publish the backend's port.
3. **Gateway → state/database:** trusted internal services; unavailable security state
   fails requests closed. Audit failures return `503`, but an already forwarded mutating
   request cannot be rolled back. Do not retry writes without idempotency support.
4. **Administrator → management API:** separate JWT audience, authenticated access,
   bounded login attempts. Browser token is memory-only; reload requires signing in.
5. **Offline training → inference:** model artifacts are executable trusted inputs.
   Never accept uploaded joblib/pickle files. Training data must be curated.

## Existing protections

- Algorithm-locked HS256, required claims, issuer/audience/expiry validation.
- Password hashing using salted PBKDF2-SHA256; constant-time hash comparison.
- Login and behavioral request limits; subject-keyed windows survive token refresh.
- Ownership and role checks in the actual backend, independent of anomaly scores.
- Bounded request/response bodies, upstream connection/read timeouts, connection pools.
- Numeric telemetry only: raw body, query, cookies, and Authorization values are not saved.
- Known route templates in audit logs avoid storing arbitrary user-controlled paths.
- Admin-rendered data uses `textContent`, not HTML interpolation.
- Local assets only, strict dashboard CSP, no browser token persistence, no permissive CORS.
- Compose binds the gateway to loopback, keeps data services internal, and runs app
  containers as a non-root user with dropped capabilities.

## Limits requiring work before any real deployment

- HTTP is acceptable only for loopback testing; use TLS and a reviewed edge configuration
  for deployment. This code is not reviewed for hostile internet exposure or DoS resilience.
- HS256 is shared between sandbox services. Use an external identity provider and asymmetric
  keys, key rotation, revocation, scoped permissions, and per-service trust boundaries.
- One static sandbox password is shared across demo users. No registration, recovery,
  enrollment, real MFA, refresh tokens, or durable user database exists.
- Redis/PostgreSQL have no TLS here; Redis has no authentication on its internal Compose
  network. Do not publish either service or share this network with untrusted workloads.
- Rate counters and quarantine state are ephemeral; restarting Redis clears them. Set an
  appropriate persistence/availability policy for a real system.
- Multiple users behind one NAT share unauthenticated limits. Distributed identities and
  low-and-slow abuse can evade simple subject-based windows. IP is not a reliable identity.
- Memory state is for one process only; running multiple workers bypasses aggregate limits.
- No WAF parser, semantic SQLi/XSS detector, geographic intelligence, anti-bot challenge,
  distributed tracing, formal NIST compliance, or complete OWASP coverage is claimed.
- The baseline model uses synthetic data and cannot establish real-world detection accuracy.
  Anomaly detection does not prove malice and is not a substitute for authorization.
- Event storage is mutable, not tamper-evident. Management login attempts are rate limited
  but not yet persisted as a separate audit trail. Add durable admin audit events/SIEM export.
- Event history is time-retained, not hard-capacity-limited. Set disk quotas and operational
  monitoring for extended tests. Schema migrations are not implemented; `create_all` is
  initialization only.
- Large/slow inbound headers, slow uploads, SSE connection floods, and total request deadlines
  need reviewed edge limits. Redis window work scales with the configured request limit;
  do not raise it to large values without profiling or replacing aggregation.
- Response buffering deliberately excludes large downloads/streaming. Set-Cookie is not
  forwarded; this demo uses bearer authentication, not browser cookie sessions.
- A manual release removes quarantine only; existing counters still apply. Safe retry and
  idempotency behavior must be defined before adding real backend write operations.

## Academic reporting

Separate rule-based enforcement, backend authorization, and model predictions in evaluation.
Report attack labels, class balance, held-out sessions, confusion matrices, false-positive
rates, per-scenario recall, and measured hardware/latencies. Verify literature references
independently. Do not copy the proposal's figures into a results section without experiments.
