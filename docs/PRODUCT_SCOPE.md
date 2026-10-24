# SecureLogPath product scope and delivery plan

## Purpose

SecureLogPath is an academic and portfolio-grade mini-SIEM demonstrator. It
makes selected algorithmic steps, measurements, and limitations observable.
It does not replace an enterprise SIEM and must not be presented as production
security monitoring or automated network defense.

## Version 1.0 scope

- React/Vite dashboard and upload portal.
- FastAPI backend with role-checked REST endpoints, background ingestion, and
  Server-Sent Events (SSE).
- PostgreSQL with the Apache 2.0 TimescaleDB edition.
- Encrypted JSONL scenario uploads; sensitive fields are decrypted in memory
  and excluded from ordinary persisted log rows and application logs.
- Custom, isolated algorithm demonstrations: RSA arithmetic/CRT, KMP,
  randomized QuickSort, binary search, Dijkstra, and Monte Carlo estimation.
- A seeded enterprise-style graph and simulated containment that changes only
  the application's graph state.
- Handcrafted deterministic scenarios and a separate generated benchmark set.
- Docker Compose startup, health checks, documented configuration, migrations,
  and operator instructions.

## Explicit boundaries

- No live packet capture, endpoint agent, enterprise product connector, or
  production cloud service in v1.
- No commands to real firewalls, routers, endpoints, or cloud control planes.
- No production readiness, high availability, horizontal scaling, or
  million-event throughput claims.
- FastAPI in-process background tasks are not durable. An interrupted job can
  be marked failed after restart; automatic continuation is not required.
- Start with a single API instance. Persist alerts and support cursor-based
  SSE recovery so a client reconnect can recover events.
- Never use the educational RSA implementation to protect real data; use a
  reviewed cryptographic library in the secure ingestion path.
- Use only synthetic fixtures in the public demo. Do not upload confidential
  or real organization logs.

## Repository structure

```text
algorithms/   Canonical pure-Python algorithms and their unit tests
backend/       FastAPI service and backend configuration
database/      Database initialization and migrations
docs/          Product scope and operations documentation
frontend/      React/Vite client and Nginx production container
compose.yaml   Local and single-host deployment services
```

All algorithm implementations live only in the root `algorithms/` package.
Python application code imports that package directly. The frontend calls API
operations and must not maintain duplicate algorithm implementations.

## Phase 1 exit criteria

- The project scope, exclusions, single-host deployment boundary, and
  repository layout are written down.
- The repository has an open-source license and excludes local secrets and
  generated data.
- Compose defines frontend, backend, and TimescaleDB with health checks and
  persistent database storage.
- Backend readiness checks its database connection; the database is not
  published on a host port.
- A clean local start is documented as `docker compose up --build`.
- No production deployment or security-audit claim is made.

## Phase 2 exit criteria

- RSA arithmetic/CRT, KMP, randomized QuickSort, binary-search bounds,
  heap-based Dijkstra, and Monte Carlo proportion estimation exist only under
  `algorithms/`.
- The package has no FastAPI, ORM, database, or browser dependencies.
- Tests exercise correctness, boundary cases, reproducibility, and invalid
  inputs for each public algorithm module.
- The algorithm guide documents interfaces, complexity, assumptions, and
  security/interpretation limits.
- The backend image imports the root package directly; no backend copy exists.

## Phase 3 scope: database and backend basics

Phase 3 establishes the persistent data model and authenticated API foundation.
The secure upload/decryption pipeline, analyst investigation APIs, live event
stream, and dashboard workflows belong to later phases.

### Phase 3 exit criteria

- Ordered SQL migrations are applied once and tracked in `schema_migrations`;
  a fresh database receives the core schema and a baseline topology.
- The schema includes users, ingestion jobs, time-partitioned security logs,
  alerts, append-only-by-application audit events, topology nodes, and edges.
- Sensitive log material has only an encrypted storage column; ordinary
  metadata columns do not contain plaintext payloads or IP addresses.
- Login uses Argon2 password hashes and short-lived signed bearer tokens. The
  API loads current user roles from the database and checks roles on protected
  routes.
- A one-time environment bootstrap can create the initial Admin without a
  built-in password. An Admin can provision Forwarder, Analyst, and Admin
  accounts. Passwords and tokens are never returned by user APIs.
- Login denials and role denials create safe audit records without credentials
  or request payloads.
- On startup, unfinished in-process jobs are marked `interrupted`, matching
  the documented single-process BackgroundTasks limit.
- Database, JWT, and bootstrap credentials come from environment configuration;
  the frontend bundle receives none of them.
- Backend basics and schema behavior are manually verified through the local
  Compose environment before this phase is called complete.

## Phase 4 scope: secure ingestion pipeline

Forwarders request the active RSA public key, then submit bounded JSONL uploads
whose sensitive bundle is encrypted with a fresh AES-256-GCM key per event.
That data key is wrapped with RSA-OAEP using SHA-256. The backend authenticates
the envelope metadata as AES-GCM associated data before parsing the plaintext
bundle. Only synthetic data belongs in local demos.

The JSONL contract has one envelope per UTF-8 line: `schema_version`, `log_id`,
timezone-aware `timestamp`, optional safe asset identifiers, and a `crypto`
object with `algorithm`, `key_id`, `wrapped_data_key`, `nonce`, and
`ciphertext`. Associated data is the compact, sorted-key UTF-8 JSON encoding of
the supplied public envelope metadata (`schema_version`, `log_id`, `timestamp`,
and whichever asset identifiers are present). The decrypted JSON object may
contain `event_type`, `source_ip`, `destination_ip`, and `payload`. Ciphertext
is retained for the sensitive bundle; IP addresses and payload are not copied
to searchable metadata or ordinary application logs.

Uploads are size/line bounded, checked for duplicate JSON keys and log IDs,
validated independently per line, and submitted as persistent ingestion jobs.
The single API process uses bounded FastAPI background tasks; it does not claim
durable queue semantics. Configured KMP signatures are matched against the
case-folded payload, and alerts are persisted with signature IDs, categories,
severity, offsets, and rule version. Invalid lines receive safe error codes.
Idempotency keys replay the existing job only when the upload digest matches.

### Phase 4 exit criteria

- The runtime-mounted private key is created locally and is excluded from Git
  and Docker build context. Its public half is available only to Forwarders.
- Ingestion accepts only bounded `.jsonl` multipart uploads and validates
  envelope shape, UTC-offset timestamps, identifiers, Base64 framing, key ID,
  AEAD authentication, and decrypted bundle schema.
- Sensitive content is decrypted only in process memory, encrypted bytes are
  retained, and plaintext IP addresses and payloads are never persisted in
  searchable columns, audit metadata, or logs.
- Valid records and signature-based alerts persist transactionally. KMP comes
  from the root `algorithms/` package; signature patterns are database-backed.
- Jobs, counts, and safe per-line error codes persist and are owner/role checked.
  Upload size, line count, concurrent processing, and idempotency are bounded.
- A synthetic Forwarder helper exercises public-key retrieval, encryption,
  upload, and job status without printing credentials or event plaintext.
- Phase 4 behavior is manually verified through the local Compose stack.

## Phase 5 scope: investigation and analytics

Analysts and Admins can search the safe indexed log metadata and persisted
alerts, inspect the seeded topology, calculate modeled shortest paths, and
simulate containment by changing an edge's blocked flag. No search endpoint
decrypts or returns event payloads or IP addresses. Dijkstra and risk-to-cost
mapping are imported from `algorithms/`; the database's 0..10 edge risk is
normalized to the algorithm's documented 1..9 input range without changing
the relative edge ranking.

The analytics API runs a seeded synthetic-data benchmark of the canonical
randomized QuickSort against Python's built-in sort, and a Monte Carlo
proportion estimate against an exact baseline when the data size is small
enough. Runs and safe metrics are persisted for history. Alerts stream as
Server-Sent Events in stable `(detected_at, alert_id)` order. The opaque SSE
event ID and `Last-Event-ID` header let a reconnect recover persisted alerts.
When no cursor is supplied, the stream starts with the latest 100 alerts and
then follows new records.

### Phase 5 exit criteria

- Analyst/Admin log search filters on indexed time and safe event/asset
  metadata, supports stable cursor pagination, and never exposes ciphertext or
  decrypted sensitive bundles.
- Analyst/Admin alert history supports severity/category/asset/time filters
  and cursor pagination; SSE uses persisted alerts and resumable cursors.
- Topology inspection reports nodes and edges. Path analysis calls canonical
  Dijkstra code and excludes blocked edges.
- Containment changes only the simulated topology edge state, is role-checked,
  audited, and explicitly reports that the action is simulated.
- Reproducible benchmarks call the canonical sorting and Monte Carlo modules,
  use bounded synthetic data, return comparative metrics, and persist runs.
- The migration, endpoint permissions, pagination, containment, benchmark
  persistence, and SSE recovery are manually verified through local Compose.

The user supplied successful local results for log and alert search, modeled
path analysis, simulated containment, benchmark persistence, and SSE delivery
on 2026-10-24, completing the Phase 5 manual verification.

## Phase 6 scope: frontend journeys and dashboard

The React client presents role-specific workflows backed only by the API. A
Forwarder can upload encrypted JSONL and follow the processing job. Analysts
and Admins can inspect the operations overview, search safe log metadata,
review persisted and live alerts, analyze modeled topology paths, simulate
edge containment, and run reproducible benchmarks. Admins can provision
accounts. The access token remains in page memory and is sent in Authorization
headers; it is not persisted in browser storage. The UI must never implement a
second copy of an algorithm or display decrypted event payloads or IPs.

### Phase 6 exit criteria

- Sign-in obtains a bearer token, loads the current user profile, handles API
  errors, and clears the in-memory session on sign-out or refresh.
- Navigation and actions reflect the authenticated Forwarder, Analyst, or
  Admin role; protected API calls still enforce authorization server-side.
- Forwarder upload submits encrypted JSONL as multipart data and shows job
  status, accepted/rejected counts, and safe per-line validation codes.
- Analyst/Admin overview, log search, and alert history show only safe
  metadata and support the API's cursor pagination.
- The alert view consumes authenticated SSE, reflects connection state, and
  displays persisted and live alerts without exposing secrets.
- Topology and path analysis use the backend API, while containment controls
  clearly identify their simulated-only effect.
- Benchmark configuration, result details, and paginated saved history use
  the benchmark API; Admin account creation uses the existing provisioning
  endpoint.
- Keyboard focus, responsive layout, empty/loading/error states, and service
  readiness are represented in the user interface.
- The frontend builds into the existing Nginx image and is manually reviewed
  through the local Compose app for each role.

## Phase 6 API and local verification

Open `http://localhost:8080` and sign in using accounts provisioned from the
API. As an Admin, verify Team access can create Forwarder and Analyst accounts.
As a Forwarder, choose an encrypted `.jsonl` fixture or send one through the
synthetic helper; confirm the job reaches a terminal status and counts are
shown. As an Analyst, inspect the overview, search for the Phase 4 demo event,
filter alerts, verify the live connection, analyze a topology path, toggle a
simulated edge, and run a seeded benchmark. Confirm a Forwarder cannot access
Analyst/Admin views or their APIs, and that signing out returns to the login
screen.

## Phase 7 scope: verification, security review, and documentation

Phase 7 checks that the documented security boundaries match the code and
deployment configuration. The frontend image uses a lockfile-based install,
login responses are marked non-cacheable, the browser UI receives restrictive
security headers, Nginx rate-limits login attempts, and proxied request bodies
are capped at the backend's hard upload ceiling plus multipart framing. These controls reduce exposure;
they do not make the demonstrator production-ready.

### Security review findings and operating limits

- Compose publishes the frontend only on `127.0.0.1` by default. The default
  stack is plain HTTP; the optional public profile adds Caddy TLS termination.
- Nginx rate-limits login requests to 10 per minute with a 5-request burst.
  The public Caddy profile overwrites the client-address header used for that
  limit. Do not publish the backend directly or bypass the frontend proxy;
  alternate reverse proxies need equivalent trusted client-address handling.
  Denied requests still create audit rows, so monitor database growth.
- Background ingestion and its concurrency bound are process-local. Run one
  API instance; do not scale horizontally or promise job recovery across a
  process restart.
- The database volume and backups are not application-encrypted. Restrict
  host access, protect backup files, and use encrypted storage appropriate to
  the deployment environment.
- The local RSA key protects the uploaded sensitive bundle in transit and at
  rest, but key rotation and recovery procedures are operator responsibilities.
  Losing the private key makes retained sensitive bundles unreadable.
- Bearer tokens expire after 30 minutes and are held only in frontend memory.
  Login responses use `Cache-Control: no-store`. The UI's CSP and related
  headers apply to frontend pages; API documentation remains available through
  its separate proxy location.
- Sample credentials, local secrets, private keys, generated test data, and
  plaintext sensitive events must not be committed. The sample `.env` values
  are placeholders and must be replaced before startup.
- This project has no external security audit, penetration test, SLA, or
  production monitoring claim. Educational RSA arithmetic is not used by the
  ingestion cryptography path.

### Phase 7 exit criteria

- Security-relevant upload, authentication, persistence, role checks, SSE, and
  simulated containment boundaries are reviewed and described accurately.
- The frontend build installs from `package-lock.json` with `npm ci`.
- The login token response is non-cacheable; the frontend has a restrictive
  Content Security Policy and browser hardening headers; proxy request size is
  bounded.
- `.gitignore`, image build contexts, and runtime mounts keep local secrets out
  of source control and images.
- Operator documentation includes secret setup, key loss/rotation implications,
  database backup protection, TLS requirements for remote access, single
  instance limits, and the login proxy's rate-limit behavior.
- A clean frontend image build and Compose health check succeed. Manual
  acceptance remains documented for each role and requires an operator to
  exercise the running UI and API.

## Phase 7 local verification

Review the relevant files and confirm that `.env`, `secrets/`, generated data,
and local encrypted fixtures are ignored by Git. Rebuild the frontend and
backend images, then check the Compose health status. On the frontend response,
inspect `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`, and `Permissions-Policy`; on `POST /api/v1/auth/login`,
confirm `Cache-Control: no-store`. Attempt a request larger than the Nginx
limit and confirm it is rejected before reaching application processing.
Before any remote deployment, verify TLS termination and the proxy's trusted
client-address handling for the login rate limit.

## Phase 8 scope: public demo deployment and operations

The recommended public demo is the existing Docker Compose stack on one
self-managed Linux host, with the optional open-source Caddy reverse proxy
terminating HTTPS. The application, proxy, database image, and deployment
configuration are open source; hosting, a public domain, DNS, and certificate
issuance are external services and may have costs or terms of use. This
deployment is not a managed Render/Vercel setup and should not be split across
serverless hosts: it depends on persistent PostgreSQL storage, a mounted
private key, long-lived SSE connections, and a single API process.

The public overlay is `compose.public.yaml`; it publishes only Caddy on ports
80 and 443. The frontend remains bound to loopback, and the backend/database
remain on the private Compose network. Caddy obtains and renews public TLS
certificates for `PUBLIC_DOMAIN`, redirects HTTP to HTTPS, and stores its
certificate state in persistent named volumes. See [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https)
and the [Caddy reverse proxy configuration](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).

### Phase 8 exit criteria

- The public profile validates and starts without publishing frontend,
  backend, or database ports to the public interface; only Caddy publishes
  ports 80/443.
- DNS points the configured public name to the host and external firewall
  rules allow HTTP/HTTPS. Caddy obtains a trusted certificate and redirects
  HTTP to HTTPS.
- Database, Caddy certificate state, and the ingestion private key have
  persistent, protected storage and documented backup/recovery handling.
- A unique Admin account is bootstrapped; bootstrap credentials are removed
  from runtime configuration after first creation; all other demo accounts
  use unique credentials.
- Login rate limiting, upload limits, API role enforcement, SSE, and health
  checks are confirmed through the public entry point.
- Operations notes cover update/rebuild, health monitoring, log review,
  database backup and restore, key loss, rollback, and teardown.
- The public deployment is labelled an educational demo, uses synthetic data,
  and makes no production-SIEM or real containment claim.

### Phase 8 deployment and operations

1. Provision a Linux host and DNS name. Set the domain's A record (and AAAA
   only if IPv6 is routed correctly) to the host. Allow inbound TCP 80/443 and
   UDP 443 if HTTP/3 is desired. Caddy's automatic HTTPS requires correct DNS,
   externally reachable ports 80/443, and persistent writable storage.
2. Install Docker Engine and the Compose plugin. Clone the repository and
   create `.env` from `.env.example`; set unique database, JWT, and bootstrap
   credentials, a unique `INGESTION_KEY_ID`, the real `PUBLIC_DOMAIN`, and an
   appropriate upload/concurrency limit. Keep `.env` and `secrets/` private.
3. Generate the ingestion key once with `docker compose run --rm keygen`.
   Back up the private key separately and securely; database backups alone
   cannot decrypt old sensitive bundles if that key is lost.
4. Validate and start with:

   ```sh
   docker compose -f compose.yaml -f compose.public.yaml --profile public config -q
   docker compose -f compose.yaml -f compose.public.yaml --profile public up --build -d
   ```

5. Check service health, then browse to `https://PUBLIC_DOMAIN`. Confirm TLS,
   HTTP redirect, login throttling, authenticated SSE, encrypted upload, and
   role-based API access. Use synthetic data only.
6. After the first successful bootstrap, remove
   `BOOTSTRAP_ADMIN_PASSWORD` from the server's runtime environment and
   recreate the backend. Keep a secure recovery process for Admin access.
7. Back up PostgreSQL data, `.env` secret values, the ingestion private key,
   and Caddy's `/data` volume using protected storage. Schedule and rehearse
   restore/rollback. Before updates, inspect migrations and back up the DB;
   apply updates by pulling a reviewed revision and rebuilding the Compose
   services. Monitor container health and logs without publishing tokens,
   plaintext events, or private keys.
8. To stop the demo, remove the Compose services but preserve volumes unless
   intentionally decommissioning. To decommission, securely remove database
   backups and key material according to the host's storage policy.

## Delivery phases

1. Foundation and scope.
2. Algorithms.
3. Database and backend basics.
4. Secure ingestion pipeline.
5. Investigation and analytics.
6. Frontend journeys and dashboard.
7. Verification, security review, and documentation.
8. Public demo deployment and operations.

Each phase must meet its own written exit criteria before it is called complete.
Integration feedback may still require revisiting earlier work.

## Phase 3 API and database notes

The backend applies forward-only SQL migrations during startup and records
their filenames in `schema_migrations`. Back up the database volume before
deploying a new version. The initial API routes are `POST /api/v1/auth/login`,
`GET /api/v1/auth/me`, and Admin-only `POST /api/v1/admin/users`. API schema
documentation is served at `/docs` while the backend is reachable.

`JWT_SIGNING_SECRET` must be a unique random value at least 32 characters long.
Set a unique `BOOTSTRAP_ADMIN_USERNAME` and
`BOOTSTRAP_ADMIN_PASSWORD` (at least 12 characters) before first startup. The
bootstrap only inserts the account when that username does not already exist;
it never resets an existing password. After the first startup, rotate or remove
the bootstrap password from the runtime environment. The API returns 503 for
login until a valid JWT signing secret is configured.

For local manual verification, open `http://localhost:8080/docs`, sign in at
`POST /api/v1/auth/login`, then use the returned short-lived bearer token for
`GET /api/v1/auth/me` and `POST /api/v1/admin/users`. A Forwarder or Analyst
token must receive 403 from the Admin user-provisioning route. Inspect
`schema_migrations`, `app_users`, `audit_events`, `topology_nodes`, and
`topology_edges` in the database to confirm bootstrap and migration state.

## Phase 4 API and local verification

Apply the additive `002_secure_ingestion.sql` migration on startup. Generate a
local runtime key with `docker compose run --rm keygen` before starting the
backend. The API exposes Forwarder-only `GET /api/v1/crypto/public-key` and
`POST /api/v1/ingestion/uploads`, plus owner/Analyst/Admin job status at
`GET /api/v1/ingestion/jobs/{job_id}`. A Forwarder can be created by the Admin
route from Phase 3. Run
`docker compose exec backend python -m app.demo_forwarder` to send one
synthetic encrypted event and inspect the resulting job status. A successful
demo event should be accepted, with a matching SQL-injection signature alert
persisted in the `alerts` table. Check `ingestion_jobs`,
`ingestion_job_line_errors`, `security_logs`, `security_log_id_registry`, and
`alerts` in PostgreSQL. Never put a private key, plaintext event, password, or
bearer token in a repository file or pasted log.

## Phase 5 API and local verification

The `003_investigation_analytics.sql` migration creates the benchmark history
table and supporting indexes. Analyst/Admin routes are `GET /api/v1/logs`,
`GET /api/v1/alerts`, `GET /api/v1/alerts/stream`, `GET /api/v1/topology`,
`POST /api/v1/topology/path`, `POST /api/v1/topology/containment`,
`POST /api/v1/analytics/benchmarks`, and `GET /api/v1/analytics/benchmarks`.
The logs route searches only time, event type, log ID, asset IDs, and alert
severity. Search windows use inclusive `start` and exclusive `end`; pages are
limited to 100 rows and use opaque `cursor` values. The same cursor format
supports `Last-Event-ID` on the alert stream.

For local verification, sign in as an Analyst/Admin and:

1. Search `/api/v1/logs` for `event_type=demo_http_request` and confirm the
   Phase 4 sample appears without source/destination IPs or payload.
2. Search `/api/v1/alerts` with `severity=high` and confirm the corresponding
   `SIG-SQLI-UNION-SELECT` alert is returned.
3. Read `/api/v1/topology`; request a path from `internet` to `db-server-01`.
   Block `web-server-01` to `app-server-01`, repeat the path request, then
   unblock that same edge to restore the seeded graph. These actions only
   alter the application simulation.
4. Run `/api/v1/analytics/benchmarks` with `dataset_size=5000`, `seed=42`,
   and `sample_fraction=0.1`, then read the benchmark history and confirm the
   stored run is present and the sort outputs match.
5. Connect to `/api/v1/alerts/stream` with the Analyst/Admin bearer token.
   Confirm recent alerts arrive with event IDs; reconnect using the last
   `Last-Event-ID`, then create another synthetic Forwarder upload and confirm
   only alerts after that cursor arrive.

Forwarder tokens must receive 403 from every Phase 5 route. The SSE endpoint
requires an Authorization header; use an EventSource client that can set
headers or a streaming `fetch` client rather than placing bearer tokens in a
URL.
