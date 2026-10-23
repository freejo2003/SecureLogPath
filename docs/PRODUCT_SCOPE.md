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
