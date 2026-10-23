# SecureLogPath

SecureLogPath is an open-source, locally runnable mini-SIEM demonstrator for
showing how log ingestion, signature matching, graph analysis, and benchmark
algorithms work. It is an educational project, not a production SIEM or an
automated response system. Containment actions are limited to the application's
simulated graph.

## Project status

Phase 1 established the repository and clean Compose foundation. Phase 2
implements the canonical pure-Python algorithm package. Phase 3 adds versioned
database migrations, the initial data model and topology, API authentication,
role checks, and audit records. Secure uploads, processing, investigation
views, and dashboard journeys remain for later phases. The project follows
`docs/PRODUCT_SCOPE.md` and the supplied SecureLogPath PRD.

## Technology and layout

- `frontend/`: React and Vite single-page application, served by Nginx.
- `backend/`: FastAPI application and PostgreSQL connectivity.
- `algorithms/`: canonical pure-Python implementation of all project algorithms.
- `database`: PostgreSQL 17 with the TimescaleDB Apache 2.0 image.
- `docs/`: product scope, architecture boundaries, and operational notes.

The database is only reachable on the internal Compose network. The frontend
is available at `http://localhost:8080` and proxies `/api/*` requests to the
backend. Database data is kept in a named volume.

Every Python application component must import algorithm implementations from
the root `algorithms/` package. Do not duplicate algorithms in the backend or
frontend; browser features call the backend, which delegates to this package.
See [the algorithms guide](algorithms/README.md).

## Start locally

Prerequisites: Docker Engine or Docker Desktop with the Compose plugin.

1. Copy `.env.example` to `.env`.
2. Replace `POSTGRES_PASSWORD` with a long, unique local secret. Replace the
   reserved JWT and Admin placeholders before those features are implemented.
3. Start the stack:

   ```sh
   docker compose up --build
   ```

4. Open `http://localhost:8080`. The initial page displays API readiness.

The API readiness endpoint is available at `http://localhost:8080/api/health/ready`.
It reports ready only when the backend can reach the database.

To stop the services while preserving database data, run `docker compose down`.
To delete the database volume as well, run `docker compose down --volumes`.

## Configuration and secrets

`.env.example` documents local settings. Replace every placeholder before
starting the stack. Use a unique random `JWT_SIGNING_SECRET` of at least 32
characters, a bootstrap Admin username, and a unique bootstrap password of at
least 12 characters. The initial Admin is inserted once; changing the bootstrap
password later does not reset an existing account. The real `.env` file,
cryptographic private keys, and generated datasets must not be committed. Use
different secrets for each environment. The frontend build must never receive
private keys, database credentials, or JWT signing secrets.

The backend applies versioned SQL migrations during startup and records them
in `schema_migrations`. Back up the database volume before deploying a new
version. Login tokens expire after 30 minutes. The API exposes interactive
documentation at `http://localhost:8080/docs`; use it to call
`POST /api/v1/auth/login`, `GET /api/v1/auth/me`, and (as Admin)
`POST /api/v1/admin/users`. See the Phase 3 notes in
`docs/PRODUCT_SCOPE.md` for manual role and database checks.

## Scope and delivery

See [Product scope and delivery phases](docs/PRODUCT_SCOPE.md) for the v1
boundary, phase exit criteria, and deployment assumptions. The initial
deployment target is one host running Docker Compose. High availability,
multiple API instances, durable distributed jobs, and production cloud scale
are outside v1.

## License

This repository is licensed under the MIT License. See `LICENSE`.
