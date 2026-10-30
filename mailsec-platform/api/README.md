# Platform API

FastAPI control plane with PostgreSQL identities, persistent revocable sessions, CSRF and a fail-closed smart-search BFF. See [API contract](API_CONTRACT.md).

## Development

```sh
cd mailsec-platform/api
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
DATABASE_URL=sqlite:///./platform.db .venv/bin/python -m platform_api.cli init-db
BOOTSTRAP_ADMIN_USERNAME=admin BOOTSTRAP_ADMIN_PASSWORD='replace-with-a-long-random-secret' .venv/bin/python -m platform_api.cli bootstrap-admin
COOKIE_SECURE=false PLATFORM_ORIGIN=http://localhost:5173 .venv/bin/uvicorn platform_api.app:app --reload --host 127.0.0.1 --port 8090
.venv/bin/python -m pytest -q
```

Production: `DATABASE_URL=postgresql+psycopg://...` and HTTPS with `COOKIE_SECURE=true` (default). The bootstrap password **must** be supplied via environment and removed after use; there is no default. `CSRF_SECRET` must be a stable random secret across replicas/restarts (otherwise sessions cannot validate); changing it invalidates sessions. `init-db` creates the v1 schema only; it refuses partial schemas. The matching PostgreSQL v1 baseline is `schema_v1.postgresql.sql`. Future schema changes require a versioned migration, not `create_all` on live data. Run DB initialization explicitly before API startup. Set `SMART_SEARCH_URL`, `SMART_SEARCH_TOKEN`, `SMART_SEARCH_TENANT_ID` and `SMART_SEARCH_DEDICATED=true` only after confirming a dedicated instance and its ClickHouse contain only the bound tenant's data. Other tenants cannot search that instance. Never expose upstream token or ClickHouse directly to browsers.

Login attempt limits are persisted by username/peer IP (5 failures/15 min). Set `PLATFORM_ORIGIN` to the exact external origin behind a reverse proxy to block cross-origin login; browser requests with mismatched Origin or cross-site Fetch Metadata are rejected. A trusted ingress should enforce additional IP rate limits and same-origin/TLS; direct public access bypassing ingress is unsupported. Session cookie is HttpOnly, SameSite=Lax, Secure by default. Bootstrap and management operations are audited. The existing smart-search service owns ClickHouse DDL and indexing; platform API does not create a misleading multi-tenant index.
