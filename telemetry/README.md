# Telemetry Dashboard

Centralized Flask web application that aggregates data from all CodeQL Devin Fixer action runs across repositories. Provides a 6-tab dashboard UI with real-time metrics, issue lifecycle tracking, and orchestrator controls.

## Setup

### 1. Create a `.env` file

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

| Variable | Required | Description |
|---|---|---|
| `GITHUB_TOKEN` | Yes | GitHub PAT with `repo` scope. Needed to discover PRs on fork repos and pull telemetry run files. |
| `DEVIN_API_KEY` | Yes | Devin API bearer token. Used to poll session statuses. |
| `ACTION_REPO` | Yes | The repo containing the telemetry data, e.g. `your-username/codeql-devin-fixer`. |
| `TELEMETRY_API_KEY` | Recommended | If set, POST endpoints require this key via `X-API-Key` or `Authorization: Bearer <key>`. |
| `FLASK_SECRET_KEY` | Recommended | Stable secret key for Flask session signing. Random if unset (sessions invalidated on restart). |
| `CACHE_TTL` | No | Seconds to cache GitHub/Devin API responses (default: 120). |
| `GITHUB_OAUTH_CLIENT_ID` | No | GitHub OAuth App client ID for user authentication. |
| `GITHUB_OAUTH_CLIENT_SECRET` | No | GitHub OAuth App client secret. |
| `CORS_ORIGINS` | No | Comma-separated allowed CORS origins (defaults to localhost). |

See [docs/CONFIG_REFERENCE.md](../docs/CONFIG_REFERENCE.md) for the complete configuration reference including deployment, Helm, and internal constants.

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the app

```bash
python app.py
```

Open http://localhost:5000 in your browser.

### Docker

```bash
docker compose up --build
```

## Features

- **6-tab dashboard** -- Overview, Repositories, Issues, Activity, Orchestrator, Settings
- **Dark/light theme** with toggle button and compact mode for dense layouts
- **Aggregated metrics** across all action runs and target repos with Chart.js trend charts
- **Repo detail pages** -- click any repo to see scoped metrics, runs, sessions, and PRs
- **Cross-run issue tracking** -- stable fingerprints classify issues as new, recurring, or fixed with SLA compliance tracking
- **Issue detail drawer** -- slide-out panel with full issue context
- **Session polling** -- fetch live Devin session statuses from the Devin API
- **PR-session linking** -- PRs are matched to Devin sessions by session ID or issue ID
- **Orchestrator controls** -- plan preview, scan/dispatch/cycle triggers, config editing, fix rate analysis
- **Demo data system** -- load/clear/regenerate sample data for demos without real scan data
- **PDF report generation** -- downloadable security compliance reports
- **Audit logging** -- all mutating actions logged with user, timestamp, and details
- **GitHub OAuth** -- user-scoped access control based on repository permissions
- **Rate limiting** -- 120 req/min default; 10/min for dispatch; 5/min for orchestrator actions
- **Server-side sessions** -- `flask-session` with `FileSystemCache` for secure token storage

## Architecture

The app is organized into 4 route Blueprints:

| Blueprint | Module | Scope |
|---|---|---|
| `api_bp` | `routes/api.py` | Core API: runs, sessions, PRs, issues, stats, dispatch, SLA, PDF reports |
| `orchestrator_bp` | `routes/orchestrator.py` | Orchestrator: plan, scan, dispatch, cycle, config, fix rates |
| `registry_bp` | `routes/registry.py` | Repo registry: CRUD for scheduled repositories |
| `demo_bp` | `routes/demo.py` | Demo data: load, clear, regenerate, edit sample data |

Supporting modules: `database.py` (SQLite), `helpers.py` (auth, pagination, audit), `oauth.py` (GitHub OAuth), `github_service.py` (PR fetching), `devin_service.py` (session polling), `aggregation.py` (metrics), `verification.py` (fix tracking), `issue_tracking.py` (SLA), `pdf_report.py` (reports).

## Key API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/stats` | GET | Aggregated metrics with period selector (7d/30d/90d/all) |
| `/api/runs` | GET | Run history (paginated) |
| `/api/sessions` | GET | Devin sessions with status filter |
| `/api/prs` | GET | Pull requests with state filter |
| `/api/issues` | GET | Issue tracking with fingerprint-based status and SLA |
| `/api/repo/<repo_url>` | GET | Repository detail view |
| `/api/sla` | GET | SLA compliance summary |
| `/api/report/pdf` | GET | Compliance PDF report |
| `/api/audit-log` | GET | Audit trail with action/user filters |
| `/api/poll` | POST | Poll Devin API for session status updates |
| `/api/refresh` | POST | Re-fetch PRs from GitHub |
| `/api/dispatch` | POST | Trigger GitHub Actions workflow |
| `/api/orchestrator/plan` | POST | Preview orchestrator dispatch decisions |
| `/api/orchestrator/scan` | POST | Trigger scans for due repositories |
| `/api/orchestrator/dispatch` | POST | Dispatch Devin sessions |
| `/api/orchestrator/cycle` | POST | Full cycle: scan + dispatch |
| `/api/orchestrator/config` | GET/PUT | Manage global orchestrator settings |
| `/api/orchestrator/fix-rates` | GET | Fix rates by CWE family |

### Pages

| URL | Description |
|---|---|
| `/` | Main dashboard with 6-tab UI |
| `/repo/<owner/repo>` | Dedicated detail page for a specific repository |
