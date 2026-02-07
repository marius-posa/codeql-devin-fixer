# Telemetry Dashboard

Centralized monitoring tool that aggregates data from all CodeQL Devin Fixer action runs across repositories.

## Setup

### 1. Create a `.env` file

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

| Variable | Required | Description |
|---|---|---|
| `GITHUB_TOKEN` | Yes | GitHub PAT with `repo` scope. Needed to discover PRs on fork repos and pull telemetry run files. Generate one at https://github.com/settings/tokens (classic token, check `repo` scope). |
| `DEVIN_API_KEY` | Yes | Devin API bearer token. Used to poll session statuses (finished, working, blocked, etc.). Get yours from the Devin dashboard. |
| `ACTION_REPO` | Yes | The repo containing the telemetry data, e.g. `marius-posa/codeql-devin-fixer`. |
| `CACHE_TTL` | No | Seconds to cache GitHub/Devin API responses (default: 120). Lower values mean fresher data but more API calls. |

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the app

```bash
python app.py
```

Open http://localhost:5000 in your browser.

## Features

- **Aggregated metrics** across all action runs and target repos
- **Repo-by-repo filtering** -- click "Filter" on any repo row to see metrics for that repo only
- **Session polling** -- click "Poll Sessions" to fetch live Devin session statuses
- **PR tracking** -- shows PRs created, merged, and open on fork repos
- **Refresh** -- pulls the latest telemetry JSON files from the action repo
- **Backfill** -- PATCH `/api/backfill` to correct old telemetry records with missing issue IDs or PR URLs

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/stats` | GET | Aggregate metrics (repos, runs, issues, sessions, PRs, fix rate) |
| `/api/runs` | GET | All telemetry run records (paginated: `?page=1&per_page=50`) |
| `/api/sessions` | GET | All Devin sessions across runs (paginated) |
| `/api/prs` | GET | All PRs from fork repos (paginated) |
| `/api/repos` | GET | Per-repo aggregated metrics |
| `/api/poll` | POST | Poll Devin API for session status updates |
| `/api/refresh` | POST | Pull latest telemetry files from GitHub |
| `/api/backfill` | POST | Patch old records with corrected issue IDs and PR URLs |
