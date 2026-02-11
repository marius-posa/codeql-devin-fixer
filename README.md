# CodeQL Devin Fixer

Automated security vulnerability remediation powered by [Devin](https://devin.ai) AI agents. Point it at any repository, and the platform scans with [CodeQL](https://codeql.github.com/), prioritizes findings by CVSS severity, batches them by CWE family, and dispatches Devin sessions that create verified fix PRs -- end to end, with no human in the loop.

**[Live Dashboard](https://marius-posa.github.io/codeql-devin-fixer/)** | **[Architecture](docs/architecture.md)** | **[Configuration Reference](docs/CONFIG_REFERENCE.md)** | **[Contributing](CONTRIBUTING.md)** | **[Changelog](CHANGELOG.md)**

### Highlights

- **End-to-end automation** -- from CodeQL scan to merged fix PR, including verification that the vulnerability is actually gone
- **Deep Devin integration** -- 8 API endpoints: session dispatch with structured output, Knowledge API for organizational memory, Send Message API for retry-with-feedback, and Playbooks API for CWE-specific fix instructions
- **Closed-loop verification** -- re-runs CodeQL on fix PRs and compares stable fingerprints to objectively confirm each issue is resolved
- **Multi-repo orchestration** -- schedules scans across a fleet of repositories with CVSS-weighted priority scoring, SLA tracking, and wave-based dispatch with fix-rate gating
- **Rich telemetry dashboard** -- Flask + SQLite web UI with 6 tabs, dark/light theme, Chart.js trend charts, issue lifecycle tracking, PDF compliance reports, and GitHub OAuth
- **Highly configurable** -- five configuration surfaces (action inputs, per-repo YAML, orchestrator registry, dashboard env, GitHub App env) with clear precedence rules
- **Production-ready** -- rate limiting, audit logging, server-side sessions, CORS restriction, prompt-injection defense, Docker and Helm deployment

Supports any language CodeQL can analyze: JavaScript/TypeScript, Python, Java, Go, Ruby, C#, C/C++, and Swift.

---

## Table of Contents

- [Architecture](#architecture)
- [How It Works](#how-it-works)
- [Installation and Quick Start](#installation-and-quick-start)
- [GitHub App](#github-app)
- [Telemetry Dashboard](#telemetry-dashboard)
- [Orchestrator](#orchestrator)
- [Creative Use of Devin](#creative-use-of-devin)
- [Devin API Integration](#devin-api-integration)
- [Action Inputs and Outputs](#action-inputs-and-outputs)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Dry Run Mode](#dry-run-mode)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Solution Reviews](#solution-reviews)

---

## Architecture

The system consists of five major subsystems that work together:

```
GitHub Actions Runner
  action.yml (composite action)
  fork_repo.py --> CodeQL analyze --> parse_sarif.py --> dispatch_devin.py (wave-based)
  persist_logs.py (to fork repo)    persist_telemetry.py (to action repo DB)

         |                         |
         v                         v
  Devin API                Telemetry Dashboard (Flask)
  /v1/sessions             5 Blueprints, 30+ endpoints
  /v1/knowledge            rate limiting, audit log
  /v1/messages             server-side sessions
  Playbooks API            SQLite DB
                                    |
                       +------------+------------+
                       v                         v
              Orchestrator              GitHub App
              (multi-repo)              (webhook-driven)
              cli, dispatch,            webhook_handler,
              scanner, state,           scan_trigger,
              alerts                    alerts, auth
```

> See [docs/architecture.md](docs/architecture.md) for detailed sequence diagrams and data flow documentation.
> Explore the codebase on [DeepWiki](https://deepwiki.com/marius-posa/codeql-devin-fixer) for auto-generated architecture documentation.

### Project Structure

```
codeql-devin-fixer/
+-- action.yml                    # Composite GitHub Action definition
+-- .github/workflows/
|   +-- codeql-fixer.yml          # Main action workflow
|   +-- orchestrator.yml          # Scheduled multi-repo orchestration
|   +-- poll-sessions.yml         # Devin session status polling
|   +-- scheduled-scan.yml        # Scheduled security scanning
|   +-- verify-fix.yml            # PR fix verification workflow
|   +-- deploy-pages.yml          # GitHub Pages deployment
+-- scripts/                      # Pipeline scripts
|   +-- parse_sarif.py            # SARIF parsing, severity scoring, fingerprinting, batching
|   +-- dispatch_devin.py         # Devin session creation with wave dispatch
|   +-- fork_repo.py              # Fork management and sync
|   +-- persist_logs.py           # Log persistence to fork repos
|   +-- persist_telemetry.py      # Telemetry record storage to SQLite
|   +-- verify_results.py         # Fix verification via fingerprint comparison
|   +-- pipeline_config.py        # Centralized config with TypedDicts + structured output schema
|   +-- devin_api.py              # Shared Devin API utilities (retry, auth, base URL)
|   +-- knowledge.py              # Devin Knowledge API client (CRUD + fix pattern storage)
|   +-- retry_feedback.py         # Send Message API for retry-with-feedback loops
|   +-- playbook_manager.py       # CWE-specific playbooks + Devin Playbooks API sync
|   +-- fix_learning.py           # Historical fix rate analysis
|   +-- repo_context.py           # Repository context enrichment (deps, tests, style)
|   +-- load_repo_config.py       # Per-repo .codeql-fixer.yml loader
|   +-- machine_config.py         # Machine-level configuration
|   +-- webhook.py                # Webhook delivery for pipeline events
|   +-- logging_config.py         # Structured JSON logging
|   +-- retry_utils.py            # Exponential backoff utilities
|   +-- github_utils.py           # GitHub API helpers
|   +-- orchestrator/             # Multi-repo orchestrator package
|       +-- cli.py                # Command routing (scan, dispatch, cycle, plan, status)
|       +-- dispatcher.py         # Session dispatch with rate limiting and fix learning
|       +-- scanner.py            # Scan triggering and SARIF retrieval
|       +-- state.py              # State persistence, cooldown, dispatch history
|       +-- alerts.py             # Alert processing and delivery
|       +-- agent.py              # Orchestrator agent mode
+-- telemetry/                    # Flask dashboard backend
|   +-- app.py                    # Flask entry point (Blueprint registration, sessions, CORS)
|   +-- routes/                   # Modular route Blueprints
|   |   +-- api.py                # Core API (runs, sessions, PRs, issues, stats, dispatch)
|   |   +-- orchestrator.py       # Orchestrator controls (plan, scan, dispatch, cycle)
|   |   +-- registry.py           # Repo registry CRUD
|   |   +-- demo.py               # Demo data management
|   +-- helpers.py                # Shared auth, pagination, audit utilities
|   +-- extensions.py             # Rate limiter configuration
|   +-- database.py               # SQLite schema, queries, migrations, audit logging
|   +-- oauth.py                  # GitHub OAuth implementation
|   +-- pdf_report.py             # PDF report generation
|   +-- demo_data.py              # Demo seed data management
|   +-- devin_service.py          # Devin API session polling
|   +-- github_service.py         # GitHub PR fetching and linking
|   +-- aggregation.py            # Metrics and SLA computation
|   +-- verification.py           # Verification record processing
|   +-- issue_tracking.py         # Issue lifecycle and SLA tracking
|   +-- templates/
|   |   +-- dashboard.html        # Main tabbed dashboard (6 tabs)
|   |   +-- repo.html             # Per-repo detail page
|   +-- static/
|   |   +-- shared.js             # UI components and rendering
|   |   +-- api.js                # Data fetching layer
|   +-- Dockerfile                # Container image
|   +-- docker-compose.yml        # Local Docker deployment
+-- github_app/                   # GitHub App for webhook automation
|   +-- app.py                    # Flask app with /healthz
|   +-- webhook_handler.py        # HMAC-verified webhook processing
|   +-- scan_trigger.py           # Automated scan triggering
|   +-- alerts.py                 # Alert delivery
|   +-- auth.py                   # JWT and installation token management
|   +-- config.py                 # App configuration
+-- playbooks/                    # CWE-specific fix instructions (YAML)
|   +-- injection.yaml            # SQL/command injection remediation
|   +-- xss.yaml                  # Cross-site scripting remediation
|   +-- path-traversal.yaml       # Path traversal remediation
+-- charts/telemetry/             # Helm chart for Kubernetes deployment
+-- docs/                         # GitHub Pages static site + solution reviews
|   +-- index.html                # Static dashboard (mirrors telemetry UI)
|   +-- architecture.md           # Architecture diagrams and data flow
|   +-- CONFIG_REFERENCE.md       # Complete configuration reference
|   +-- SOLUTION_REVIEW_V*.md     # Solution reviews V1-V5
+-- tests/                        # Test suite (32 files, ~11,400 lines)
+-- repo_registry.json            # Multi-repo scan configuration
+-- CONTRIBUTING.md               # Contribution guide
+-- CHANGELOG.md                  # Version history
```

### Database Schema

The telemetry system uses SQLite with these core tables:

| Table | Purpose |
|-------|---------|
| `runs` | Scan execution records (target_repo, issues_found, timestamp) |
| `sessions` | Devin session records (session_id, status, pr_url) |
| `issues` | Vulnerability instances (fingerprint, rule_id, severity_tier, cwe_family) |
| `prs` | Pull request records (pr_number, html_url, state, merged) |
| `session_issue_ids` | Session-to-issue mapping |
| `pr_issue_ids` | PR-to-issue mapping |
| `issues_fts` | FTS5 full-text search index on issues |
| `audit_log` | Audit trail for all mutating operations |
| `orchestrator_kv` | Key-value store for orchestrator state |

---

## How It Works

### Pipeline Steps

1. **Fork** the target repository into your GitHub account (or reuse an existing fork)
2. **Clone** the fork and **analyze** with CodeQL (auto-detects languages from manifests)
3. **Parse** SARIF results, assign each issue a unique tracking ID (`CQLF-R{run}-{seq}`), and compute a stable fingerprint for cross-run tracking
4. **Prioritize** by CVSS severity score (adversary perspective) and **batch** by CWE vulnerability family
5. **Enrich** prompts with CWE playbooks, fix learning data, repo context, knowledge from past fixes, and code snippets
6. **Dispatch** Devin sessions per batch using wave-based dispatch (severity-first with fix-rate gating)
7. **Verify** fixes by re-running CodeQL on PR branches and comparing fingerprints
8. **Retry** failed fixes using the Send Message API to provide feedback to active sessions
9. **Learn** from successful fixes by storing patterns in the Devin Knowledge API
10. **Persist** logs to the fork and telemetry records to the SQLite database
11. **Display** aggregated metrics in the telemetry dashboard

### Prioritization

Issues are ranked from an adversary's perspective -- which vulnerabilities are easiest to exploit with the highest impact:

| Tier | CVSS Score | Examples | SLA |
|------|-----------|----------|-----|
| Critical | 9.0 - 10.0 | SQL injection, command injection, code injection | 24 hours |
| High | 7.0 - 8.9 | XSS, SSRF, deserialization, auth bypass | 72 hours |
| Medium | 4.0 - 6.9 | Info disclosure, open redirect, weak crypto | 168 hours |
| Low | 0.1 - 3.9 | Minor info leaks, code quality issues | 720 hours |

### Batching Strategy

Issues are grouped by CWE vulnerability family so Devin can focus on related issues together:

| Family | CWEs | Examples |
|--------|------|----------|
| `injection` | CWE-78, 89, 94 | SQLi, command injection, code injection |
| `xss` | CWE-79, 80 | Cross-site scripting |
| `path-traversal` | CWE-22, 23, 36 | Directory traversal |
| `ssrf` | CWE-918 | Server-side request forgery |
| `auth` | CWE-287, 306, 862, 863 | Authentication/authorization |
| `crypto` | CWE-327, 328, 330, 338 | Weak cryptography |
| `info-disclosure` | CWE-200, 209, 532 | Information leaks |
| `deserialization` | CWE-502 | Insecure deserialization |
| `redirect` | CWE-601 | Open redirect |
| `xxe` | CWE-611 | XML external entity |
| `csrf` | CWE-352 | Cross-site request forgery |
| `prototype-pollution` | CWE-1321 | Prototype pollution |
| `regex-dos` | CWE-1333, 730 | Regular expression DoS |

Highest-severity batches are dispatched first. When wave dispatch is enabled, batches are grouped into waves by severity tier and dispatched sequentially, with fix-rate gating between waves.

---

## Installation and Quick Start

### Prerequisites

- A GitHub account with a [Personal Access Token (PAT)](https://github.com/settings/tokens) that has `repo` scope
- A [Devin API key](https://docs.devin.ai/api-reference/overview) for creating AI fix sessions
- Python 3.11+ (for local development/dashboard)

### Option A: Fork This Repo (Recommended)

1. **Fork** this repository on GitHub
2. In your fork, go to **Settings > Secrets and variables > Actions**
3. Add these **repository secrets**:

   | Secret | Purpose | How to create |
   |--------|---------|---------------|
   | `DEVIN_API_KEY` | Devin API authentication | [Devin API docs](https://docs.devin.ai/api-reference/overview) |
   | `GH_PAT` | Fork creation, log persistence, dashboard push | [Create a PAT](https://github.com/settings/tokens) with `repo` scope |

4. Go to **Actions** > **CodeQL Devin Fixer** > **Run workflow**
5. Enter the target repository URL and configure options
6. The action will fork the target, analyze it with CodeQL, and create Devin fix sessions

> **Why a PAT?** The default `secrets.GITHUB_TOKEN` is scoped only to the repo running the workflow. A Personal Access Token with `repo` scope is required for cross-repo fork and push operations.

### Option B: Use as a Reusable Action

Reference this action from any workflow:

```yaml
name: Fix Security Issues
on:
  workflow_dispatch:
    inputs:
      target_repo:
        description: "Repository URL to analyze"
        required: true
        type: string

permissions:
  contents: write
  security-events: write

jobs:
  fix:
    runs-on: ubuntu-latest
    steps:
      - uses: marius-posa/codeql-devin-fixer@main
        with:
          target_repo: ${{ inputs.target_repo }}
          github_token: ${{ secrets.GH_PAT }}
          devin_api_key: ${{ secrets.DEVIN_API_KEY }}
          persist_logs: "true"
```

### Option C: Clone and Customize

```bash
git clone https://github.com/marius-posa/codeql-devin-fixer.git
cd codeql-devin-fixer
```

Edit `.github/workflows/codeql-fixer.yml` to change defaults, then push to your fork and add the required secrets.

### One-Click Setup

Run the setup script for guided configuration:

```bash
bash setup.sh
```

This creates the workflow file, prompts for secrets, and runs a dry-run verification.

---

## GitHub App

The GitHub App enables webhook-driven automation: scans trigger automatically on push events to default branches, and events are processed without manual workflow dispatch.

See [`github_app/README.md`](github_app/README.md) for the full setup guide.

### Quick Start

1. [Create a GitHub App](https://docs.github.com/en/apps/creating-github-apps) in your org/account settings:
   - **Webhook URL**: `https://your-server.com/api/github/webhook`
   - **Permissions**: `contents: read`, `pull_requests: write`, `security_events: read`
   - **Events**: `installation`, `push`
2. Generate a private key (`.pem` file) and note the App ID
3. Set environment variables (see [`.env.example`](github_app/.env.example) for all options):
   ```bash
   export GITHUB_APP_ID=<your-app-id>
   export GITHUB_APP_PRIVATE_KEY_PATH=<path-to-private-key.pem>
   export GITHUB_APP_WEBHOOK_SECRET=<your-webhook-secret>
   export DEVIN_API_KEY=<your-devin-api-key>
   ```
4. Run the GitHub App server:
   ```bash
   pip install -r github_app/requirements.txt
   python -m github_app
   ```
5. Or via Docker:
   ```bash
   docker build -f github_app/Dockerfile -t codeql-fixer-app .
   docker run -p 3000:3000 --env-file github_app/.env codeql-fixer-app
   ```

### Features

- **Scan on push**: Automatically triggers CodeQL analysis when code is pushed to default branches
- **Webhook signature verification**: HMAC-SHA256 verification of all incoming webhooks
- **Installation token management**: JWT-based authentication with automatic token refresh and caching
- **Health endpoint**: `GET /healthz` for container orchestration probes
- **Manual scan**: `POST /api/github/scan` to trigger scans on demand
- **Installation management**: `GET /api/github/installations` and `GET /api/github/installations/<id>/repos`
- **Alert processing**: Webhook delivery for scan lifecycle events (verified fixes, SLA breaches, cycle summaries)

---

## Telemetry Dashboard

The telemetry dashboard is a centralized Flask web application that aggregates data from all action runs across every target repository.

### Setup

```bash
cd telemetry
cp .env.example .env    # Edit with your secrets
pip install -r requirements.txt
python app.py           # Starts on http://localhost:5000
```

### Docker

```bash
cd telemetry
docker compose up --build
```

### Dashboard Tabs

| Tab | Features |
|-----|----------|
| **Overview** | Metric cards, security health trend (Chart.js), severity/category breakdowns, orchestrator quick view, period selector (7d/30d/90d/all) |
| **Repositories** | Repo table with per-repo metrics, drill-down to dedicated repo detail page with trend charts |
| **Issues** | Issue tracking with fingerprint-based status (new/recurring/fixed), SLA compliance panel, fix verification stats, CSV export, issue detail drawer |
| **Activity** | Run history, Devin sessions with live status polling, pull request tracking with merge status |
| **Orchestrator** | Status panel, scan/dispatch/cycle controls, issue prioritization scoring, fix rate analysis by CWE family, config editor |
| **Settings** | Demo data management (load/clear/regenerate/edit JSON), export (CSV/PDF), global defaults, scheduled repo registry with add/edit/remove, audit log with action/user filters and JSON export |

### Dashboard Features

- **Dark/light theme** with toggle button
- **Compact mode** for dense table layouts
- **Loading skeletons** for perceived performance
- **Issue detail drawer** -- slide-out panel with full issue context
- **PDF report generation** -- downloadable security compliance report
- **Demo data system** -- load realistic sample data for demos without real scan data
- **Audit logging** -- all mutating actions logged with user, timestamp, and details
- **OAuth authentication** -- GitHub OAuth for user-scoped access
- **API key authentication** -- `TELEMETRY_API_KEY` for programmatic access to mutating endpoints
- **Rate limiting** -- 120 requests/min default; 10/min for dispatch; 5/min for orchestrator actions
- **Server-side sessions** -- `flask-session` with `FileSystemCache` for secure token storage

### API Endpoints

The dashboard exposes 30+ REST endpoints organized into Blueprints:

| Category | Endpoints |
|----------|-----------|
| **Stats** | `GET /api/stats?period=7d` -- Aggregated metrics |
| **Runs** | `GET /api/runs?repo=X&page=1` -- Run history (paginated) |
| **Sessions** | `GET /api/sessions?status=finished` -- Session list |
| **PRs** | `GET /api/prs?state=open` -- PR list |
| **Issues** | `GET /api/issues?status=recurring&severity=high` -- Issue tracking |
| **Repos** | `GET /api/repo/<repo_url>` -- Repository detail view |
| **SLA** | `GET /api/sla` -- SLA compliance summary |
| **Reports** | `GET /api/report/pdf?repo=X` -- Compliance PDF report |
| **Audit** | `GET /api/audit-log` -- Audit trail with filters |
| **Orchestrator** | `POST /api/orchestrator/{plan,scan,dispatch,cycle}` -- Controls |
| **Config** | `GET/PUT /api/orchestrator/config` -- Manage global settings |
| **Fix Rates** | `GET /api/orchestrator/fix-rates` -- Fix rates by CWE family |
| **Refresh** | `POST /api/refresh` -- Re-fetch PRs from GitHub |
| **Poll** | `POST /api/poll` -- Update Devin session statuses |
| **Dispatch** | `POST /api/dispatch` -- Trigger GitHub Actions workflow |

### Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `GITHUB_TOKEN` | Yes | PAT with `repo` scope for GitHub API calls |
| `DEVIN_API_KEY` | Yes | Devin API key for polling session statuses |
| `ACTION_REPO` | Yes | Your fork's full name (e.g., `your-username/codeql-devin-fixer`) |
| `FLASK_SECRET_KEY` | Recommended | Stable secret key for Flask sessions (random if unset -- set this for production) |
| `TELEMETRY_API_KEY` | Optional | API key to gate mutating endpoints |
| `CORS_ORIGINS` | Optional | Comma-separated allowed CORS origins (defaults to localhost) |
| `SESSION_COOKIE_SECURE` | Optional | Set to `false` for local HTTP development (defaults to `true`) |
| `GITHUB_OAUTH_CLIENT_ID` | Optional | GitHub OAuth App client ID |
| `GITHUB_OAUTH_CLIENT_SECRET` | Optional | GitHub OAuth App client secret |

---

## Orchestrator

The multi-repo orchestrator manages scanning and dispatch across a fleet of repositories. It uses a `repo_registry.json` configuration file to define which repos to scan, their schedules, and priority levels.

### Commands

```bash
python -m scripts.orchestrator plan       # Preview which repos are due for scanning
python -m scripts.orchestrator scan       # Trigger scans for due repos
python -m scripts.orchestrator dispatch   # Dispatch Devin sessions for scanned repos
python -m scripts.orchestrator cycle      # Full cycle: scan -> dispatch -> verify -> alert
python -m scripts.orchestrator status     # Check orchestrator status
```

### Configuration (`repo_registry.json`)

```json
{
  "schema_version": 1,
  "defaults": {
    "schedule": "weekly",
    "severity_threshold": "medium",
    "batch_size": 5,
    "max_sessions": 10
  },
  "concurrency": {
    "max_parallel_scans": 3,
    "max_parallel_dispatches": 5
  },
  "repos": [
    {
      "repo": "https://github.com/org/frontend-app",
      "schedule": "daily",
      "importance": "critical",
      "severity_threshold": "low"
    },
    {
      "repo": "https://github.com/org/backend-api",
      "schedule": "weekly",
      "importance": "high"
    }
  ]
}
```

The orchestrator is also controllable from the dashboard's Orchestrator tab, which provides plan preview, one-click scan/dispatch/cycle buttons, and configuration editing.

### Priority Scoring

The orchestrator uses a multi-factor weighted formula to prioritize issues:

| Factor | Weight | Description |
|--------|--------|-------------|
| Repo importance | 35% | From `repo_registry.json` importance field |
| Severity | 30% | CVSS-based severity tier |
| SLA urgency | 15% | Proximity to SLA breach deadline |
| Fix feasibility | 10% | Historical fix rate for this CWE family |
| Recurrence | 10% | How many consecutive runs the issue has appeared in |

### Per-Repo Configuration

Target repositories can include a `.codeql-fixer.yml` file to customize behavior:

```yaml
severity_threshold: medium
batch_size: 3
max_sessions: 5
exclude_paths:
  - "vendor/**"
  - "test/**"
```

---

## Creative Use of Devin

This project uses Devin in several creative ways beyond simple "prompt and wait":

### 1. CWE-Specific Playbooks with API Sync

Each vulnerability family has a dedicated playbook (`playbooks/*.yaml`) with structured fix instructions. Playbooks are synced to the Devin Playbooks API via `sync_to_devin_api()`, enabling native playbook integration where Devin interprets instructions as structured steps rather than free-text.

### 2. Knowledge API for Fix Learning

When a PR is verified as a successful fix, `knowledge.py::store_fix_knowledge()` extracts the PR diff, classifies the fix pattern, and stores it in the Devin Knowledge API. When dispatching future sessions for the same CWE family, `build_knowledge_context()` retrieves these entries and includes them in the prompt -- creating organizational memory where Devin learns from past successes.

### 3. Retry-with-Feedback via Send Message API

When verification labels a PR as `codeql-needs-work`, `retry_feedback.py` sends the verification results back to the active Devin session via `POST /v1/sessions/{id}/message`. If the session has ended, it creates a follow-up session with context from the previous attempt. This enables iterative improvement rather than fire-and-forget dispatch.

### 4. Structured Output Schema

Sessions are created with a `STRUCTURED_OUTPUT_SCHEMA` that defines the expected JSON structure for progress updates. This enables real-time tracking of which issues Devin is attempting, which it has fixed, and which are blocked.

### 5. Repository Context Enrichment

Before dispatching, `repo_context.py` analyzes the target repository to extract package managers, test frameworks, code style, and related test files. This context is included in the prompt so Devin understands the project's conventions.

### 6. Fix Learning with Adaptive Dispatch

`fix_learning.py` analyzes historical fix rates by CWE family. This drives prompt enrichment ("Previous attempts at fixing XSS had a 50% success rate") and dispatch gating (skip CWE families below a configurable threshold to save ACUs).

### 7. Wave-Based Dispatch

Instead of dispatching all batches simultaneously, wave dispatch groups batches by severity and dispatches them in waves. After each wave, the fix rate is computed. If it drops below a configurable threshold, dispatch halts -- saving ACUs when fixes are unlikely to succeed.

### 8. Verification Loop

After Devin creates fix PRs, `verify_results.py` re-runs CodeQL on the PR branch and compares fingerprints. Issues are labeled as `verified-fix`, `codeql-needs-work`, or `codeql-still-present`, closing the feedback loop.

### 9. Prompt Injection Defense

`sanitize_prompt_text()` strips potential prompt injection attempts from issue descriptions and code snippets before including them in Devin prompts.

### 10. Idempotent Sessions and Rich Tagging

All sessions are created with `idempotent: True`, preventing duplicates on retry. Sessions are tagged with severity tier, batch ID, CWE families, run number, and issue IDs for querying and filtering.

---

## Devin API Integration

The solution integrates with 8 Devin API endpoints:

| Endpoint | Module | Purpose |
|----------|--------|---------|
| `POST /v1/sessions` | `dispatch_devin.py` | Create fix sessions with structured output schema |
| `GET /v1/sessions/{id}` | `devin_service.py` | Poll session status and extract PR URLs |
| `POST /v1/sessions/{id}/message` | `retry_feedback.py` | Send verification feedback for iterative fixes |
| `GET /v1/knowledge` | `knowledge.py` | Retrieve fix patterns for prompt enrichment |
| `POST /v1/knowledge` | `knowledge.py` | Store successful fix patterns |
| `PUT /v1/knowledge/{id}` | `knowledge.py` | Update existing knowledge entries |
| `DELETE /v1/knowledge/{id}` | `knowledge.py` | Remove outdated knowledge |
| Playbooks API (sync) | `playbook_manager.py` | Push CWE playbooks to Devin for native use |

All API calls go through `devin_api.py` which provides centralized base URL configuration, `request_with_retry()` with exponential backoff (3 retries, 5s delay), terminal status detection, and session ID normalization.

---

## Action Inputs and Outputs

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `target_repo` | Yes | - | GitHub repo URL to analyze |
| `github_token` | No | - | PAT with `repo` scope for fork/push operations |
| `languages` | No | auto-detect | Comma-separated CodeQL languages |
| `batch_size` | No | `5` | Max issues per Devin session |
| `max_sessions` | No | `25` | Max Devin sessions to create |
| `severity_threshold` | No | `low` | Minimum severity: `critical`, `high`, `medium`, `low` |
| `queries` | No | `security-extended` | CodeQL query suite |
| `devin_api_key` | Yes | - | Devin API key (use a repository secret) |
| `dry_run` | No | `false` | Generate prompts without creating sessions |
| `persist_logs` | No | `true` | Commit run logs to the fork |
| `mode` | No | `basic` | Pipeline mode: `basic` (scan+dispatch) or `orchestrator` (scan only) |
| `enable_knowledge` | No | `false` | Enable Devin Knowledge API integration |
| `enable_retry_feedback` | No | `false` | Enable retry-with-feedback via Send Message API |

### Outputs

| Output | Description |
|--------|-------------|
| `total_issues` | Number of security issues found |
| `total_batches` | Number of batches created |
| `sessions_created` | Number of Devin sessions dispatched |
| `sessions_failed` | Number of sessions that failed |
| `session_urls` | Comma-separated Devin session URLs |
| `fork_url` | URL of the fork used for scanning |
| `run_label` | Label for this run's logs |
| `mode` | Pipeline mode that was used |

---

## Configuration

| Surface | Scope | Key Settings |
|---------|-------|--------------|
| `action.yml` inputs | Per-run | `target_repo`, `batch_size`, `max_sessions`, `severity_threshold`, `mode` |
| `.codeql-fixer.yml` (in target repo) | Per-repo | `severity_threshold`, `batch_size`, `exclude_paths`, custom CWE families |
| `repo_registry.json` | Orchestrator | Per-repo schedules, importance, overrides, concurrency limits |
| `telemetry/.env` | Dashboard | `GITHUB_TOKEN`, `DEVIN_API_KEY`, `ACTION_REPO`, `FLASK_SECRET_KEY` |
| `github_app/.env` | GitHub App | `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET` |

### Secrets Reference

| Secret | Used By | Purpose |
|--------|---------|---------|
| `DEVIN_API_KEY` | Action, Dashboard | Devin API authentication |
| `GH_PAT` / `GITHUB_TOKEN` | Action, Dashboard | GitHub API access (`repo` scope) |
| `TELEMETRY_API_KEY` | Dashboard | Gate mutating API endpoints |
| `FLASK_SECRET_KEY` | Dashboard | Flask session signing (set a stable value for production) |
| `GITHUB_APP_ID` | GitHub App | App identity |
| `GITHUB_APP_PRIVATE_KEY` | GitHub App | JWT signing |
| `GITHUB_WEBHOOK_SECRET` | GitHub App | Webhook signature verification |
| `GITHUB_OAUTH_CLIENT_ID` | Dashboard OAuth | GitHub OAuth App ID |
| `GITHUB_OAUTH_CLIENT_SECRET` | Dashboard OAuth | GitHub OAuth App secret |

---

## Deployment

### Local Development

```bash
git clone https://github.com/marius-posa/codeql-devin-fixer.git
cd codeql-devin-fixer

python -m venv .venv && source .venv/bin/activate
pip install -r telemetry/requirements.txt
pip install pytest requests jinja2 pyyaml

cd telemetry && cp .env.example .env
python app.py
# Open http://localhost:5000
```

### Docker

```bash
cd telemetry
docker compose up --build
```

### Kubernetes (Helm)

```bash
helm install telemetry charts/telemetry/ \
  --set env.GITHUB_TOKEN=$GITHUB_TOKEN \
  --set env.DEVIN_API_KEY=$DEVIN_API_KEY \
  --set env.ACTION_REPO=your-username/codeql-devin-fixer
```

### GitHub Pages

The `docs/` folder is published as a GitHub Pages site at **https://marius-posa.github.io/codeql-devin-fixer/**. When making changes to `telemetry/templates/` or `telemetry/static/`, sync corresponding files to `docs/` to keep the public site up to date.

### Running Tests

```bash
python -m pytest tests/ -v
```

---

## Dry Run Mode

Test the full pipeline without creating Devin sessions or consuming ACUs:

```yaml
- uses: marius-posa/codeql-devin-fixer@main
  with:
    target_repo: "https://github.com/juice-shop/juice-shop"
    devin_api_key: "not-needed-for-dry-run"
    dry_run: "true"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ERROR: Fork creation failed (403)` | `GITHUB_TOKEN` used instead of PAT | Add `GH_PAT` secret with `repo` scope |
| `WARNING: git push failed` | PAT lacks `repo` scope or is expired | Regenerate PAT with `repo` scope |
| Dashboard empty | No logs persisted yet | Enable `persist_logs: "true"` |
| `No SARIF file found` | CodeQL found no supported languages | Check `languages` input |
| Sessions stuck in "running" | Session polling not triggered | Click "Poll Sessions" in dashboard |
| Dashboard 401 errors | `TELEMETRY_API_KEY` set but not provided | Include API key in `X-API-Key` header |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. Quick summary:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r telemetry/requirements.txt
pip install pytest requests jinja2 pyyaml
python -m pytest tests/ -v
cd telemetry && python app.py
```

### Areas for Contribution

- **Accessibility**: WCAG 2.1 AA compliance (ARIA attributes, keyboard navigation)
- **Chart.js migration**: `repo.html` still uses hand-rolled SVG for charts
- **API documentation**: OpenAPI/Swagger docs for the 30+ endpoints
- **Additional playbooks**: New CWE family playbooks (e.g., SSRF, deserialization, auth bypass)
- **PostgreSQL support**: Database migration from SQLite for multi-node deployment
- **Frontend tests**: UI component tests for `shared.js` and dashboard templates

---

## Solution Reviews

This project has undergone iterative solution reviews documenting its evolution:

| Review | Focus | Key Changes |
|--------|-------|-------------|
| [V1](docs/SOLUTION_REVIEW.md) | Foundation | Clean architecture, missing retries, no auth, no verification loop |
| [V2](docs/SOLUTION_REVIEW_V2.md) | Resilience | Exponential backoff, Flask dashboard, shared utilities |
| [V3](docs/SOLUTION_REVIEW_V3.md) | Scale | Orchestrator engine, GitHub App, SQLite, verification loop, playbooks |
| [V4](docs/SOLUTION_REVIEW_V4.md) | Maturity | Orchestrator decomposed, structured logging, TypedDicts, wave dispatch, audit logging, Chart.js, tabbed UI, demo data |
| [V5](docs/SOLUTION_REVIEW_V5.md) | Deep Integration | Blueprint split, server-side sessions, CORS restriction, rate limiting, Knowledge API, Send Message API, structured output, Playbooks API sync |

---

## License

This project is provided as-is for educational and assessment purposes.
