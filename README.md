# CodeQL Devin Fixer

A GitHub Action and platform that runs [CodeQL](https://codeql.github.com/) security analysis on any repository, prioritizes vulnerabilities by severity, groups them into batches, and creates [Devin](https://devin.ai) AI agent sessions to automatically fix each batch with a pull request.

**[Live Dashboard (GitHub Pages)](https://marius-posa.github.io/codeql-devin-fixer/)** | **[Architecture](docs/architecture.md)** | **[Contributing](CONTRIBUTING.md)** | **[Changelog](CHANGELOG.md)**

---

## Table of Contents

- [Scope](#scope)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [GitHub App Installation](#github-app)
- [Telemetry Dashboard](#telemetry-dashboard)
- [Orchestrator](#orchestrator)
- [Creative Use of Devin](#creative-use-of-devin)
- [Action Inputs and Outputs](#action-inputs-and-outputs)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Dry Run Mode](#dry-run-mode)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Solution Reviews](#solution-reviews)

---

## Scope

CodeQL Devin Fixer is a **full-stack security remediation platform** that automates the entire lifecycle of finding and fixing security vulnerabilities:

| Layer | Component | Purpose |
|-------|-----------|---------|
| **Scanning** | GitHub Action (`action.yml`) | Runs CodeQL analysis, parses SARIF results, dispatches Devin sessions |
| **Fixing** | Devin API integration | AI agent sessions that read code, understand vulnerabilities, and create fix PRs |
| **Orchestration** | Multi-repo orchestrator (`scripts/orchestrator/`) | Schedules scans across a fleet of repositories with priority-based dispatch |
| **Verification** | Verification loop (`scripts/verify_results.py`) | Re-runs CodeQL on fix PRs to confirm vulnerabilities are resolved |
| **Telemetry** | Flask dashboard (`telemetry/`) | Centralized web UI aggregating metrics across all repos, runs, sessions, and PRs |
| **Automation** | GitHub App (`github_app/`) | Webhook-driven automation for scan-on-push and event-based triggers |
| **Deployment** | Docker + Helm (`telemetry/Dockerfile`, `charts/`) | Container and Kubernetes deployment for the telemetry dashboard |

The platform supports **any repository** that CodeQL can analyze: JavaScript/TypeScript, Python, Java, Go, Ruby, C#, C/C++, and Swift.

---

## How It Works

```
                    +-----------------+
                    | Target Repo(s)  |
                    +--------+--------+
                             |
                    1. Fork and Clone
                             |
                    +--------v--------+
                    | CodeQL Analysis  |
                    | (auto-detect     |
                    |  languages)      |
                    +--------+--------+
                             |
                    2. Parse SARIF
                             |
                    +--------v--------+
                    | Prioritize and   |
                    | Batch by CWE     |
                    | Family + Severity|
                    +--------+--------+
                             |
                    3. Dispatch to Devin
                    (wave-based, severity-first)
                             |
              +--------------+--------------+
              |              |              |
        +-----v-----+  +----v----+  +------v------+
        | Session 1  |  | Session2|  | Session N   |
        | (Injection)|  | (XSS)  |  | (Crypto)    |
        +-----+------+  +----+---+  +------+------+
              |              |              |
              +------+-------+------+-------+
                     |              |
              4. Fix PRs on Fork   |
                     |              |
              +------v--------------v------+
              | Verification Loop           |
              | (Re-run CodeQL on PR branch,|
              |  compare fingerprints)      |
              +------+---------------------+
                     |
              5. Telemetry and Reporting
                     |
              +------v---------------------+
              | Dashboard: metrics, SLA,    |
              | audit log, PDF reports      |
              +----------------------------+
```

### Pipeline Steps

1. **Fork** the target repository into your GitHub account (or reuse an existing fork)
2. **Clone** the fork and **analyze** with CodeQL (auto-detects languages from manifests)
3. **Parse** SARIF results, assign each issue a unique tracking ID (`CQLF-R{run}-{seq}`), and compute a stable fingerprint for cross-run tracking
4. **Prioritize** by CVSS severity score (adversary perspective) and **batch** by CWE vulnerability family
5. **Dispatch** Devin sessions per batch with CWE-specific playbooks, fix learning context, and repository context analysis
6. **Verify** fixes by re-running CodeQL on PR branches and comparing fingerprints
7. **Persist** logs to the fork and telemetry records to the action repo's SQLite database
8. **Display** aggregated metrics in the telemetry dashboard

### Prioritization

Issues are ranked from an adversary's perspective -- which vulnerabilities are easiest to exploit with the highest impact:

| Tier | CVSS Score | Examples |
|------|-----------|----------|
| Critical | 9.0 - 10.0 | SQL injection, command injection, code injection, path traversal |
| High | 7.0 - 8.9 | XSS, SSRF, deserialization, authentication bypass |
| Medium | 4.0 - 6.9 | Information disclosure, open redirect, weak crypto, CSRF |
| Low | 0.1 - 3.9 | Minor info leaks, code quality issues |

### Batching Strategy

Issues are grouped by CWE vulnerability family so Devin can focus on related issues together:

- **injection** -- SQLi, command injection, code injection (CWE-78, 89, 94, ...)
- **xss** -- Cross-site scripting (CWE-79, 80)
- **path-traversal** -- Directory traversal (CWE-22, 23, 36)
- **ssrf** -- Server-side request forgery (CWE-918)
- **deserialization** -- Insecure deserialization (CWE-502)
- **auth** -- Authentication/authorization issues (CWE-287, 306, 862, 863)
- **crypto** -- Weak cryptography (CWE-327, 328, 330, 338)
- **info-disclosure** -- Information leaks (CWE-200, 209, 532)
- **redirect** -- Open redirect (CWE-601)
- **xxe** -- XML external entity (CWE-611)
- **csrf** -- Cross-site request forgery (CWE-352)
- **prototype-pollution** -- Prototype pollution (CWE-1321)
- **regex-dos** -- Regular expression DoS (CWE-1333, 730)

Highest-severity batches are dispatched first. When wave dispatch is enabled, batches are grouped into waves by severity tier and dispatched sequentially, with fix-rate gating between waves.

---

## Architecture

```
GitHub Actions Runner
  action.yml (composite action)
  fork_repo.py -> CodeQL analyze -> parse_sarif.py -> dispatch_devin.py (wave-based)
  persist_logs.py (to fork repo)    persist_telemetry.py (to action repo DB)

         |                         |
         v                         v
  Devin API                Telemetry Dashboard (Flask)
  /v1/sessions             Overview | Issues | Orchestrator tabs
  Session 1..N             SQLite DB: runs, sessions, PRs, issues,
                           audit_log, verification records
                                    |
                       +------------+------------+
                       v                         v
              Orchestrator              GitHub App
              (multi-repo)              (webhook-driven)
              cli, dispatch,            webhook_handler,
              scanner, state,           scan_trigger,
              alerts                    alerts, auth
```

### Project Structure

```
codeql-devin-fixer/
+-- action.yml                    # Composite GitHub Action definition
+-- .github/workflows/            # CI/CD and orchestrator workflows
|   +-- codeql-fixer.yml          # Main action workflow
|   +-- orchestrator.yml          # Multi-repo orchestration schedule
|   +-- poll-sessions.yml         # Session status polling schedule
+-- scripts/                      # Pipeline scripts
|   +-- parse_sarif.py            # SARIF parsing, severity scoring, batching
|   +-- dispatch_devin.py         # Devin session creation with wave dispatch
|   +-- fork_repo.py              # Fork management and sync
|   +-- persist_logs.py           # Log persistence to fork repos
|   +-- persist_telemetry.py      # Telemetry record storage
|   +-- verify_results.py         # Fix verification loop
|   +-- pipeline_config.py        # Centralized config with TypedDicts
|   +-- logging_config.py         # Structured JSON logging
|   +-- retry_utils.py            # Exponential backoff utilities
|   +-- playbook_manager.py       # CWE-specific playbook loading
|   +-- fix_learning.py           # Historical fix rate analysis
|   +-- repo_context.py           # Repository context enrichment
|   +-- orchestrator/             # Multi-repo orchestrator package
|       +-- cli.py                # Command routing (scan, dispatch, cycle)
|       +-- dispatcher.py         # Session dispatch with rate limiting
|       +-- scanner.py            # Scan triggering and SARIF retrieval
|       +-- state.py              # State persistence and cooldown
|       +-- alerts.py             # Alert processing and delivery
+-- telemetry/                    # Flask dashboard backend
|   +-- app.py                    # Main Flask application (40+ API endpoints)
|   +-- database.py               # SQLite schema, queries, audit logging
|   +-- oauth.py                  # GitHub OAuth authentication
|   +-- pdf_report.py             # PDF report generation
|   +-- demo_data.py              # Demo seed data management
|   +-- devin_service.py          # Devin API session polling
|   +-- github_service.py         # GitHub PR fetching and linking
|   +-- aggregation.py            # SLA compliance computation
|   +-- verification.py           # Verification record processing
|   +-- templates/                # Server-rendered HTML templates
|   |   +-- dashboard.html        # Main tabbed dashboard (6 tabs)
|   |   +-- repo.html             # Per-repo detail page
|   |   +-- dispatch_modal.html   # Workflow dispatch dialog
|   +-- static/                   # CSS and JavaScript
|   +-- Dockerfile                # Container image for telemetry
|   +-- docker-compose.yml        # Local Docker deployment
+-- github_app/                   # GitHub App for webhook automation
|   +-- app.py                    # Flask app with /healthz
|   +-- webhook_handler.py        # Webhook event processing
|   +-- scan_trigger.py           # Automated scan triggering
|   +-- alerts.py                 # Alert delivery (webhook, Slack)
|   +-- auth.py                   # JWT and installation token management
|   +-- config.py                 # App configuration
+-- playbooks/                    # CWE-specific fix instructions
|   +-- injection.yaml            # SQL/command injection playbook
|   +-- xss.yaml                  # Cross-site scripting playbook
|   +-- path-traversal.yaml       # Path traversal playbook
+-- charts/telemetry/             # Helm chart for Kubernetes deployment
+-- docs/                         # GitHub Pages static site + reviews
|   +-- index.html                # Static dashboard (mirrors telemetry UI)
|   +-- architecture.md           # Architecture diagrams
|   +-- SOLUTION_REVIEW.md        # V1 review
|   +-- SOLUTION_REVIEW_V2.md     # V2 review
|   +-- SOLUTION_REVIEW_V3.md     # V3 review
|   +-- SOLUTION_REVIEW_V4.md     # V4 review
+-- tests/                        # Test suite (30 files, ~8,700 lines)
+-- repo_registry.json            # Multi-repo scan configuration
+-- CONTRIBUTING.md               # Contribution guide
+-- CHANGELOG.md                  # Version history
```

See [docs/architecture.md](docs/architecture.md) for a detailed flow diagram with sequence diagrams.

---

## Quick Start

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
      - uses: YOUR_USERNAME/codeql-devin-fixer@main
        with:
          target_repo: ${{ inputs.target_repo }}
          github_token: ${{ secrets.GH_PAT }}
          devin_api_key: ${{ secrets.DEVIN_API_KEY }}
          persist_logs: "true"
```

### Option C: Clone and Customize

```bash
git clone https://github.com/YOUR_USERNAME/codeql-devin-fixer.git
cd codeql-devin-fixer
```

Edit `.github/workflows/codeql-fixer.yml` to change defaults, then push and add the required secrets.

### One-Click Setup

Run the setup script for guided configuration:

```bash
bash setup.sh
```

This creates the workflow file, prompts for secrets, and runs a dry-run verification.

---

## GitHub App

The GitHub App enables webhook-driven automation: scans trigger automatically on push events to default branches, and events are processed without manual workflow dispatch.

### Installation

1. Create a GitHub App in your org/account settings:
   - **Webhook URL**: Point to your GitHub App server (e.g., `https://your-server.com/webhook`)
   - **Permissions**: `contents: read`, `pull_requests: write`, `security_events: read`
   - **Events**: `push`, `pull_request`, `code_scanning_alert`
2. Generate a private key and note the App ID
3. Set environment variables:
   ```
   GITHUB_APP_ID=<your-app-id>
   GITHUB_APP_PRIVATE_KEY=<path-to-private-key.pem>
   GITHUB_WEBHOOK_SECRET=<your-webhook-secret>
   ```
4. Run the GitHub App server:
   ```bash
   cd github_app
   pip install -r requirements.txt
   python main.py
   ```

### Features

- **Scan on push**: Automatically triggers CodeQL analysis when code is pushed to default branches
- **Webhook signature verification**: HMAC-SHA256 verification of all incoming webhooks
- **Installation token management**: JWT-based authentication with automatic token refresh
- **Health endpoint**: `/healthz` for container orchestration probes
- **Alert processing**: Webhook delivery for scan lifecycle events

---

## Telemetry Dashboard

The telemetry dashboard is a centralized Flask web application that aggregates data from all action runs across every target repository.

### Setup

```bash
cd telemetry
cp .env.example .env
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000` in your browser.

### Docker

```bash
cd telemetry
docker compose up --build
```

### Dashboard Tabs

| Tab | Features |
|-----|----------|
| **Overview** | Metric cards, security health trend (Chart.js), severity/category breakdowns, orchestrator quick view, period selector (7d/30d/90d/all) |
| **Repositories** | Repo table with per-repo metrics, drill-down to dedicated repo detail page |
| **Issues** | Issue tracking with fingerprint-based status (new/recurring/fixed), SLA compliance panel, fix verification stats, CSV export, issue detail drawer |
| **Activity** | Run history, Devin sessions with live status polling, pull request tracking with merge status |
| **Orchestrator** | Orchestrator status, scan/dispatch/cycle controls, issue prioritization scoring, fix rate analysis by CWE family, config editor |
| **Settings** | Demo data management (load/clear/regenerate/edit JSON), export (CSV/PDF), global defaults, scheduled repo registry with add/edit/remove, audit log with action/user filters and JSON export |

### Features

- **Dark/light theme** with toggle button
- **Compact mode** for dense table layouts
- **Loading skeletons** for perceived performance
- **Issue detail drawer** -- slide-out panel with full issue context
- **PDF report generation** -- downloadable security report
- **Demo data system** -- load realistic sample data for demos without real scan data
- **Audit logging** -- all mutating actions logged with user, timestamp, and details
- **OAuth authentication** -- GitHub OAuth for user-scoped access
- **API key authentication** -- `TELEMETRY_API_KEY` for programmatic access to mutating endpoints

### Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `GITHUB_TOKEN` | Yes | PAT with `repo` scope for GitHub API calls |
| `DEVIN_API_KEY` | Yes | Devin API key for polling session statuses |
| `ACTION_REPO` | Yes | Your fork's full name (e.g., `your-username/codeql-devin-fixer`) |
| `FLASK_SECRET_KEY` | Recommended | Stable secret key for Flask sessions (random if unset) |
| `TELEMETRY_API_KEY` | Optional | API key to gate mutating endpoints |
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

### Per-Repo Configuration

Target repositories can include a `.codeql-fixer.yml` file to customize behavior:

```yaml
severity_threshold: medium
batch_size: 3
max_sessions: 5
exclude_paths:
  - "vendor/**"
  - "test/**"
cwe_families:
  injection:
    - CWE-89
    - CWE-78
```

See `.codeql-fixer.example.yml` for all available options.

---

## Creative Use of Devin

This project uses Devin in several creative ways beyond simple "prompt and wait":

### 1. CWE-Specific Playbooks

Each vulnerability family has a dedicated playbook (`playbooks/*.yaml`) with structured fix instructions. When dispatching a session, the relevant playbook is injected into the prompt, giving Devin step-by-step guidance specific to the vulnerability type (e.g., parameterized queries for SQL injection, output encoding for XSS).

### 2. Repository Context Enrichment

Before dispatching, `repo_context.py` analyzes the target repository to extract:
- Package manager and dependencies (package.json, requirements.txt, go.mod, etc.)
- Test framework in use (pytest, jest, junit, etc.)
- Code style patterns
- Related test files for the affected source files

This context is included in the prompt so Devin understands the project's conventions.

### 3. Fix Learning

`fix_learning.py` analyzes historical fix rates by CWE family. If injection fixes have a 90% success rate but XSS fixes only 50%, this data is included in the prompt for XSS batches: "Previous attempts at fixing XSS had a 50% success rate. Common issues were [...]". This helps Devin learn from past outcomes.

### 4. Wave-Based Dispatch

Instead of dispatching all batches simultaneously, wave dispatch groups batches by severity and dispatches them in waves. After each wave completes, the fix rate is computed. If it drops below a configurable threshold, dispatch halts -- saving ACUs by not dispatching to Devin when fixes are unlikely to succeed.

### 5. Verification Loop

After Devin creates fix PRs, `verify_results.py` re-runs CodeQL on the PR branch and compares fingerprints with the original scan. Issues are labeled as `verified-fix`, `codeql-needs-work`, or `codeql-still-present`. This closes the feedback loop and provides ground-truth data on fix effectiveness.

### 6. Prompt Injection Defense

`sanitize_prompt_text()` in `dispatch_devin.py` strips potential prompt injection attempts from issue descriptions and code snippets before including them in the Devin prompt. This prevents malicious code comments from manipulating Devin's behavior.

### 7. Idempotent Sessions

All sessions are created with `idempotent: True`, preventing duplicate sessions if the pipeline retries due to transient failures.

### 8. Rich Tagging

Sessions are tagged with severity tier, batch ID, CWE families, run number, and issue IDs. This enables querying and filtering sessions in the Devin platform.

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
| `include_paths` | No | - | Globs to include (narrows analysis) |
| `exclude_paths` | No | - | Globs to exclude |
| `devin_api_key` | Yes | - | Devin API key (use a repository secret) |
| `max_acu_per_session` | No | - | ACU limit per Devin session |
| `dry_run` | No | `false` | Generate prompts without creating sessions |
| `default_branch` | No | `main` | Default branch of the target repo |
| `persist_logs` | No | `true` | Commit run logs to the fork |
| `max_failure_rate` | No | `50` | Max allowed failure rate (%) before action fails |
| `wave_dispatch` | No | `false` | Enable wave-based dispatch by severity tier |
| `prompt_template` | No | - | Custom Jinja2 prompt template path |

### Outputs

| Output | Description |
|--------|-------------|
| `total_issues` | Number of security issues found |
| `total_batches` | Number of batches created |
| `sessions_created` | Number of Devin sessions dispatched |
| `session_urls` | Comma-separated Devin session URLs |
| `fork_url` | URL of the fork used for scanning |
| `run_label` | Label for this run's logs |

---

## Configuration

> **Full reference:** [`docs/CONFIG_REFERENCE.md`](docs/CONFIG_REFERENCE.md) documents every option, type, default, and precedence rule across all configuration surfaces.

Configuration is spread across several surfaces depending on the component:

| Surface | Scope | Key Settings |
|---------|-------|--------------|
| `action.yml` inputs | Per-run | `target_repo`, `batch_size`, `max_sessions`, `severity_threshold`, `wave_dispatch` |
| `.codeql-fixer.yml` (in target repo) | Per-repo | `severity_threshold`, `batch_size`, `exclude_paths`, custom CWE families |
| `repo_registry.json` | Multi-repo orchestrator | Per-repo schedules, importance, overrides, concurrency limits |
| `telemetry/.env` | Dashboard | `GITHUB_TOKEN`, `DEVIN_API_KEY`, `ACTION_REPO`, `FLASK_SECRET_KEY` |
| `github_app/.env` | GitHub App | `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET` |
| `PipelineConfig` (`scripts/pipeline_config.py`) | Pipeline internals | All environment variables consumed by pipeline scripts |

### Secrets Reference

| Secret | Used By | Purpose | Required Scope |
|--------|---------|---------|----------------|
| `DEVIN_API_KEY` | Action, Dashboard | Devin API authentication | Session creation |
| `GH_PAT` / `GITHUB_TOKEN` | Action, Dashboard | GitHub API access | `repo` scope |
| `TELEMETRY_API_KEY` | Dashboard | Gate mutating API endpoints | N/A (custom string) |
| `FLASK_SECRET_KEY` | Dashboard | Flask session signing | N/A (random string) |
| `GITHUB_APP_ID` | GitHub App | App identity | N/A |
| `GITHUB_APP_PRIVATE_KEY` | GitHub App | JWT signing | N/A |
| `GITHUB_WEBHOOK_SECRET` | GitHub App | Webhook signature verification | N/A |
| `GITHUB_OAUTH_CLIENT_ID` | Dashboard OAuth | GitHub OAuth App ID | N/A |
| `GITHUB_OAUTH_CLIENT_SECRET` | Dashboard OAuth | GitHub OAuth App secret | N/A |

---

## Deployment

### Local Development

```bash
git clone https://github.com/YOUR_USERNAME/codeql-devin-fixer.git
cd codeql-devin-fixer
python -m venv .venv && source .venv/bin/activate
pip install -r telemetry/requirements.txt
pip install pytest requests jinja2

cd telemetry && cp .env.example .env
python app.py
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

The Helm chart deploys the telemetry dashboard with a persistent volume for the SQLite database.

### GitHub Pages

The `docs/` folder is published as a GitHub Pages site, providing a static version of the dashboard. When making changes to `telemetry/templates/` or `telemetry/static/`, sync corresponding files to `docs/` to keep the public site up to date.

---

## Dry Run Mode

Test the full pipeline without creating Devin sessions:

```yaml
- uses: YOUR_USERNAME/codeql-devin-fixer@main
  with:
    target_repo: "https://github.com/juice-shop/juice-shop"
    devin_api_key: "not-needed-for-dry-run"
    dry_run: "true"
```

This generates all analysis artifacts (SARIF, batches, prompts) without calling the Devin API. Check the uploaded artifacts for the generated prompts.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ERROR: Fork creation failed (403)` | `GITHUB_TOKEN` used instead of PAT | Add `GH_PAT` secret with `repo` scope |
| `WARNING: git push failed` | PAT lacks `repo` scope or is expired | Regenerate PAT with `repo` scope |
| Fork not created | `github_token` input not set | Pass `github_token: ${{ secrets.GH_PAT }}` |
| Dashboard empty | No logs persisted yet | Enable `persist_logs: "true"` and ensure PAT has push access |
| `No SARIF file found` | CodeQL found no supported languages | Check `languages` input or verify target repo has supported code |
| Telemetry not appearing | `ACTION_REPO` env var not set | Set `ACTION_REPO` to `your-username/codeql-devin-fixer` |
| Sessions stuck in "running" | Session polling not triggered | Click "Poll Sessions" in dashboard or check poll-sessions.yml workflow |
| Orchestrator errors | Missing secrets or state file | Check `repo_registry.json` exists and secrets are configured |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. Quick summary:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r telemetry/requirements.txt
pip install pytest requests jinja2
python -m pytest tests/ -v
```

Branch naming: `feature/per-repo-config`, `fix/sarif-parsing-edge-case`, `docs/architecture-diagram`

Commit format: `feat(parse): add support for custom CWE family mappings`

---

## Solution Reviews

This project has undergone iterative solution reviews documenting its evolution:

| Review | Focus | Key Findings |
|--------|-------|-------------|
| [V1](docs/SOLUTION_REVIEW.md) | Foundation | Clean architecture, missing retries, no auth, no verification loop |
| [V2](docs/SOLUTION_REVIEW_V2.md) | Resilience | Exponential backoff added, Flask dashboard created, shared utilities |
| [V3](docs/SOLUTION_REVIEW_V3.md) | Scale | Orchestrator engine, GitHub App, SQLite migration, verification loop, playbooks |
| [V4](docs/SOLUTION_REVIEW_V4.md) | Maturity | Orchestrator decomposed, structured logging, TypedDicts, wave dispatch, audit logging, Chart.js, tabbed UI, demo data |

---

## License

This project is provided as-is for educational and assessment purposes.
