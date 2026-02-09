# Configuration Reference

Complete reference for every configurable option in the CodeQL Devin Fixer platform.

Configuration is spread across several surfaces depending on the component. This document maps every option, its type, default value, and which component consumes it.

---

## Table of Contents

- [Configuration Surfaces](#configuration-surfaces)
- [1. GitHub Action Inputs](#1-github-action-inputs)
- [2. GitHub Action Outputs](#2-github-action-outputs)
- [3. Pipeline Environment Variables](#3-pipeline-environment-variables)
- [4. Per-Repo Configuration](#4-per-repo-configuration)
- [5. Orchestrator Registry](#5-orchestrator-registry)
- [6. Telemetry Dashboard](#6-telemetry-dashboard)
- [7. GitHub App](#7-github-app)
- [8. Webhook Configuration](#8-webhook-configuration)
- [9. Logging](#9-logging)
- [10. Deployment](#10-deployment)
- [11. Internal Constants](#11-internal-constants)
- [Configuration Precedence](#configuration-precedence)
- [Secrets Reference](#secrets-reference)
- [Cross-Surface Option Map](#cross-surface-option-map)

---

## Configuration Surfaces

| Surface | File(s) | Scope | Description |
|---------|---------|-------|-------------|
| Action inputs | `action.yml` | Per-run | Workflow dispatch inputs for the GitHub Action |
| `PipelineConfig` | `scripts/pipeline_config.py` | Pipeline scripts | Dataclass loading all pipeline env vars |
| Per-repo config | `.codeql-fixer.yml` in target repo | Per-repo | Override action defaults without modifying workflows |
| Orchestrator registry | `repo_registry.json` | Multi-repo | Fleet-wide repo schedules, defaults, and overrides |
| Telemetry env | `telemetry/.env` | Dashboard | Environment variables for the Flask dashboard |
| GitHub App env | `github_app/.env` | GitHub App | Environment variables for the webhook server |
| Webhook env | Pipeline env vars | Per-run | Webhook delivery configuration |
| Logging env | `LOG_LEVEL` env var | All components | Structured logging level |
| Helm values | `charts/telemetry/values.yaml` | Kubernetes | Helm chart values for k8s deployment |
| Docker Compose | `telemetry/docker-compose.yml` | Docker | Container deployment configuration |

---

## 1. GitHub Action Inputs

Defined in `action.yml`. Set via workflow dispatch or reusable action `with:` block.

### Scan Configuration

| Input | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `target_repo` | string | — | Yes | GitHub repository to analyze. Accepts full URL (`https://github.com/owner/repo`) or `owner/repo` shorthand. |
| `languages` | string | auto-detect | No | Comma-separated CodeQL languages (e.g., `javascript,python`). Auto-detected from manifests if empty. |
| `queries` | string | `security-extended` | No | CodeQL query suite to run (e.g., `security-extended`, `security-and-quality`). |
| `include_paths` | string | `""` | No | Newline- or comma-separated globs to include (limits analysis scope). |
| `exclude_paths` | string | `""` | No | Newline- or comma-separated globs to exclude from analysis. |
| `default_branch` | string | `main` | No | Default branch of the target repo. |
| `config_file` | string | `""` | No | Path to a `.codeql-fixer.yml` in the target repo (auto-detected if empty). |

### Dispatch Configuration

| Input | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `batch_size` | string | `5` | No | Maximum number of issues per Devin session/batch. |
| `max_sessions` | string | `25` | No | Maximum number of Devin sessions to create. |
| `severity_threshold` | string | `low` | No | Minimum severity to include: `critical`, `high`, `medium`, `low`. |
| `max_acu_per_session` | string | `""` | No | Maximum ACU limit per Devin session (platform default if empty). |
| `dry_run` | string | `false` | No | If `true`, generate prompts but do not create Devin sessions. |
| `max_failure_rate` | string | `50` | No | Maximum session failure rate (0–100) before the dispatch step exits non-zero. |
| `mode` | string | `basic` | No | Pipeline mode: `basic` (scan + dispatch) or `orchestrator` (scan only, defer dispatch). |
| `prompt_template` | string | `""` | No | Path to a custom Jinja2 prompt template file (overrides default prompt generation). |

### Authentication

| Input | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `github_token` | string | `""` | No | GitHub PAT with `repo` scope for fork creation, log persistence, and dashboard push. |
| `devin_api_key` | string | — | Yes | Devin API key for creating fix sessions (use a repository secret). |

### Webhook

| Input | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `webhook_url` | string | `""` | No | URL to receive lifecycle webhook notifications. |
| `webhook_secret` | string | `""` | No | Shared secret for HMAC-SHA256 webhook payload signing. |

### Persistence

| Input | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `persist_logs` | string | `true` | No | Persist run logs to the fork repository. |

---

## 2. GitHub Action Outputs

Defined in `action.yml`. Available to downstream workflow steps.

| Output | Description |
|--------|-------------|
| `total_issues` | Total number of security issues found by CodeQL. |
| `total_batches` | Number of batches created from parsed issues. |
| `sessions_created` | Number of Devin sessions successfully dispatched. |
| `sessions_failed` | Number of Devin sessions that failed to create. |
| `session_urls` | Comma-separated list of Devin session URLs. |
| `fork_url` | URL of the fork used for scanning. |
| `run_label` | Label for this run's logs (e.g., `run-42`). |
| `logs_persisted` | Whether run logs were successfully pushed to the fork. |
| `mode` | Pipeline mode that was used (`basic` or `orchestrator`). |

---

## 3. Pipeline Environment Variables

Loaded by `PipelineConfig.from_env()` in `scripts/pipeline_config.py`. These are set automatically by `action.yml` steps or manually when running scripts outside of GitHub Actions.

### Shared Across Scripts

| Env Var | Field | Type | Default | Used By |
|---------|-------|------|---------|---------|
| `GITHUB_TOKEN` | `github_token` | str | `""` | fork_repo, persist_logs, persist_telemetry, orchestrator |
| `TARGET_REPO` | `target_repo` | str | `""` | parse_sarif, dispatch_devin, persist_telemetry |
| `DEFAULT_BRANCH` | `default_branch` | str | `main` | fork_repo, dispatch_devin |
| `MODE` | `mode` | str | `basic` | parse_sarif (controls orchestrator-mode behavior) |

### parse_sarif.py

| Env Var | Field | Type | Default | Description |
|---------|-------|------|---------|-------------|
| `BATCH_SIZE` | `batch_size` | int | `5` | Max issues per batch. |
| `MAX_SESSIONS` | `max_sessions` | int | `25` | Max batches to create. |
| `SEVERITY_THRESHOLD` | `severity_threshold` | str | `low` | Minimum severity tier. |
| `RUN_NUMBER` | `run_number` | str | `""` | GitHub Actions run number for issue ID generation. |

### dispatch_devin.py

| Env Var | Field | Type | Default | Description |
|---------|-------|------|---------|-------------|
| `DEVIN_API_KEY` | `devin_api_key` | str | `""` | Devin API authentication key. |
| `MAX_ACU_PER_SESSION` | `max_acu_per_session` | int \| None | `None` | ACU cap per session. |
| `DRY_RUN` | `dry_run` | bool | `false` | Skip actual Devin API calls. |
| `FORK_URL` | `fork_url` | str | `""` | URL of the fork for Devin to work on. |
| `RUN_ID` | `run_id` | str | `""` | GitHub Actions run ID. |
| `MAX_FAILURE_RATE` | `max_failure_rate` | int | `50` | Failure rate threshold (%). |

### Wave Dispatch

| Env Var | Field | Type | Default | Description |
|---------|-------|------|---------|-------------|
| `WAVE_DISPATCH` | `wave_dispatch` | bool | `false` | Enable wave-based dispatch by severity tier. |
| `WAVE_FIX_RATE_THRESHOLD` | `wave_fix_rate_threshold` | float | `0.5` | Minimum fix rate to continue dispatching waves. |
| `WAVE_POLL_INTERVAL` | `wave_poll_interval` | int | `60` | Seconds between session status polls during wave dispatch. |
| `WAVE_TIMEOUT` | `wave_timeout` | int | `3600` | Maximum seconds to wait for a wave to complete. |

### fork_repo.py

| Env Var | Field | Type | Default | Description |
|---------|-------|------|---------|-------------|
| `FORK_OWNER` | `fork_owner` | str | `""` | GitHub user/org that owns the fork. |

### persist_logs.py

| Env Var | Field | Type | Default | Description |
|---------|-------|------|---------|-------------|
| `REPO_DIR` | `repo_dir` | str | `""` | Path to the cloned fork on disk. |
| `RUN_LABEL` | `run_label` | str | `""` | Label identifying this run's log directory. |

### persist_telemetry.py

| Env Var | Field | Type | Default | Description |
|---------|-------|------|---------|-------------|
| `ACTION_REPO` | `action_repo` | str | `""` | Repo containing the telemetry database (e.g., `user/codeql-devin-fixer`). |

### Context-Rich Prompts / Fix Learning

| Env Var | Field | Type | Default | Description |
|---------|-------|------|---------|-------------|
| `TARGET_DIR` | `target_dir` | str | `""` | Path to the cloned target repo on disk. |
| `TELEMETRY_DIR` | `telemetry_dir` | str | `""` | Path to telemetry data directory. |
| `PLAYBOOKS_DIR` | `playbooks_dir` | str | `""` | Path to CWE playbook YAML files. |

### Legacy / Dashboard Generation

| Env Var | Field | Type | Default | Description |
|---------|-------|------|---------|-------------|
| `LOGS_DIR` | `logs_dir` | str | `logs` | Directory containing run log files. |
| `DASHBOARD_OUTPUT_DIR` | `dashboard_output_dir` | str | `dashboard` | Output directory for generated dashboard. |

---

## 4. Per-Repo Configuration

File: `.codeql-fixer.yml` or `.codeql-fixer.yaml` placed at the root of a **target** repository.

See `.codeql-fixer.example.yml` for a template.

All fields are optional. Omitted fields fall back to action input values.

| Key | Type | Default | Validation | Description |
|-----|------|---------|------------|-------------|
| `severity_threshold` | string | (from action input) | Must be `critical`, `high`, `medium`, or `low` | Minimum severity tier. |
| `batch_size` | int | (from action input) | Range: 1–50 | Max issues per Devin session. |
| `max_sessions` | int | (from action input) | Range: 1–100 | Max Devin sessions to create. |
| `exclude_paths` | list[string] | (from action input) | Must be a list | Glob patterns to exclude from CodeQL analysis. Combined with action-level `exclude_paths`. |
| `cwe_families` | dict[string, list[string]] | (built-in families) | Must be a mapping | Custom CWE-to-family mappings that extend (not replace) the built-in definitions. |

### Example

```yaml
severity_threshold: medium
batch_size: 3
max_sessions: 10
exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "test/fixtures/**"
cwe_families:
  my-custom-family:
    - cwe-999
    - cwe-998
```

---

## 5. Orchestrator Registry

File: `repo_registry.json` at the repository root. Manages multi-repo scanning and dispatch.

### Top-Level Structure

```json
{
  "version": "2.0",
  "defaults": { ... },
  "concurrency": { ... },
  "orchestrator": { ... },
  "repos": [ ... ]
}
```

### `defaults`

Global defaults applied to all repos unless overridden.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `languages` | string | `""` | CodeQL languages (auto-detect if empty). |
| `queries` | string | `security-extended` | CodeQL query suite. |
| `batch_size` | int | `5` | Max issues per batch. |
| `max_sessions` | int | `5` | Max sessions per dispatch. |
| `severity_threshold` | string | `low` | Minimum severity tier. |
| `default_branch` | string | `main` | Default branch for target repos. |
| `persist_logs` | bool | `true` | Persist run logs to fork. |
| `dry_run` | bool | `false` | Dry-run mode. |
| `include_paths` | string | `""` | Glob patterns to include. |
| `exclude_paths` | string | `""` | Glob patterns to exclude. |

### `concurrency`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_parallel` | int | `3` | Maximum parallel scans/dispatches. |
| `delay_seconds` | int | `30` | Delay between dispatches (seconds). |

### `orchestrator`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `global_session_limit` | int | `20` | Maximum sessions across all repos within the rate-limit window. |
| `global_session_limit_period_hours` | int | `24` | Rate-limit window in hours. |
| `objectives` | list[object] | `[]` | Security objectives (see below). |
| `alert_on_verified_fix` | bool | `true` | Send alert when a fix is verified. |
| `alert_severities` | list[string] | `["critical", "high"]` | Severity tiers that trigger alerts. |

#### Objective Schema

```json
{
  "name": "Zero critical issues",
  "description": "Eliminate all critical-severity findings",
  "target_severity": "critical",
  "target_count": 0,
  "target_reduction_pct": 0,
  "priority": 1
}
```

### `repos[]`

Per-repo entries in the `repos` array.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `repo` | string | — | Repository URL (e.g., `https://github.com/org/repo`). |
| `enabled` | bool | `true` | Whether this repo is active for scanning. |
| `importance` | string | `medium` | Importance level: `critical`, `high`, `medium`, `low`. |
| `importance_score` | int | `50` | Numeric importance (0–100). Used in priority scoring. |
| `schedule` | string | `weekly` | Scan schedule: `hourly`, `daily`, `weekly`, `biweekly`, `monthly`. |
| `max_sessions_per_cycle` | int | `5` | Max sessions to create per orchestrator cycle for this repo. |
| `auto_scan` | bool | `true` | Automatically trigger scans when due. |
| `auto_dispatch` | bool | `true` | Automatically dispatch sessions after scanning. |
| `adaptive_commit_threshold` | int | `50` | Commit count since last scan that triggers an early scan. |
| `tags` | list[string] | `[]` | Arbitrary tags for filtering/organization. |
| `overrides` | object | `{}` | Per-repo overrides for any `defaults` key (e.g., `languages`, `severity_threshold`). |

---

## 6. Telemetry Dashboard

Environment variables for the Flask dashboard (`telemetry/app.py`). Set in `telemetry/.env` (copy from `.env.example`).

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GITHUB_TOKEN` | Yes | — | GitHub PAT with `repo` scope for API calls (PR fetching, telemetry file discovery). |
| `DEVIN_API_KEY` | Yes | — | Devin API key for polling session statuses. |
| `ACTION_REPO` | Yes | — | Repo containing telemetry data (e.g., `your-username/codeql-devin-fixer`). |
| `TELEMETRY_API_KEY` | Recommended | — | API key to gate mutating endpoints. If set, POST requests require `X-API-Key` or `Authorization: Bearer <key>`. |
| `CACHE_TTL` | No | `120` | Seconds to cache GitHub/Devin API responses. Lower values = fresher data, more API calls. |
| `FLASK_SECRET_KEY` | Recommended | (random) | Stable secret key for Flask session signing. Random if unset (sessions invalidated on restart). |
| `GITHUB_OAUTH_CLIENT_ID` | No | — | GitHub OAuth App client ID for user authentication. |
| `GITHUB_OAUTH_CLIENT_SECRET` | No | — | GitHub OAuth App client secret. |
| `REDACT_TELEMETRY_URLS` | No | `false` | If `true`, omit run and fork URLs from telemetry records (for shared/public dashboards). |

---

## 7. GitHub App

Environment variables for the GitHub App webhook server (`github_app/`). Set in `github_app/.env` (copy from `.env.example`).

Loaded by `AppConfig.from_env()` in `github_app/config.py`.

### Required

| Variable | `AppConfig` Field | Type | Description |
|----------|-------------------|------|-------------|
| `GITHUB_APP_ID` | `app_id` | int | GitHub App ID (from app settings page). |
| `GITHUB_APP_PRIVATE_KEY_PATH` | `private_key_path` | str | Path to the private key PEM file downloaded from app settings. |
| `GITHUB_APP_WEBHOOK_SECRET` | `webhook_secret` | str | Webhook secret configured in the app settings (HMAC-SHA256 verification). |

### Optional — Authentication

| Variable | `AppConfig` Field | Type | Default | Description |
|----------|-------------------|------|---------|-------------|
| `DEVIN_API_KEY` | `devin_api_key` | str | `""` | Devin API key for creating fix sessions from webhook events. |

### Optional — Server

| Variable | `AppConfig` Field | Type | Default | Description |
|----------|-------------------|------|---------|-------------|
| `SERVER_HOST` | `server_host` | str | `0.0.0.0` | Host to bind the Flask server. |
| `SERVER_PORT` | `server_port` | int | `3000` | Port to bind the Flask server. |
| `FLASK_DEBUG` | `debug` | bool | `false` | Enable Flask debug mode. |
| `LOG_LEVEL` | `log_level` | str | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |

### Optional — Default Scan Settings

These defaults apply when the GitHub App triggers scans. Can be overridden per-repo via `.codeql-fixer.yml`.

| Variable | `AppConfig` Field | Type | Default | Description |
|----------|-------------------|------|---------|-------------|
| `DEFAULT_BATCH_SIZE` | `default_batch_size` | int | `5` | Max issues per batch. |
| `DEFAULT_MAX_SESSIONS` | `default_max_sessions` | int | `25` | Max sessions per scan. |
| `DEFAULT_SEVERITY_THRESHOLD` | `default_severity_threshold` | str | `low` | Minimum severity tier. |
| `DEFAULT_QUERIES` | `default_queries` | str | `security-extended` | CodeQL query suite. |
| `DEFAULT_BRANCH` | `default_branch` | str | `main` | Default branch of target repos. |

---

## 8. Webhook Configuration

Webhooks send HTTP POST notifications at pipeline lifecycle events. Configured via action inputs or environment variables.

| Source | Variable | Description |
|--------|----------|-------------|
| Action input | `webhook_url` | Destination URL for webhook payloads. |
| Action input | `webhook_secret` | HMAC-SHA256 signing secret. |
| Env var | `WEBHOOK_URL` | Same as above, used when running scripts directly. |
| Env var | `WEBHOOK_SECRET` | Same as above, used when running scripts directly. |

### Supported Events

| Event | Trigger |
|-------|---------|
| `scan_started` | After target repo clone, before CodeQL analysis. |
| `scan_completed` | After SARIF parsing, includes issue and batch counts. |
| `session_created` | Each time a Devin session is successfully created. |
| `fix_verified` | When a fix PR passes re-verification. |
| `objective_met` | When a security objective is achieved. |
| `sla_breach` | When an issue exceeds its SLA window. |
| `cycle_completed` | After a full orchestrator cycle finishes. |

### Payload Format

All payloads are JSON with a common envelope:

```json
{
  "event": "<event_name>",
  "timestamp": "2026-01-15T10:30:00+00:00",
  "target_repo": "https://github.com/org/repo",
  "run_id": "12345678"
}
```

When `webhook_secret` is set, payloads are signed with HMAC-SHA256 and the signature is sent in the `X-Hub-Signature-256` header (same format as GitHub webhooks).

---

## 9. Logging

All pipeline scripts and the orchestrator use structured JSON-lines logging via `scripts/logging_config.py`.

| Variable | Scope | Default | Description |
|----------|-------|---------|-------------|
| `LOG_LEVEL` | All scripts, GitHub App | `INFO` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`. |

Log records are emitted to stderr as single-line JSON objects:

```json
{"timestamp": "2026-01-15T10:30:00+00:00", "level": "INFO", "logger": "dispatch_devin", "message": "Session created", "session_id": "abc123"}
```

Extra fields (`repo`, `run_id`, `batch_id`, `session_id`, `file`) are included when passed via `extra={}` in log calls.

---

## 10. Deployment

### Docker Compose (`telemetry/docker-compose.yml`)

| Setting | Value | Description |
|---------|-------|-------------|
| Port mapping | `5000:5000` | Dashboard accessible on host port 5000. |
| Volume | `telemetry-data:/app/runs` | Persistent storage for SQLite database and run data. |

Environment variables are passed through from the host `.env` file:

- `GITHUB_TOKEN`, `DEVIN_API_KEY`, `ACTION_REPO`, `TELEMETRY_API_KEY`, `CACHE_TTL`

### Helm Chart (`charts/telemetry/values.yaml`)

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | `1` | Number of pod replicas. |
| `image.repository` | `codeql-devin-fixer-telemetry` | Container image name. |
| `image.pullPolicy` | `IfNotPresent` | Kubernetes image pull policy. |
| `image.tag` | `latest` | Image tag. |
| `service.type` | `ClusterIP` | Kubernetes service type. |
| `service.port` | `5000` | Service port. |
| `ingress.enabled` | `false` | Enable Kubernetes Ingress. |
| `ingress.hosts[].host` | `telemetry.local` | Ingress hostname. |
| `env.GITHUB_TOKEN` | `""` | GitHub PAT (set via `--set` or values override). |
| `env.DEVIN_API_KEY` | `""` | Devin API key. |
| `env.ACTION_REPO` | `""` | Telemetry data repo. |
| `env.TELEMETRY_API_KEY` | `""` | API key for mutating endpoints. |
| `env.CACHE_TTL` | `120` | API response cache TTL (seconds). |
| `existingSecret` | `""` | Name of an existing Kubernetes Secret to mount as env vars. |
| `persistence.enabled` | `true` | Enable persistent volume for SQLite data. |
| `persistence.size` | `1Gi` | Volume size. |
| `persistence.storageClass` | `""` | Storage class (cluster default if empty). |
| `resources.requests.cpu` | `100m` | CPU request. |
| `resources.requests.memory` | `128Mi` | Memory request. |
| `resources.limits.cpu` | `500m` | CPU limit. |
| `resources.limits.memory` | `256Mi` | Memory limit. |

---

## 11. Internal Constants

Hardcoded values in the codebase that affect behavior but are not externally configurable.

### Orchestrator (`scripts/orchestrator/state.py`)

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_DISPATCH_ATTEMPTS_DEFAULT` | `3` | Max dispatch attempts before an issue is marked as needing human review. |
| `COOLDOWN_HOURS` | `[24, 72, 168]` | Escalating cooldown periods (hours) after consecutive dispatch failures: 1 day, 3 days, 7 days. |
| `SEVERITY_WEIGHTS` | `critical=1.0, high=0.75, medium=0.5, low=0.25` | Weights used in priority scoring. |

### Scanner (`scripts/orchestrator/scanner.py`)

| Constant | Value | Description |
|----------|-------|-------------|
| `SCHEDULE_INTERVALS` | `hourly=1h, daily=1d, weekly=7d, biweekly=14d, monthly=30d` | Mapping of schedule names to time intervals. |
| `ADAPTIVE_COMMIT_THRESHOLD` | `50` | Default commit count that triggers an early scan (overridable per-repo in registry). |

### Telemetry (`telemetry/config.py`)

| Constant | Value | Description |
|----------|-------|-------------|
| `DEVIN_API_BASE` | `https://api.devin.ai/v1` | Devin API base URL. |

---

## Configuration Precedence

When the same option can be set in multiple places, the following precedence applies (highest to lowest):

### Pipeline (action.yml → scripts)

```
1. .codeql-fixer.yml (per-repo config in target repo)    ← highest
2. action.yml inputs (workflow dispatch / reusable action)
3. PipelineConfig defaults (hardcoded in dataclass)       ← lowest
```

Specifically, `load_repo_config.py` reads `.codeql-fixer.yml` and falls back to the action input values (`INPUT_BATCH_SIZE`, `INPUT_MAX_SESSIONS`, etc.) for any keys not present in the YAML file.

### Orchestrator (registry → scripts)

```
1. repos[].overrides (per-repo overrides in registry)     ← highest
2. repos[] top-level fields (per-repo settings)
3. defaults (global defaults in registry)
4. Hardcoded defaults in state.py / scanner.py            ← lowest
```

The `get_repo_config()` function in `state.py` merges these layers.

### GitHub App

```
1. .codeql-fixer.yml in the target repo                   ← highest
2. AppConfig environment variables (DEFAULT_*)
3. AppConfig dataclass defaults                            ← lowest
```

---

## Secrets Reference

All secrets should be stored in GitHub Actions secrets, `.env` files (never committed), or Kubernetes Secrets.

| Secret | Used By | Purpose | Notes |
|--------|---------|---------|-------|
| `DEVIN_API_KEY` | Action, Dashboard, GitHub App | Devin API authentication for session creation and polling. | Required for non-dry-run operation. |
| `GH_PAT` / `GITHUB_TOKEN` | Action, Dashboard, Orchestrator | GitHub API access for fork creation, PR fetching, log persistence, and workflow dispatch. | Requires `repo` scope. |
| `TELEMETRY_API_KEY` | Dashboard | Gates mutating API endpoints (`POST /api/*`). | Custom random string. |
| `FLASK_SECRET_KEY` | Dashboard | Flask session cookie signing. | Random string; sessions invalidated if changed. |
| `GITHUB_APP_ID` | GitHub App | App identity for JWT generation. | Integer from app settings page. |
| `GITHUB_APP_PRIVATE_KEY_PATH` | GitHub App | Path to PEM file for JWT signing. | Downloaded from app settings. |
| `GITHUB_APP_WEBHOOK_SECRET` | GitHub App | HMAC-SHA256 webhook signature verification. | Must match the value in GitHub App settings. |
| `GITHUB_OAUTH_CLIENT_ID` | Dashboard (OAuth) | GitHub OAuth App client ID. | From OAuth App settings. |
| `GITHUB_OAUTH_CLIENT_SECRET` | Dashboard (OAuth) | GitHub OAuth App client secret. | From OAuth App settings. |
| `WEBHOOK_URL` | Action (pipeline) | Destination URL for lifecycle webhooks. | HTTPS recommended. |
| `WEBHOOK_SECRET` | Action (pipeline) | HMAC-SHA256 signing secret for webhook payloads. | Shared with the receiving server. |

---

## Cross-Surface Option Map

Options that appear across multiple configuration surfaces. The "Env Var" column shows the environment variable name consumed by `PipelineConfig`.

| Option | action.yml | `.codeql-fixer.yml` | `repo_registry.json` | `AppConfig` | Env Var |
|--------|-----------|---------------------|---------------------|-------------|---------|
| Batch size | `batch_size` | `batch_size` | `defaults.batch_size` | `DEFAULT_BATCH_SIZE` | `BATCH_SIZE` |
| Max sessions | `max_sessions` | `max_sessions` | `defaults.max_sessions` | `DEFAULT_MAX_SESSIONS` | `MAX_SESSIONS` |
| Severity threshold | `severity_threshold` | `severity_threshold` | `defaults.severity_threshold` | `DEFAULT_SEVERITY_THRESHOLD` | `SEVERITY_THRESHOLD` |
| Query suite | `queries` | — | `defaults.queries` | `DEFAULT_QUERIES` | — |
| Exclude paths | `exclude_paths` | `exclude_paths` | `defaults.exclude_paths` | — | — |
| Include paths | `include_paths` | — | `defaults.include_paths` | — | — |
| Languages | `languages` | — | `defaults.languages` | — | — |
| Default branch | `default_branch` | — | `defaults.default_branch` | `DEFAULT_BRANCH` | `DEFAULT_BRANCH` |
| Dry run | `dry_run` | — | `defaults.dry_run` | — | `DRY_RUN` |
| Persist logs | `persist_logs` | — | `defaults.persist_logs` | — | — |
| Devin API key | `devin_api_key` | — | — | `DEVIN_API_KEY` | `DEVIN_API_KEY` |
| GitHub token | `github_token` | — | — | — | `GITHUB_TOKEN` |
