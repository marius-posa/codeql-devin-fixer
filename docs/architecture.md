# Architecture

This document describes the high-level architecture and data flow of the CodeQL Devin Fixer system.

## System Overview

```
+-------------------+
| User / Schedule   |
| (workflow_dispatch)|
+--------+----------+
         |
         v
+--------+----------+     +---------------------------+
| GitHub Actions    |     | Target Repository         |
| Workflow Runner   |     | (e.g., juice-shop)        |
+--------+----------+     +-------------+-------------+
         |                              |
         v                              |
+--------+----------+                   |
| 1. Fork Target    |  fork/sync        |
|    fork_repo.py   +<------------------+
+--------+----------+
         |
         v
+--------+----------+
| 2. Clone Fork     |
|    git clone      |
+--------+----------+
         |
         v
+--------+--------------+
| 3. Load Per-Repo      |
|    Config (.codeql-    |
|    fixer.yml)          |
|    load_repo_config.py |
+--------+--------------+
         |
         v
+--------+----------+
| 4. CodeQL Analysis|
|    - init         |
|    - autobuild    |
|    - analyze      |
+--------+----------+
         |
         | SARIF output
         v
+--------+----------+
| 5. Parse SARIF    |
|    parse_sarif.py |
|    - extract      |
|    - deduplicate  |
|    - prioritize   |
|    - assign IDs   |
|    - batch by CWE |
+--------+----------+
         |
         | batches.json, issues.json
         v
+--------+----------+     +---------------------------+
| 6. Dispatch Devin |     | Devin AI Platform         |
|    dispatch_      +---->| - Clone fork              |
|    devin.py       |     | - Fix issues              |
+--------+----------+     | - Create PRs              |
         |                +-------------+-------------+
         |                              |
         v                              | PRs on fork
+--------+----------+                   |
| 7. Persist Logs   |                   |
|    persist_logs.py|                   |
+--------+----------+                   |
         |                              |
         v                              |
+--------+----------+                   |
| 8. Push Telemetry |                   |
|    persist_       |                   |
|    telemetry.py   |                   |
+--------+----------+                   |
         |                              |
         | JSON record                  |
         v                              |
+--------+----------+                   |
| telemetry/runs/   |                   |
| *.json            |                   |
+--------+----------+                   |
         |                              |
         v                              |
+--------+----------+     +-------------+-------------+
| Telemetry Server  |     | GitHub API                |
| (Flask app.py)    +---->| - Fetch PRs               |
|                   |     | - Match to sessions       |
| - /api/runs       |     +---------------------------+
| - /api/sessions   |
| - /api/prs        |     +---------------------------+
| - /api/stats      +---->| Devin API                 |
| - /api/issues     |     | - Poll session status     |
| - /api/dispatch   |     +---------------------------+
+--------+----------+
         |
         v
+--------+----------+
| Dashboard UI      |
| (browser)         |
| - Metrics cards   |
| - Trend charts    |
| - Run history     |
| - Session table   |
| - PR tracking     |
| - Issue lifecycle  |
+-------------------+
```

## Data Flow

### 1. Pipeline Execution (GitHub Actions)

```
workflow_dispatch(target_repo, options)
    |
    +-- fork_repo.py: Create/sync fork of target repo
    |
    +-- load_repo_config.py: Read .codeql-fixer.yml from target (if present)
    |
    +-- CodeQL CLI: Create database, analyze, output SARIF
    |
    +-- parse_sarif.py: Parse SARIF -> deduplicate -> prioritize -> batch
    |       |
    |       +-- Output: issues.json (all issues with IDs and fingerprints)
    |       +-- Output: batches.json (grouped by CWE family)
    |
    +-- dispatch_devin.py: For each batch -> build prompt -> create Devin session
    |       |
    |       +-- Optional: Load custom Jinja2 prompt template
    |       +-- Optional: Send webhook (session_created) per session
    |       +-- Output: sessions.json (session IDs and URLs)
    |
    +-- persist_logs.py: Commit results to fork's logs/ directory
    |
    +-- persist_telemetry.py: Push JSON record to telemetry/runs/
```

### 2. Telemetry Aggregation (Flask Server)

```
telemetry/runs/*.json  (on disk)
    |
    +-- _Cache.get_runs(): Load and cache run records
    |
    +-- aggregation.py: Compute sessions, stats, per-repo breakdowns
    |
    +-- issue_tracking.py: Track issue fingerprints across runs
    |       |
    |       +-- Classify: new / recurring / fixed
    |
    +-- github_service.py: Fetch PRs from GitHub API, link to sessions
    |
    +-- devin_service.py: Poll Devin API for session status updates
    |
    +-- REST API endpoints serve aggregated data to the dashboard UI
```

### 3. Webhook Notifications (Optional)

```
Pipeline Events                     Your Integration
    |                                    |
    +-- scan_started    -- POST -->  Slack / PagerDuty / custom
    +-- scan_completed  -- POST -->  webhook endpoint
    +-- session_created -- POST -->
```

Payloads are JSON-encoded and optionally signed with HMAC-SHA256.

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Fork before scanning | User may not own the target repo; Devin needs a repo it can push PRs to |
| Batch by CWE family | Related vulnerabilities share remediation patterns, improving fix quality |
| CVSS-based severity tiers | Aligns with NVD/GitHub Advisory severity scale |
| Stable issue fingerprints | Enables cross-run tracking (new/recurring/fixed) |
| Per-repo config file | Allows customization without modifying the workflow, reducing friction for multi-repo deployments |
| Webhook integration | Enables organizations to plug into existing monitoring without code changes |
| JSON file telemetry | Simple, git-native storage; works for <100 repos without infrastructure |

## Deployment Options

| Method | Best for | Command |
|---|---|---|
| GitHub Actions (direct) | Individual repos | `uses: marius-posa/codeql-devin-fixer@main` |
| Fork + customize | Teams needing custom workflows | Fork repo, edit workflow, add secrets |
| Docker | Self-hosted telemetry dashboard | `cd telemetry && docker compose up` |
| Helm chart | Kubernetes environments | `helm install telemetry ./charts/telemetry` |
| Setup script | Quick onboarding | `curl -sSL .../setup.sh \| bash` |
