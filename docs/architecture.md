# Architecture

High-level architecture and data flow for the CodeQL Devin Fixer platform.

## System Overview

The platform has six major subsystems:

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
              cli, dispatcher,          webhook_handler,
              scanner, state,           scan_trigger,
              alerts, agent             alerts, auth
```

## Pipeline Flow

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
+--------+--------------+
| 2. Load Per-Repo      |
|    Config (.codeql-    |
|    fixer.yml)          |
|    load_repo_config.py |
+--------+--------------+
         |
         v
+--------+----------+
| 3. CodeQL Analysis|
|    - init         |
|    - autobuild    |
|    - analyze      |
+--------+----------+
         |
         | SARIF output
         v
+--------+----------+
| 4. Parse SARIF    |
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
| 5. Dispatch Devin |     | Devin AI Platform         |
|    dispatch_      +---->| - Clone fork              |
|    devin.py       |     | - Fix issues              |
+--------+----------+     | - Create PRs              |
         |                +-------------+-------------+
         |                              |
         v                              | PRs on fork
+--------+----------+                   |
| 6. Persist Logs   |                   |
|    persist_logs.py|                   |
+--------+----------+                   |
         |                              |
         v                              v
+--------+----------+     +-------------+-------------+
| 7. Push Telemetry |     | 8. Verify Fixes           |
|    persist_       |     |    verify_results.py      |
|    telemetry.py   |     |    - re-run CodeQL on PR  |
+--------+----------+     |    - compare fingerprints |
         |                +-------------+-------------+
         |                              |
         | JSON record                  | retry / knowledge
         v                              v
+--------+----------+     +-------------+-------------+
| SQLite DB         |     | Devin API                 |
| telemetry.db      |     | - Send Message (feedback) |
+--------+----------+     | - Knowledge API (store)   |
         |                +---------------------------+
         v
+--------+----------+     +---------------------------+
| Telemetry Server  |     | GitHub API                |
| (Flask app.py)    +---->| - Fetch PRs               |
| 5 Blueprints:     |     | - Match to sessions       |
|   api, orchestrator,    +---------------------------+
|   registry, demo, |
|   oauth           |
|                   |     +---------------------------+
| 30+ endpoints     +---->| Devin API                 |
| Rate limiting     |     | - Poll session status     |
| Audit logging     |     +---------------------------+
| OAuth + API keys  |
+--------+----------+
         |
         v
+--------+----------+
| Dashboard UI      |
| 6 tabs:           |
| - Overview        |
| - Repositories    |
| - Issues          |
| - Activity        |
| - Orchestrator    |
| - Settings        |
+-------------------+
```

## Data Flow Details

### Pipeline Execution (GitHub Actions)

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
    +-- dispatch_devin.py: For each batch -> enrich prompt -> create Devin session
    |       |
    |       +-- Enrich with: CWE playbooks, fix learning, repo context, knowledge, code snippets
    |       +-- Wave dispatch: group by severity tier, gate on fix rate between waves
    |       +-- Optional: Send webhook (session_created) per session
    |       +-- Output: sessions.json (session IDs and URLs)
    |
    +-- persist_logs.py: Commit results to fork's logs/ directory
    |
    +-- persist_telemetry.py: Push JSON record to SQLite database
```

### Verification Loop

```
PR created by Devin on fork
    |
    +-- verify-fix.yml: Triggered on PR open/synchronize
    |
    +-- verify_results.py: Re-run CodeQL on PR branch
    |       |
    |       +-- Compare original fingerprints to post-fix scan
    |       +-- Classify: verified_fixed / still_present / not_targeted
    |       +-- Label PR: verified-fix / codeql-partial-fix / codeql-needs-work
    |
    +-- retry_feedback.py: If codeql-needs-work, send feedback to Devin session
    |       |
    |       +-- Active session: POST /v1/sessions/{id}/message
    |       +-- Ended session: Create follow-up session with prior context
    |
    +-- knowledge.py: If verified fix, store fix pattern in Knowledge API
```

### Telemetry Aggregation (Flask Server)

```
SQLite database (telemetry.db)
    |
    +-- database.py: Schema, queries, migrations, audit logging
    |
    +-- aggregation.py: Compute sessions, stats, per-repo breakdowns
    |
    +-- issue_tracking.py: Track issue fingerprints across runs
    |       |
    |       +-- Classify: new / recurring / fixed
    |       +-- Compute SLA status: on_track / at_risk / breached / met
    |
    +-- github_service.py: Fetch PRs from GitHub API, link to sessions
    |
    +-- devin_service.py: Poll Devin API for session status updates
    |
    +-- routes/: 5 Blueprints serve aggregated data to dashboard UI
```

### Webhook Notifications (Optional)

```
Pipeline Events                     Your Integration
    |                                    |
    +-- scan_started    -- POST -->  Slack / PagerDuty / custom
    +-- scan_completed  -- POST -->  webhook endpoint
    +-- session_created -- POST -->
    +-- fix_verified    -- POST -->
    +-- sla_breach      -- POST -->
```

Payloads are JSON-encoded and optionally signed with HMAC-SHA256 (`X-Hub-Signature-256` header).

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Fork before scanning | User may not own the target repo; Devin needs a repo it can push PRs to |
| Batch by CWE family | Related vulnerabilities share remediation patterns, improving fix quality |
| CVSS-based severity tiers | Aligns with NVD/GitHub Advisory severity scale |
| Stable issue fingerprints | Enables cross-run tracking (new/recurring/fixed) without relying on line numbers |
| Wave-based dispatch | Dispatches high-severity batches first; halts if fix rate drops below threshold to save ACUs |
| Per-repo config file | Allows customization without modifying the workflow, reducing friction for multi-repo deployments |
| SQLite telemetry database | Lightweight, zero-dependency storage with FTS5 full-text search; migrated from JSON for query performance |
| Blueprint-based Flask app | Modular route organization (api, orchestrator, registry, demo, oauth) for maintainability |
| Knowledge API integration | Organizational memory -- successful fix patterns are stored and reused in future prompts |
| Webhook integration | Enables organizations to plug into existing monitoring without code changes |

## Deployment Options

| Method | Best for | Command |
|---|---|---|
| GitHub Actions (direct) | Individual repos | `uses: marius-posa/codeql-devin-fixer@main` |
| Fork + customize | Teams needing custom workflows | Fork repo, edit workflow, add secrets |
| Docker | Self-hosted telemetry dashboard | `cd telemetry && docker compose up` |
| Helm chart | Kubernetes environments | `helm install telemetry ./charts/telemetry` |
| Setup script | Quick onboarding | `bash setup.sh` |
