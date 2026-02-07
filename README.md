# CodeQL Devin Fixer

A GitHub Action that runs CodeQL security analysis on any repository, prioritizes vulnerabilities by severity, groups them into batches, and creates [Devin](https://devin.ai) sessions to fix each batch with a pull request.

## How It Works

1. **Fork** the target repository into your GitHub account (or reuse an existing fork)
2. **Clone** the fork
3. **Analyze** with CodeQL (auto-detects languages)
4. **Parse** SARIF results and assign each issue a unique tracking ID (`CQLF-R{run}-{seq}`)
5. **Prioritize** by CVSS severity score (adversary perspective)
6. **Batch** by vulnerability family (e.g., all XSS together, all SQLi together)
7. **Dispatch** a Devin session per batch -- each session creates a fix PR on the fork
8. **Persist logs** to `logs/run-{label}/` in the fork for historical tracking
9. **Generate a dashboard** with metrics on runs, issues, sessions, and PRs

## Prioritization

Issues are ranked from an adversary's perspective -- which vulnerabilities are easiest to exploit with the highest impact:

| Tier | CVSS Score | Examples |
|------|-----------|----------|
| Critical | 9.0 - 10.0 | SQL injection, command injection, code injection, path traversal |
| High | 7.0 - 8.9 | XSS, SSRF, deserialization, authentication bypass |
| Medium | 4.0 - 6.9 | Information disclosure, open redirect, weak crypto, CSRF |
| Low | 0.1 - 3.9 | Minor info leaks, code quality issues |

## Quick Start

### 1. Prerequisites

You need two secrets configured in your repository:

| Secret | Purpose | How to create |
|--------|---------|---------------|
| `DEVIN_API_KEY` | Devin API authentication | [Devin API docs](https://docs.devin.ai/api-reference/overview) |
| `GH_PAT` | Fork creation, log persistence, dashboard push | [Create a PAT](https://github.com/settings/tokens) with **`repo`** scope |

> **Why a PAT?** The default `secrets.GITHUB_TOKEN` is an installation token scoped only to the repo running the workflow. It cannot create forks or push to other repositories. A Personal Access Token with `repo` scope is required for these cross-repo operations.

### 2. As a Reusable Action

Reference this action in your workflow:

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
          generate_dashboard: "true"
```

### 3. Run from This Repo

1. Fork or clone this repo
2. Add `DEVIN_API_KEY` and `GH_PAT` as repository secrets
3. Go to **Actions** > **CodeQL Devin Fixer** > **Run workflow**
4. Enter the target repository URL and configure options
5. The action will fork the target, analyze, and create Devin fix sessions

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `target_repo` | Yes | - | GitHub repo URL to analyze |
| `github_token` | No | - | PAT with `repo` scope for fork/push operations |
| `languages` | No | auto-detect | Comma-separated CodeQL languages (javascript, python, java, go, ruby, csharp, cpp, swift) |
| `batch_size` | No | `5` | Max issues per Devin session |
| `max_sessions` | No | `25` | Max Devin sessions to create |
| `severity_threshold` | No | `low` | Minimum severity: `critical`, `high`, `medium`, `low` |
| `queries` | No | `security-extended` | CodeQL query suite (`security-extended`, `security-and-quality`) |
| `include_paths` | No | `` | Newline/comma-separated globs to include (narrows analysis) |
| `exclude_paths` | No | `` | Newline/comma-separated globs to exclude |
| `devin_api_key` | Yes | - | Devin API key (use a repository secret) |
| `max_acu_per_session` | No | - | ACU limit per Devin session |
| `dry_run` | No | `false` | Generate prompts without creating sessions |
| `default_branch` | No | `main` | Default branch of the target repo |
| `persist_logs` | No | `true` | Commit run logs to the fork's `logs/` directory |

## Outputs

| Output | Description |
|--------|-------------|
| `total_issues` | Number of security issues found |
| `total_batches` | Number of batches created |
| `sessions_created` | Number of Devin sessions dispatched |
| `session_urls` | Comma-separated Devin session URLs |
| `fork_url` | URL of the fork used for scanning |
| `run_label` | Label for this run's logs (e.g. `run-11-2025-06-01-120000`) |

## Batching Strategy

Issues are grouped by CWE vulnerability family:

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

Highest-severity batches are dispatched first.

## Example: Analyzing juice-shop

```yaml
- uses: marius-posa/codeql-devin-fixer@main
  with:
    target_repo: "https://github.com/juice-shop/juice-shop"
    languages: "javascript"
    batch_size: 5
    max_sessions: 10
    severity_threshold: "medium"
    devin_api_key: ${{ secrets.DEVIN_API_KEY }}
```

## Fork Management

The action automatically forks the target repository into your GitHub account before scanning. This ensures:

- **You don't need write access** to the upstream repo.
- **Devin can create PRs** on a repo you control.
- **Upstream stays clean** -- no branches or PRs are created on the original.

On subsequent runs against the same target, the action detects the existing fork (via the GitHub API) and reuses it. The fork's default branch is synced with upstream before analysis to ensure results are current.

## Issue Tracking

Every issue found by CodeQL is assigned a unique ID in the format:

```
CQLF-R{run_number}-{sequence}
```

For example, `CQLF-R11-0042` is the 42nd issue found in run #11. These IDs appear in:

- `issues.json` and `batches.json` output files
- Devin session prompts
- PR titles created by Devin (e.g. `fix(CQLF-R11-0001,CQLF-R11-0002): resolve injection security issues`)

This makes it straightforward to trace a PR back to the exact issues it addresses.

### Cross-Run Issue Fingerprinting

Each issue also receives a stable **fingerprint** based on `rule_id + file + start_line`. This fingerprint persists across runs, allowing the telemetry dashboard to classify each unique issue as:

| Status | Meaning |
|--------|---------|
| **Recurring** | Same issue found in multiple runs including the latest |
| **New** | Issue only appeared in the latest run |
| **Fixed** | Issue was found in previous runs but not in the latest |

The fingerprint is stored in telemetry records and displayed in the dashboard's Issue Tracking panel.

## Log Persistence

When `persist_logs` is enabled (default), the action commits run results to `logs/run-{label}/` in the fork repository. Each run directory contains:

| File | Contents |
|------|----------|
| `run_log.json` | Run metadata (timestamp, issue counts, thresholds) |
| `issues.json` | All issues with severity, CWE, and location data |
| `batches.json` | Batches sent to Devin |
| `sessions.json` | Devin session IDs and URLs |
| `summary.md` | Human-readable summary |
| `prompt_batch_N.txt` | Exact prompt sent to each Devin session |
| `manifest.json` | File listing for this run |

These logs serve as a permanent audit trail and are the data source for the dashboard.

## Telemetry Dashboard

The telemetry dashboard is a centralized web app that aggregates data from **all** action runs across every target repository. Unlike per-repo dashboards, it gives you a single view of your entire security remediation pipeline.

### Setup

```bash
cd telemetry
cp .env.example .env
# Edit .env with your GITHUB_TOKEN, DEVIN_API_KEY, and ACTION_REPO
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:5000` in your browser.

### How it works

1. Each action run pushes a JSON telemetry record to `telemetry/runs/` in this repo (via the GitHub Contents API).
2. The Flask app reads all records, polls the Devin API for session statuses, and queries GitHub for PR outcomes.
3. The dashboard displays aggregated metrics across all repos and runs.

### Dashboard features

- **Metric cards** -- repos scanned, total runs, issues found, Devin sessions (created/finished), PRs (created/merged/open), fix rate
- **Severity breakdown** -- horizontal bar chart aggregated across all runs
- **Category breakdown** -- bar chart of issues by CWE family
- **Repositories** -- list of all repos scanned, with a dedicated detail page per repo
- **Run history** -- table with per-run details (target, issues, batches, sessions, timestamp)
- **Devin sessions** -- table with live status, issue IDs, and PR links (click "Poll Sessions" to refresh)
- **Pull requests** -- table with status badges, issue IDs, and links; PRs are linked to sessions by matching Devin session IDs in the PR body
- **Issue tracking** -- cross-run fingerprinting to identify recurring, new, and fixed issues
- **Repo detail page** -- click any repo to see repo-scoped metrics, runs, sessions, and PRs

### Environment variables

| Variable | Purpose |
|----------|---------|
| `GITHUB_TOKEN` | PAT with `repo` scope for GitHub API calls |
| `DEVIN_API_KEY` | Devin API key for polling session statuses |
| `ACTION_REPO` | This repo's full name (e.g. `marius-posa/codeql-devin-fixer`) |

## Notes

- ACU usage is not reported with the public v1 API; enterprise APIs expose ACU via different auth.
- "Issues addressed" is a proxy: sum of issues in batches where a session finished and produced a PR (does not re-run CodeQL on PRs).

## Dry Run Mode

Test without creating Devin sessions:

```yaml
- uses: marius-posa/codeql-devin-fixer@main
  with:
    target_repo: "https://github.com/juice-shop/juice-shop"
    devin_api_key: "not-needed-for-dry-run"
    dry_run: "true"
```

This generates all analysis artifacts (SARIF, batches, prompts) without calling the Devin API. Check the uploaded artifacts for the generated prompts.

## Artifacts

Every run uploads these artifacts:

- `issues.json` -- All parsed issues with severity and CWE data
- `batches.json` -- Grouped batches ready for dispatch
- `summary.md` -- Human-readable analysis summary
- `sessions.json` -- Created Devin session details
- `outcomes.json` -- Session outcomes (status, PR URLs) when waiting is enabled
- `prompt_batch_N.txt` -- The exact prompt sent to each Devin session
- SARIF results from CodeQL

## Requirements

- GitHub Actions runner (ubuntu-latest)
- [Devin API key](https://docs.devin.ai/api-reference/overview) with session creation permissions
- Personal Access Token (`GH_PAT`) with `repo` scope for fork operations
- Target repository must be accessible (public or with appropriate credentials)

## Architecture

```
workflow_dispatch (target_repo, options)
    |
    v
fork_repo.py: fork target (or reuse existing fork) + sync with upstream
    |
    v
Clone fork
    |
    v
CodeQL: database create + analyze -> SARIF
    |
    v
parse_sarif.py: parse -> deduplicate -> assign IDs -> prioritize -> batch
    |
    v
dispatch_devin.py: create Devin session per batch
    |
    v
persist_logs.py: commit run results to logs/run-{label}/ in fork
    |
    v
persist_telemetry.py: push run record to telemetry/runs/ in action repo
    |
    v
Each Devin session: clone fork -> fix issues -> create PR on fork

                     ~~~  Centralized Telemetry  ~~~

telemetry/runs/*.json  <--  aggregated from all action runs
    |
    v
telemetry/app.py  <--  Flask server (reads runs, polls Devin + GitHub APIs)
    |
    v
Dashboard UI at http://localhost:5000
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ERROR: Fork creation failed (403)` | `GITHUB_TOKEN` used instead of PAT | Add `GH_PAT` secret with `repo` scope and update workflow |
| `WARNING: git push failed` | PAT lacks `repo` scope or is expired | Regenerate PAT with `repo` scope |
| Fork not created | `github_token` input not set | Pass `github_token: ${{ secrets.GH_PAT }}` in workflow |
| Dashboard empty | No logs persisted yet | Enable `persist_logs: "true"` and ensure PAT has push access |
| `No SARIF file found` | CodeQL analysis found no supported languages | Check `languages` input or verify target repo has supported code |

## Fork and Use This Action (Step-by-step)

1. Fork this repository to your GitHub account.
2. In your fork, add repository secrets under Settings → Secrets and variables → Actions:
   - GH_PAT: Personal Access Token with repo scope (used for forking/pushing logs)
   - DEVIN_API_KEY: Your Devin API key
3. Go to Actions → CodeQL Devin Fixer → Run workflow.
4. Provide target_repo and any optional inputs, then Run.
5. The workflow will fork the target (if needed), analyze with CodeQL, dispatch Devin sessions, create PRs, and persist logs to logs/ in your fork.

## Telemetry Dashboard: UI-based secrets (no .env required)

You can run the dashboard and supply credentials via the in-app Settings (stored only in your browser session):



Then open http://localhost:5000 and click Settings to enter:
- GitHub Token (PAT with repo scope)
- Devin API Key
- Action Repository (e.g., marius-posa/codeql-devin-fixer)

These values are sent as headers for each request and override environment variables. You can still use a .env file as a fallback.
