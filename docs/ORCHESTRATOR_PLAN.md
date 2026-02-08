# Devin Session Orchestrator Plan

> **Ticket:** [MP-38](https://linear.app/mp-swe-projects/issue/MP-38/devin-session-orchestrator)
> **Status:** Planning (no code changes)

## 1. Problem Statement

The current system is **run-centric**: a CodeQL scan runs on a single repo, issues are discovered, batched, and Devin sessions are dispatched immediately within that same workflow run. This creates several problems:

- **Duplicate work** -- recurring issues that already have a Devin session or a PR get re-dispatched on every new scan, wasting ACU budget.
- **No cross-repo prioritization** -- a repo with 3 low-severity issues gets the same treatment as a repo with 40 critical issues; there is no global view.
- **Scans and fixes are coupled** -- you cannot run a CodeQL scan to update the issue database without also triggering Devin sessions, or vice versa.
- **No cost controls** -- there is no global rate limit on session creation; running scans on many repos in succession can create an unbounded number of sessions.
- **No lifecycle alerting** -- when a critical issue gets a verified fix, nobody is notified outside the PR itself.

The orchestrator solves all of these by introducing a **global decision layer** that sits between issue discovery and session dispatch.

---

## 2. Architecture Overview

```
                         ┌──────────────────────┐
                         │   Repo Registry       │
                         │  (repo_registry.json) │
                         └──────────┬───────────┘
                                    │
┌────────────────┐    ┌─────────────▼───────────────┐    ┌──────────────────┐
│  CodeQL Scan   │───>│     ORCHESTRATOR ENGINE      │───>│  Devin Sessions  │
│  (action.yml   │    │                               │    │  (dispatch_devin │
│   mode=orch)   │    │  - Global issue state         │    │   .py)           │
│                │    │  - Priority scoring            │    └──────────────────┘
└────────────────┘    │  - Dedup / skip logic          │
                      │  - Rate limiter                │    ┌──────────────────┐
┌────────────────┐    │  - Objective tracker           │───>│  GitHub App      │
│  Telemetry DB  │───>│                               │    │  Alerts           │
│  (SQLite +     │    └───────────────────────────────┘    └──────────────────┘
│   JSON runs)   │
└────────────────┘
```

The orchestrator is a **new Python module** (`scripts/orchestrator.py`) that can be invoked:
1. As a step within the existing `action.yml` composite action (when `mode=orchestrator`).
2. As a standalone script from the GitHub App server or a scheduled workflow.
3. As a CLI tool for local testing and manual dispatch.

---

## 3. Action Modes

The `action.yml` gains a new `mode` input with three values:

| Mode | Scan | Log Issues | Dispatch Sessions | Description |
|------|------|-----------|-------------------|-------------|
| `dry-run` | Yes | Yes (to stdout only) | No | Existing behavior. Generates prompts but creates nothing. |
| `basic` | Yes | Yes (to telemetry) | Yes (immediately) | Existing behavior. Run-centric: scan -> batch -> dispatch. |
| `orchestrator` | Yes | Yes (to telemetry) | **Deferred** | New. Scan results are recorded; dispatch is a separate decision. |

### 3.1 Mode Behavior

**`dry-run`** (unchanged)
- Runs CodeQL, parses SARIF, generates prompts.
- No sessions created, no telemetry persisted.
- Useful for testing prompt generation.

**`basic`** (unchanged, current default)
- Full pipeline: fork -> scan -> parse -> dispatch -> persist.
- Sessions are created immediately based on the current run's issues.
- Remains the default for backwards compatibility.

**`orchestrator`** (new)
- Runs CodeQL, parses SARIF, persists telemetry (issues + fingerprints).
- Does **not** dispatch sessions.
- Instead, updates the global issue state in the telemetry store.
- Session dispatch happens separately via `scripts/orchestrator.py dispatch`.

### 3.2 Implementation in `action.yml`

```yaml
inputs:
  mode:
    description: "Pipeline mode: dry-run, basic, or orchestrator"
    required: false
    default: "basic"
```

The `dispatch` step becomes conditional:

```yaml
- name: Dispatch Devin sessions
  if: inputs.mode == 'basic'
  # ... existing dispatch logic ...

- name: Record issues for orchestrator
  if: inputs.mode == 'orchestrator'
  shell: bash
  run: |
    python scripts/orchestrator.py ingest \
      --batches "$OUTPUT_DIR/batches.json" \
      --issues "$OUTPUT_DIR/issues.json" \
      --run-label "$RUN_LABEL" \
      --target-repo "$TARGET_REPO"
```

---

## 4. Fingerprint Logic Assessment

### 4.1 Current State

The existing `compute_fingerprint()` in `scripts/parse_sarif.py` (lines 620-653) uses a 3-tier stability hierarchy:

1. **SARIF `partialFingerprints`** (best) -- CodeQL's content-based hash (`primaryLocationLineHash`) survives line shifts. Fingerprint = `SHA256(rule_id | partial_fp)[:16]`.
2. **rule_id + file + message** (good) -- the diagnostic message often contains enough context (e.g., tainted variable name) to distinguish issues. Fingerprint = `SHA256(rule_id | file | message)[:16]`.
3. **rule_id + file + start_line** (fragile) -- falls back to line number when message is empty. Fingerprint = `SHA256(rule_id | file | start_line)[:16]`.

### 4.2 Assessment

The fingerprint logic is **good enough for the orchestrator** with two improvements:

**Strength:** Tier 1 (partialFingerprints) is excellent. CodeQL's `primaryLocationLineHash` is based on the content of the line, not its position. Most CodeQL queries emit this, so the majority of issues get stable fingerprints that survive refactoring.

**Weakness 1: Tier 3 is too fragile for orchestrator use.** When a developer adds a blank line above a vulnerability, the fingerprint changes and the orchestrator sees it as a "new" issue + a "fixed" issue. This can trigger unnecessary sessions.

**Recommendation:** Add a **Tier 2.5** fallback: `rule_id + file + normalized_snippet`. Extract the source line content (already available via `_extract_code_snippet` in `dispatch_devin.py`) and normalize it (strip whitespace, collapse runs). This is more stable than line numbers but less reliable than CodeQL's built-in hash.

```python
def compute_fingerprint(issue: dict[str, Any], target_dir: str = "") -> str:
    # Tier 1: SARIF partialFingerprints (unchanged)
    # Tier 2: rule_id + file + message (unchanged)
    # Tier 2.5 (NEW): rule_id + file + normalized source content
    if target_dir and locs:
        file_path = locs[0].get("file", "")
        start_line = locs[0].get("start_line", 0)
        if file_path and start_line > 0:
            snippet = _read_source_line(target_dir, file_path, start_line)
            if snippet:
                normalized = re.sub(r'\s+', ' ', snippet).strip()
                raw = f"{rule_id}|{file_path}|{normalized}"
                return hashlib.sha256(raw.encode()).hexdigest()[:16]
    # Tier 3: rule_id + file + start_line (unchanged fallback)
```

**Weakness 2: 16-char hex prefix has a collision risk at scale.** With 16 hex chars (64 bits), the birthday bound is ~2^32 (4 billion). At the expected scale of thousands of issues this is fine, but extending to 20 chars (80 bits) is cheap insurance.

**Recommendation:** Extend fingerprint length from 16 to 20 hex characters in the next schema version. The orchestrator should accept both lengths for backwards compatibility.

### 4.3 Cross-Run Tracking

The existing `track_issues_across_runs()` in `telemetry/issue_tracking.py` classifies issues as `new`, `recurring`, or `fixed` by comparing fingerprints across runs per repo. This logic is sound and directly usable by the orchestrator. The orchestrator will consume its output to determine which issues need sessions.

---

## 5. Repo Registry (Enhanced)

### 5.1 Current State

`repo_registry.json` exists with basic fields: `repo`, `enabled`, `schedule`, `overrides`. It lacks priority/importance fields.

### 5.2 Enhanced Schema

```json
{
  "version": "2.0",
  "defaults": {
    "languages": "",
    "queries": "security-extended",
    "batch_size": 5,
    "max_sessions_per_run": 5,
    "severity_threshold": "low",
    "default_branch": "main",
    "persist_logs": true,
    "dry_run": false,
    "include_paths": "",
    "exclude_paths": ""
  },
  "orchestrator": {
    "global_session_limit": 20,
    "global_session_limit_period_hours": 24,
    "objectives": [
      {
        "name": "eliminate-critical",
        "description": "Fix all critical-severity issues",
        "target_severity": "critical",
        "target_count": 0,
        "priority": 1
      },
      {
        "name": "reduce-high",
        "description": "Reduce high-severity issues by 50%",
        "target_severity": "high",
        "target_reduction_pct": 50,
        "priority": 2
      }
    ],
    "alert_on_verified_fix": true,
    "alert_severities": ["critical", "high"]
  },
  "repos": [
    {
      "repo": "https://github.com/juice-shop/juice-shop",
      "enabled": true,
      "importance": "high",
      "importance_score": 90,
      "schedule": "weekly",
      "severity_threshold": "medium",
      "max_sessions_per_cycle": 10,
      "auto_scan": true,
      "auto_dispatch": true,
      "tags": ["production", "web-app"],
      "overrides": {
        "languages": "javascript"
      }
    },
    {
      "repo": "https://github.com/example/internal-api",
      "enabled": true,
      "importance": "critical",
      "importance_score": 100,
      "schedule": "daily",
      "severity_threshold": "high",
      "max_sessions_per_cycle": 15,
      "auto_scan": true,
      "auto_dispatch": true,
      "tags": ["production", "api", "pci"],
      "overrides": {
        "languages": "java"
      }
    }
  ]
}
```

**New fields:**

| Field | Type | Description |
|-------|------|-------------|
| `importance` | `"critical" \| "high" \| "medium" \| "low"` | Human-readable priority tier |
| `importance_score` | `int (0-100)` | Numeric priority for fine-grained ordering |
| `max_sessions_per_cycle` | `int` | Per-repo session cap per orchestrator cycle |
| `auto_scan` | `bool` | Whether the orchestrator can trigger CodeQL scans |
| `auto_dispatch` | `bool` | Whether the orchestrator can create Devin sessions |
| `tags` | `list[str]` | Metadata tags for filtering and grouping |
| `orchestrator.global_session_limit` | `int` | Max sessions across all repos per period |
| `orchestrator.global_session_limit_period_hours` | `int` | Rate limit window |
| `orchestrator.objectives` | `list[Objective]` | Goal-driven dispatch targets |

### 5.3 Registry API

The telemetry dashboard already has registry CRUD endpoints (`/api/registry`, `/api/registry/add`, `/api/registry/remove` in `telemetry/app.py` lines 614-684). These will be extended to support the new fields. The orchestrator reads the registry at the start of each cycle.

---

## 6. Global Issue State

### 6.1 Issue State Model

The orchestrator maintains a unified view of every issue ever discovered. Each issue has a lifecycle state:

```
            ┌──────────┐
            │          │
   ┌───────>│   NEW    │
   │        │          │
   │        └─────┬────┘
   │              │
   │              ▼
   │        ┌──────────┐
   │        │          │
   │   ┌───>│RECURRING │<──────┐
   │   │    │          │       │
   │   │    └─────┬────┘       │
   │   │          │            │
   │   │          ▼            │
   │   │    ┌──────────┐       │
   │   │    │ SESSION   │       │ (fix not verified)
   │   │    │ DISPATCHED│───────┘
   │   │    └─────┬────┘
   │   │          │
   │   │          ▼
   │   │    ┌──────────┐
   │   │    │ PR OPEN  │───────┐
   │   │    │          │       │ (PR closed without merge)
   │   │    └─────┬────┘       │
   │   │          │            │
   │   │          ▼            ▼
   │   │    ┌──────────┐  ┌──────────┐
   │   │    │ PR MERGED│  │ PR FAILED│──> back to RECURRING
   │   │    │          │  │          │
   │   │    └─────┬────┘  └──────────┘
   │   │          │
   │   │          ▼
   │   │    ┌──────────┐
   │   │    │ VERIFIED │ (CodeQL re-scan confirms fix)
   │   │    │ FIXED    │
   │   │    └─────┬────┘
   │   │          │
   │   │          ▼ (reappears in later scan)
   │   └──────────┘
   │
   │        ┌──────────┐
   └────────│  FIXED   │ (fingerprint absent from latest scan)
            │          │
            └──────────┘
```

### 6.2 State Derivation

The orchestrator derives issue state by combining multiple data sources:

| Source | Data Used | State Derived |
|--------|-----------|---------------|
| `issue_tracking.track_issues_across_runs()` | Fingerprint presence in latest scan | `new`, `recurring`, `fixed` |
| `telemetry/runs/*.json` sessions | `session_id`, `status`, `issue_ids` | `session_dispatched` |
| `devin_service.poll_devin_sessions()` | Session status + `pr_url` | `pr_open` |
| `github_service.fetch_prs_from_github_to_db()` | PR state (`open`/`merged`/`closed`) | `pr_merged`, `pr_failed` |
| `verification.build_fingerprint_fix_map()` | Verification records | `verified_fixed` |

The orchestrator queries these in order and assigns the most advanced state. An issue that is `recurring` but has a `verified_fixed` record is considered fixed.

### 6.3 Skip Logic

The orchestrator **skips** dispatching a session for an issue when any of these are true:

| Condition | Reason |
|-----------|--------|
| Issue state is `fixed` or `verified_fixed` | Already resolved |
| Issue state is `session_dispatched` and session is still active | Work in progress |
| Issue state is `pr_open` | PR awaiting review/merge |
| Issue state is `pr_merged` (even without verification) | Likely fixed, await next scan |
| Issue has been dispatched N times with no successful fix | Diminishing returns (configurable) |
| Issue's CWE family has `should_skip_family()` returning True | Historical fix rate too low |

---

## 7. Priority Scoring

### 7.1 Issue Priority Score

Each issue gets a composite priority score used for dispatch ordering:

```python
def compute_issue_priority(issue: dict, repo_config: dict) -> float:
    repo_importance = repo_config.get("importance_score", 50) / 100.0  # 0-1
    severity_weight = {
        "critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25
    }.get(issue["severity_tier"], 0.1)

    recurrence_bonus = min(issue.get("appearances", 1) * 0.05, 0.3)

    sla_urgency = 0.0
    if issue.get("sla_status") == "breached":
        sla_urgency = 0.4
    elif issue.get("sla_status") == "at-risk":
        sla_urgency = 0.2

    fix_rate = get_family_fix_rate(issue["cwe_family"])
    feasibility = fix_rate if fix_rate > 0 else 0.5  # neutral if no data

    score = (
        repo_importance * 0.35
        + severity_weight * 0.30
        + sla_urgency * 0.15
        + feasibility * 0.10
        + recurrence_bonus * 0.10
    )
    return round(score, 4)
```

**Weight rationale:**
- **Repo importance (35%)**: The most important repos should be fixed first -- this is the user's primary control lever.
- **Severity (30%)**: Critical issues before low ones within the same repo.
- **SLA urgency (15%)**: Issues breaching SLA deadlines get a boost.
- **Feasibility (10%)**: Families with higher historical fix rates are prioritized (better ROI per ACU).
- **Recurrence (10%)**: Long-standing issues that keep reappearing get a slight boost.

### 7.2 Dispatch Ordering

Issues are sorted by descending priority score. The orchestrator walks the sorted list and creates sessions until one of the limits is hit:
1. Global session limit for the period.
2. Per-repo session limit for the cycle.
3. All eligible issues are covered.

---

## 8. Orchestrator Engine (`scripts/orchestrator.py`)

### 8.1 CLI Interface

```
scripts/orchestrator.py <command> [options]

Commands:
  ingest     Record scan results without dispatching sessions
  plan       Compute dispatch plan (dry-run; shows what would be dispatched)
  dispatch   Execute the dispatch plan (create Devin sessions)
  scan       Trigger CodeQL scans for repos due for scanning
  status     Show global issue state and session status
  cycle      Full orchestrator cycle: scan due repos, then dispatch
```

### 8.2 Orchestrator Cycle

A full `cycle` command performs these steps:

```
1. Load repo registry
2. For each repo where auto_scan=true and schedule is due:
   a. Trigger a CodeQL scan (via workflow_dispatch or direct execution)
   b. Wait for scan completion (optional, or run async)
3. Load global issue state from telemetry
4. Poll Devin API for session status updates
5. Poll GitHub API for PR status updates
6. Derive issue lifecycle states
7. Filter out ineligible issues (skip logic from section 6.3)
8. Score remaining issues (priority scoring from section 7)
9. Check rate limits and budget
10. Create dispatch plan (sorted issues -> batches -> sessions)
11. Execute dispatch plan (create Devin sessions)
12. Update telemetry with new session records
13. Send alerts for any verified fixes (section 10)
14. Persist orchestrator state (for resume/audit)
```

### 8.3 Scan Triggering

The orchestrator can trigger CodeQL scans independently of session dispatch:

```python
def trigger_scan(repo_config: dict, github_token: str) -> dict:
    """Trigger a CodeQL scan via workflow_dispatch."""
    owner_repo = extract_owner_repo(repo_config["repo"])
    resp = requests.post(
        f"https://api.github.com/repos/{action_repo}/actions/workflows/codeql-fixer.yml/dispatches",
        headers=gh_headers(github_token),
        json={
            "ref": "main",
            "inputs": {
                "target_repo": repo_config["repo"],
                "mode": "orchestrator",
                "severity_threshold": repo_config.get("severity_threshold", "low"),
                "dry_run": "false",
                **repo_config.get("overrides", {}),
            },
        },
    )
    return {"status": "triggered" if resp.status_code == 204 else "failed"}
```

This means the orchestrator can:
- Trigger scans on a schedule without creating sessions.
- Trigger sessions later when the global state is assessed.
- Trigger scans for newly added repos immediately.

### 8.4 Batch Formation

The orchestrator reuses the existing `batch_issues()` logic from `parse_sarif.py` but operates on the **global filtered issue set** rather than a single run's issues:

```python
def form_dispatch_batches(
    scored_issues: list[dict],
    repo_configs: dict[str, dict],
    global_limit: int,
    rate_limiter: RateLimiter,
) -> list[dict]:
    batches = []
    sessions_planned = 0

    # Group by repo, then batch within each repo
    by_repo = group_by_repo(scored_issues)
    
    # Interleave repos by priority to ensure fair distribution
    repo_queue = PriorityQueue()
    for repo, issues in by_repo.items():
        config = repo_configs[repo]
        repo_queue.put((-config["importance_score"], repo, issues))
    
    while not repo_queue.empty() and sessions_planned < global_limit:
        _, repo, issues = repo_queue.get()
        config = repo_configs[repo]
        repo_limit = config.get("max_sessions_per_cycle", 5)
        repo_sessions = 0
        
        repo_batches = batch_issues(
            issues,
            batch_size=config.get("batch_size", 5),
            max_batches=min(repo_limit, global_limit - sessions_planned),
        )
        
        for batch in repo_batches:
            if not rate_limiter.can_create_session():
                break
            batches.append(batch)
            sessions_planned += 1
            repo_sessions += 1
    
    return batches
```

---

## 9. Rate Limiting and Objectives

### 9.1 Rate Limiter

```python
@dataclass
class RateLimiter:
    max_sessions: int           # e.g., 20
    period_hours: int           # e.g., 24
    created_timestamps: list[datetime]  # persisted to orchestrator state

    def can_create_session(self) -> bool:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.period_hours)
        recent = [t for t in self.created_timestamps if t > cutoff]
        return len(recent) < self.max_sessions

    def record_session(self) -> None:
        self.created_timestamps.append(datetime.now(timezone.utc))
```

The rate limiter state is persisted to `telemetry/orchestrator_state.json` so limits survive across invocations.

### 9.2 Objectives

Objectives define **goals** the orchestrator works toward. They influence priority scoring and provide progress tracking.

```python
@dataclass
class Objective:
    name: str
    target_severity: str        # e.g., "critical"
    target_count: int           # desired remaining count (0 = eliminate all)
    target_reduction_pct: int   # alternative: reduce by percentage
    priority: int               # objective ordering

    def progress(self, current_issues: list[dict]) -> dict:
        matching = [i for i in current_issues 
                    if i["severity_tier"] == self.target_severity
                    and i["status"] in ("new", "recurring")]
        return {
            "objective": self.name,
            "current_count": len(matching),
            "target_count": self.target_count,
            "met": len(matching) <= self.target_count,
        }
```

When evaluating priority, issues that contribute to an active objective get a boost:

```python
objective_boost = 0.0
for obj in active_objectives:
    if issue["severity_tier"] == obj.target_severity and not obj.is_met():
        objective_boost = max(objective_boost, 0.15 * (1.0 / obj.priority))
score += objective_boost
```

### 9.3 Budget Awareness

The orchestrator integrates with `fix_learning.py`'s `compute_acu_budget()` to set per-session ACU limits. Sessions for CWE families with high historical fix rates get smaller budgets (they resolve quickly), while difficult families get larger budgets.

---

## 10. GitHub App Alerts

### 10.1 Alert Triggers

The orchestrator produces alerts in the GitHub App when:

| Event | Alert Type | Recipients |
|-------|-----------|------------|
| Critical issue gets a verified fix | `issue_resolved` | Repo admins/watchers |
| All critical issues in a repo are fixed | `objective_met` | Repo admins/watchers |
| SLA breach for a critical/high issue | `sla_breach` | Repo admins/watchers |
| Orchestrator cycle completed | `cycle_summary` | Configured webhook |

### 10.2 Implementation

Alerts are sent as **GitHub Issues** on the target repo (using the GitHub App's installation token) and optionally via the existing webhook system:

```python
def send_verified_fix_alert(
    issue: dict,
    pr_url: str,
    verification_record: dict,
    installation_token: str,
) -> None:
    """Create a GitHub Issue or comment to notify about a verified fix."""
    repo = extract_owner_repo(issue["target_repo"])
    title = (
        f"[CodeQL Fixer] Verified fix: {issue['rule_id']} "
        f"({issue['severity_tier'].upper()})"
    )
    body = (
        f"## Verified Security Fix\n\n"
        f"**Issue:** {issue['rule_id']} ({issue['cwe_family']})\n"
        f"**Severity:** {issue['severity_tier'].upper()}\n"
        f"**File:** {issue['file']}:{issue['start_line']}\n"
        f"**PR:** {pr_url}\n"
        f"**Fix Rate:** {verification_record['summary']['fix_rate']}%\n\n"
        f"This issue has been verified as fixed by CodeQL re-analysis."
    )
    # POST to GitHub Issues API using installation token
    requests.post(
        f"https://api.github.com/repos/{repo}/issues",
        headers=gh_headers(installation_token),
        json={"title": title, "body": body, "labels": ["security", "verified-fix"]},
    )
```

For the webhook path, the existing `scripts/webhook.py` is extended with new event types: `fix_verified`, `objective_met`, `sla_breach`, `cycle_completed`.

### 10.3 GitHub App Integration

The existing `github_app/webhook_handler.py` handles `push` events. The orchestrator uses the GitHub App's **installation token** (obtained via `github_app/auth.py`) to post alerts on repos where the app is installed. This requires:

1. Adding an `alert()` method to the GitHub App server that the orchestrator can call.
2. Storing installation IDs per repo in the registry (the `handle_installation` handler already captures these).
3. Extending the registry schema to include `installation_id` (auto-populated when the app is installed on a repo).

---

## 11. Orchestrator State Persistence

The orchestrator maintains its own state file at `telemetry/orchestrator_state.json`:

```json
{
  "last_cycle": "2026-02-08T19:00:00Z",
  "rate_limiter": {
    "created_timestamps": ["2026-02-08T18:30:00Z", "2026-02-08T18:45:00Z"]
  },
  "dispatch_history": {
    "abc123def456": {
      "fingerprint": "abc123def456",
      "dispatch_count": 2,
      "last_dispatched": "2026-02-08T18:30:00Z",
      "last_session_id": "devin-94023bac82cc4440b6190b9442ece081",
      "last_outcome": "pr_merged"
    }
  },
  "objective_progress": [
    {
      "name": "eliminate-critical",
      "current_count": 3,
      "target_count": 0,
      "met": false,
      "last_checked": "2026-02-08T19:00:00Z"
    }
  ],
  "scan_schedule": {
    "https://github.com/juice-shop/juice-shop": {
      "last_scan": "2026-02-07T10:00:00Z",
      "next_due": "2026-02-14T10:00:00Z"
    }
  }
}
```

The `dispatch_history` tracks how many times each issue (by fingerprint) has been dispatched and what the outcome was. This powers the "max dispatch attempts" skip logic and provides audit trail.

---

## 12. Scheduled Workflow

A new GitHub Actions workflow triggers the orchestrator on a schedule:

```yaml
name: Orchestrator Cycle
on:
  schedule:
    - cron: "0 */6 * * *"  # every 6 hours
  workflow_dispatch:
    inputs:
      command:
        description: "Orchestrator command: cycle, dispatch, scan, status"
        default: "cycle"

jobs:
  orchestrate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install requests jinja2 pyyaml
      - run: |
          python scripts/orchestrator.py ${{ inputs.command || 'cycle' }}
        env:
          DEVIN_API_KEY: ${{ secrets.DEVIN_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GH_PAT }}
          ACTION_REPO: ${{ github.repository }}
```

---

## 13. Telemetry Dashboard Integration

The orchestrator's state is exposed through new API endpoints in `telemetry/app.py`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/orchestrator/status` | GET | Current orchestrator state, rate limit usage, objective progress |
| `/api/orchestrator/plan` | GET | Preview of what the next dispatch cycle would do |
| `/api/orchestrator/dispatch` | POST | Trigger an orchestrator dispatch cycle |
| `/api/orchestrator/scan` | POST | Trigger CodeQL scans for specified or all due repos |
| `/api/orchestrator/history` | GET | Dispatch history for a given issue fingerprint |

The dashboard frontend (`docs/index.html`) gains an "Orchestrator" tab showing:
- Global issue state breakdown (new/recurring/dispatched/fixed/verified)
- Objective progress bars
- Rate limit usage meter
- Dispatch history timeline
- Per-repo priority ranking

---

## 14. Additional Smart Orchestrator Ideas

### 14.1 Adaptive Scan Frequency

Repos with rapidly changing codebases (many commits since last scan) should be scanned more frequently. The orchestrator can check commit counts via the GitHub API and adjust scan schedules dynamically:

```python
def should_scan_now(repo: str, schedule: str, last_scan: datetime) -> bool:
    # Check schedule
    if not is_due(schedule, last_scan):
        # But check commit velocity -- scan early if lots of changes
        commits_since = get_commit_count_since(repo, last_scan)
        if commits_since > 50:  # significant changes
            return True
        return False
    return True
```

### 14.2 Fix Pattern Learning

When a Devin session successfully fixes an issue (verified), extract the diff and store it as a `fix_example` in telemetry. The existing `fix_learning.py` already supports `find_fix_examples()` and `prompt_fix_examples()`. The orchestrator automates this collection:

1. After a PR is merged and verified, fetch the PR diff via GitHub API.
2. Store the diff (truncated) with CWE family and file metadata in the telemetry record.
3. Future Devin sessions for the same CWE family receive these examples in their prompts.

This creates a **feedback loop**: each successful fix improves future fix quality.

### 14.3 Issue Clustering

Group related issues not just by CWE family but by code locality. Issues in the same file or module are more likely to have a common root cause. The orchestrator can use `_file_proximity_score()` from `parse_sarif.py` to create "super-batches" that give Devin a more complete picture:

```python
def cluster_related_issues(issues: list[dict]) -> list[list[dict]]:
    """Group issues that likely share a root cause."""
    clusters = []
    for issue in issues:
        placed = False
        for cluster in clusters:
            if any(_file_proximity_score(issue, c) > 0.5 for c in cluster):
                cluster.append(issue)
                placed = True
                break
        if not placed:
            clusters.append([issue])
    return clusters
```

### 14.4 Cost Tracking

Track ACU consumption per session and compute cost metrics:
- Cost per verified fix (total ACU / verified fixes)
- Cost per CWE family
- Cost per repo
- Projected monthly cost at current dispatch rate

This data informs budget decisions and helps tune the `max_acu_per_session` setting.

### 14.5 Devin Session Monitoring

Instead of just polling for completion, the orchestrator can monitor active sessions and intervene:
- If a session is running longer than expected for its CWE family, log a warning.
- If a session fails, automatically retry with an enhanced prompt (including the error context from the failed session).
- If multiple sessions for the same CWE family fail, escalate (alert + stop dispatching that family).

### 14.6 Dependency-Aware Prioritization

Some issues are more impactful than others based on where they sit in the dependency graph. An SQL injection in a core authentication module affects every endpoint, while an XSS in an admin-only debug page has limited blast radius. The orchestrator could use a lightweight dependency analysis (file import graph) to estimate blast radius and boost priority accordingly.

### 14.7 Cooldown Periods

After a Devin session fails to fix an issue, apply an exponential cooldown before retrying:
- 1st failure: wait 24 hours before redispatching
- 2nd failure: wait 72 hours
- 3rd failure: wait 1 week
- 4th failure: mark as "needs-human-review" and stop dispatching

This prevents burning ACU on issues that Devin consistently struggles with.

---

## 15. File Changes Summary

| File | Change Type | Description |
|------|------------|-------------|
| `scripts/orchestrator.py` | **New** | Core orchestrator engine |
| `scripts/parse_sarif.py` | Modify | Add Tier 2.5 fingerprint fallback; extend hash length |
| `scripts/pipeline_config.py` | Modify | Add `mode` field to `PipelineConfig` |
| `action.yml` | Modify | Add `mode` input; conditional dispatch step |
| `repo_registry.json` | Modify | Enhanced schema with importance, objectives, rate limits |
| `telemetry/app.py` | Modify | New `/api/orchestrator/*` endpoints |
| `telemetry/orchestrator_state.json` | **New** | Persistent orchestrator state |
| `github_app/webhook_handler.py` | Modify | Add alert sending capability |
| `github_app/alerts.py` | **New** | Alert formatting and delivery |
| `.github/workflows/orchestrator.yml` | **New** | Scheduled orchestrator workflow |
| `docs/static/orchestrator.js` | **New** | Dashboard orchestrator tab |
| `tests/test_orchestrator.py` | **New** | Orchestrator unit tests |

---

## 16. Migration Path

The orchestrator is additive -- it does not break existing behavior:

1. **Phase 1**: Add `mode` input to `action.yml` with `basic` as default. Existing users see no change.
2. **Phase 2**: Implement `scripts/orchestrator.py` with `ingest`, `plan`, and `status` commands.
3. **Phase 3**: Implement `dispatch` command and rate limiting.
4. **Phase 4**: Add scheduled workflow and dashboard integration.
5. **Phase 5**: Add GitHub App alerts and adaptive features.

Each phase is independently deployable and testable.

---

## 17. Open Questions

These are design decisions that can be made during implementation:

1. **State storage**: Should orchestrator state live in SQLite (alongside telemetry) or in a separate JSON file? JSON is simpler for version control; SQLite is better for querying. **Recommendation**: Start with JSON, migrate to SQLite if query patterns become complex.

2. **Scan triggering mechanism**: Should the orchestrator trigger scans via `workflow_dispatch` (requires the repo to have the workflow) or directly invoke the pipeline scripts (requires the runner to have CodeQL)? **Recommendation**: Use `workflow_dispatch` for remote repos; direct invocation for the action repo itself.

3. **Alert delivery**: GitHub Issues vs. GitHub Discussions vs. webhook-only? **Recommendation**: Start with webhook events (most flexible); add GitHub Issues as opt-in for high-severity verified fixes.
