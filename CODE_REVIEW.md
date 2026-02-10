# Code Review: Recent PRs (MP-76)

Comprehensive review of recently merged PRs (MP-72, MP-70, MP-66, MP-64, MP-63, MP-60) covering redundancies, duplication, inconsistencies, and improvement suggestions.

---

## Critical Issues

### 1. Two incompatible `request_with_retry` functions

**Files:** `scripts/devin_api.py:36-61`, `scripts/retry_utils.py:40-93`

Two functions with the same name but completely different contracts:

| Aspect | `devin_api.py` | `retry_utils.py` |
|--------|---------------|-------------------|
| Signature | `(method, url, api_key, json_data)` | `(method, url, *, **kwargs)` |
| Return type | `dict` (parsed JSON) | `requests.Response` (raw) |
| Backoff | Linear (`RETRY_DELAY * attempt`) | Exponential with jitter (`base * 2^attempt + rand`) |
| Error handling | Retries all `RequestException` | Retries `ConnectionError`, `Timeout`, specific status codes |

Callers are split across the codebase: `dispatch_devin.py`, `knowledge.py`, `retry_feedback.py` use the `devin_api` version; `orchestrator/scanner.py`, `orchestrator/dispatcher.py` use the `retry_utils` version.

**Recommendation:** Consolidate into a single module. The `retry_utils` version has the better backoff strategy; adapt it to also support the Devin-API-specific auth header pattern via a thin wrapper.

---

### 2. `FamilyStats` missing `avg_acu` attribute

**File:** `scripts/orchestrator/agent.py:115`

```python
"avg_acu": round(stats.avg_acu, 1) if stats.avg_acu else 0,
```

But `FamilyStats` in `scripts/fix_learning.py:136-147` has no `avg_acu` field:

```python
@dataclass
class FamilyStats:
    total_sessions: int = 0
    finished_sessions: int = 0
    failed_sessions: int = 0
    total_issues: int = 0
```

This will raise `AttributeError` at runtime when `build_agent_triage_input` is called.

**Fix:** Add `avg_acu: float | None = None` to `FamilyStats` and populate it from telemetry data, or remove the reference in `agent.py`.

---

### 3. Inconsistent SLA deadline constants

**Files:** `telemetry/issue_tracking.py:3-8`, `scripts/orchestrator/agent.py:118-123`

```python
# issue_tracking.py
DEFAULT_SLA_HOURS = {"critical": 48, "high": 96, "medium": 168, "low": 336}

# agent.py
sla_deadlines = {"critical_hours": 24, "high_hours": 72, "medium_hours": 168, "low_hours": 720}
```

Critical SLA differs by 2x (48h vs 24h), low differs by 2x (336h vs 720h). The agent sends these to the Devin triage session, so its prioritization decisions are based on different SLA windows than the dashboard displays.

**Fix:** Define SLA constants in one place (e.g., `pipeline_config.py`) and import everywhere.

---

## Duplication

### 4. Duplicated `load_state` / `_load_orchestrator_state`

**Files:** `scripts/orchestrator/state.py:149-165`, `telemetry/routes/orchestrator.py:23-43`

Both functions do the same thing: get a DB connection, check if orchestrator state is empty, migrate from JSON file if needed, and return the state. The telemetry route reimplements the logic instead of importing the existing `load_state()`.

**Fix:** Have the route import and call `orchestrator.state.load_state()` directly.

---

### 5. Duplicated registry loaders with inconsistent defaults

**Files:** `scripts/orchestrator/state.py:131-135`, `telemetry/routes/registry.py:18-22`

```python
# state.py
return {"version": "2.0", "defaults": {}, "orchestrator": {}, "repos": []}

# registry.py
return {"version": "1.0", "defaults": {}, "concurrency": {"max_parallel": 3, "delay_seconds": 30}, "repos": []}
```

Different default versions (`"2.0"` vs `"1.0"`), and the registry route includes a `concurrency` key that `state.py` omits while `state.py` includes an `orchestrator` key that the route omits.

**Fix:** Single `load_registry()` function shared between scripts and telemetry.

---

### 6. Duplicated effectiveness report logic

**Files:** `scripts/orchestrator/agent.py:328-378`, `telemetry/routes/orchestrator.py:394-446`

The `build_effectiveness_report()` function in `agent.py` and the `api_orchestrator_effectiveness()` endpoint contain nearly identical loops computing agent vs deterministic fix rates. The route doesn't call the existing function.

**Fix:** Have the route call `agent.build_effectiveness_report()`.

---

### 7. Duplicated agent score merging

**Files:** `scripts/orchestrator/agent.py:283-303`, `telemetry/routes/orchestrator.py:369-382`

`merge_agent_scores()` exists as a proper function, but the `api_orchestrator_agent_plan()` endpoint reimplements the same logic inline.

**Fix:** Import and call `merge_agent_scores()` in the route.

---

### 8. Inline `clean_session_id` duplication

**Files:** `scripts/orchestrator/agent.py:212,232`, `telemetry/routes/orchestrator.py:67-68`

The `clean_session_id()` function exists in `devin_api.py` but multiple places inline the same logic:

```python
# agent.py:232
clean_id = session_id.replace("devin-", "")

# routes/orchestrator.py:67-68
if sid.startswith("devin-"):
    sid = sid[6:]
```

**Fix:** Import and use `clean_session_id()` consistently.

---

### 9. Overlapping CWE fix patterns

**Files:** `scripts/knowledge.py:73-91`, `scripts/fix_learning.py:44-132`

`_classify_fix_pattern()` in `knowledge.py` maps CWE families to short pattern descriptions. `CWE_FIX_HINTS` in `fix_learning.py` maps the same families to longer hint strings. These serve overlapping purposes but have diverged (e.g., `fix_learning.py` covers more families like `hardcoded-credentials`, `file-upload`, `race-condition`, `memory-safety`).

**Fix:** Remove `_classify_fix_pattern()` and derive the short description from `CWE_FIX_HINTS` to maintain a single source of truth.

---

## Inconsistencies

### 10. Inconsistent logging setup

**Files:** `scripts/devin_api.py:9`, `scripts/logging_config.py`, `telemetry/helpers.py:73`

Most modules use the structured JSON logger via `setup_logging(__name__)`, but `devin_api.py` uses raw `logging.getLogger(__name__)` which outputs unstructured text. `telemetry/helpers.py:73` also falls back to a raw logger for audit warnings.

**Fix:** Use `setup_logging()` in `devin_api.py` for consistency.

---

### 11. Inconsistent header construction patterns

**Files:** `scripts/devin_api.py:29-33`, `telemetry/config.py:16-24`, `scripts/github_utils.py:21-33`

Three different patterns for building API headers:
- `devin_api.headers(api_key)` -- takes key as parameter
- `config.devin_headers()` -- reads key from env var
- `config.gh_headers()` -- wraps `github_utils.gh_headers()`, reads token from env var

The telemetry `config.py` duplicates `devin_api.headers()` functionality under a different name.

**Fix:** Standardize on a single pattern per API. For Devin API, use `devin_api.headers()` everywhere.

---

### 12. Inconsistent `init_db` call patterns

Across the codebase, some callers call `init_db(conn)` before every operation while others assume it's already initialized:

- `orchestrator/state.py:load_state()` calls `init_db(conn)` every time
- `orchestrator/state.py:save_state()` calls `init_db(conn)` every time
- `orchestrator/dispatcher.py:cmd_ingest()` calls `init_db(conn)`
- `telemetry/routes/api.py` uses `db_connection()` context manager (which does NOT call `init_db`)

The `db_connection()` context manager in `database.py` doesn't call `init_db()`, so routes rely on the app startup having called it. But the orchestrator scripts call it defensively on every operation, adding overhead.

**Fix:** Call `init_db()` once at connection creation time inside `get_connection()` or `db_connection()`, and remove redundant calls.

---

## Code Quality

### 13. Excessive `sys.path` manipulation

**Files:** `scripts/orchestrator/state.py:25-28`, `scripts/knowledge.py:8`, `telemetry/config.py:8-9`, `scripts/orchestrator/alerts.py:33-34,53-54`

Multiple modules insert directories into `sys.path` at import time. This is fragile, order-dependent, and makes the import graph hard to reason about.

**Fix:** Convert the project to use proper Python packaging with a `pyproject.toml` and installable packages. Short-term, centralize `sys.path` setup in a single entry-point module.

---

### 14. Overly large files

- `telemetry/database.py` -- **1613 lines**. Contains schema creation, CRUD operations, query helpers, orchestrator state management, audit logging, search functionality, and fingerprint refresh logic. Could be split into `schema.py`, `queries.py`, `orchestrator_state.py`, `audit.py`.

- `scripts/dispatch_devin.py` -- **1095 lines**. The `main()` function alone is ~300 lines with deeply nested logic for wave dispatch, knowledge storage, and retry processing.

**Recommendation:** Break these into focused modules. For `dispatch_devin.py`, extract wave dispatch logic and post-dispatch actions (knowledge, retry) into separate functions/modules.

---

### 15. `__init__.py` re-exports private symbols

**File:** `scripts/orchestrator/__init__.py`

Re-exports underscore-prefixed functions like `_build_fp_to_tracking_ids`, `_cooldown_remaining_hours`, `_issue_file`, `_issue_start_line`, etc. These are implementation details.

**Fix:** Only re-export public API symbols. If external code needs these helpers, rename them to remove the underscore prefix.

---

### 16. Repeated pagination boilerplate

**Files:** `telemetry/database.py` (multiple functions), `telemetry/helpers.py:76-86`

The pagination pattern (`total_row`, `offset`, `LIMIT ? OFFSET ?`, return dict with `items/page/per_page/total/pages`) is repeated verbatim in `query_runs`, `query_sessions`, `query_prs`, etc. Meanwhile, `helpers._paginate()` does in-memory pagination on already-fetched lists.

**Fix:** Create a generic `paginated_query()` helper in `database.py` that takes a base query and parameters, applies pagination, and returns the standard response dict.

---

### 17. `TERMINAL_STATUSES` includes both "canceled" and "cancelled"

**File:** `scripts/devin_api.py:16-19`

```python
TERMINAL_STATUSES = frozenset(
    {"finished", "blocked", "expired", "failed", "canceled", "cancelled",
     "stopped", "error"}
)
```

Including both spellings is defensive but suggests uncertainty about the API contract. Worth confirming which spelling the Devin API actually uses and documenting it.

---

### 18. `subprocess.run` with full environment passthrough

**File:** `telemetry/routes/orchestrator.py:175-176`

```python
result = subprocess.run(
    cmd, capture_output=True, text=True, timeout=120,
    cwd=str(_ORCHESTRATOR_DIR.parent),
    env={**os.environ},
)
```

Passing `env={**os.environ}` is equivalent to the default behavior (inheriting the parent environment). The explicit spread is unnecessary and slightly misleading -- it suggests intent to modify the env, but nothing is added or removed.

**Fix:** Remove `env={**os.environ}` or explicitly pass only the required variables.

---

## Minor Suggestions

### 19. Type annotations

Several functions use `dict` instead of more specific types:
- `knowledge.py` functions return `dict` where `dict[str, Any]` would be clearer
- `helpers.py:_paginate` takes `list` not `list[dict]`
- Route handlers use bare `dict` throughout

### 20. Error handling in `_audit()`

**File:** `telemetry/helpers.py:65-73`

```python
def _audit(action: str, resource: str = "", details: str = "") -> None:
    try:
        conn = get_connection()
        try:
            insert_audit_log(conn, _get_audit_user(), action, resource, details)
        finally:
            conn.close()
    except Exception:
        logging.getLogger(__name__).warning(...)
```

Opens a new connection for every audit log entry. Since routes already have a `db_connection()` context manager open, this creates unnecessary connection overhead.

**Fix:** Accept an optional `conn` parameter and reuse the existing connection when available.

### 21. `fetch_pr_diff` doesn't use retry logic

**File:** `scripts/devin_api.py:88-115`

`fetch_pr_diff()` uses raw `requests.get()` without retry, even though it lives in the same module as `request_with_retry()`. GitHub API calls are prone to transient failures.

---

## Summary

| Category | Count | Severity |
|----------|-------|----------|
| Critical (runtime bugs, data inconsistency) | 3 | High |
| Duplication (redundant code) | 6 | Medium |
| Inconsistencies (style, patterns) | 3 | Medium |
| Code quality (maintainability) | 6 | Low-Medium |
| Minor suggestions | 3 | Low |
| **Total** | **21** | |

The most impactful changes would be:
1. Fix the `FamilyStats.avg_acu` missing attribute (runtime bug)
2. Unify SLA constants (data correctness)
3. Consolidate `request_with_retry` (reduce confusion, improve reliability)
4. Have telemetry routes import orchestrator functions instead of reimplementing them (eliminate drift)
