# SQLite Migration Plan

**Ticket**: [MP-33](https://linear.app/mp-swe-projects/issue/MP-33/plan-migration-to-sqlite)
**Repository**: https://github.com/marius-posa/codeql-devin-fixer
**Context**: [Solution Review V2, Section 6.2](./SOLUTION_REVIEW_V2.md)

---

## Problem Statement

Telemetry is stored as JSON files in `telemetry/runs/`, loaded into memory on each request (with a TTL cache). This works for <50 repos with <100 runs each, but breaks at enterprise scale:

- Git repos have practical limits on file count and push frequency
- Loading all JSON files into memory on every cache miss doesn't scale
- No indexing, filtering, or aggregation at the storage level
- In-memory pagination (`_paginate()`) requires loading all records before slicing
- Aggregation functions (`aggregate_stats`, `aggregate_sessions`, `build_repos_dict`) iterate all runs on every request
- Issue tracking (`track_issues_across_runs`) does O(runs * fingerprints) work on every call

SQLite requires zero infrastructure, can be deployed alongside the Flask app, and handles thousands of repos with millions of records.

---

## 1. Schema Definition

### 1.1 `runs` Table

Stores one row per action run. Replaces the per-file JSON records in `telemetry/runs/`.

```sql
CREATE TABLE runs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    target_repo         TEXT    NOT NULL,
    fork_url            TEXT    NOT NULL DEFAULT '',
    run_number          INTEGER NOT NULL,
    run_id              TEXT    NOT NULL DEFAULT '',
    run_url             TEXT    NOT NULL DEFAULT '',
    run_label           TEXT    NOT NULL DEFAULT '',
    timestamp           TEXT    NOT NULL,  -- ISO 8601
    issues_found        INTEGER NOT NULL DEFAULT 0,
    batches_created     INTEGER NOT NULL DEFAULT 0,
    zero_issue_run      INTEGER NOT NULL DEFAULT 0,  -- boolean
    severity_breakdown  TEXT    NOT NULL DEFAULT '{}',  -- JSON dict, see design note below
    category_breakdown  TEXT    NOT NULL DEFAULT '{}',  -- JSON dict, see design note below
    source_file         TEXT    NOT NULL DEFAULT '',  -- original JSON filename for traceability
    UNIQUE(run_label)
);

CREATE INDEX idx_runs_target_repo ON runs(target_repo);
CREATE INDEX idx_runs_timestamp   ON runs(timestamp);
CREATE INDEX idx_runs_run_number  ON runs(run_number);
```

**Design notes:**
- `severity_breakdown` and `category_breakdown` are stored as JSON text columns on the `runs` table **in addition to** the normalized `issues` table. This is necessary because some older runs (e.g., `juice-shop_run_12` through `_run_14`) have breakdown data and `issues_found > 0` but no `issue_fingerprints` array. Deriving breakdowns solely from the `issues` table would produce empty dicts for these runs. The JSON columns preserve the original data losslessly. For runs **with** fingerprints, the `issues` table is the canonical source and can be used for filtering/aggregation; the JSON columns serve as a fast denormalized read cache and as the fallback for fingerprint-less runs.
- `run_label` is unique per run (format: `run-{number}-{date}-{time}`) and serves as the natural key for idempotent migration.
- `source_file` preserves the original JSON filename for debugging and rollback.

### 1.2 `sessions` Table

Stores one row per Devin session. Currently nested inside run JSON as `sessions[]`.

```sql
CREATE TABLE sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    session_id   TEXT    NOT NULL DEFAULT '',  -- Devin session UUID
    session_url  TEXT    NOT NULL DEFAULT '',
    batch_id     INTEGER,
    status       TEXT    NOT NULL DEFAULT 'unknown',
    pr_url       TEXT    NOT NULL DEFAULT ''
);

-- Partial unique index: only enforce uniqueness on non-empty session IDs.
-- Future runs could theoretically produce empty session_id values (e.g., failed
-- session creation), and multiple such rows must be allowed.
CREATE UNIQUE INDEX idx_sessions_session_id_unique
    ON sessions(session_id) WHERE session_id != '';

CREATE INDEX idx_sessions_run_id  ON sessions(run_id);
CREATE INDEX idx_sessions_status  ON sessions(status);
```

### 1.3 `session_issue_ids` Table

Maps sessions to their issue IDs. Currently `issue_ids[]` array in each session record.

```sql
CREATE TABLE session_issue_ids (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    issue_id   TEXT    NOT NULL  -- e.g. "CQLF-R18-0001"
);

CREATE INDEX idx_session_issue_ids_session ON session_issue_ids(session_id);
CREATE INDEX idx_session_issue_ids_issue   ON session_issue_ids(issue_id);
```

### 1.4 `issues` Table

Stores one row per issue fingerprint occurrence per run. Currently nested inside run JSON as `issue_fingerprints[]`.

```sql
CREATE TABLE issues (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    issue_ext_id   TEXT    NOT NULL DEFAULT '',  -- e.g. "CQLF-R18-0001"
    fingerprint    TEXT    NOT NULL,
    rule_id        TEXT    NOT NULL DEFAULT '',
    severity_tier  TEXT    NOT NULL DEFAULT 'unknown',
    cwe_family     TEXT    NOT NULL DEFAULT 'other',
    file           TEXT    NOT NULL DEFAULT '',
    start_line     INTEGER NOT NULL DEFAULT 0,
    description    TEXT    NOT NULL DEFAULT '',  -- future: from solution review 3.2
    resolution     TEXT    NOT NULL DEFAULT '',  -- future: from solution review 3.2
    code_churn     INTEGER NOT NULL DEFAULT 0,  -- future: from solution review 3.2
    UNIQUE(run_id, fingerprint)
);

CREATE INDEX idx_issues_run_id      ON issues(run_id);
CREATE INDEX idx_issues_fingerprint ON issues(fingerprint);
CREATE INDEX idx_issues_rule_id     ON issues(rule_id);
CREATE INDEX idx_issues_severity    ON issues(severity_tier);
CREATE INDEX idx_issues_cwe_family  ON issues(cwe_family);
CREATE INDEX idx_issues_file        ON issues(file);
```

**Design notes:**
- `UNIQUE(run_id, fingerprint)` prevents duplicate fingerprints within a single run.
- `description`, `resolution`, and `code_churn` columns are included now (defaulting to empty) to support future data model enhancements from Solution Review V2 section 3.2, avoiding a schema migration later.
- The `severity_breakdown` and `category_breakdown` dicts from run JSON are now derived: `SELECT severity_tier, COUNT(*) FROM issues WHERE run_id = ? GROUP BY severity_tier`.

### 1.5 `prs` Table

Stores PR data fetched from the GitHub API. Currently only held in the in-memory cache.

```sql
CREATE TABLE prs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pr_number   INTEGER NOT NULL,
    title       TEXT    NOT NULL DEFAULT '',
    html_url    TEXT    NOT NULL DEFAULT '',
    state       TEXT    NOT NULL DEFAULT '',
    merged      INTEGER NOT NULL DEFAULT 0,  -- boolean
    created_at  TEXT    NOT NULL DEFAULT '',
    repo        TEXT    NOT NULL DEFAULT '',  -- fork repo full name
    user        TEXT    NOT NULL DEFAULT '',
    session_id  TEXT    NOT NULL DEFAULT '',  -- matched Devin session ID
    fetched_at  TEXT    NOT NULL DEFAULT '',  -- when this record was last refreshed
    UNIQUE(html_url)
);

CREATE INDEX idx_prs_repo       ON prs(repo);
CREATE INDEX idx_prs_state      ON prs(state);
CREATE INDEX idx_prs_session_id ON prs(session_id);
```

### 1.6 `pr_issue_ids` Table

Maps PRs to their referenced issue IDs. Currently `issue_ids[]` array in each PR record.

```sql
CREATE TABLE pr_issue_ids (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    pr_id    INTEGER NOT NULL REFERENCES prs(id) ON DELETE CASCADE,
    issue_id TEXT    NOT NULL  -- e.g. "CQLF-R18-0001"
);

CREATE INDEX idx_pr_issue_ids_pr    ON pr_issue_ids(pr_id);
CREATE INDEX idx_pr_issue_ids_issue ON pr_issue_ids(issue_id);
```

### 1.7 Entity-Relationship Summary

```
runs 1──* sessions 1──* session_issue_ids
  │
  └── 1──* issues

prs 1──* pr_issue_ids
```

PRs link to sessions via `prs.session_id = sessions.session_id` (text match, not FK, since PRs are fetched independently from GitHub).

---

## 2. Migration Strategy

### 2.1 New Module: `telemetry/database.py`

A new module encapsulating all SQLite operations:

```python
# telemetry/database.py
import sqlite3
import pathlib

DB_PATH = pathlib.Path(__file__).parent / "telemetry.db"

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db() -> None:
    """Create tables if they don't exist."""
    conn = get_connection()
    conn.executescript(SCHEMA_SQL)
    conn.close()
```

**Key decisions:**
- **WAL mode**: Enables concurrent readers while one writer operates, critical for a web server.
- **`sqlite3.Row` row factory**: Allows dict-like access to query results.
- **DB location**: `telemetry/telemetry.db` alongside the Flask app. Configurable via `TELEMETRY_DB_PATH` environment variable for deployment flexibility.
- **No ORM**: Raw SQL keeps the dependency footprint minimal and SQLite queries transparent. The app already uses plain dicts throughout; adding SQLAlchemy would be over-engineering for this use case.

### 2.2 One-Time JSON Migration: `telemetry/migrate_json_to_sqlite.py`

A standalone script (also callable from app startup) that:

1. Scans `telemetry/runs/*.json`
2. For each file, inserts a `runs` row (skipping if `run_label` already exists)
3. Inserts child `sessions`, `session_issue_ids`, and `issues` rows
4. Logs progress and reports totals

```python
# telemetry/migrate_json_to_sqlite.py
def migrate_json_files(runs_dir: pathlib.Path, conn: sqlite3.Connection) -> dict:
    """Migrate all JSON run files into SQLite. Idempotent via run_label uniqueness."""
    stats = {"migrated": 0, "skipped": 0, "errors": 0}
    for fp in sorted(runs_dir.glob("*.json")):
        try:
            with open(fp) as f:
                data = json.load(f)
            run_label = data.get("run_label", "")
            # Check if already migrated
            existing = conn.execute(
                "SELECT id FROM runs WHERE run_label = ?", (run_label,)
            ).fetchone()
            if existing:
                stats["skipped"] += 1
                continue
            _insert_run(conn, data, fp.name)
            stats["migrated"] += 1
        except (json.JSONDecodeError, OSError, sqlite3.Error) as exc:
            print(f"ERROR migrating {fp.name}: {exc}")
            stats["errors"] += 1
    conn.commit()
    return stats
```

**Idempotency**: Uses `run_label` uniqueness to skip already-migrated files. Safe to re-run.

### 2.3 App Startup Integration

In `app.py`, during initialization:

```python
from database import init_db, get_connection, DB_PATH
from migrate_json_to_sqlite import migrate_json_files

init_db()

if not DB_PATH.exists() or _is_db_empty():
    conn = get_connection()
    stats = migrate_json_files(RUNS_DIR, conn)
    print(f"Migration complete: {stats}")
    conn.close()
```

After migration is stable and verified, the JSON loading path (`_load_runs_from_disk`) and `_Cache` class can be removed.

---

## 3. Write Path Changes

### 3.1 `/api/refresh` Endpoint (app.py:356-403)

**Current behavior**: Downloads JSON files from GitHub to `telemetry/runs/`, invalidates in-memory cache.

**New behavior**: Downloads JSON files from GitHub, parses each, and inserts directly into SQLite. Optionally still writes JSON files as a backup/archive.

```python
@app.route("/api/refresh", methods=["POST"])
@require_api_key
def api_refresh():
    # ... (existing GitHub download logic) ...
    conn = get_connection()
    for item in items:
        # Download JSON content
        dl_resp = requests.get(item["download_url"], timeout=30)
        if dl_resp.status_code == 200:
            data = dl_resp.json()
            run_label = data.get("run_label", "")
            existing = conn.execute(
                "SELECT id FROM runs WHERE run_label = ?", (run_label,)
            ).fetchone()
            if not existing:
                _insert_run(conn, data, item["name"])
                downloaded += 1
    conn.commit()
    conn.close()
    # ... return response ...
```

### 3.2 `/api/poll` Endpoint (app.py:330-344)

**Current behavior**: Polls Devin API for session statuses, updates JSON files on disk via `save_session_updates()`.

**New behavior**: Updates `sessions` table directly:

```sql
UPDATE sessions SET status = ?, pr_url = ? WHERE session_id = ?
```

`devin_service.py`'s `save_session_updates()` is replaced by a `db_update_sessions()` function in `database.py`.

### 3.3 `/api/poll-prs` Endpoint (app.py:347-353)

**Current behavior**: Fetches PRs from GitHub, stores in `_Cache._prs`.

**New behavior**: Upserts into `prs` table:

```sql
INSERT INTO prs (pr_number, title, html_url, state, merged, created_at, repo, user, session_id, fetched_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(html_url) DO UPDATE SET
    state = excluded.state,
    merged = excluded.merged,
    session_id = excluded.session_id,
    fetched_at = excluded.fetched_at
```

### 3.4 `/api/backfill` Endpoint (app.py:417-456)

**Current behavior**: Patches JSON files on disk to fill in missing PR URLs and clean empty issue IDs.

**New behavior**: SQL updates directly:

```sql
-- Link PRs to sessions by issue ID
UPDATE sessions SET pr_url = (
    SELECT p.html_url FROM prs p
    JOIN pr_issue_ids pi ON pi.pr_id = p.id
    JOIN session_issue_ids si ON si.issue_id = pi.issue_id
    WHERE si.session_id = sessions.id
    LIMIT 1
) WHERE pr_url = '' AND EXISTS (
    SELECT 1 FROM session_issue_ids si
    JOIN pr_issue_ids pi ON pi.issue_id = si.issue_id
    WHERE si.session_id = sessions.id
);
```

### 3.5 External Write Path: `scripts/persist_telemetry.py`

This script runs in GitHub Actions and pushes JSON to the repo via the GitHub Contents API. **No changes needed** for the initial migration -- the `/api/refresh` endpoint already pulls these JSON files from GitHub and will now insert them into SQLite.

Future optimization: Add a `/api/ingest` endpoint that accepts a telemetry record directly via POST, allowing `persist_telemetry.py` to write to both the git repo (for backup) and the dashboard's SQLite DB simultaneously.

---

## 4. Read Path Changes (Query Layer)

### 4.1 `/api/runs` (app.py:288-293)

**Before**: `cache.get_runs()` loads all JSON, sorts in Python, paginates in Python.

**After**:
```sql
SELECT r.*,
    (SELECT json_group_object(severity_tier, cnt) FROM
        (SELECT severity_tier, COUNT(*) as cnt FROM issues WHERE run_id = r.id GROUP BY severity_tier)
    ) as severity_breakdown,
    (SELECT json_group_object(cwe_family, cnt) FROM
        (SELECT cwe_family, COUNT(*) as cnt FROM issues WHERE run_id = r.id GROUP BY cwe_family)
    ) as category_breakdown
FROM runs r
ORDER BY r.run_number DESC
LIMIT ? OFFSET ?
```

Pagination is now SQL-native (LIMIT/OFFSET) instead of loading all records and slicing.

### 4.2 `/api/sessions` (app.py:296-303)

**Before**: `aggregate_sessions(runs)` iterates all runs and flattens sessions. `link_prs_to_sessions` does a second pass.

**After**:
```sql
SELECT s.*, r.target_repo, r.fork_url, r.run_number, r.run_id as run_ext_id,
       r.run_url, r.run_label, r.timestamp
FROM sessions s
JOIN runs r ON s.run_id = r.id
ORDER BY r.timestamp DESC
LIMIT ? OFFSET ?
```

PR linking is already stored in `sessions.pr_url` (updated by `/api/poll`), eliminating the runtime join.

### 4.3 `/api/prs` (app.py:306-311)

**Before**: `cache.get_prs(runs)` calls GitHub API on cache miss.

**After**:
```sql
SELECT p.*,
    (SELECT json_group_array(issue_id) FROM pr_issue_ids WHERE pr_id = p.id) as issue_ids
FROM prs p
ORDER BY p.created_at DESC
LIMIT ? OFFSET ?
```

PR data is served from SQLite. The `/api/poll-prs` endpoint refreshes the `prs` table periodically.

### 4.4 `/api/stats` (app.py:314-319)

**Before**: `aggregate_stats(runs, sessions, prs)` iterates all records in Python.

**After**: Single SQL query:
```sql
SELECT
    COUNT(DISTINCT r.target_repo) as repos_scanned,
    COUNT(DISTINCT r.id) as total_runs,
    SUM(r.issues_found) as total_issues,
    (SELECT COUNT(*) FROM sessions WHERE session_id != '') as sessions_created,
    (SELECT COUNT(*) FROM sessions WHERE status = 'finished') as sessions_finished,
    (SELECT COUNT(*) FROM sessions WHERE pr_url != '') as sessions_with_pr,
    (SELECT COUNT(*) FROM prs) as prs_total,
    (SELECT COUNT(*) FROM prs WHERE merged = 1) as prs_merged,
    (SELECT COUNT(*) FROM prs WHERE state = 'open') as prs_open,
    (SELECT COUNT(*) FROM prs WHERE state = 'closed' AND merged = 0) as prs_closed
FROM runs r
```

For `latest_issues` / `latest_severity` / `latest_category` (stats from only the most recent run per repo):
```sql
WITH latest_runs AS (
    SELECT r.* FROM runs r
    INNER JOIN (
        SELECT target_repo, MAX(timestamp) as max_ts
        FROM runs GROUP BY target_repo
    ) lr ON r.target_repo = lr.target_repo AND r.timestamp = lr.max_ts
)
SELECT
    SUM(issues_found) as latest_issues
FROM latest_runs
```

### 4.5 `/api/repos` (app.py:322-327)

**Before**: `build_repos_dict(runs, sessions, prs)` does three full passes.

**After**:
```sql
SELECT
    r.target_repo as repo,
    MAX(r.fork_url) as fork_url,
    COUNT(DISTINCT r.id) as runs,
    SUM(r.issues_found) as issues_found,
    COUNT(DISTINCT CASE WHEN s.session_id != '' THEN s.id END) as sessions_created,
    COUNT(DISTINCT CASE WHEN s.status IN ('finished', 'stopped') THEN s.id END) as sessions_finished,
    MAX(r.timestamp) as last_run
FROM runs r
LEFT JOIN sessions s ON s.run_id = r.id
GROUP BY r.target_repo
ORDER BY last_run DESC
```

PR counts per repo require joining through fork URLs (same logic as current Python code, but in SQL).

### 4.6 `/api/issues` (app.py:459-467)

**Before**: `track_issues_across_runs(runs)` does O(runs * fingerprints) in-memory computation.

**After**: The issue tracking logic (new/recurring/fixed classification) translates to SQL:

```sql
WITH fingerprint_appearances AS (
    SELECT
        i.fingerprint,
        i.rule_id,
        i.severity_tier,
        i.cwe_family,
        i.file,
        i.start_line,
        i.description,
        i.resolution,
        i.code_churn,
        r.target_repo,
        r.run_number,
        r.timestamp,
        i.issue_ext_id,
        COUNT(*) OVER (PARTITION BY i.fingerprint) as appearance_count,
        ROW_NUMBER() OVER (PARTITION BY i.fingerprint ORDER BY r.timestamp ASC) as first_rank,
        ROW_NUMBER() OVER (PARTITION BY i.fingerprint ORDER BY r.timestamp DESC) as last_rank
    FROM issues i
    JOIN runs r ON i.run_id = r.id
),
latest_run_per_repo AS (
    SELECT target_repo, MAX(id) as latest_run_id
    FROM runs GROUP BY target_repo
),
latest_fingerprints AS (
    SELECT DISTINCT i.fingerprint
    FROM issues i
    JOIN latest_run_per_repo lr ON i.run_id = lr.latest_run_id
)
SELECT
    fa.fingerprint,
    fa.rule_id,
    fa.severity_tier,
    fa.cwe_family,
    fa.file,
    fa.start_line,
    fa.description,
    fa.resolution,
    fa.code_churn,
    fa.target_repo,
    fa.appearance_count as appearances,
    -- first/last seen
    FIRST_VALUE(fa.run_number) OVER (PARTITION BY fa.fingerprint ORDER BY fa.timestamp ASC) as first_seen_run,
    FIRST_VALUE(fa.timestamp) OVER (PARTITION BY fa.fingerprint ORDER BY fa.timestamp ASC) as first_seen_date,
    FIRST_VALUE(fa.run_number) OVER (PARTITION BY fa.fingerprint ORDER BY fa.timestamp DESC) as last_seen_run,
    FIRST_VALUE(fa.timestamp) OVER (PARTITION BY fa.fingerprint ORDER BY fa.timestamp DESC) as last_seen_date,
    -- status classification
    CASE
        WHEN lf.fingerprint IS NULL THEN 'fixed'
        WHEN fa.appearance_count > 1 THEN 'recurring'
        ELSE 'new'
    END as status
FROM fingerprint_appearances fa
LEFT JOIN latest_fingerprints lf ON fa.fingerprint = lf.fingerprint
WHERE fa.last_rank = 1  -- one row per fingerprint
ORDER BY
    CASE
        WHEN lf.fingerprint IS NULL THEN 2  -- fixed
        WHEN fa.appearance_count > 1 THEN 0  -- recurring
        ELSE 1  -- new
    END,
    fa.timestamp DESC
```

**Preserving `has_older_runs_without_fps` logic**: The current Python code in `issue_tracking.py` has a nuanced heuristic: if a repo has runs that predate fingerprinting (i.e., runs without `issue_fingerprints`), then even a single-appearance fingerprint is classified as `recurring` rather than `new`, because the issue may have existed in those earlier un-fingerprinted runs. The SQL query above preserves this by adding a subquery:

```sql
-- Add to the CTE chain:
runs_without_fps_per_repo AS (
    SELECT r.target_repo, COUNT(*) as cnt
    FROM runs r
    WHERE r.id NOT IN (SELECT DISTINCT run_id FROM issues)
    AND r.issues_found > 0
    GROUP BY r.target_repo
)
```

The status classification then becomes:
```sql
CASE
    WHEN lf.fingerprint IS NULL THEN 'fixed'
    WHEN fa.appearance_count > 1 THEN 'recurring'
    WHEN rwf.cnt > 0 THEN 'recurring'  -- older runs without fingerprints exist
    ELSE 'new'
END as status
```

This matches the existing Python behavior and is important because 3 of the 10 current runs (juice-shop runs 12-14) have `issues_found > 0` but no `issue_fingerprints`.

### 4.7 `/api/repo/<path:repo_url>` (app.py:225-285)

**Before**: Loads all data, filters by repo in Python.

**After**: All queries add `WHERE r.target_repo = ?` filter. SQL handles this efficiently via the `idx_runs_target_repo` index.

### 4.8 Full-Text Search (New Capability)

```sql
CREATE VIRTUAL TABLE issues_fts USING fts5(
    fingerprint, rule_id, file, description,
    content=issues, content_rowid=id
);

-- Triggers to keep FTS in sync
CREATE TRIGGER issues_ai AFTER INSERT ON issues BEGIN
    INSERT INTO issues_fts(rowid, fingerprint, rule_id, file, description)
    VALUES (new.id, new.fingerprint, new.rule_id, new.file, new.description);
END;
```

New endpoint:
```
GET /api/issues/search?q=xss+materialize&repo=...
```

---

## 5. Affected Files and Modules

### Files to Modify

| File | Change |
|------|--------|
| `telemetry/app.py` | Replace `_Cache` class and all `cache.*` calls with `database.py` queries. Remove `_load_runs_from_disk()`. Update all API endpoints. |
| `telemetry/config.py` | Add `DB_PATH` configuration. Keep `RUNS_DIR` for migration. |
| `telemetry/aggregation.py` | **Delete entirely.** `aggregate_sessions()`, `aggregate_stats()`, and `build_repos_dict()` are replaced by SQL queries. |
| `telemetry/issue_tracking.py` | **Delete entirely.** `track_issues_across_runs()` is replaced by the SQL query in section 4.6. |
| `telemetry/github_service.py` | Modify `fetch_prs_from_github()` to write results to `prs` table. `link_prs_to_sessions()` becomes a SQL UPDATE. `collect_session_ids()` becomes a SQL query. |
| `telemetry/devin_service.py` | Modify `poll_devin_sessions()` to read sessions from DB. Replace `save_session_updates()` with SQL UPDATE. |
| `telemetry/requirements.txt` | No new dependencies (sqlite3 is in Python stdlib). |
| `telemetry/.gitignore` | Add `telemetry.db` to prevent committing the database. |

### Files to Create

| File | Purpose |
|------|---------|
| `telemetry/database.py` | SQLite connection management, schema creation, query helpers. |
| `telemetry/migrate_json_to_sqlite.py` | One-time JSON-to-SQLite migration script. |
| `tests/test_database.py` | Tests for database module and migration. |
| `tests/test_app_sqlite.py` | Tests for updated API endpoints with SQLite backend. |

### Files Unchanged

| File | Reason |
|------|--------|
| `scripts/persist_telemetry.py` | Still pushes JSON to GitHub repo. Dashboard pulls via `/api/refresh`. |
| `telemetry/templates/*.html` | Dashboard UI fetches from the same API endpoints; response format stays the same. |
| `telemetry/static/*` | No frontend changes. |

---

## 6. Implementation Phases

### Phase 1: Foundation (database.py + migration)

1. Create `telemetry/database.py` with schema creation and connection helpers.
2. Create `telemetry/migrate_json_to_sqlite.py` with idempotent JSON migration.
3. Write tests for migration: verify all 10 existing JSON files produce correct rows.
4. Add `telemetry.db` to `.gitignore`.

### Phase 2: Read Path (query layer)

1. Create query functions in `database.py` for each API endpoint.
2. Update `app.py` endpoints one-by-one to use SQL queries instead of in-memory logic.
3. Maintain response format compatibility (same JSON structure returned to frontend).
4. Delete `aggregation.py` and `issue_tracking.py` after their logic is replaced.
5. Write tests for each query function.

### Phase 3: Write Path

1. Update `/api/refresh` to insert into SQLite.
2. Update `/api/poll` to update sessions in SQLite.
3. Update `/api/poll-prs` to upsert PRs into SQLite.
4. Update `/api/backfill` to use SQL updates.
5. Remove `_Cache` class from `app.py`.

### Phase 4: New Capabilities

1. Add FTS5 virtual table for issue search.
2. Add `/api/issues/search` endpoint.
3. Add time-range filtering to relevant endpoints (`?from=...&to=...`).

---

## 7. Cache Removal Plan

The `_Cache` class (app.py:109-174) manages three caches:

1. **Runs cache** (`_runs`, `_runs_fingerprint`): Replaced by SQLite. All run queries go directly to DB.
2. **PR cache** (`_prs`, `_prs_ts`): Replaced by `prs` table. TTL-based refresh becomes a periodic `/api/poll-prs` call (or a background thread).
3. **Polled sessions cache** (`_sessions_polled`, `_sessions_ts`): Replaced by `sessions` table. Session status is updated in-place.

After Phase 3 is complete, the `_Cache` class and all `cache.*` references can be deleted. The `_load_runs_from_disk()` function is also removed.

**TTL for external API freshness**: The current 120-second TTL for PR and session data is a rate-limiting mechanism for external API calls. This concern is orthogonal to storage. After the migration, implement a `last_refreshed` timestamp in a `metadata` table (or use `prs.fetched_at`) to decide when to re-poll external APIs.

---

## 8. API Response Compatibility

All API endpoints must return the **exact same JSON structure** as today. The frontend templates (`dashboard.html`, `repo.html`) and `shared.js` parse these responses. Any schema change in API responses would require coordinated frontend updates.

Specific compatibility requirements:

| Endpoint | Response field | Source today | Source after |
|----------|---------------|-------------|-------------|
| `/api/runs` | `items[].severity_breakdown` | JSON dict from file | SQL `GROUP BY` → dict |
| `/api/runs` | `items[].category_breakdown` | JSON dict from file | SQL `GROUP BY` → dict |
| `/api/sessions` | `items[].issue_ids` | Nested array | `session_issue_ids` → array |
| `/api/prs` | `items[].issue_ids` | Regex-extracted array | `pr_issue_ids` → array |
| `/api/stats` | All fields | `aggregate_stats()` | SQL aggregation |
| `/api/repos` | All fields | `build_repos_dict()` | SQL `GROUP BY` |
| `/api/issues` | All fields | `track_issues_across_runs()` | SQL window functions |

The query functions in `database.py` must transform SQL rows back into these exact dict structures.

---

## 9. Testing Strategy

### Unit Tests

- **`test_database.py`**: Schema creation, insert helpers, query functions. Use an in-memory SQLite DB (`:memory:`) for speed.
- **`test_migration.py`**: Feed the 10 existing JSON files through `migrate_json_files()`, verify row counts and data integrity.
- **`test_app_sqlite.py`**: Flask test client against the updated endpoints. Verify response format matches current behavior.

### Integration Tests

- Migrate existing JSON files, run all API endpoints, compare output against current (JSON-backed) output. This is the primary regression gate.
- Script approach: Start the old app, capture all endpoint responses. Start the new app (SQLite-backed), capture all endpoint responses. Diff.

### Data Integrity Checks

After migration, verify:
```sql
-- Total runs matches JSON file count
SELECT COUNT(*) FROM runs;  -- should equal number of .json files

-- Total issues per run matches issues_found
SELECT r.id, r.issues_found, COUNT(i.id) as actual
FROM runs r LEFT JOIN issues i ON i.run_id = r.id
GROUP BY r.id
HAVING r.issues_found != actual;  -- should return 0 rows

-- All sessions have valid run references
SELECT COUNT(*) FROM sessions WHERE run_id NOT IN (SELECT id FROM runs);  -- should be 0
```

---

## 10. Rollback Plan

1. **JSON files are preserved.** The migration does not delete JSON files from `telemetry/runs/`. They remain the source of truth until the migration is verified.
2. **Feature flag.** Add `USE_SQLITE=true|false` environment variable. When false, fall back to the current JSON + in-memory cache path. This enables instant rollback without a code deploy.
3. **Database reset.** Deleting `telemetry.db` and restarting the app triggers a fresh migration from JSON files.

---

## 11. Performance Expectations

| Operation | Current (JSON) | After (SQLite) |
|-----------|---------------|----------------|
| First request after restart | ~100ms (load all JSON) | ~1ms (DB already populated) |
| `/api/stats` | O(runs + sessions + PRs) | O(1) via indexed aggregation |
| `/api/issues` | O(runs × fingerprints) | O(fingerprints) via indexed query |
| `/api/runs?page=50` | Load all, slice in Python | `LIMIT 50 OFFSET 2450` |
| `/api/repo/<repo>` | Load all, filter in Python | Indexed `WHERE target_repo = ?` |
| Storage at 1000 runs | ~1000 JSON files + full in-memory copy | ~5MB SQLite file |
| Concurrent reads | Thread-safe via `_Cache._lock` | Native via WAL mode |

---

## 12. Deployment Considerations

- **SQLite file location**: Default `telemetry/telemetry.db`. Override via `TELEMETRY_DB_PATH` env var for containerized deployments where the app directory may be read-only.
- **Docker volume mount**: If deployed in Docker, mount a volume at the DB path for persistence across container restarts.
- **Backup**: `sqlite3 telemetry.db ".backup backup.db"` or simply copy the file (safe with WAL mode when no writers are active). The JSON files also serve as a natural backup.
- **Concurrency**: SQLite WAL mode supports unlimited concurrent readers with one writer. The Flask app runs single-process by default (Gunicorn with 1 worker). For multi-worker deployments, ensure all workers point to the same DB file and use WAL mode.
