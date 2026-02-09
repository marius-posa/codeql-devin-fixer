"""SQLite database module for the telemetry system.

Replaces the JSON-file + in-memory cache approach with a single SQLite
database.  WAL mode is enabled for concurrent reads.
"""

import json
import os
import pathlib
import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = pathlib.Path(
    os.environ.get(
        "TELEMETRY_DB_PATH",
        str(pathlib.Path(__file__).parent / "telemetry.db"),
    )
)

SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS runs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    target_repo         TEXT    NOT NULL,
    fork_url            TEXT    NOT NULL DEFAULT '',
    run_number          INTEGER NOT NULL,
    run_id              TEXT    NOT NULL DEFAULT '',
    run_url             TEXT    NOT NULL DEFAULT '',
    run_label           TEXT    NOT NULL DEFAULT '',
    timestamp           TEXT    NOT NULL,
    issues_found        INTEGER NOT NULL DEFAULT 0,
    batches_created     INTEGER NOT NULL DEFAULT 0,
    zero_issue_run      INTEGER NOT NULL DEFAULT 0,
    severity_breakdown  TEXT    NOT NULL DEFAULT '{}',
    category_breakdown  TEXT    NOT NULL DEFAULT '{}',
    source_file         TEXT    NOT NULL DEFAULT '',
    UNIQUE(run_label)
);

CREATE INDEX IF NOT EXISTS idx_runs_target_repo           ON runs(target_repo);
CREATE INDEX IF NOT EXISTS idx_runs_timestamp              ON runs(timestamp);
CREATE INDEX IF NOT EXISTS idx_runs_run_number             ON runs(run_number);
CREATE INDEX IF NOT EXISTS idx_runs_target_repo_timestamp  ON runs(target_repo, timestamp);

CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    session_id   TEXT    NOT NULL DEFAULT '',
    session_url  TEXT    NOT NULL DEFAULT '',
    batch_id     INTEGER,
    status       TEXT    NOT NULL DEFAULT 'unknown',
    pr_url       TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_run_id  ON sessions(run_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status  ON sessions(status);

CREATE TABLE IF NOT EXISTS session_issue_ids (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    issue_id   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_issue_ids_session ON session_issue_ids(session_id);
CREATE INDEX IF NOT EXISTS idx_session_issue_ids_issue   ON session_issue_ids(issue_id);

CREATE TABLE IF NOT EXISTS issues (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    issue_ext_id   TEXT    NOT NULL DEFAULT '',
    fingerprint    TEXT    NOT NULL,
    rule_id        TEXT    NOT NULL DEFAULT '',
    severity_tier  TEXT    NOT NULL DEFAULT 'unknown',
    cwe_family     TEXT    NOT NULL DEFAULT 'other',
    file           TEXT    NOT NULL DEFAULT '',
    start_line     INTEGER NOT NULL DEFAULT 0,
    description    TEXT    NOT NULL DEFAULT '',
    resolution     TEXT    NOT NULL DEFAULT '',
    code_churn     INTEGER NOT NULL DEFAULT 0,
    UNIQUE(run_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_issues_run_id      ON issues(run_id);
CREATE INDEX IF NOT EXISTS idx_issues_fingerprint ON issues(fingerprint);
CREATE INDEX IF NOT EXISTS idx_issues_rule_id     ON issues(rule_id);
CREATE INDEX IF NOT EXISTS idx_issues_severity    ON issues(severity_tier);
CREATE INDEX IF NOT EXISTS idx_issues_cwe_family  ON issues(cwe_family);
CREATE INDEX IF NOT EXISTS idx_issues_file        ON issues(file);

CREATE TABLE IF NOT EXISTS prs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pr_number   INTEGER NOT NULL,
    title       TEXT    NOT NULL DEFAULT '',
    html_url    TEXT    NOT NULL DEFAULT '',
    state       TEXT    NOT NULL DEFAULT '',
    merged      INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT '',
    repo        TEXT    NOT NULL DEFAULT '',
    user        TEXT    NOT NULL DEFAULT '',
    session_id  TEXT    NOT NULL DEFAULT '',
    fetched_at  TEXT    NOT NULL DEFAULT '',
    UNIQUE(html_url)
);

CREATE INDEX IF NOT EXISTS idx_prs_repo       ON prs(repo);
CREATE INDEX IF NOT EXISTS idx_prs_state      ON prs(state);
CREATE INDEX IF NOT EXISTS idx_prs_session_id ON prs(session_id);

CREATE TABLE IF NOT EXISTS pr_issue_ids (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    pr_id    INTEGER NOT NULL REFERENCES prs(id) ON DELETE CASCADE,
    issue_id TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pr_issue_ids_pr    ON pr_issue_ids(pr_id);
CREATE INDEX IF NOT EXISTS idx_pr_issue_ids_issue ON pr_issue_ids(issue_id);

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT    NOT NULL,
    user      TEXT    NOT NULL DEFAULT '',
    action    TEXT    NOT NULL,
    resource  TEXT    NOT NULL DEFAULT '',
    details   TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_user      ON audit_log(user);
CREATE INDEX IF NOT EXISTS idx_audit_log_action    ON audit_log(action);
"""

_FTS_SCHEMA_SQL = """\
CREATE VIRTUAL TABLE IF NOT EXISTS issues_fts USING fts5(
    fingerprint, rule_id, file, description,
    content=issues, content_rowid=id
);

CREATE TRIGGER IF NOT EXISTS issues_ai AFTER INSERT ON issues BEGIN
    INSERT INTO issues_fts(rowid, fingerprint, rule_id, file, description)
    VALUES (new.id, new.fingerprint, new.rule_id, new.file, new.description);
END;

CREATE TRIGGER IF NOT EXISTS issues_ad AFTER DELETE ON issues BEGIN
    INSERT INTO issues_fts(issues_fts, rowid, fingerprint, rule_id, file, description)
    VALUES ('delete', old.id, old.fingerprint, old.rule_id, old.file, old.description);
END;

CREATE TRIGGER IF NOT EXISTS issues_au AFTER UPDATE ON issues BEGIN
    INSERT INTO issues_fts(issues_fts, rowid, fingerprint, rule_id, file, description)
    VALUES ('delete', old.id, old.fingerprint, old.rule_id, old.file, old.description);
    INSERT INTO issues_fts(rowid, fingerprint, rule_id, file, description)
    VALUES (new.id, new.fingerprint, new.rule_id, new.file, new.description);
END;
"""


def _has_fts5(conn: sqlite3.Connection) -> bool:
    try:
        row = conn.execute(
            "SELECT 1 FROM pragma_compile_options WHERE compile_options LIKE '%FTS5%'"
        ).fetchone()
        return row is not None
    except sqlite3.OperationalError:
        return False


def get_connection(db_path: pathlib.Path | None = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
    conn.executescript(SCHEMA_SQL)
    if _has_fts5(conn):
        conn.executescript(_FTS_SCHEMA_SQL)
    if own_conn:
        conn.close()


def is_db_empty(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT COUNT(*) FROM runs").fetchone()
    return row[0] == 0


# ---------------------------------------------------------------------------
# Insert helpers
# ---------------------------------------------------------------------------

def insert_run(conn: sqlite3.Connection, data: dict, source_file: str = "") -> int | None:
    run_label = data.get("run_label", "")
    existing = conn.execute(
        "SELECT id FROM runs WHERE run_label = ?", (run_label,)
    ).fetchone()
    if existing:
        return None

    sev = data.get("severity_breakdown", {})
    cat = data.get("category_breakdown", {})
    cur = conn.execute(
        """INSERT INTO runs
           (target_repo, fork_url, run_number, run_id, run_url, run_label,
            timestamp, issues_found, batches_created, zero_issue_run,
            severity_breakdown, category_breakdown, source_file)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data.get("target_repo", ""),
            data.get("fork_url", ""),
            data.get("run_number", 0),
            data.get("run_id", ""),
            data.get("run_url", ""),
            run_label,
            data.get("timestamp", ""),
            data.get("issues_found", 0),
            data.get("batches_created", 0),
            int(bool(data.get("zero_issue_run", False))),
            json.dumps(sev) if isinstance(sev, dict) else str(sev),
            json.dumps(cat) if isinstance(cat, dict) else str(cat),
            source_file,
        ),
    )
    run_db_id = cur.lastrowid

    for s in data.get("sessions", []):
        sess_cur = conn.execute(
            """INSERT INTO sessions (run_id, session_id, session_url, batch_id, status, pr_url)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                run_db_id,
                s.get("session_id", ""),
                s.get("session_url", ""),
                s.get("batch_id"),
                s.get("status", "unknown"),
                s.get("pr_url", ""),
            ),
        )
        sess_db_id = sess_cur.lastrowid
        for iid in s.get("issue_ids", []):
            if iid:
                conn.execute(
                    "INSERT INTO session_issue_ids (session_id, issue_id) VALUES (?, ?)",
                    (sess_db_id, iid),
                )

    for iss in data.get("issue_fingerprints", []):
        fp = iss.get("fingerprint", "")
        if not fp:
            continue
        try:
            conn.execute(
                """INSERT INTO issues
                   (run_id, issue_ext_id, fingerprint, rule_id, severity_tier,
                    cwe_family, file, start_line, description, resolution, code_churn)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_db_id,
                    iss.get("id", ""),
                    fp,
                    iss.get("rule_id", ""),
                    iss.get("severity_tier", "unknown"),
                    iss.get("cwe_family", "other"),
                    iss.get("file", ""),
                    iss.get("start_line", 0),
                    iss.get("description", ""),
                    iss.get("resolution", ""),
                    iss.get("code_churn", 0),
                ),
            )
        except sqlite3.IntegrityError:
            pass

    return run_db_id


def upsert_pr(conn: sqlite3.Connection, pr: dict) -> int:
    html_url = pr.get("html_url", "")
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO prs (pr_number, title, html_url, state, merged,
                            created_at, repo, user, session_id, fetched_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(html_url) DO UPDATE SET
               state = excluded.state,
               merged = excluded.merged,
               session_id = excluded.session_id,
               fetched_at = excluded.fetched_at""",
        (
            pr.get("pr_number", 0),
            pr.get("title", ""),
            html_url,
            pr.get("state", ""),
            int(bool(pr.get("merged", False))),
            pr.get("created_at", ""),
            pr.get("repo", ""),
            pr.get("user", ""),
            pr.get("session_id", ""),
            now,
        ),
    )
    row = conn.execute("SELECT id FROM prs WHERE html_url = ?", (html_url,)).fetchone()
    pr_db_id = row["id"]

    conn.execute("DELETE FROM pr_issue_ids WHERE pr_id = ?", (pr_db_id,))
    for iid in pr.get("issue_ids", []):
        if iid:
            conn.execute(
                "INSERT INTO pr_issue_ids (pr_id, issue_id) VALUES (?, ?)",
                (pr_db_id, iid),
            )
    return pr_db_id


# ---------------------------------------------------------------------------
# Read helpers — runs
# ---------------------------------------------------------------------------

def _run_row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["severity_breakdown"] = json.loads(d.get("severity_breakdown") or "{}")
    d["category_breakdown"] = json.loads(d.get("category_breakdown") or "{}")
    d["zero_issue_run"] = bool(d.get("zero_issue_run", 0))
    d.pop("source_file", None)
    return d


def _build_run_item(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    d = _run_row_to_dict(row)
    run_db_id = row["id"]
    has_issues = conn.execute(
        "SELECT 1 FROM issues WHERE run_id = ? LIMIT 1", (run_db_id,)
    ).fetchone()
    if has_issues:
        sev_rows = conn.execute(
            "SELECT severity_tier, COUNT(*) as cnt FROM issues WHERE run_id = ? GROUP BY severity_tier",
            (run_db_id,),
        ).fetchall()
        d["severity_breakdown"] = {r["severity_tier"]: r["cnt"] for r in sev_rows}
        cat_rows = conn.execute(
            "SELECT cwe_family, COUNT(*) as cnt FROM issues WHERE run_id = ? GROUP BY cwe_family",
            (run_db_id,),
        ).fetchall()
        d["category_breakdown"] = {r["cwe_family"]: r["cnt"] for r in cat_rows}

    sess_rows = conn.execute(
        "SELECT * FROM sessions WHERE run_id = ?", (run_db_id,)
    ).fetchall()
    sessions_list = []
    for sr in sess_rows:
        iid_rows = conn.execute(
            "SELECT issue_id FROM session_issue_ids WHERE session_id = ?",
            (sr["id"],),
        ).fetchall()
        sessions_list.append({
            "session_id": sr["session_id"],
            "session_url": sr["session_url"],
            "batch_id": sr["batch_id"],
            "status": sr["status"],
            "issue_ids": [r["issue_id"] for r in iid_rows],
            "pr_url": sr["pr_url"],
        })
    d["sessions"] = sessions_list

    fps_rows = conn.execute(
        "SELECT * FROM issues WHERE run_id = ?", (run_db_id,)
    ).fetchall()
    d["issue_fingerprints"] = [
        {
            "id": fr["issue_ext_id"],
            "fingerprint": fr["fingerprint"],
            "rule_id": fr["rule_id"],
            "severity_tier": fr["severity_tier"],
            "cwe_family": fr["cwe_family"],
            "file": fr["file"],
            "start_line": fr["start_line"],
            "description": fr["description"],
            "resolution": fr["resolution"],
            "code_churn": fr["code_churn"],
        }
        for fr in fps_rows
    ]
    d.pop("id", None)
    return d


def query_runs(
    conn: sqlite3.Connection,
    page: int = 1,
    per_page: int = 50,
    target_repo: str = "",
) -> dict:
    where = ""
    params: list = []
    if target_repo:
        where = "WHERE r.target_repo = ?"
        params.append(target_repo)

    total_row = conn.execute(
        f"SELECT COUNT(*) FROM runs r {where}", params
    ).fetchone()
    total = total_row[0]

    offset = (page - 1) * per_page
    params_q = list(params) + [per_page, offset]
    rows = conn.execute(
        f"""SELECT r.* FROM runs r
            {where}
            ORDER BY r.run_number DESC
            LIMIT ? OFFSET ?""",
        params_q,
    ).fetchall()

    items = [_build_run_item(conn, row) for row in rows]
    pages = max(1, (total + per_page - 1) // per_page)
    return {"items": items, "page": page, "per_page": per_page, "total": total, "pages": pages}


def query_all_runs(conn: sqlite3.Connection, target_repo: str = "") -> list[dict]:
    where = ""
    params: list = []
    if target_repo:
        where = "WHERE r.target_repo = ?"
        params.append(target_repo)
    rows = conn.execute(
        f"SELECT r.* FROM runs r {where} ORDER BY r.run_number DESC", params
    ).fetchall()
    return [_build_run_item(conn, row) for row in rows]


# ---------------------------------------------------------------------------
# Read helpers — sessions
# ---------------------------------------------------------------------------

def _build_session_item(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    iid_rows = conn.execute(
        "SELECT issue_id FROM session_issue_ids WHERE session_id = ?",
        (row["id"],),
    ).fetchall()
    return {
        "session_id": row["session_id"],
        "session_url": row["session_url"],
        "batch_id": row["batch_id"],
        "status": row["status"],
        "issue_ids": [r["issue_id"] for r in iid_rows],
        "target_repo": row["target_repo"],
        "fork_url": row["fork_url"],
        "run_number": row["run_number"],
        "run_id": row["run_ext_id"],
        "run_url": row["run_url"],
        "run_label": row["run_label"],
        "timestamp": row["timestamp"],
        "pr_url": row["pr_url"],
    }


def query_sessions(
    conn: sqlite3.Connection,
    page: int = 1,
    per_page: int = 50,
    target_repo: str = "",
) -> dict:
    where = ""
    params: list = []
    if target_repo:
        where = "WHERE r.target_repo = ?"
        params.append(target_repo)

    total_row = conn.execute(
        f"SELECT COUNT(*) FROM sessions s JOIN runs r ON s.run_id = r.id {where}",
        params,
    ).fetchone()
    total = total_row[0]

    offset = (page - 1) * per_page
    params_q = list(params) + [per_page, offset]
    rows = conn.execute(
        f"""SELECT s.*, r.target_repo, r.fork_url, r.run_number,
                   r.run_id as run_ext_id, r.run_url, r.run_label, r.timestamp
            FROM sessions s
            JOIN runs r ON s.run_id = r.id
            {where}
            ORDER BY r.timestamp DESC
            LIMIT ? OFFSET ?""",
        params_q,
    ).fetchall()

    items = [_build_session_item(conn, row) for row in rows]
    pages = max(1, (total + per_page - 1) // per_page)
    return {"items": items, "page": page, "per_page": per_page, "total": total, "pages": pages}


def query_all_sessions(conn: sqlite3.Connection, target_repo: str = "") -> list[dict]:
    where = ""
    params: list = []
    if target_repo:
        where = "WHERE r.target_repo = ?"
        params.append(target_repo)
    rows = conn.execute(
        f"""SELECT s.*, r.target_repo, r.fork_url, r.run_number,
                   r.run_id as run_ext_id, r.run_url, r.run_label, r.timestamp
            FROM sessions s
            JOIN runs r ON s.run_id = r.id
            {where}
            ORDER BY r.timestamp DESC""",
        params,
    ).fetchall()
    return [_build_session_item(conn, row) for row in rows]


# ---------------------------------------------------------------------------
# Read helpers — PRs
# ---------------------------------------------------------------------------

def _build_pr_item(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    iid_rows = conn.execute(
        "SELECT issue_id FROM pr_issue_ids WHERE pr_id = ?", (row["id"],)
    ).fetchall()
    return {
        "pr_number": row["pr_number"],
        "title": row["title"],
        "html_url": row["html_url"],
        "state": row["state"],
        "merged": bool(row["merged"]),
        "created_at": row["created_at"],
        "repo": row["repo"],
        "issue_ids": [r["issue_id"] for r in iid_rows],
        "user": row["user"],
        "session_id": row["session_id"],
    }


def query_prs(
    conn: sqlite3.Connection,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    total_row = conn.execute("SELECT COUNT(*) FROM prs").fetchone()
    total = total_row[0]
    offset = (page - 1) * per_page
    rows = conn.execute(
        "SELECT * FROM prs ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    ).fetchall()
    items = [_build_pr_item(conn, row) for row in rows]
    pages = max(1, (total + per_page - 1) // per_page)
    return {"items": items, "page": page, "per_page": per_page, "total": total, "pages": pages}


def query_all_prs(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM prs ORDER BY created_at DESC").fetchall()
    return [_build_pr_item(conn, row) for row in rows]


# ---------------------------------------------------------------------------
# Read helpers — stats
# ---------------------------------------------------------------------------

def query_stats(conn: sqlite3.Connection, target_repo: str = "", period: str = "all") -> dict:
    cutoff = ""
    if period and period != "all":
        days_map = {"7d": 7, "30d": 30, "90d": 90}
        days = days_map.get(period)
        if days:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    where_parts = []
    params: list = []
    if target_repo:
        where_parts.append("r.target_repo = ?")
        params.append(target_repo)
    if cutoff:
        where_parts.append("r.timestamp >= ?")
        params.append(cutoff)
    where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

    row = conn.execute(
        f"""SELECT
                COUNT(DISTINCT r.target_repo) as repos_scanned,
                COUNT(DISTINCT r.id) as total_runs,
                COALESCE(SUM(r.issues_found), 0) as total_issues
            FROM runs r {where}""",
        params,
    ).fetchone()
    repos_scanned = row["repos_scanned"]
    total_runs = row["total_runs"]
    total_issues = row["total_issues"]

    repo_rows = conn.execute(
        f"SELECT DISTINCT r.target_repo FROM runs r {where}", params
    ).fetchall()
    repo_list = sorted(r["target_repo"] for r in repo_rows)

    sess_where = where.replace("r.", "r2.") if where else ""
    sess_params = list(params)
    s_row = conn.execute(
        f"""SELECT
                COUNT(CASE WHEN s.session_id != '' THEN 1 END) as sessions_created,
                COUNT(CASE WHEN s.status = 'finished' THEN 1 END) as sessions_finished,
                COUNT(CASE WHEN s.pr_url != '' THEN 1 END) as sessions_with_pr
            FROM sessions s
            JOIN runs r2 ON s.run_id = r2.id
            {sess_where}""",
        sess_params,
    ).fetchone()
    sessions_created = s_row["sessions_created"]
    sessions_finished = s_row["sessions_finished"]
    sessions_with_pr = s_row["sessions_with_pr"]

    all_prs = query_all_prs(conn)
    if cutoff:
        session_ids_in_period = set()
        all_issue_ids_in_period = set()
        sess_rows = conn.execute(
            f"""SELECT s.session_id, s.id as sid FROM sessions s
                JOIN runs r2 ON s.run_id = r2.id {sess_where}""",
            sess_params,
        ).fetchall()
        for sr in sess_rows:
            if sr["session_id"]:
                session_ids_in_period.add(sr["session_id"])
            iids = conn.execute(
                "SELECT issue_id FROM session_issue_ids WHERE session_id = ?",
                (sr["sid"],),
            ).fetchall()
            for iid in iids:
                all_issue_ids_in_period.add(iid["issue_id"])
        filtered_prs = [
            p for p in all_prs
            if p.get("session_id") in session_ids_in_period
            or any(pid in all_issue_ids_in_period for pid in p.get("issue_ids", []))
        ]
    else:
        filtered_prs = all_prs

    pr_merged = sum(1 for p in filtered_prs if p.get("merged", False))
    pr_open = sum(1 for p in filtered_prs if p.get("state") == "open")
    pr_closed = sum(1 for p in filtered_prs if p.get("state") == "closed" and not p.get("merged", False))

    severity_agg: dict[str, int] = {}
    category_agg: dict[str, int] = {}
    run_rows = conn.execute(
        f"SELECT r.severity_breakdown, r.category_breakdown FROM runs r {where}", params
    ).fetchall()
    for rr in run_rows:
        for tier, count in json.loads(rr["severity_breakdown"] or "{}").items():
            severity_agg[tier] = severity_agg.get(tier, 0) + count
        for cat, count in json.loads(rr["category_breakdown"] or "{}").items():
            category_agg[cat] = category_agg.get(cat, 0) + count

    latest_rows = conn.execute(
        f"""SELECT lr.* FROM runs lr
            INNER JOIN (
                SELECT target_repo, MAX(timestamp) as max_ts
                FROM runs r {where}
                GROUP BY target_repo
            ) sub ON lr.target_repo = sub.target_repo AND lr.timestamp = sub.max_ts""",
        params,
    ).fetchall()
    latest_issues = sum(r["issues_found"] for r in latest_rows)
    latest_severity: dict[str, int] = {}
    latest_category: dict[str, int] = {}
    for r in latest_rows:
        for tier, count in json.loads(r["severity_breakdown"] or "{}").items():
            latest_severity[tier] = latest_severity.get(tier, 0) + count
        for cat, count in json.loads(r["category_breakdown"] or "{}").items():
            latest_category[cat] = latest_category.get(cat, 0) + count

    return {
        "repos_scanned": repos_scanned,
        "repo_list": repo_list,
        "total_runs": total_runs,
        "total_issues": total_issues,
        "latest_issues": latest_issues,
        "latest_severity": latest_severity,
        "latest_category": latest_category,
        "sessions_created": sessions_created,
        "sessions_finished": sessions_finished,
        "sessions_with_pr": sessions_with_pr,
        "prs_total": len(filtered_prs),
        "prs_merged": pr_merged,
        "prs_open": pr_open,
        "prs_closed": pr_closed,
        "fix_rate": round(pr_merged / max(len(filtered_prs), 1) * 100, 1),
        "severity_breakdown": severity_agg,
        "category_breakdown": category_agg,
    }


# ---------------------------------------------------------------------------
# Read helpers — repos
# ---------------------------------------------------------------------------

def query_repos(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """SELECT
               r.target_repo as repo,
               MAX(r.fork_url) as fork_url,
               COUNT(DISTINCT r.id) as runs,
               COALESCE(SUM(r.issues_found), 0) as issues_found,
               COUNT(DISTINCT CASE WHEN s.session_id != '' THEN s.id END) as sessions_created,
               COUNT(DISTINCT CASE WHEN s.status IN ('finished', 'stopped') THEN s.id END) as sessions_finished,
               MAX(r.timestamp) as last_run
           FROM runs r
           LEFT JOIN sessions s ON s.run_id = r.id
           GROUP BY r.target_repo
           ORDER BY last_run DESC"""
    ).fetchall()

    all_prs = query_all_prs(conn)
    repos_list = []
    for row in rows:
        repo = row["repo"]
        fork_url = row["fork_url"]

        sev_agg: dict[str, int] = {}
        cat_agg: dict[str, int] = {}
        run_rows = conn.execute(
            "SELECT severity_breakdown, category_breakdown FROM runs WHERE target_repo = ?",
            (repo,),
        ).fetchall()
        for rr in run_rows:
            for tier, count in json.loads(rr["severity_breakdown"] or "{}").items():
                sev_agg[tier] = sev_agg.get(tier, 0) + count
            for cat, count in json.loads(rr["category_breakdown"] or "{}").items():
                cat_agg[cat] = cat_agg.get(cat, 0) + count

        repo_prs = [
            p for p in all_prs
            if fork_url and p.get("repo", "") and p["repo"] in fork_url
        ]
        prs_total = len(repo_prs)
        prs_merged = sum(1 for p in repo_prs if p.get("merged"))
        prs_open = sum(1 for p in repo_prs if p.get("state") == "open")

        repos_list.append({
            "repo": repo,
            "fork_url": fork_url,
            "runs": row["runs"],
            "issues_found": row["issues_found"],
            "sessions_created": row["sessions_created"],
            "sessions_finished": row["sessions_finished"],
            "prs_total": prs_total,
            "prs_merged": prs_merged,
            "prs_open": prs_open,
            "severity_breakdown": sev_agg,
            "category_breakdown": cat_agg,
            "last_run": row["last_run"],
        })
    return repos_list


# ---------------------------------------------------------------------------
# Read helpers — issues (cross-run tracking)
# ---------------------------------------------------------------------------

def query_issues(conn: sqlite3.Connection, target_repo: str = "") -> list[dict]:
    where = ""
    params: list = []
    if target_repo:
        where = "WHERE r.target_repo = ?"
        params.append(target_repo)

    rows = conn.execute(
        f"""SELECT i.*, r.target_repo, r.run_number, r.timestamp, r.id as db_run_id
            FROM issues i
            JOIN runs r ON i.run_id = r.id
            {where}
            ORDER BY r.timestamp ASC""",
        params,
    ).fetchall()

    fp_history: dict[str, list[dict]] = {}
    fp_metadata: dict[str, dict] = {}
    for row in rows:
        fp = row["fingerprint"]
        if fp not in fp_history:
            fp_history[fp] = []
        fp_history[fp].append({
            "run_number": row["run_number"],
            "timestamp": row["timestamp"],
            "issue_id": row["issue_ext_id"],
            "target_repo": row["target_repo"],
        })
        if fp not in fp_metadata:
            fp_metadata[fp] = {
                "rule_id": row["rule_id"],
                "severity_tier": row["severity_tier"],
                "cwe_family": row["cwe_family"],
                "file": row["file"],
                "start_line": row["start_line"],
                "description": row["description"],
                "resolution": row["resolution"],
                "code_churn": row["code_churn"],
            }

    repo_filter_sql = "WHERE r.target_repo = ?" if target_repo else ""
    repo_params = [target_repo] if target_repo else []

    runs_per_repo: dict[str, int] = {}
    runs_with_fps_per_repo: dict[str, int] = {}
    all_runs = conn.execute(
        f"SELECT r.id, r.target_repo FROM runs r {repo_filter_sql}", repo_params
    ).fetchall()
    for ar in all_runs:
        repo = ar["target_repo"]
        runs_per_repo[repo] = runs_per_repo.get(repo, 0) + 1
        has_fps = conn.execute(
            "SELECT 1 FROM issues WHERE run_id = ? LIMIT 1", (ar["id"],)
        ).fetchone()
        if has_fps:
            runs_with_fps_per_repo[repo] = runs_with_fps_per_repo.get(repo, 0) + 1

    latest_run_per_repo: dict[str, int] = {}
    latest_where = "WHERE" if not repo_filter_sql else repo_filter_sql + " AND"
    lr_rows = conn.execute(
        f"SELECT target_repo, id as latest_run_id FROM runs r {latest_where} id IN (SELECT r2.id FROM runs r2 WHERE r2.target_repo = r.target_repo ORDER BY r2.timestamp DESC LIMIT 1)",
        repo_params,
    ).fetchall()
    for lr in lr_rows:
        latest_run_per_repo[lr["target_repo"]] = lr["latest_run_id"]

    latest_fps: set[str] = set()
    for repo, run_id in latest_run_per_repo.items():
        fp_rows = conn.execute(
            "SELECT DISTINCT fingerprint FROM issues WHERE run_id = ?", (run_id,)
        ).fetchall()
        for fr in fp_rows:
            latest_fps.add(fr["fingerprint"])

    from issue_tracking import compute_sla_status, _parse_ts

    result: list[dict] = []
    for fp, appearances in fp_history.items():
        first = appearances[0]
        latest = appearances[-1]
        run_numbers = [a["run_number"] for a in appearances]
        repo = first["target_repo"]

        has_older_runs_without_fps = (
            runs_per_repo.get(repo, 0) > runs_with_fps_per_repo.get(repo, 0)
        )

        if fp in latest_fps:
            if len(appearances) > 1 or has_older_runs_without_fps:
                status = "recurring"
            else:
                status = "new"
        else:
            status = "fixed"

        meta = fp_metadata.get(fp, {})

        fix_duration_hours = None
        if status == "fixed":
            first_ts = _parse_ts(first["timestamp"])
            latest_ts = _parse_ts(latest["timestamp"])
            if first_ts and latest_ts:
                delta = latest_ts - first_ts
                fix_duration_hours = round(delta.total_seconds() / 3600, 1)

        found_at_ts = _parse_ts(first["timestamp"])
        fixed_at_ts = _parse_ts(latest["timestamp"]) if status == "fixed" else None
        sla = compute_sla_status(
            meta.get("severity_tier", ""), found_at_ts, fixed_at_ts,
        )

        result.append({
            "fingerprint": fp,
            "rule_id": meta.get("rule_id", ""),
            "severity_tier": meta.get("severity_tier", ""),
            "cwe_family": meta.get("cwe_family", ""),
            "file": meta.get("file", ""),
            "start_line": meta.get("start_line", 0),
            "description": meta.get("description", ""),
            "resolution": meta.get("resolution", ""),
            "code_churn": meta.get("code_churn", 0),
            "status": status,
            "first_seen_run": first["run_number"],
            "first_seen_date": first["timestamp"],
            "last_seen_run": latest["run_number"],
            "last_seen_date": latest["timestamp"],
            "target_repo": repo,
            "appearances": len(appearances),
            "run_numbers": run_numbers,
            "latest_issue_id": latest["issue_id"],
            "fix_duration_hours": fix_duration_hours,
            "found_at": first["timestamp"],
            "fixed_at": latest["timestamp"] if status == "fixed" else None,
            "sla_status": sla["sla_status"],
            "sla_limit_hours": sla["sla_limit_hours"],
            "sla_hours_elapsed": sla["sla_hours_elapsed"],
            "sla_hours_remaining": sla["sla_hours_remaining"],
        })

    _STATUS_ORDER = {"recurring": 0, "new": 1, "fixed": 2}
    result.sort(key=lambda x: (
        _STATUS_ORDER.get(x["status"], 3),
        x.get("last_seen_date", ""),
    ))
    return result


# ---------------------------------------------------------------------------
# Read helpers — FTS search
# ---------------------------------------------------------------------------

def search_issues(conn: sqlite3.Connection, query: str, target_repo: str = "") -> list[dict]:
    if not _has_fts5(conn):
        return []
    try:
        conn.execute("SELECT 1 FROM issues_fts LIMIT 0")
    except sqlite3.OperationalError:
        return []

    fts_rows = conn.execute(
        "SELECT rowid, rank FROM issues_fts WHERE issues_fts MATCH ? ORDER BY rank LIMIT 100",
        (query,),
    ).fetchall()
    if not fts_rows:
        return []

    rowids = [r["rowid"] for r in fts_rows]
    placeholders = ",".join("?" * len(rowids))
    issue_rows = conn.execute(
        f"""SELECT i.*, r.target_repo, r.run_number, r.timestamp
            FROM issues i JOIN runs r ON i.run_id = r.id
            WHERE i.id IN ({placeholders})""",
        rowids,
    ).fetchall()

    if target_repo:
        issue_rows = [r for r in issue_rows if r["target_repo"] == target_repo]

    return [
        {
            "fingerprint": r["fingerprint"],
            "rule_id": r["rule_id"],
            "severity_tier": r["severity_tier"],
            "cwe_family": r["cwe_family"],
            "file": r["file"],
            "start_line": r["start_line"],
            "description": r["description"],
            "target_repo": r["target_repo"],
            "run_number": r["run_number"],
            "timestamp": r["timestamp"],
        }
        for r in issue_rows
    ]


# ---------------------------------------------------------------------------
# Write helpers — session / PR updates
# ---------------------------------------------------------------------------

def update_session(conn: sqlite3.Connection, session_id: str, status: str = "", pr_url: str = "") -> bool:
    parts = []
    params: list = []
    if status:
        parts.append("status = ?")
        params.append(status)
    if pr_url:
        parts.append("pr_url = ?")
        params.append(pr_url)
    if not parts:
        return False
    params.append(session_id)
    cur = conn.execute(
        f"UPDATE sessions SET {', '.join(parts)} WHERE session_id = ?",
        params,
    )
    return cur.rowcount > 0


def backfill_pr_urls(conn: sqlite3.Connection) -> int:
    patched = 0
    sessions = conn.execute(
        "SELECT s.id, s.session_id FROM sessions s WHERE s.pr_url = ''"
    ).fetchall()
    for s in sessions:
        iid_rows = conn.execute(
            "SELECT issue_id FROM session_issue_ids WHERE session_id = ?",
            (s["id"],),
        ).fetchall()
        for iid_row in iid_rows:
            pr_row = conn.execute(
                """SELECT p.html_url FROM prs p
                   JOIN pr_issue_ids pi ON pi.pr_id = p.id
                   WHERE pi.issue_id = ?
                   LIMIT 1""",
                (iid_row["issue_id"],),
            ).fetchone()
            if pr_row:
                conn.execute(
                    "UPDATE sessions SET pr_url = ? WHERE id = ?",
                    (pr_row["html_url"], s["id"]),
                )
                patched += 1
                break
    return patched


def collect_session_ids_from_db(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT DISTINCT session_id FROM sessions WHERE session_id != '' AND session_id != 'dry-run'"
    ).fetchall()
    ids: set[str] = set()
    for r in rows:
        sid = r["session_id"]
        clean = sid.replace("devin-", "") if sid.startswith("devin-") else sid
        ids.add(clean)
    return ids


# ---------------------------------------------------------------------------
# Audit log helpers
# ---------------------------------------------------------------------------

def insert_audit_log(
    conn: sqlite3.Connection,
    user: str,
    action: str,
    resource: str = "",
    details: str = "",
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """INSERT INTO audit_log (timestamp, user, action, resource, details)
           VALUES (?, ?, ?, ?, ?)""",
        (now, user, action, resource, details),
    )
    conn.commit()
    return cur.lastrowid or 0


def query_audit_logs(
    conn: sqlite3.Connection,
    page: int = 1,
    per_page: int = 50,
    action_filter: str = "",
    user_filter: str = "",
) -> dict:
    conditions: list[str] = []
    params: list[str] = []
    if action_filter:
        conditions.append("action = ?")
        params.append(action_filter)
    if user_filter:
        conditions.append("user = ?")
        params.append(user_filter)

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    total_row = conn.execute(
        f"SELECT COUNT(*) FROM audit_log {where}", params
    ).fetchone()
    total = total_row[0]

    offset = (page - 1) * per_page
    rows = conn.execute(
        f"""SELECT * FROM audit_log {where}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?""",
        params + [per_page, offset],
    ).fetchall()

    items = [dict(r) for r in rows]
    pages = max(1, (total + per_page - 1) // per_page)
    return {"items": items, "page": page, "per_page": per_page, "total": total, "pages": pages}


def export_audit_logs(
    conn: sqlite3.Connection,
    since: str = "",
) -> list[dict]:
    if since:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE timestamp >= ? ORDER BY timestamp",
            (since,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp"
        ).fetchall()
    return [dict(r) for r in rows]


def auto_export_audit_log(conn: sqlite3.Connection, logs_dir: str = "") -> str:
    if not logs_dir:
        logs_dir = str(pathlib.Path(__file__).resolve().parent.parent / "logs")
    log_path = pathlib.Path(logs_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    entries = export_audit_logs(conn)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = log_path / f"audit-log-{ts}.json"
    with open(out, "w") as f:
        import json as _json
        _json.dump({"exported_at": ts, "entries": entries}, f, indent=2)
        f.write("\n")
    return str(out)


def collect_search_repos_from_db(conn: sqlite3.Connection) -> set[str]:
    from urllib.parse import urlparse
    rows = conn.execute(
        "SELECT DISTINCT target_repo, fork_url FROM runs"
    ).fetchall()
    repos: set[str] = set()
    for row in rows:
        for url_field in (row["target_repo"], row["fork_url"]):
            parsed = urlparse(url_field)
            if parsed.hostname == "github.com":
                path = parsed.path.strip("/")
                if path:
                    repos.add(path)
    return repos
