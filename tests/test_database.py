"""Unit tests for telemetry/database.py — SQLite schema, insert helpers, and query functions."""

import json
import os
import pathlib
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

import pytest
from database import (
    get_connection,
    init_db,
    is_db_empty,
    insert_run,
    upsert_pr,
    query_runs,
    query_all_runs,
    query_sessions,
    query_all_sessions,
    query_prs,
    query_all_prs,
    query_stats,
    query_repos,
    query_issues,
    search_issues,
    update_session,
    backfill_pr_urls,
    collect_session_ids_from_db,
    collect_search_repos_from_db,
)


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = pathlib.Path(tmpdir) / "test.db"
        conn = get_connection(db_path)
        init_db(conn)
        yield conn
        conn.close()


def _sample_run(run_number=1, repo="https://github.com/owner/repo", label=None):
    return {
        "target_repo": repo,
        "fork_url": "https://github.com/fork/repo",
        "run_number": run_number,
        "run_id": f"id-{run_number}",
        "run_url": f"https://github.com/owner/repo/actions/runs/{run_number}",
        "run_label": label or f"owner_repo_run_{run_number}_20260101_120000",
        "timestamp": f"2026-01-{run_number:02d}T12:00:00Z",
        "issues_found": 3,
        "batches_created": 1,
        "zero_issue_run": False,
        "severity_breakdown": {"high": 2, "medium": 1},
        "category_breakdown": {"injection": 2, "xss": 1},
        "sessions": [
            {
                "session_id": f"sess-{run_number}-1",
                "session_url": f"https://app.devin.ai/sessions/sess-{run_number}-1",
                "batch_id": 1,
                "status": "finished",
                "issue_ids": [f"CQLF-R{run_number}-0001", f"CQLF-R{run_number}-0002"],
                "pr_url": "",
            }
        ],
        "issue_fingerprints": [
            {
                "fingerprint": f"fp-{run_number}-a",
                "id": f"CQLF-R{run_number}-0001",
                "rule_id": "js/sql-injection",
                "severity_tier": "high",
                "cwe_family": "injection",
                "file": "src/db.js",
                "start_line": 42,
                "description": "SQL injection in query",
                "resolution": "Use parameterized queries",
                "code_churn": 5,
            },
            {
                "fingerprint": f"fp-{run_number}-b",
                "id": f"CQLF-R{run_number}-0002",
                "rule_id": "js/xss",
                "severity_tier": "medium",
                "cwe_family": "xss",
                "file": "src/view.js",
                "start_line": 10,
                "description": "XSS in template",
                "resolution": "Escape output",
                "code_churn": 2,
            },
        ],
    }


class TestSchema:
    def test_tables_created(self, db):
        tables = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        assert "runs" in tables
        assert "sessions" in tables
        assert "session_issue_ids" in tables
        assert "issues" in tables
        assert "prs" in tables
        assert "pr_issue_ids" in tables
        assert "metadata" in tables

    def test_wal_mode(self, db):
        row = db.execute("PRAGMA journal_mode").fetchone()
        assert row[0] == "wal"

    def test_foreign_keys_on(self, db):
        row = db.execute("PRAGMA foreign_keys").fetchone()
        assert row[0] == 1

    def test_empty_db(self, db):
        assert is_db_empty(db) is True


class TestInsertRun:
    def test_insert_and_retrieve(self, db):
        run_id = insert_run(db, _sample_run(), "file1.json")
        db.commit()
        assert run_id is not None
        assert not is_db_empty(db)
        row = db.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        assert row["run_number"] == 1
        assert row["target_repo"] == "https://github.com/owner/repo"

    def test_idempotent_insert(self, db):
        data = _sample_run()
        first = insert_run(db, data, "f.json")
        db.commit()
        second = insert_run(db, data, "f.json")
        assert first is not None
        assert second is None
        count = db.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        assert count == 1

    def test_sessions_inserted(self, db):
        run_id = insert_run(db, _sample_run(), "f.json")
        db.commit()
        sessions = db.execute("SELECT * FROM sessions WHERE run_id = ?", (run_id,)).fetchall()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "sess-1-1"

    def test_session_issue_ids_inserted(self, db):
        run_id = insert_run(db, _sample_run(), "f.json")
        db.commit()
        sess = db.execute("SELECT id FROM sessions WHERE run_id = ?", (run_id,)).fetchone()
        iids = db.execute(
            "SELECT issue_id FROM session_issue_ids WHERE session_id = ?", (sess["id"],)
        ).fetchall()
        assert len(iids) == 2
        assert {r["issue_id"] for r in iids} == {"CQLF-R1-0001", "CQLF-R1-0002"}

    def test_issue_fingerprints_inserted(self, db):
        run_id = insert_run(db, _sample_run(), "f.json")
        db.commit()
        issues = db.execute("SELECT * FROM issues WHERE run_id = ?", (run_id,)).fetchall()
        assert len(issues) == 2
        fps = {r["fingerprint"] for r in issues}
        assert fps == {"fp-1-a", "fp-1-b"}

    def test_severity_breakdown_stored_as_json(self, db):
        run_id = insert_run(db, _sample_run(), "f.json")
        db.commit()
        row = db.execute("SELECT severity_breakdown FROM runs WHERE id = ?", (run_id,)).fetchone()
        parsed = json.loads(row["severity_breakdown"])
        assert parsed == {"high": 2, "medium": 1}


class TestUpsertPr:
    def test_insert_pr(self, db):
        pr_id = upsert_pr(db, {
            "pr_number": 42,
            "title": "Fix injection",
            "html_url": "https://github.com/owner/repo/pull/42",
            "state": "open",
            "merged": False,
            "created_at": "2026-01-01T00:00:00Z",
            "repo": "fork/repo",
            "user": "devin",
            "session_id": "sess-1",
            "issue_ids": ["CQLF-R1-0001"],
        })
        db.commit()
        assert pr_id is not None
        row = db.execute("SELECT * FROM prs WHERE id = ?", (pr_id,)).fetchone()
        assert row["title"] == "Fix injection"

    def test_upsert_updates_existing(self, db):
        pr_data = {
            "pr_number": 42,
            "title": "Fix injection",
            "html_url": "https://github.com/owner/repo/pull/42",
            "state": "open",
            "merged": False,
            "created_at": "2026-01-01T00:00:00Z",
            "repo": "fork/repo",
            "user": "devin",
            "session_id": "",
            "issue_ids": [],
        }
        upsert_pr(db, pr_data)
        db.commit()
        pr_data["state"] = "closed"
        pr_data["merged"] = True
        upsert_pr(db, pr_data)
        db.commit()
        count = db.execute("SELECT COUNT(*) FROM prs").fetchone()[0]
        assert count == 1
        row = db.execute("SELECT state, merged FROM prs").fetchone()
        assert row["state"] == "closed"
        assert row["merged"] == 1


class TestQueryRuns:
    def test_paginated(self, db):
        for i in range(1, 6):
            insert_run(db, _sample_run(run_number=i, label=f"run-{i}"), f"f{i}.json")
        db.commit()
        result = query_runs(db, page=1, per_page=2)
        assert result["total"] == 5
        assert len(result["items"]) == 2
        assert result["pages"] == 3
        assert result["items"][0]["run_number"] == 5

    def test_filter_by_repo(self, db):
        insert_run(db, _sample_run(run_number=1, repo="https://github.com/a/b", label="r1"), "f1.json")
        insert_run(db, _sample_run(run_number=2, repo="https://github.com/c/d", label="r2"), "f2.json")
        db.commit()
        result = query_runs(db, target_repo="https://github.com/a/b")
        assert result["total"] == 1

    def test_includes_sessions_and_fingerprints(self, db):
        insert_run(db, _sample_run(), "f.json")
        db.commit()
        result = query_runs(db)
        item = result["items"][0]
        assert "sessions" in item
        assert len(item["sessions"]) == 1
        assert "issue_fingerprints" in item
        assert len(item["issue_fingerprints"]) == 2


class TestQueryAllRuns:
    def test_returns_all(self, db):
        for i in range(1, 4):
            insert_run(db, _sample_run(run_number=i, label=f"r{i}"), f"f{i}.json")
        db.commit()
        runs = query_all_runs(db)
        assert len(runs) == 3

    def test_filter_by_repo(self, db):
        insert_run(db, _sample_run(run_number=1, repo="https://github.com/a/b", label="r1"), "f1.json")
        insert_run(db, _sample_run(run_number=2, repo="https://github.com/c/d", label="r2"), "f2.json")
        db.commit()
        runs = query_all_runs(db, target_repo="https://github.com/c/d")
        assert len(runs) == 1
        assert runs[0]["target_repo"] == "https://github.com/c/d"


class TestQuerySessions:
    def test_paginated(self, db):
        for i in range(1, 4):
            insert_run(db, _sample_run(run_number=i, label=f"r{i}"), f"f{i}.json")
        db.commit()
        result = query_sessions(db, page=1, per_page=2)
        assert result["total"] == 3
        assert len(result["items"]) == 2

    def test_session_has_required_fields(self, db):
        insert_run(db, _sample_run(), "f.json")
        db.commit()
        result = query_sessions(db)
        s = result["items"][0]
        assert "session_id" in s
        assert "status" in s
        assert "issue_ids" in s
        assert "target_repo" in s


class TestQueryPrs:
    def test_empty(self, db):
        result = query_prs(db)
        assert result["total"] == 0
        assert result["items"] == []

    def test_with_prs(self, db):
        upsert_pr(db, {
            "pr_number": 1, "title": "PR1",
            "html_url": "https://github.com/o/r/pull/1",
            "state": "open", "merged": False,
            "created_at": "2026-01-01", "repo": "fork/r",
            "user": "u", "session_id": "s1",
            "issue_ids": ["I1"],
        })
        db.commit()
        result = query_prs(db)
        assert result["total"] == 1
        pr = result["items"][0]
        assert pr["title"] == "PR1"
        assert pr["issue_ids"] == ["I1"]


class TestQueryStats:
    def test_empty_db(self, db):
        stats = query_stats(db)
        assert stats["total_runs"] == 0
        assert stats["total_issues"] == 0

    def test_aggregation(self, db):
        insert_run(db, _sample_run(run_number=1, label="r1"), "f1.json")
        insert_run(db, _sample_run(run_number=2, label="r2"), "f2.json")
        db.commit()
        stats = query_stats(db)
        assert stats["total_runs"] == 2
        assert stats["repos_scanned"] == 1

    def test_period_filter(self, db):
        old = _sample_run(run_number=1, label="old")
        old["timestamp"] = "2020-01-01T00:00:00Z"
        insert_run(db, old, "old.json")
        new = _sample_run(run_number=2, label="new")
        new["timestamp"] = "2099-01-01T00:00:00Z"
        insert_run(db, new, "new.json")
        db.commit()
        stats = query_stats(db, period="7d")
        assert stats["total_runs"] == 1


class TestQueryRepos:
    def test_empty(self, db):
        assert query_repos(db) == []

    def test_groups_by_repo(self, db):
        insert_run(db, _sample_run(run_number=1, repo="https://github.com/a/b", label="r1"), "f1.json")
        insert_run(db, _sample_run(run_number=2, repo="https://github.com/a/b", label="r2"), "f2.json")
        insert_run(db, _sample_run(run_number=3, repo="https://github.com/c/d", label="r3"), "f3.json")
        db.commit()
        repos = query_repos(db)
        assert len(repos) == 2
        ab = next(r for r in repos if r["repo"] == "https://github.com/a/b")
        assert ab["runs"] == 2


class TestQueryIssues:
    def test_empty(self, db):
        assert query_issues(db) == []

    def test_tracks_across_runs(self, db):
        r1 = _sample_run(run_number=1, label="r1")
        r2 = _sample_run(run_number=2, label="r2")
        r2["issue_fingerprints"][0]["fingerprint"] = "fp-1-a"
        insert_run(db, r1, "f1.json")
        insert_run(db, r2, "f2.json")
        db.commit()
        issues = query_issues(db)
        fp_a = next(i for i in issues if i["fingerprint"] == "fp-1-a")
        assert fp_a["appearances"] >= 2


class TestSearchIssues:
    def test_search_returns_matches(self, db):
        insert_run(db, _sample_run(), "f.json")
        db.commit()
        results = search_issues(db, "injection")
        assert len(results) >= 1


class TestUpdateSession:
    def test_updates_status(self, db):
        insert_run(db, _sample_run(), "f.json")
        db.commit()
        update_session(db, "sess-1-1", status="stopped")
        db.commit()
        row = db.execute("SELECT status FROM sessions WHERE session_id = 'sess-1-1'").fetchone()
        assert row["status"] == "stopped"

    def test_updates_pr_url(self, db):
        insert_run(db, _sample_run(), "f.json")
        db.commit()
        update_session(db, "sess-1-1", pr_url="https://github.com/o/r/pull/1")
        db.commit()
        row = db.execute("SELECT pr_url FROM sessions WHERE session_id = 'sess-1-1'").fetchone()
        assert row["pr_url"] == "https://github.com/o/r/pull/1"


class TestCollectHelpers:
    def test_collect_session_ids(self, db):
        insert_run(db, _sample_run(), "f.json")
        db.commit()
        ids = collect_session_ids_from_db(db)
        assert "sess-1-1" in ids

    def test_collect_search_repos(self, db):
        insert_run(db, _sample_run(), "f.json")
        db.commit()
        repos = collect_search_repos_from_db(db)
        assert len(repos) >= 1
