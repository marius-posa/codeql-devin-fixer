"""Unit tests for scripts/orchestrator — orchestrator engine CLI."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

import pytest
from unittest.mock import patch, MagicMock
from scripts.orchestrator import (
    RateLimiter,
    Objective,
    compute_issue_priority,
    get_repo_config,
    load_registry,
    load_state,
    save_state,
    should_skip_issue,
    _derive_issue_state,
    _build_fp_to_tracking_ids,
    _session_matches_issue,
    _pr_matches_issue,
    _fallback_fingerprint,
    _session_fingerprints,
    _pr_fingerprints,
    _form_dispatch_batches,
    _build_orchestrator_prompt,
    _is_scan_due,
    _resolve_target_repo,
    cmd_ingest,
    cmd_plan,
    cmd_status,
    cmd_dispatch,
    cmd_scan,
    cmd_cycle,
    SEVERITY_WEIGHTS,
    SCHEDULE_INTERVALS,
    AGENT_TRIAGE_OUTPUT_SCHEMA,
    build_agent_triage_input,
    parse_agent_decisions,
    merge_agent_scores,
    build_effectiveness_report,
    save_agent_triage_results,
    load_agent_triage_results,
    cmd_agent_triage,
    create_agent_triage_session,
)
from scripts.fix_learning import FixLearning
import database as database_mod
from database import get_connection, init_db, insert_run
import scripts.orchestrator.state as orchestrator_state_mod
import scripts.orchestrator.dispatcher as orchestrator_dispatcher_mod


@pytest.fixture
def tmp_env(monkeypatch, tmp_path):
    db_path = tmp_path / "test.db"
    state_path = tmp_path / "orchestrator_state.json"
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    registry_path = tmp_path / "repo_registry.json"
    registry_path.write_text(json.dumps({
        "version": "2.0",
        "defaults": {
            "enabled": True,
            "importance": "medium",
            "importance_score": 50,
            "schedule": "weekly",
            "max_sessions_per_cycle": 5,
        },
        "orchestrator": {
            "global_session_limit": 20,
            "global_session_limit_period_hours": 24,
            "objectives": [],
            "alert_on_verified_fix": True,
            "alert_severities": ["critical", "high"],
        },
        "repos": [
            {
                "repo": "https://github.com/owner/repo",
                "enabled": True,
                "importance": "high",
                "importance_score": 90,
                "schedule": "weekly",
                "max_sessions_per_cycle": 10,
                "auto_scan": True,
                "auto_dispatch": True,
                "tags": ["web-app"],
                "overrides": {},
            }
        ],
    }))

    monkeypatch.setattr(orchestrator_state_mod, "REGISTRY_PATH", registry_path)
    monkeypatch.setattr(orchestrator_state_mod, "STATE_PATH", state_path)
    monkeypatch.setattr(orchestrator_state_mod, "RUNS_DIR", runs_dir)
    monkeypatch.setattr(database_mod, "DB_PATH", db_path)

    conn = get_connection(db_path)
    init_db(conn)
    conn.close()

    return {
        "db_path": db_path,
        "state_path": state_path,
        "runs_dir": runs_dir,
        "registry_path": registry_path,
        "tmp_path": tmp_path,
    }


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
            },
            {
                "fingerprint": f"fp-{run_number}-c",
                "id": f"CQLF-R{run_number}-0003",
                "rule_id": "js/path-injection",
                "severity_tier": "high",
                "cwe_family": "path-traversal",
                "file": "src/files.js",
                "start_line": 55,
                "description": "Path traversal vulnerability",
            },
        ],
    }


class TestRateLimiter:
    def test_initial_state_can_create(self):
        rl = RateLimiter(max_sessions=5, period_hours=24)
        assert rl.can_create_session()
        assert rl.recent_count() == 0

    def test_after_recording_session(self):
        rl = RateLimiter(max_sessions=5, period_hours=24)
        rl.record_session()
        assert rl.recent_count() == 1
        assert rl.can_create_session()

    def test_at_limit(self):
        rl = RateLimiter(max_sessions=2, period_hours=24)
        rl.record_session()
        rl.record_session()
        assert rl.recent_count() == 2
        assert not rl.can_create_session()

    def test_serialization_roundtrip(self):
        rl = RateLimiter(max_sessions=10, period_hours=12)
        rl.record_session()
        data = rl.to_dict()
        rl2 = RateLimiter.from_dict(data)
        assert rl2.max_sessions == 10
        assert rl2.period_hours == 12
        assert len(rl2.created_timestamps) == 1


class TestObjective:
    def test_progress_no_matching(self):
        obj = Objective(
            name="Fix all critical",
            target_severity="critical",
            target_count=0,
        )
        issues = [{"severity_tier": "high", "status": "new"}]
        p = obj.progress(issues)
        assert p["met"]
        assert p["current_count"] == 0

    def test_progress_with_matching(self):
        obj = Objective(
            name="Fix all critical",
            target_severity="critical",
            target_count=0,
        )
        issues = [
            {"severity_tier": "critical", "status": "new"},
            {"severity_tier": "critical", "status": "recurring"},
        ]
        p = obj.progress(issues)
        assert not p["met"]
        assert p["current_count"] == 2

    def test_progress_uses_derived_state(self):
        obj = Objective(
            name="Fix all critical",
            target_severity="critical",
            target_count=0,
        )
        issues = [
            {"severity_tier": "critical", "status": "new", "derived_state": "pr_merged"},
            {"severity_tier": "critical", "status": "recurring", "derived_state": "new"},
        ]
        p = obj.progress(issues)
        assert p["current_count"] == 1

    def test_from_dict(self):
        data = {
            "name": "Reduce high",
            "target_severity": "high",
            "target_count": 5,
            "priority": 2,
        }
        obj = Objective.from_dict(data)
        assert obj.name == "Reduce high"
        assert obj.target_count == 5


class TestGetRepoConfig:
    def test_known_repo(self, tmp_env):
        registry = load_registry()
        config = get_repo_config(registry, "https://github.com/owner/repo")
        assert config["importance_score"] == 90
        assert config["max_sessions_per_cycle"] == 10

    def test_unknown_repo_gets_defaults(self, tmp_env):
        registry = load_registry()
        config = get_repo_config(registry, "https://github.com/unknown/repo")
        assert config["importance_score"] == 50
        assert config["max_sessions_per_cycle"] == 5


class TestDeriveIssueState:
    def test_new_issue(self):
        issue = {"fingerprint": "fp-new", "status": "new"}
        state = _derive_issue_state(issue, [], [], {}, {})
        assert state == "new"

    def test_verified_fixed(self):
        issue = {"fingerprint": "fp-fixed", "status": "new"}
        fp_fix_map = {"fp-fixed": {"fixed_by_session": "s1"}}
        state = _derive_issue_state(issue, [], [], fp_fix_map, {})
        assert state == "verified_fixed"

    def test_pr_merged_by_fingerprint(self):
        issue = {"fingerprint": "fp-1", "status": "new"}
        prs = [{"merged": True, "state": "closed", "html_url": "url", "issue_ids": ["fp-1"]}]
        state = _derive_issue_state(issue, [], prs, {}, {})
        assert state == "pr_merged"

    def test_pr_merged_by_tracking_id(self):
        issue = {"fingerprint": "fp-hash-1", "status": "new", "latest_issue_id": "CQLF-R1-0001"}
        prs = [{"merged": True, "state": "closed", "html_url": "url", "issue_ids": ["CQLF-R1-0001"]}]
        fp_map = {"fp-hash-1": {"CQLF-R1-0001"}}
        state = _derive_issue_state(issue, [], prs, {}, {}, fp_map)
        assert state == "pr_merged"

    def test_pr_open(self):
        issue = {"fingerprint": "fp-1", "status": "new"}
        prs = [{"merged": False, "state": "open", "html_url": "url", "issue_ids": ["fp-1"]}]
        state = _derive_issue_state(issue, [], prs, {}, {})
        assert state == "pr_open"

    def test_session_dispatched_by_fingerprint(self):
        issue = {"fingerprint": "fp-1", "status": "new"}
        sessions = [{
            "session_id": "sess-1",
            "status": "running",
            "issue_ids": ["fp-1"],
        }]
        state = _derive_issue_state(issue, sessions, [], {}, {})
        assert state == "session_dispatched"

    def test_session_dispatched_by_tracking_id(self):
        issue = {"fingerprint": "fp-hash-1", "status": "new", "latest_issue_id": "CQLF-R1-0001"}
        sessions = [{
            "session_id": "sess-1",
            "status": "running",
            "issue_ids": ["CQLF-R1-0001"],
        }]
        fp_map = {"fp-hash-1": {"CQLF-R1-0001"}}
        state = _derive_issue_state(issue, sessions, [], {}, {}, fp_map)
        assert state == "session_dispatched"


class TestBuildFpToTrackingIds:
    def test_builds_mapping(self):
        issues = [
            {"fingerprint": "fp-1", "latest_issue_id": "CQLF-R1-0001"},
            {"fingerprint": "fp-2", "latest_issue_id": "CQLF-R1-0002"},
        ]
        mapping = _build_fp_to_tracking_ids(issues)
        assert "CQLF-R1-0001" in mapping["fp-1"]
        assert "CQLF-R1-0002" in mapping["fp-2"]

    def test_skips_empty_fingerprints(self):
        issues = [{"fingerprint": "", "latest_issue_id": "CQLF-R1-0001"}]
        mapping = _build_fp_to_tracking_ids(issues)
        assert len(mapping) == 0


class TestSessionMatchesIssue:
    def test_matches_by_fingerprint(self):
        session = {"issue_ids": ["fp-1", "fp-2"]}
        assert _session_matches_issue(session, "fp-1", set())

    def test_matches_by_tracking_id(self):
        session = {"issue_ids": ["CQLF-R1-0001"]}
        assert _session_matches_issue(session, "fp-hash", {"CQLF-R1-0001"})

    def test_no_match(self):
        session = {"issue_ids": ["CQLF-R1-0001"]}
        assert not _session_matches_issue(session, "fp-hash", {"CQLF-R1-9999"})


class TestPrMatchesIssue:
    def test_matches_by_tracking_id(self):
        pr = {"html_url": "url", "issue_ids": ["CQLF-R1-0001"]}
        assert _pr_matches_issue(pr, [], "fp-hash", {"CQLF-R1-0001"})

    def test_no_match(self):
        pr = {"html_url": "url", "issue_ids": ["CQLF-R1-9999"]}
        assert not _pr_matches_issue(pr, [], "fp-hash", {"CQLF-R1-0001"})


class TestShouldSkipIssue:
    def test_skip_fixed(self):
        fl = FixLearning(runs=[])
        skip, reason = should_skip_issue({}, "fixed", {}, fl)
        assert skip
        assert reason == "already_resolved"

    def test_skip_verified_fixed(self):
        fl = FixLearning(runs=[])
        skip, reason = should_skip_issue({}, "verified_fixed", {}, fl)
        assert skip
        assert reason == "already_resolved"

    def test_skip_session_active(self):
        fl = FixLearning(runs=[])
        skip, reason = should_skip_issue({}, "session_dispatched", {}, fl)
        assert skip
        assert reason == "session_active"

    def test_skip_pr_open(self):
        fl = FixLearning(runs=[])
        skip, reason = should_skip_issue({}, "pr_open", {}, fl)
        assert skip
        assert reason == "pr_awaiting_review"

    def test_skip_max_attempts(self):
        fl = FixLearning(runs=[])
        dispatch_history = {"fp-1": {"dispatch_count": 5}}
        skip, reason = should_skip_issue(
            {"fingerprint": "fp-1"}, "new", dispatch_history, fl,
        )
        assert skip
        assert "max_attempts_reached" in reason

    def test_no_skip_new_issue(self):
        fl = FixLearning(runs=[])
        skip, reason = should_skip_issue(
            {"fingerprint": "fp-new", "cwe_family": "injection"}, "new", {}, fl,
        )
        assert not skip
        assert reason == ""


class TestComputeIssuePriority:
    def test_high_importance_high_severity(self):
        issue = {
            "severity_tier": "critical",
            "cwe_family": "injection",
            "appearances": 3,
            "sla_status": "breached",
        }
        repo_config = {"importance_score": 90}
        fl = FixLearning(runs=[])
        score = compute_issue_priority(issue, repo_config, [], fl)
        assert score > 0.5

    def test_low_importance_low_severity(self):
        issue = {
            "severity_tier": "low",
            "cwe_family": "info-disclosure",
            "appearances": 1,
        }
        repo_config = {"importance_score": 20}
        fl = FixLearning(runs=[])
        score = compute_issue_priority(issue, repo_config, [], fl)
        assert score < 0.5

    def test_objective_boost(self):
        issue = {"severity_tier": "critical", "cwe_family": "injection", "status": "new"}
        repo_config = {"importance_score": 50}
        fl = FixLearning(runs=[])
        obj = Objective(name="Fix critical", target_severity="critical", target_count=0, priority=1)
        score_with = compute_issue_priority(issue, repo_config, [obj], fl)
        score_without = compute_issue_priority(issue, repo_config, [], fl)
        assert score_with > score_without


class TestFallbackFingerprint:
    def test_produces_fingerprint(self):
        issue = {"rule_id": "js/sql-injection", "file": "src/db.js", "start_line": 42}
        fp = _fallback_fingerprint(issue)
        assert len(fp) == 20
        assert isinstance(fp, str)

    def test_deterministic(self):
        issue = {"rule_id": "js/sql-injection", "file": "src/db.js", "start_line": 42}
        fp1 = _fallback_fingerprint(issue)
        fp2 = _fallback_fingerprint(issue)
        assert fp1 == fp2

    def test_different_for_different_input(self):
        issue1 = {"rule_id": "js/sql-injection", "file": "src/db.js", "start_line": 42}
        issue2 = {"rule_id": "js/xss", "file": "src/view.js", "start_line": 10}
        assert _fallback_fingerprint(issue1) != _fallback_fingerprint(issue2)


class TestStatePersistence:
    def test_save_and_load(self, tmp_env):
        state = {
            "last_cycle": "2026-01-01T00:00:00Z",
            "rate_limiter": {"created_timestamps": ["2026-01-01T00:00:00Z"]},
            "dispatch_history": {"fp-1": {"dispatch_count": 2, "fingerprint": "fp-1", "last_dispatched": "", "last_session_id": "", "consecutive_failures": 0}},
            "objective_progress": [],
            "scan_schedule": {},
        }
        save_state(state)
        loaded = load_state()
        assert loaded["last_cycle"] == "2026-01-01T00:00:00Z"
        assert loaded["dispatch_history"]["fp-1"]["dispatch_count"] == 2
        assert loaded["rate_limiter"]["created_timestamps"] == ["2026-01-01T00:00:00Z"]

    def test_load_missing_returns_defaults(self, tmp_env):
        state = load_state()
        assert state["last_cycle"] is None
        assert state["dispatch_history"] == {}


class TestCmdIngest:
    def test_ingest_creates_db_record(self, tmp_env):
        batches = {"batches": [{"id": 1, "issues": ["I1"]}]}
        issues = {"issues": [
            {
                "id": "I1",
                "fingerprint": "fp-ingest-1",
                "rule_id": "js/sql-injection",
                "severity_tier": "high",
                "cwe_family": "injection",
                "message": "SQL injection",
                "locations": [{"file": "src/db.js", "start_line": 42}],
            }
        ]}
        batches_path = tmp_env["tmp_path"] / "batches.json"
        issues_path = tmp_env["tmp_path"] / "issues.json"
        batches_path.write_text(json.dumps(batches))
        issues_path.write_text(json.dumps(issues))

        class Args:
            pass
        args = Args()
        args.batches = str(batches_path)
        args.issues = str(issues_path)
        args.run_label = "test-run-1"
        args.target_repo = "https://github.com/owner/repo"

        result = cmd_ingest(args)
        assert result == 0

        conn = get_connection(tmp_env["db_path"])
        init_db(conn)
        count = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        assert count == 1
        conn.close()

    def test_ingest_updates_state(self, tmp_env):
        batches = {"batches": []}
        issues = {"issues": []}
        batches_path = tmp_env["tmp_path"] / "batches.json"
        issues_path = tmp_env["tmp_path"] / "issues.json"
        batches_path.write_text(json.dumps(batches))
        issues_path.write_text(json.dumps(issues))

        class Args:
            pass
        args = Args()
        args.batches = str(batches_path)
        args.issues = str(issues_path)
        args.run_label = "test-run-2"
        args.target_repo = "https://github.com/owner/repo"

        cmd_ingest(args)
        state = load_state()
        assert state["last_cycle"] is not None
        assert "https://github.com/owner/repo" in state["scan_schedule"]

    def test_ingest_missing_file_returns_error(self, tmp_env):
        class Args:
            pass
        args = Args()
        args.batches = "/nonexistent/batches.json"
        args.issues = "/nonexistent/issues.json"
        args.run_label = "test-run-3"
        args.target_repo = "https://github.com/owner/repo"

        result = cmd_ingest(args)
        assert result == 1


class TestCmdPlan:
    def test_plan_empty_db(self, tmp_env, capsys):
        class Args:
            pass
        args = Args()
        args.repo = ""
        args.json = True

        result = cmd_plan(args)
        assert result == 0

        output = json.loads(capsys.readouterr().out)
        assert output["total_issues"] == 0
        assert output["sessions_planned"] == 0

    def test_plan_with_issues(self, tmp_env, capsys):
        conn = get_connection(tmp_env["db_path"])
        init_db(conn)
        insert_run(conn, _sample_run(run_number=1, label="r1"))
        conn.commit()
        conn.close()

        class Args:
            pass
        args = Args()
        args.repo = ""
        args.json = True

        result = cmd_plan(args)
        assert result == 0

        output = json.loads(capsys.readouterr().out)
        assert output["total_issues"] >= 1
        assert output["rate_limit_max"] == 20

    def test_plan_text_output(self, tmp_env, capfd):
        conn = get_connection(tmp_env["db_path"])
        init_db(conn)
        insert_run(conn, _sample_run(run_number=1, label="r1"))
        conn.commit()
        conn.close()

        class Args:
            pass
        args = Args()
        args.repo = ""
        args.json = False

        result = cmd_plan(args)
        assert result == 0

        output = capfd.readouterr().err
        assert "ORCHESTRATOR DISPATCH PLAN" in output

    def test_plan_respects_repo_filter(self, tmp_env, capsys):
        conn = get_connection(tmp_env["db_path"])
        init_db(conn)
        insert_run(conn, _sample_run(run_number=1, repo="https://github.com/a/b", label="r1"))
        insert_run(conn, _sample_run(run_number=2, repo="https://github.com/c/d", label="r2"))
        conn.commit()
        conn.close()

        class Args:
            pass
        args = Args()
        args.repo = "https://github.com/a/b"
        args.json = True

        result = cmd_plan(args)
        assert result == 0

        output = json.loads(capsys.readouterr().out)
        assert output["repo_filter"] == "https://github.com/a/b"


class TestCmdStatus:
    def test_status_empty_db(self, tmp_env, capsys):
        class Args:
            pass
        args = Args()
        args.repo = ""
        args.json = True

        result = cmd_status(args)
        assert result == 0

        output = json.loads(capsys.readouterr().out)
        assert output["total_issues"] == 0
        assert output["total_sessions"] == 0

    def test_status_with_data(self, tmp_env, capsys):
        conn = get_connection(tmp_env["db_path"])
        init_db(conn)
        insert_run(conn, _sample_run(run_number=1, label="r1"))
        conn.commit()
        conn.close()

        class Args:
            pass
        args = Args()
        args.repo = ""
        args.json = True

        result = cmd_status(args)
        assert result == 0

        output = json.loads(capsys.readouterr().out)
        assert output["total_issues"] >= 1
        assert output["total_sessions"] >= 1
        assert "rate_limit" in output

    def test_status_text_output(self, tmp_env, capfd):
        class Args:
            pass
        args = Args()
        args.repo = ""
        args.json = False

        result = cmd_status(args)
        assert result == 0

        output = capfd.readouterr().err
        assert "ORCHESTRATOR STATUS" in output

    def test_status_rate_limit_info(self, tmp_env, capsys):
        class Args:
            pass
        args = Args()
        args.repo = ""
        args.json = True

        result = cmd_status(args)
        assert result == 0

        output = json.loads(capsys.readouterr().out)
        rl = output["rate_limit"]
        assert rl["max"] == 20
        assert rl["period_hours"] == 24
        assert rl["remaining"] == 20


class TestSessionFingerprints:
    def test_extracts_issue_ids(self):
        session = {"issue_ids": ["fp-1", "fp-2"]}
        fps = _session_fingerprints(session)
        assert fps == {"fp-1", "fp-2"}

    def test_empty_session(self):
        session = {}
        fps = _session_fingerprints(session)
        assert fps == set()


class TestPrFingerprints:
    def test_extracts_from_issue_ids(self):
        pr = {"html_url": "url1", "issue_ids": ["fp-1", "fp-2"]}
        fps = _pr_fingerprints(pr, [])
        assert fps == {"fp-1", "fp-2"}

    def test_extracts_from_linked_sessions(self):
        pr = {"html_url": "url1", "issue_ids": [], "session_id": "sess-1"}
        sessions = [{
            "session_id": "sess-1",
            "pr_url": "url1",
            "issue_ids": ["fp-3"],
        }]
        fps = _pr_fingerprints(pr, sessions)
        assert "fp-3" in fps


class TestSeverityWeights:
    def test_all_severities_present(self):
        assert "critical" in SEVERITY_WEIGHTS
        assert "high" in SEVERITY_WEIGHTS
        assert "medium" in SEVERITY_WEIGHTS
        assert "low" in SEVERITY_WEIGHTS

    def test_ordering(self):
        assert SEVERITY_WEIGHTS["critical"] > SEVERITY_WEIGHTS["high"]
        assert SEVERITY_WEIGHTS["high"] > SEVERITY_WEIGHTS["medium"]
        assert SEVERITY_WEIGHTS["medium"] > SEVERITY_WEIGHTS["low"]


class TestFormDispatchBatches:
    def test_groups_by_repo_and_family(self):
        eligible = [
            {"target_repo": "https://github.com/a/b", "cwe_family": "injection", "severity_tier": "high", "priority_score": 0.8, "fingerprint": "fp1", "file": "a.js", "start_line": 1, "description": "d"},
            {"target_repo": "https://github.com/a/b", "cwe_family": "injection", "severity_tier": "medium", "priority_score": 0.6, "fingerprint": "fp2", "file": "b.js", "start_line": 2, "description": "d"},
            {"target_repo": "https://github.com/a/b", "cwe_family": "xss", "severity_tier": "high", "priority_score": 0.7, "fingerprint": "fp3", "file": "c.js", "start_line": 3, "description": "d"},
        ]
        registry = {"repos": [], "defaults": {"max_sessions_per_cycle": 5, "batch_size": 5}}
        rl = RateLimiter(max_sessions=10, period_hours=24)
        batches = _form_dispatch_batches(eligible, registry, rl, 10)
        assert len(batches) == 2
        families = {b["cwe_family"] for b in batches}
        assert families == {"injection", "xss"}

    def test_respects_remaining_capacity(self):
        eligible = [
            {"target_repo": "https://github.com/a/b", "cwe_family": "injection", "severity_tier": "high", "priority_score": 0.8, "fingerprint": "fp1", "file": "a.js", "start_line": 1, "description": "d"},
            {"target_repo": "https://github.com/a/b", "cwe_family": "xss", "severity_tier": "high", "priority_score": 0.7, "fingerprint": "fp2", "file": "b.js", "start_line": 2, "description": "d"},
        ]
        registry = {"repos": [], "defaults": {"max_sessions_per_cycle": 5, "batch_size": 5}}
        rl = RateLimiter(max_sessions=10, period_hours=24)
        batches = _form_dispatch_batches(eligible, registry, rl, 1)
        assert len(batches) == 1

    def test_respects_rate_limiter(self):
        eligible = [
            {"target_repo": "https://github.com/a/b", "cwe_family": "injection", "severity_tier": "high", "priority_score": 0.8, "fingerprint": "fp1", "file": "a.js", "start_line": 1, "description": "d"},
        ]
        registry = {"repos": [], "defaults": {"max_sessions_per_cycle": 5, "batch_size": 5}}
        rl = RateLimiter(max_sessions=0, period_hours=24)
        batches = _form_dispatch_batches(eligible, registry, rl, 10)
        assert len(batches) == 0

    def test_empty_eligible(self):
        rl = RateLimiter(max_sessions=10, period_hours=24)
        batches = _form_dispatch_batches([], {"repos": [], "defaults": {}}, rl, 10)
        assert len(batches) == 0


class TestBuildOrchestratorPrompt:
    def test_produces_prompt_string(self):
        batch = {
            "batch_id": 1,
            "target_repo": "https://github.com/a/b",
            "cwe_family": "injection",
            "severity_tier": "high",
            "issue_count": 1,
            "issues": [{
                "id": "CQLF-R1-0001",
                "rule_id": "js/sql-injection",
                "severity_tier": "high",
                "cwe_family": "injection",
                "locations": [{"file": "src/db.js", "start_line": 42}],
                "message": "SQL injection",
            }],
        }
        repo_config = {"default_branch": "main"}
        fl = FixLearning(runs=[])
        prompt = _build_orchestrator_prompt(batch, repo_config, fl)
        assert "https://github.com/a/b" in prompt
        assert "injection" in prompt
        assert "CQLF-R1-0001" in prompt
        assert "src/db.js" in prompt

    def test_includes_fix_hint(self):
        batch = {
            "batch_id": 1,
            "target_repo": "https://github.com/a/b",
            "cwe_family": "injection",
            "severity_tier": "high",
            "issue_count": 1,
            "issues": [{
                "id": "I1",
                "rule_id": "js/sql-injection",
                "severity_tier": "high",
                "cwe_family": "injection",
                "locations": [{"file": "src/db.js", "start_line": 42}],
                "message": "SQL injection",
            }],
        }
        repo_config = {"default_branch": "main"}
        fl = FixLearning(runs=[])
        prompt = _build_orchestrator_prompt(batch, repo_config, fl)
        assert "Fix pattern hint" in prompt


class TestCmdDispatch:
    def test_dispatch_dry_run_empty_db(self, tmp_env, capsys):
        class Args:
            pass
        args = Args()
        args.repo = ""
        args.json = True
        args.dry_run = True
        args.max_sessions = None

        result = cmd_dispatch(args)
        assert result == 0
        output = json.loads(capsys.readouterr().out)
        assert output["sessions_created"] == 0

    def test_dispatch_dry_run_with_issues(self, tmp_env, capsys):
        conn = get_connection(tmp_env["db_path"])
        init_db(conn)
        insert_run(conn, _sample_run(run_number=1, label="dispatch-r1"))
        conn.commit()
        conn.close()

        class Args:
            pass
        args = Args()
        args.repo = ""
        args.json = True
        args.dry_run = True
        args.max_sessions = None

        result = cmd_dispatch(args)
        assert result == 0
        output = json.loads(capsys.readouterr().out)
        assert output["dry_run"] is True
        assert output["sessions_dry_run"] >= 1
        assert output["sessions_created"] == 0

    def test_dispatch_dry_run_text_output(self, tmp_env, capfd):
        conn = get_connection(tmp_env["db_path"])
        init_db(conn)
        insert_run(conn, _sample_run(run_number=1, label="dispatch-text-r1"))
        conn.commit()
        conn.close()

        class Args:
            pass
        args = Args()
        args.repo = ""
        args.json = False
        args.dry_run = True
        args.max_sessions = None

        result = cmd_dispatch(args)
        assert result == 0
        output = capfd.readouterr().err
        assert "DRY RUN" in output

    def test_dispatch_no_api_key_without_dry_run(self, tmp_env, monkeypatch, capfd):
        monkeypatch.delenv("DEVIN_API_KEY", raising=False)

        class Args:
            pass
        args = Args()
        args.repo = ""
        args.json = False
        args.dry_run = False
        args.max_sessions = None

        result = cmd_dispatch(args)
        assert result == 1
        captured = capfd.readouterr()
        assert "DEVIN_API_KEY" in captured.err

    def test_dispatch_max_sessions_override(self, tmp_env, capsys):
        conn = get_connection(tmp_env["db_path"])
        init_db(conn)
        insert_run(conn, _sample_run(run_number=1, label="dispatch-max-r1"))
        conn.commit()
        conn.close()

        class Args:
            pass
        args = Args()
        args.repo = ""
        args.json = True
        args.dry_run = True
        args.max_sessions = 1

        result = cmd_dispatch(args)
        assert result == 0
        output = json.loads(capsys.readouterr().out)
        assert output["sessions_dry_run"] <= 1

    def test_dispatch_creates_session(self, tmp_env, monkeypatch, capsys):
        conn = get_connection(tmp_env["db_path"])
        init_db(conn)
        insert_run(conn, _sample_run(run_number=1, label="dispatch-live-r1"))
        conn.commit()
        conn.close()

        monkeypatch.setenv("DEVIN_API_KEY", "test-key")
        monkeypatch.setattr(orchestrator_dispatcher_mod, "_HAS_DISPATCH", True)

        mock_create = MagicMock(return_value={
            "session_id": "sess-test-123",
            "url": "https://app.devin.ai/sessions/sess-test-123",
        })
        with patch("scripts.orchestrator.dispatcher.create_devin_session", mock_create, create=True):
            class Args:
                pass
            args = Args()
            args.repo = ""
            args.json = True
            args.dry_run = False
            args.max_sessions = 1

            result = cmd_dispatch(args)
            assert result == 0
            output = json.loads(capsys.readouterr().out)
            assert output["sessions_created"] >= 1
            assert mock_create.called

        state = load_state()
        assert state["last_cycle"] is not None
        assert len(state.get("dispatch_history", {})) > 0

    def test_dispatch_handles_api_error(self, tmp_env, monkeypatch, capsys):
        conn = get_connection(tmp_env["db_path"])
        init_db(conn)
        insert_run(conn, _sample_run(run_number=1, label="dispatch-err-r1"))
        conn.commit()
        conn.close()

        monkeypatch.setenv("DEVIN_API_KEY", "test-key")
        monkeypatch.setattr(orchestrator_dispatcher_mod, "_HAS_DISPATCH", True)

        mock_create = MagicMock(side_effect=RuntimeError("API down"))
        with patch("scripts.orchestrator.dispatcher.create_devin_session", mock_create, create=True):
            class Args:
                pass
            args = Args()
            args.repo = ""
            args.json = True
            args.dry_run = False
            args.max_sessions = 1

            result = cmd_dispatch(args)
            assert result == 1
            output = json.loads(capsys.readouterr().out)
            assert output["sessions_failed"] >= 1

    def test_dispatch_respects_repo_filter(self, tmp_env, capsys):
        conn = get_connection(tmp_env["db_path"])
        init_db(conn)
        insert_run(conn, _sample_run(run_number=1, repo="https://github.com/a/b", label="dispatch-filter-r1"))
        insert_run(conn, _sample_run(run_number=2, repo="https://github.com/c/d", label="dispatch-filter-r2"))
        conn.commit()
        conn.close()

        class Args:
            pass
        args = Args()
        args.repo = "https://github.com/a/b"
        args.json = True
        args.dry_run = True
        args.max_sessions = None

        result = cmd_dispatch(args)
        assert result == 0
        output = json.loads(capsys.readouterr().out)
        assert output["repo_filter"] == "https://github.com/a/b"
        for r in output.get("results", []):
            assert r["target_repo"] == "https://github.com/a/b"


class TestResolveTargetRepo:
    def test_returns_original_when_accessible(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("scripts.orchestrator.scanner.request_with_retry", return_value=mock_resp):
            result = _resolve_target_repo(
                "https://github.com/juice-shop/juice-shop",
                "fake-token",
                "marius-posa/codeql-devin-fixer",
            )
        assert result == "https://github.com/juice-shop/juice-shop"

    def test_falls_back_to_fork_when_no_access(self):
        no_access = MagicMock()
        no_access.status_code = 403
        fork_found = MagicMock()
        fork_found.status_code = 200
        with patch("scripts.orchestrator.scanner.request_with_retry", side_effect=[no_access, fork_found]):
            result = _resolve_target_repo(
                "https://github.com/juice-shop/juice-shop",
                "fake-token",
                "marius-posa/codeql-devin-fixer",
            )
        assert result == "https://github.com/marius-posa/juice-shop"

    def test_returns_original_when_no_fork_exists(self):
        no_access = MagicMock()
        no_access.status_code = 403
        no_fork = MagicMock()
        no_fork.status_code = 404
        with patch("scripts.orchestrator.scanner.request_with_retry", side_effect=[no_access, no_fork]):
            result = _resolve_target_repo(
                "https://github.com/juice-shop/juice-shop",
                "fake-token",
                "marius-posa/codeql-devin-fixer",
            )
        assert result == "https://github.com/juice-shop/juice-shop"

    def test_skips_fork_check_when_owner_matches(self):
        no_access = MagicMock()
        no_access.status_code = 403
        with patch("scripts.orchestrator.scanner.request_with_retry", return_value=no_access) as mock_req:
            result = _resolve_target_repo(
                "https://github.com/marius-posa/some-repo",
                "fake-token",
                "marius-posa/codeql-devin-fixer",
            )
        assert result == "https://github.com/marius-posa/some-repo"
        assert mock_req.call_count == 1

    def test_handles_invalid_repo_url(self):
        result = _resolve_target_repo("not-a-url", "token", "owner/repo")
        assert result == "not-a-url"


class TestScheduleIntervals:
    def test_known_intervals(self):
        assert "hourly" in SCHEDULE_INTERVALS
        assert "daily" in SCHEDULE_INTERVALS
        assert "weekly" in SCHEDULE_INTERVALS
        assert "biweekly" in SCHEDULE_INTERVALS
        assert "monthly" in SCHEDULE_INTERVALS

    def test_ordering(self):
        assert SCHEDULE_INTERVALS["hourly"] < SCHEDULE_INTERVALS["daily"]
        assert SCHEDULE_INTERVALS["daily"] < SCHEDULE_INTERVALS["weekly"]
        assert SCHEDULE_INTERVALS["weekly"] < SCHEDULE_INTERVALS["monthly"]


class TestIsScanDue:
    def test_disabled_repo(self):
        config = {"repo": "https://github.com/a/b", "enabled": False}
        assert _is_scan_due(config, {}) is False

    def test_auto_scan_disabled(self):
        config = {"repo": "https://github.com/a/b", "enabled": True, "auto_scan": False}
        assert _is_scan_due(config, {}) is False

    def test_never_scanned(self):
        config = {"repo": "https://github.com/a/b", "enabled": True, "auto_scan": True}
        assert _is_scan_due(config, {}) is True

    def test_recently_scanned(self):
        from datetime import datetime, timezone
        config = {"repo": "https://github.com/a/b", "enabled": True, "auto_scan": True, "schedule": "weekly"}
        now = datetime.now(timezone.utc).isoformat()
        schedule = {"https://github.com/a/b": {"last_scan": now}}
        assert _is_scan_due(config, schedule) is False

    def test_overdue_scan(self):
        from datetime import datetime, timezone, timedelta
        config = {"repo": "https://github.com/a/b", "enabled": True, "auto_scan": True, "schedule": "daily"}
        old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        schedule = {"https://github.com/a/b": {"last_scan": old}}
        assert _is_scan_due(config, schedule) is True


class TestCmdScan:
    def test_scan_dry_run(self, tmp_env, capsys):
        class Args:
            repo = ""
            json = True
            dry_run = True

        result = cmd_scan(Args())
        assert result == 0
        output = json.loads(capsys.readouterr().out)
        assert output["dry_run"] is True
        assert output["total_repos"] >= 1

    def test_scan_dry_run_with_repo_filter(self, tmp_env, capsys):
        class Args:
            repo = "https://github.com/owner/repo"
            json = True
            dry_run = True

        result = cmd_scan(Args())
        assert result == 0
        output = json.loads(capsys.readouterr().out)
        assert output["repo_filter"] == "https://github.com/owner/repo"
        for r in output.get("results", []):
            assert r["repo"] == "https://github.com/owner/repo"

    def test_scan_requires_github_token(self, tmp_env, monkeypatch, capsys):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("ACTION_REPO", raising=False)

        class Args:
            repo = ""
            json = False
            dry_run = False

        result = cmd_scan(Args())
        assert result == 1

    def test_scan_updates_state(self, tmp_env, capsys):
        class Args:
            repo = ""
            json = True
            dry_run = True

        cmd_scan(Args())
        state = load_state()
        assert "scan_schedule" in state

    def test_scan_text_output(self, tmp_env, capfd):
        class Args:
            repo = ""
            json = False
            dry_run = True

        result = cmd_scan(Args())
        assert result == 0
        output = capfd.readouterr().err
        assert "DRY RUN" in output


class TestCmdCycle:
    def test_cycle_dry_run_json(self, tmp_env, capsys):
        class Args:
            repo = ""
            json = True
            dry_run = True
            max_sessions = None

        result = cmd_cycle(Args())
        assert result == 0
        output = json.loads(capsys.readouterr().out)
        assert "scan" in output
        assert "dispatch" in output
        assert output["dry_run"] is True

    def test_cycle_updates_last_cycle(self, tmp_env, capsys):
        class Args:
            repo = ""
            json = True
            dry_run = True
            max_sessions = None

        cmd_cycle(Args())
        state = load_state()
        assert state["last_cycle"] is not None

    def test_cycle_text_output(self, tmp_env, capfd):
        class Args:
            repo = ""
            json = False
            dry_run = True
            max_sessions = None

        result = cmd_cycle(Args())
        assert result == 0
        output = capfd.readouterr().err
        assert "ORCHESTRATOR CYCLE" in output
        assert "Scanning" in output
        assert "Dispatching" in output

    def test_cycle_with_repo_filter(self, tmp_env, capsys):
        class Args:
            repo = "https://github.com/owner/repo"
            json = True
            dry_run = True
            max_sessions = None

        result = cmd_cycle(Args())
        assert result == 0
        output = json.loads(capsys.readouterr().out)
        assert output["repo_filter"] == "https://github.com/owner/repo"


class TestAgentTriageOutputSchema:
    def test_schema_has_required_fields(self):
        assert "properties" in AGENT_TRIAGE_OUTPUT_SCHEMA
        assert "decisions" in AGENT_TRIAGE_OUTPUT_SCHEMA["properties"]
        assert "status" in AGENT_TRIAGE_OUTPUT_SCHEMA["properties"]
        assert AGENT_TRIAGE_OUTPUT_SCHEMA["required"] == ["status", "decisions"]

    def test_decision_item_schema(self):
        items = AGENT_TRIAGE_OUTPUT_SCHEMA["properties"]["decisions"]["items"]
        assert "fingerprint" in items["properties"]
        assert "priority_score" in items["properties"]
        assert "dispatch" in items["properties"]
        assert "reasoning" in items["properties"]


class TestBuildAgentTriageInput:
    def test_builds_input_with_issues(self):
        issues = [
            {
                "fingerprint": "fp-1",
                "rule_id": "js/sql-injection",
                "severity_tier": "high",
                "cwe_family": "injection",
                "target_repo": "https://github.com/owner/repo",
                "file": "src/db.js",
                "start_line": 42,
                "message": "SQL injection",
                "appearances": 2,
                "status": "new",
                "sla_status": "on_track",
                "priority_score": 0.7,
            }
        ]
        fl = FixLearning(runs=[])
        orch_config = {"objectives": []}
        rate_limiter_info = {"remaining": 5, "max": 10, "period_hours": 24}

        result = build_agent_triage_input(issues, fl, orch_config, rate_limiter_info)

        assert result["total_issues"] == 1
        assert len(result["issue_inventory"]) == 1
        assert result["issue_inventory"][0]["fingerprint"] == "fp-1"
        assert result["issue_inventory"][0]["deterministic_score"] == 0.7
        assert result["sla_deadlines"]["critical_hours"] == 48
        assert result["acu_budget"]["remaining_sessions"] == 5
        assert result["acu_budget"]["max_sessions"] == 10
        assert "timestamp" in result

    def test_builds_input_empty_issues(self):
        fl = FixLearning(runs=[])
        result = build_agent_triage_input([], fl, {}, {"remaining": 0, "max": 0})
        assert result["total_issues"] == 0
        assert result["issue_inventory"] == []


class TestParseAgentDecisions:
    def test_parses_valid_output(self):
        structured_output = {
            "status": "done",
            "decisions": [
                {
                    "fingerprint": "fp-1",
                    "priority_score": 85,
                    "reasoning": "Critical SQL injection",
                    "dispatch": True,
                },
                {
                    "fingerprint": "fp-2",
                    "priority_score": 30,
                    "reasoning": "Low impact",
                    "dispatch": False,
                },
            ],
        }
        decisions = parse_agent_decisions(structured_output)
        assert len(decisions) == 2
        assert decisions[0]["fingerprint"] == "fp-1"
        assert decisions[0]["agent_priority_score"] == 85.0
        assert decisions[0]["dispatch"] is True
        assert decisions[1]["fingerprint"] == "fp-2"
        assert decisions[1]["agent_priority_score"] == 30.0
        assert decisions[1]["dispatch"] is False

    def test_parses_none_output(self):
        assert parse_agent_decisions(None) == []

    def test_parses_empty_decisions(self):
        assert parse_agent_decisions({"status": "done", "decisions": []}) == []

    def test_skips_entries_without_fingerprint(self):
        structured_output = {
            "status": "done",
            "decisions": [
                {"priority_score": 50, "dispatch": True},
                {"fingerprint": "fp-1", "priority_score": 80, "dispatch": True},
            ],
        }
        decisions = parse_agent_decisions(structured_output)
        assert len(decisions) == 1
        assert decisions[0]["fingerprint"] == "fp-1"


class TestMergeAgentScores:
    def test_merges_matching_fingerprints(self):
        plan = [
            {"fingerprint": "fp-1", "priority_score": 0.7},
            {"fingerprint": "fp-2", "priority_score": 0.5},
        ]
        agent_decisions = [
            {"fingerprint": "fp-1", "agent_priority_score": 85, "reasoning": "High impact", "dispatch": True},
        ]
        merged = merge_agent_scores(plan, agent_decisions)
        assert len(merged) == 2
        assert merged[0]["agent_priority_score"] == 85
        assert merged[0]["agent_reasoning"] == "High impact"
        assert merged[0]["agent_dispatch"] is True
        assert merged[1]["agent_priority_score"] is None
        assert merged[1]["agent_dispatch"] is None

    def test_merges_empty_agent_decisions(self):
        plan = [{"fingerprint": "fp-1", "priority_score": 0.7}]
        merged = merge_agent_scores(plan, [])
        assert len(merged) == 1
        assert merged[0]["agent_priority_score"] is None

    def test_preserves_original_fields(self):
        plan = [{"fingerprint": "fp-1", "priority_score": 0.7, "rule_id": "js/xss"}]
        agent_decisions = [{"fingerprint": "fp-1", "agent_priority_score": 90, "dispatch": True}]
        merged = merge_agent_scores(plan, agent_decisions)
        assert merged[0]["rule_id"] == "js/xss"
        assert merged[0]["priority_score"] == 0.7


class TestBuildEffectivenessReport:
    def test_basic_report(self):
        dispatch_history = {
            "fp-1": {"dispatch_count": 1, "recommendation_source": "agent"},
            "fp-2": {"dispatch_count": 1, "recommendation_source": "deterministic"},
        }
        agent_triage = {
            "decisions": [
                {"fingerprint": "fp-1", "dispatch": True},
                {"fingerprint": "fp-3", "dispatch": False},
            ],
        }
        fp_fix_map = {"fp-1": {"fixed_by_session": "s1"}}

        report = build_effectiveness_report(dispatch_history, agent_triage, fp_fix_map)

        assert report["agent"]["recommended"] == 1
        assert report["agent"]["not_recommended"] == 1
        assert report["agent"]["dispatched"] == 1
        assert report["agent"]["fixed"] == 1
        assert report["agent"]["fix_rate"] == 100.0
        assert report["deterministic"]["dispatched"] == 1
        assert report["deterministic"]["fixed"] == 0
        assert report["deterministic"]["fix_rate"] == 0.0
        assert "timestamp" in report

    def test_empty_history(self):
        report = build_effectiveness_report({}, {}, {})
        assert report["agent"]["dispatched"] == 0
        assert report["deterministic"]["dispatched"] == 0
        assert report["agent"]["recommended"] == 0


class TestSaveAndLoadAgentTriageResults:
    def test_save_and_load(self, tmp_env):
        decisions = [
            {"fingerprint": "fp-1", "agent_priority_score": 80, "dispatch": True},
        ]
        save_agent_triage_results(decisions, "sess-agent-1", "Focus on injection")
        loaded = load_agent_triage_results()
        assert loaded["session_id"] == "sess-agent-1"
        assert loaded["strategy_notes"] == "Focus on injection"
        assert len(loaded["decisions"]) == 1
        assert "timestamp" in loaded

    def test_load_empty_returns_empty(self, tmp_env):
        loaded = load_agent_triage_results()
        assert loaded == {}


class TestCmdAgentTriage:
    def test_dry_run_empty_db(self, tmp_env, capsys):
        class Args:
            repo = ""
            json = True
            dry_run = True

        result = cmd_agent_triage(Args())
        assert result == 0
        output = json.loads(capsys.readouterr().out)
        assert output["status"] == "no_issues"

    def test_dry_run_with_issues(self, tmp_env, capsys):
        run = _sample_run(run_number=1, label="agent-r1")
        run["sessions"] = []
        conn = get_connection(tmp_env["db_path"])
        init_db(conn)
        insert_run(conn, run)
        conn.commit()
        conn.close()

        class Args:
            repo = ""
            json = True
            dry_run = True

        result = cmd_agent_triage(Args())
        assert result == 0
        output = json.loads(capsys.readouterr().out)
        assert output["status"] == "dry_run"
        assert output["total_issues"] > 0
        assert len(output["decisions"]) > 0
        for d in output["decisions"]:
            assert "fingerprint" in d
            assert "agent_priority_score" in d

    def test_requires_api_key_without_dry_run(self, tmp_env, monkeypatch):
        monkeypatch.delenv("DEVIN_API_KEY", raising=False)

        class Args:
            repo = ""
            json = False
            dry_run = False

        result = cmd_agent_triage(Args())
        assert result == 1


class TestCreateAgentTriageSession:
    @patch("scripts.orchestrator.agent.request_with_retry")
    def test_payload_uses_max_acu_limit(self, mock_request):
        mock_request.return_value = {"session_id": "s1", "url": "u1"}
        triage_input = {"total_issues": 3, "issues": [], "fix_rates": {}, "acu_budget": 10}
        create_agent_triage_session("key", triage_input, max_acu=5)
        payload = mock_request.call_args[1].get("json_data") or mock_request.call_args.kwargs.get("json_data")
        assert payload["max_acu_limit"] == 5
        assert "max_acu" not in payload

    @patch("scripts.orchestrator.agent.request_with_retry")
    def test_payload_omits_max_acu_limit_when_zero(self, mock_request):
        mock_request.return_value = {"session_id": "s1", "url": "u1"}
        triage_input = {"total_issues": 3, "issues": [], "fix_rates": {}, "acu_budget": 10}
        create_agent_triage_session("key", triage_input, max_acu=0)
        payload = mock_request.call_args[1].get("json_data") or mock_request.call_args.kwargs.get("json_data")
        assert "max_acu_limit" not in payload
