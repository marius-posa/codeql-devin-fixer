"""Tests for compute_fingerprint and _track_issues_across_runs."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from scripts.parse_sarif import compute_fingerprint, FINGERPRINT_LENGTH, _read_source_line


def _make_issue(
    rule_id="js/sql-injection",
    file="routes/login.ts",
    start_line=34,
    message="This query depends on a user-provided value.",
    partial_fingerprints=None,
):
    issue = {
        "rule_id": rule_id,
        "locations": [{"file": file, "start_line": start_line}],
        "message": message,
    }
    if partial_fingerprints is not None:
        issue["partial_fingerprints"] = partial_fingerprints
    return issue


class TestComputeFingerprint:
    def test_same_issue_same_fingerprint(self):
        a = _make_issue()
        b = _make_issue()
        assert compute_fingerprint(a) == compute_fingerprint(b)

    def test_different_rule_different_fingerprint(self):
        a = _make_issue(rule_id="js/sql-injection")
        b = _make_issue(rule_id="js/code-injection")
        assert compute_fingerprint(a) != compute_fingerprint(b)

    def test_message_based_stable_across_line_shifts(self):
        a = _make_issue(start_line=34)
        b = _make_issue(start_line=40)
        assert compute_fingerprint(a) == compute_fingerprint(b)

    def test_different_messages_different_fingerprint(self):
        a = _make_issue(message="Tainted value flows to sink A.")
        b = _make_issue(message="Tainted value flows to sink B.")
        assert compute_fingerprint(a) != compute_fingerprint(b)

    def test_partial_fingerprints_preferred(self):
        a = _make_issue(partial_fingerprints={"primaryLocationLineHash": "abc123"})
        b = _make_issue(partial_fingerprints={"primaryLocationLineHash": "abc123"})
        assert compute_fingerprint(a) == compute_fingerprint(b)

        c = _make_issue(partial_fingerprints={"primaryLocationLineHash": "xyz789"})
        assert compute_fingerprint(a) != compute_fingerprint(c)

    def test_partial_fingerprints_ignore_line_and_message(self):
        a = _make_issue(
            start_line=1,
            message="msg1",
            partial_fingerprints={"primaryLocationLineHash": "stable"},
        )
        b = _make_issue(
            start_line=999,
            message="msg2",
            partial_fingerprints={"primaryLocationLineHash": "stable"},
        )
        assert compute_fingerprint(a) == compute_fingerprint(b)

    def test_fallback_to_start_line_when_no_message(self):
        a = _make_issue(message="", start_line=10)
        b = _make_issue(message="", start_line=20)
        assert compute_fingerprint(a) != compute_fingerprint(b)

    def test_empty_issue_does_not_crash(self):
        fp = compute_fingerprint({})
        assert isinstance(fp, str)
        assert len(fp) == FINGERPRINT_LENGTH

    def test_fingerprint_length_is_20(self):
        fp = compute_fingerprint(_make_issue())
        assert len(fp) == 20

    def test_target_dir_tier_used_when_no_message(self, tmp_path):
        src = tmp_path / "routes" / "login.ts"
        src.parent.mkdir(parents=True)
        src.write_text("line1\nconst q = db.query(input);\nline3\n")
        issue = _make_issue(message="", start_line=2)
        fp_with_dir = compute_fingerprint(issue, target_dir=str(tmp_path))
        fp_without_dir = compute_fingerprint(issue)
        assert fp_with_dir != fp_without_dir

    def test_target_dir_tier_stable_across_line_shifts(self, tmp_path):
        src = tmp_path / "routes" / "login.ts"
        src.parent.mkdir(parents=True)
        src.write_text("\nconst q = db.query(input);\nline3\n")
        issue_a = _make_issue(message="", start_line=2)
        fp_a = compute_fingerprint(issue_a, target_dir=str(tmp_path))
        src.write_text("extra\n\nconst q = db.query(input);\nline3\n")
        issue_b = _make_issue(message="", start_line=3)
        fp_b = compute_fingerprint(issue_b, target_dir=str(tmp_path))
        assert fp_a == fp_b

    def test_target_dir_tier_ignores_whitespace_changes(self, tmp_path):
        src = tmp_path / "routes" / "login.ts"
        src.parent.mkdir(parents=True)
        src.write_text("  const q = db.query(input);  \n")
        issue = _make_issue(message="", start_line=1)
        fp1 = compute_fingerprint(issue, target_dir=str(tmp_path))
        src.write_text("    const  q  =  db.query(input);\n")
        fp2 = compute_fingerprint(issue, target_dir=str(tmp_path))
        assert fp1 == fp2

    def test_target_dir_not_used_when_message_present(self, tmp_path):
        src = tmp_path / "routes" / "login.ts"
        src.parent.mkdir(parents=True)
        src.write_text("const q = db.query(input);\n")
        issue = _make_issue(message="This query depends on user input.", start_line=1)
        fp_with = compute_fingerprint(issue, target_dir=str(tmp_path))
        fp_without = compute_fingerprint(issue)
        assert fp_with == fp_without


class TestTrackIssuesAcrossRuns:
    def _import_tracker(self):
        sys.path.insert(
            0, os.path.join(os.path.dirname(__file__), "..", "telemetry")
        )
        from app import _track_issues_across_runs

        return _track_issues_across_runs

    def _make_run(self, run_number, repo, fingerprints, timestamp=None):
        ts = timestamp or f"2026-01-01T00:00:{run_number:02d}Z"
        return {
            "run_number": run_number,
            "target_repo": repo,
            "timestamp": ts,
            "issue_fingerprints": fingerprints,
        }

    def test_empty_runs(self):
        track = self._import_tracker()
        assert track([]) == []

    def test_single_run_all_new(self):
        track = self._import_tracker()
        runs = [
            self._make_run(1, "r", [
                {"fingerprint": "aaa", "id": "I1", "rule_id": "r1",
                 "severity_tier": "high", "cwe_family": "xss",
                 "file": "a.js", "start_line": 1},
            ]),
        ]
        result = track(runs)
        assert len(result) == 1
        assert result[0]["status"] == "new"
        assert result[0]["rule_id"] == "r1"

    def test_recurring_across_two_runs(self):
        track = self._import_tracker()
        fp = [
            {"fingerprint": "aaa", "id": "I1", "rule_id": "r1",
             "severity_tier": "high", "cwe_family": "xss",
             "file": "a.js", "start_line": 1},
        ]
        runs = [
            self._make_run(1, "r", fp, "2026-01-01T00:00:01Z"),
            self._make_run(2, "r", fp, "2026-01-01T00:00:02Z"),
        ]
        result = track(runs)
        assert len(result) == 1
        assert result[0]["status"] == "recurring"
        assert result[0]["appearances"] == 2

    def test_fixed_issue(self):
        track = self._import_tracker()
        fp_a = {"fingerprint": "aaa", "id": "I1", "rule_id": "r1",
                "severity_tier": "high", "cwe_family": "xss",
                "file": "a.js", "start_line": 1}
        runs = [
            self._make_run(1, "r", [fp_a], "2026-01-01T00:00:01Z"),
            self._make_run(2, "r", [], "2026-01-01T00:00:02Z"),
        ]
        result = track(runs)
        assert len(result) == 1
        assert result[0]["status"] == "fixed"

    def test_older_runs_without_fps_marks_recurring(self):
        track = self._import_tracker()
        fp = [
            {"fingerprint": "aaa", "id": "I1", "rule_id": "r1",
             "severity_tier": "high", "cwe_family": "xss",
             "file": "a.js", "start_line": 1},
        ]
        runs = [
            self._make_run(1, "r", [], "2026-01-01T00:00:01Z"),
            self._make_run(2, "r", [], "2026-01-01T00:00:02Z"),
            self._make_run(3, "r", fp, "2026-01-01T00:00:03Z"),
        ]
        result = track(runs)
        assert len(result) == 1
        assert result[0]["status"] == "recurring"

    def test_metadata_populated(self):
        track = self._import_tracker()
        runs = [
            self._make_run(1, "r", [
                {"fingerprint": "aaa", "id": "I1", "rule_id": "r1",
                 "severity_tier": "critical", "cwe_family": "injection",
                 "file": "login.ts", "start_line": 42},
            ]),
        ]
        result = track(runs)
        r = result[0]
        assert r["rule_id"] == "r1"
        assert r["severity_tier"] == "critical"
        assert r["cwe_family"] == "injection"
        assert r["file"] == "login.ts"
        assert r["start_line"] == 42

    def test_scalability_10k_issues(self):
        track = self._import_tracker()
        fps = [
            {"fingerprint": f"fp{i:05d}", "id": f"I{i}", "rule_id": "r1",
             "severity_tier": "high", "cwe_family": "xss",
             "file": f"file{i}.js", "start_line": i}
            for i in range(10_000)
        ]
        runs = [
            self._make_run(1, "r", fps[:8000], "2026-01-01T00:00:01Z"),
            self._make_run(2, "r", fps[2000:], "2026-01-01T00:00:02Z"),
        ]
        result = track(runs)
        statuses = {r["status"] for r in result}
        assert "recurring" in statuses
        assert "new" in statuses
        assert "fixed" in statuses
        assert len(result) == 10_000

    def test_sort_order(self):
        track = self._import_tracker()
        fp_rec = {"fingerprint": "rec", "id": "I1", "rule_id": "r1",
                  "severity_tier": "high", "cwe_family": "xss",
                  "file": "a.js", "start_line": 1}
        fp_new = {"fingerprint": "new", "id": "I2", "rule_id": "r2",
                  "severity_tier": "low", "cwe_family": "other",
                  "file": "b.js", "start_line": 2}
        fp_fix = {"fingerprint": "fix", "id": "I3", "rule_id": "r3",
                  "severity_tier": "medium", "cwe_family": "crypto",
                  "file": "c.js", "start_line": 3}
        runs = [
            self._make_run(1, "r", [fp_rec, fp_fix], "2026-01-01T00:00:01Z"),
            self._make_run(2, "r", [fp_rec, fp_new], "2026-01-01T00:00:02Z"),
        ]
        result = track(runs)
        assert [r["status"] for r in result] == ["recurring", "new", "fixed"]
