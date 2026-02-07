"""Unit tests for fix_learning.py module."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.fix_learning import (
    CWE_FIX_HINTS,
    FamilyStats,
    FixLearning,
)


class TestCweFixHints:
    def test_injection_hint_exists(self):
        assert "injection" in CWE_FIX_HINTS
        assert "parameterized" in CWE_FIX_HINTS["injection"].lower()

    def test_xss_hint_exists(self):
        assert "xss" in CWE_FIX_HINTS
        assert "escape" in CWE_FIX_HINTS["xss"].lower()

    def test_path_traversal_hint_exists(self):
        assert "path-traversal" in CWE_FIX_HINTS

    def test_all_major_families_covered(self):
        expected = [
            "injection", "xss", "path-traversal", "ssrf", "deserialization",
            "auth", "crypto", "info-disclosure", "redirect", "xxe", "csrf",
            "prototype-pollution", "hardcoded-credentials",
        ]
        for family in expected:
            assert family in CWE_FIX_HINTS, f"Missing hint for {family}"


class TestFamilyStats:
    def test_fix_rate_no_sessions(self):
        s = FamilyStats()
        assert s.fix_rate == 0.0

    def test_fix_rate_all_finished(self):
        s = FamilyStats(total_sessions=5, finished_sessions=5)
        assert s.fix_rate == 1.0

    def test_fix_rate_partial(self):
        s = FamilyStats(total_sessions=10, finished_sessions=7)
        assert s.fix_rate == 0.7

    def test_fix_rate_none_finished(self):
        s = FamilyStats(total_sessions=5, finished_sessions=0)
        assert s.fix_rate == 0.0


def _make_telemetry_run(
    families: list[str],
    session_statuses: list[str],
    target_repo: str = "https://github.com/org/repo",
) -> dict:
    fingerprints = []
    for i, fam in enumerate(families):
        fingerprints.append({
            "id": f"CQLF-R1-{i + 1:04d}",
            "fingerprint": f"fp-{i}",
            "rule_id": f"rule-{fam}",
            "severity_tier": "high",
            "cwe_family": fam,
            "file": f"src/{fam}/file.js",
            "start_line": 10,
        })
    sessions = []
    for i, status in enumerate(session_statuses):
        issue_ids = [fingerprints[i]["id"]] if i < len(fingerprints) else []
        sessions.append({
            "session_id": f"sess-{i}",
            "session_url": f"https://app.devin.ai/sessions/sess-{i}",
            "batch_id": i + 1,
            "status": status,
            "issue_ids": issue_ids,
        })
    return {
        "target_repo": target_repo,
        "run_number": 1,
        "timestamp": "2025-01-01T00:00:00Z",
        "issues_found": len(fingerprints),
        "issue_fingerprints": fingerprints,
        "sessions": sessions,
    }


class TestFixLearning:
    def test_from_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fl = FixLearning.from_telemetry_dir(tmpdir)
            assert fl.runs == []

    def test_from_nonexistent_dir(self):
        fl = FixLearning.from_telemetry_dir("/nonexistent/path")
        assert fl.runs == []

    def test_from_dir_with_runs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run = _make_telemetry_run(["injection"], ["finished"])
            with open(os.path.join(tmpdir, "run1.json"), "w") as f:
                json.dump(run, f)
            fl = FixLearning.from_telemetry_dir(tmpdir)
            assert len(fl.runs) == 1

    def test_skips_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "bad.json"), "w") as f:
                f.write("not json")
            run = _make_telemetry_run(["injection"], ["finished"])
            with open(os.path.join(tmpdir, "good.json"), "w") as f:
                json.dump(run, f)
            fl = FixLearning.from_telemetry_dir(tmpdir)
            assert len(fl.runs) == 1

    def test_family_fix_rates_basic(self):
        run = _make_telemetry_run(
            ["injection", "xss"],
            ["finished", "error: timeout"],
        )
        fl = FixLearning(runs=[run])
        rates = fl.family_fix_rates()
        assert "injection" in rates
        assert rates["injection"].finished_sessions == 1
        assert "xss" in rates

    def test_prioritized_families(self):
        run = _make_telemetry_run(
            ["injection", "xss", "auth"],
            ["finished", "error: fail", "finished"],
        )
        fl = FixLearning(runs=[run])
        result = fl.prioritized_families()
        families = [f for f, _ in result]
        assert "injection" in families
        assert "auth" in families

    def test_should_skip_family_insufficient_data(self):
        run = _make_telemetry_run(["injection"], ["error: fail"])
        fl = FixLearning(runs=[run])
        assert fl.should_skip_family("injection", min_sessions=3) is False

    def test_should_skip_family_low_rate(self):
        runs = []
        for _ in range(4):
            runs.append(_make_telemetry_run(["injection"], ["error: fail"]))
        fl = FixLearning(runs=runs)
        assert fl.should_skip_family("injection", min_sessions=3) is True

    def test_should_not_skip_unknown_family(self):
        fl = FixLearning(runs=[])
        assert fl.should_skip_family("unknown-family") is False

    def test_prompt_context_with_hint(self):
        fl = FixLearning(runs=[])
        ctx = fl.prompt_context_for_family("injection")
        assert "parameterized" in ctx.lower()

    def test_prompt_context_with_history(self):
        run = _make_telemetry_run(["injection"], ["finished"])
        fl = FixLearning(runs=[run])
        ctx = fl.prompt_context_for_family("injection")
        assert "Historical fix rate" in ctx

    def test_prompt_context_unknown_family(self):
        fl = FixLearning(runs=[])
        ctx = fl.prompt_context_for_family("unknown-family-xyz")
        assert ctx == ""
