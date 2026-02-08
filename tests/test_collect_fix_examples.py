"""Unit tests for _collect_fix_examples in persist_telemetry.py."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.persist_telemetry import _collect_fix_examples


def _write_fix_diffs(tmpdir, data):
    with open(os.path.join(tmpdir, "fix_diffs.json"), "w") as f:
        json.dump(data, f)


class TestCollectFixExamples:
    def test_no_diff_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            result = _collect_fix_examples(d, [], [])
            assert result == []

    def test_empty_diff_list(self):
        with tempfile.TemporaryDirectory() as d:
            _write_fix_diffs(d, [])
            result = _collect_fix_examples(d, [], [])
            assert result == []

    def test_single_diff_with_finished_session(self):
        with tempfile.TemporaryDirectory() as d:
            _write_fix_diffs(d, [
                {"session_id": "s1", "diff": "- bad\n+ good", "file": "src/db.js"},
            ])
            sessions = [{"session_id": "s1", "status": "finished", "batch_id": 1}]
            batches = [{"batch_id": 1, "cwe_family": "injection", "issues": []}]
            result = _collect_fix_examples(d, sessions, batches)
            assert len(result) == 1
            assert result[0]["cwe_family"] == "injection"
            assert result[0]["file"] == "src/db.js"
            assert "- bad" in result[0]["diff"]

    def test_skips_non_finished_sessions(self):
        with tempfile.TemporaryDirectory() as d:
            _write_fix_diffs(d, [
                {"session_id": "s1", "diff": "some diff"},
            ])
            sessions = [{"session_id": "s1", "status": "error: timeout", "batch_id": 1}]
            batches = [{"batch_id": 1, "cwe_family": "xss", "issues": []}]
            result = _collect_fix_examples(d, sessions, batches)
            assert result == []

    def test_skips_created_sessions(self):
        with tempfile.TemporaryDirectory() as d:
            _write_fix_diffs(d, [
                {"session_id": "s1", "diff": "some diff"},
            ])
            sessions = [{"session_id": "s1", "status": "created", "batch_id": 1}]
            batches = [{"batch_id": 1, "cwe_family": "xss", "issues": []}]
            result = _collect_fix_examples(d, sessions, batches)
            assert result == []

    def test_stopped_session_included(self):
        with tempfile.TemporaryDirectory() as d:
            _write_fix_diffs(d, [
                {"session_id": "s1", "diff": "diff content"},
            ])
            sessions = [{"session_id": "s1", "status": "stopped", "batch_id": 1}]
            batches = [{"batch_id": 1, "cwe_family": "auth", "issues": []}]
            result = _collect_fix_examples(d, sessions, batches)
            assert len(result) == 1

    def test_truncates_large_diffs(self):
        with tempfile.TemporaryDirectory() as d:
            _write_fix_diffs(d, [
                {"session_id": "s1", "diff": "x" * 10000},
            ])
            sessions = [{"session_id": "s1", "status": "finished", "batch_id": 1}]
            batches = [{"batch_id": 1, "cwe_family": "injection", "issues": []}]
            result = _collect_fix_examples(d, sessions, batches)
            assert len(result[0]["diff"]) == 5000

    def test_skips_empty_diffs(self):
        with tempfile.TemporaryDirectory() as d:
            _write_fix_diffs(d, [
                {"session_id": "s1", "diff": ""},
            ])
            sessions = [{"session_id": "s1", "status": "finished", "batch_id": 1}]
            batches = [{"batch_id": 1, "cwe_family": "injection", "issues": []}]
            result = _collect_fix_examples(d, sessions, batches)
            assert result == []

    def test_file_from_batch_issues_when_missing(self):
        with tempfile.TemporaryDirectory() as d:
            _write_fix_diffs(d, [
                {"session_id": "s1", "diff": "diff content", "file": ""},
            ])
            sessions = [{"session_id": "s1", "status": "finished", "batch_id": 1}]
            batches = [{
                "batch_id": 1,
                "cwe_family": "injection",
                "issues": [{"locations": [{"file": "src/handler.js"}]}],
            }]
            result = _collect_fix_examples(d, sessions, batches)
            assert result[0]["file"] == "src/handler.js"

    def test_family_from_entry_when_no_batch(self):
        with tempfile.TemporaryDirectory() as d:
            _write_fix_diffs(d, [
                {"session_id": "", "diff": "diff", "cwe_family": "xss", "file": "f.js"},
            ])
            result = _collect_fix_examples(d, [], [])
            assert len(result) == 1
            assert result[0]["cwe_family"] == "xss"

    def test_single_dict_diff_data(self):
        with tempfile.TemporaryDirectory() as d:
            _write_fix_diffs(d, {"session_id": "s1", "diff": "diff", "file": "f.js"})
            sessions = [{"session_id": "s1", "status": "finished", "batch_id": 1}]
            batches = [{"batch_id": 1, "cwe_family": "crypto", "issues": []}]
            result = _collect_fix_examples(d, sessions, batches)
            assert len(result) == 1
            assert result[0]["cwe_family"] == "crypto"

    def test_multiple_sessions_mixed_status(self):
        with tempfile.TemporaryDirectory() as d:
            _write_fix_diffs(d, [
                {"session_id": "s1", "diff": "good diff", "file": "a.js"},
                {"session_id": "s2", "diff": "bad diff", "file": "b.js"},
                {"session_id": "s3", "diff": "ok diff", "file": "c.js"},
            ])
            sessions = [
                {"session_id": "s1", "status": "finished", "batch_id": 1},
                {"session_id": "s2", "status": "error: fail", "batch_id": 2},
                {"session_id": "s3", "status": "stopped", "batch_id": 3},
            ]
            batches = [
                {"batch_id": 1, "cwe_family": "injection", "issues": []},
                {"batch_id": 2, "cwe_family": "xss", "issues": []},
                {"batch_id": 3, "cwe_family": "auth", "issues": []},
            ]
            result = _collect_fix_examples(d, sessions, batches)
            assert len(result) == 2
            families = {r["cwe_family"] for r in result}
            assert "injection" in families
            assert "auth" in families
            assert "xss" not in families
