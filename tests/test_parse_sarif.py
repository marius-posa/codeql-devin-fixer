"""Unit tests for parse_sarif.py core functions.

Covers: classify_severity, extract_cwes, normalize_cwe, get_cwe_family,
parse_sarif, deduplicate_issues, prioritize_issues, batch_issues.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.parse_sarif import (
    classify_severity,
    extract_cwes,
    normalize_cwe,
    get_cwe_family,
    parse_sarif,
    deduplicate_issues,
    prioritize_issues,
    batch_issues,
    assign_issue_ids,
    generate_summary,
    _file_proximity_score,
    _sort_by_file_proximity,
    _get_issue_files,
    _get_issue_dirs,
)


class TestClassifySeverity:
    def test_critical_lower_bound(self):
        assert classify_severity(9.0) == "critical"

    def test_critical_upper_bound(self):
        assert classify_severity(10.0) == "critical"

    def test_critical_mid(self):
        assert classify_severity(9.5) == "critical"

    def test_high_lower_bound(self):
        assert classify_severity(7.0) == "high"

    def test_high_upper_bound(self):
        assert classify_severity(8.9) == "high"

    def test_medium_lower_bound(self):
        assert classify_severity(4.0) == "medium"

    def test_medium_upper_bound(self):
        assert classify_severity(6.9) == "medium"

    def test_low_lower_bound(self):
        assert classify_severity(0.1) == "low"

    def test_low_upper_bound(self):
        assert classify_severity(3.9) == "low"

    def test_zero_score(self):
        assert classify_severity(0.0) == "none"

    def test_negative_score_returns_none(self):
        assert classify_severity(-1.0) == "none"

    def test_above_ten_returns_none(self):
        assert classify_severity(11.0) == "none"

    def test_boundary_between_low_and_medium(self):
        assert classify_severity(3.9) == "low"
        assert classify_severity(4.0) == "medium"

    def test_boundary_between_medium_and_high(self):
        assert classify_severity(6.9) == "medium"
        assert classify_severity(7.0) == "high"

    def test_boundary_between_high_and_critical(self):
        assert classify_severity(8.9) == "high"
        assert classify_severity(9.0) == "critical"


class TestNormalizeCwe:
    def test_standard_format(self):
        assert normalize_cwe("cwe-79") == "cwe-79"

    def test_uppercase(self):
        assert normalize_cwe("CWE-079") == "cwe-79"

    def test_mixed_case(self):
        assert normalize_cwe("Cwe-79") == "cwe-79"

    def test_leading_zeros(self):
        assert normalize_cwe("CWE-0079") == "cwe-79"

    def test_many_leading_zeros(self):
        assert normalize_cwe("cwe-00089") == "cwe-89"

    def test_no_leading_zeros(self):
        assert normalize_cwe("cwe-89") == "cwe-89"

    def test_large_number(self):
        assert normalize_cwe("CWE-1321") == "cwe-1321"

    def test_malformed_no_dash(self):
        result = normalize_cwe("cwe79")
        assert result == "cwe79"

    def test_malformed_no_prefix(self):
        result = normalize_cwe("79")
        assert result == "79"

    def test_empty_string(self):
        result = normalize_cwe("")
        assert result == ""


class TestExtractCwes:
    def test_standard_cwe_tags(self):
        tags = ["external/cwe/cwe-79", "external/cwe/cwe-80"]
        result = extract_cwes(tags)
        assert result == ["cwe-79", "cwe-80"]

    def test_no_cwe_tags(self):
        tags = ["security", "correctness"]
        assert extract_cwes(tags) == []

    def test_mixed_tags(self):
        tags = ["security", "external/cwe/cwe-89", "correctness"]
        result = extract_cwes(tags)
        assert result == ["cwe-89"]

    def test_leading_zeros_in_tag(self):
        tags = ["external/cwe/cwe-079"]
        result = extract_cwes(tags)
        assert result == ["cwe-79"]

    def test_empty_tags(self):
        assert extract_cwes([]) == []

    def test_non_cwe_external_tags(self):
        tags = ["external/other/something"]
        assert extract_cwes(tags) == []

    def test_multiple_cwes(self):
        tags = [
            "external/cwe/cwe-89",
            "external/cwe/cwe-564",
            "external/cwe/cwe-943",
        ]
        result = extract_cwes(tags)
        assert result == ["cwe-89", "cwe-564", "cwe-943"]


class TestGetCweFamily:
    def test_known_injection_cwe(self):
        assert get_cwe_family(["cwe-89"]) == "injection"

    def test_known_xss_cwe(self):
        assert get_cwe_family(["cwe-79"]) == "xss"

    def test_known_path_traversal(self):
        assert get_cwe_family(["cwe-22"]) == "path-traversal"

    def test_known_crypto(self):
        assert get_cwe_family(["cwe-327"]) == "crypto"

    def test_known_auth(self):
        assert get_cwe_family(["cwe-287"]) == "auth"

    def test_unknown_cwe_returns_other(self):
        assert get_cwe_family(["cwe-999"]) == "other"

    def test_empty_list_returns_other(self):
        assert get_cwe_family([]) == "other"

    def test_first_recognized_wins(self):
        assert get_cwe_family(["cwe-999", "cwe-79"]) == "xss"

    def test_ssrf(self):
        assert get_cwe_family(["cwe-918"]) == "ssrf"

    def test_deserialization(self):
        assert get_cwe_family(["cwe-502"]) == "deserialization"

    def test_redirect(self):
        assert get_cwe_family(["cwe-601"]) == "redirect"

    def test_csrf(self):
        assert get_cwe_family(["cwe-352"]) == "csrf"

    def test_prototype_pollution(self):
        assert get_cwe_family(["cwe-1321"]) == "prototype-pollution"

    def test_hardcoded_credentials(self):
        assert get_cwe_family(["cwe-798"]) == "hardcoded-credentials"

    def test_memory_safety(self):
        assert get_cwe_family(["cwe-119"]) == "memory-safety"


def _make_sarif(runs=None, version="2.1.0"):
    """Helper to build a minimal SARIF structure."""
    sarif = {"version": version, "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"}
    if runs is not None:
        sarif["runs"] = runs
    else:
        sarif["runs"] = []
    return sarif


def _write_sarif(sarif_data, tmpdir):
    path = os.path.join(tmpdir, "test.sarif")
    with open(path, "w") as f:
        json.dump(sarif_data, f)
    return path


class TestParseSarif:
    def test_valid_sarif_with_one_result(self):
        sarif = _make_sarif(runs=[{
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "rules": [{
                        "id": "js/sql-injection",
                        "name": "SqlInjection",
                        "shortDescription": {"text": "SQL injection"},
                        "properties": {
                            "tags": ["external/cwe/cwe-89"],
                            "security-severity": "9.8",
                        },
                    }],
                },
            },
            "results": [{
                "ruleId": "js/sql-injection",
                "level": "error",
                "message": {"text": "User input flows to SQL query."},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/db.js"},
                        "region": {"startLine": 42, "endLine": 42, "startColumn": 5},
                    },
                }],
            }],
        }])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(sarif, tmpdir)
            issues = parse_sarif(path)
        assert len(issues) == 1
        issue = issues[0]
        assert issue["rule_id"] == "js/sql-injection"
        assert issue["severity_score"] == 9.8
        assert issue["severity_tier"] == "critical"
        assert issue["cwes"] == ["cwe-89"]
        assert issue["cwe_family"] == "injection"
        assert issue["locations"][0]["file"] == "src/db.js"
        assert issue["locations"][0]["start_line"] == 42
        assert issue["message"] == "User input flows to SQL query."

    def test_empty_runs(self):
        sarif = _make_sarif(runs=[])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(sarif, tmpdir)
            issues = parse_sarif(path)
        assert issues == []

    def test_run_with_no_results(self):
        sarif = _make_sarif(runs=[{
            "tool": {"driver": {"name": "CodeQL", "rules": []}},
            "results": [],
        }])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(sarif, tmpdir)
            issues = parse_sarif(path)
        assert issues == []

    def test_missing_fields_gracefully_handled(self):
        sarif = _make_sarif(runs=[{
            "tool": {"driver": {"name": "CodeQL"}},
            "results": [{"ruleId": "unknown-rule", "message": {"text": "something"}}],
        }])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(sarif, tmpdir)
            issues = parse_sarif(path)
        assert len(issues) == 1
        assert issues[0]["rule_id"] == "unknown-rule"
        assert issues[0]["severity_score"] == 0.0
        assert issues[0]["cwes"] == []

    def test_multiple_runs(self):
        run_template = {
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "rules": [{
                        "id": "js/xss",
                        "name": "Xss",
                        "properties": {
                            "tags": ["external/cwe/cwe-79"],
                            "security-severity": "7.5",
                        },
                    }],
                },
            },
            "results": [{
                "ruleId": "js/xss",
                "level": "error",
                "message": {"text": "XSS vuln"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/view.js"},
                        "region": {"startLine": 10},
                    },
                }],
            }],
        }
        sarif = _make_sarif(runs=[run_template, run_template])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(sarif, tmpdir)
            issues = parse_sarif(path)
        assert len(issues) == 2

    def test_extensions_with_rules(self):
        sarif = _make_sarif(runs=[{
            "tool": {
                "driver": {"name": "CodeQL", "rules": []},
                "extensions": [{
                    "name": "codeql/javascript-queries",
                    "rules": [{
                        "id": "js/path-injection",
                        "name": "PathInjection",
                        "shortDescription": {"text": "Path injection"},
                        "properties": {
                            "tags": ["external/cwe/cwe-22"],
                            "security-severity": "7.5",
                        },
                    }],
                }],
            },
            "results": [{
                "ruleId": "js/path-injection",
                "level": "error",
                "message": {"text": "User controls file path."},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/files.js"},
                        "region": {"startLine": 5},
                    },
                }],
            }],
        }])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(sarif, tmpdir)
            issues = parse_sarif(path)
        assert len(issues) == 1
        assert issues[0]["rule_id"] == "js/path-injection"
        assert issues[0]["cwes"] == ["cwe-22"]
        assert issues[0]["cwe_family"] == "path-traversal"
        assert issues[0]["severity_score"] == 7.5

    def test_fallback_severity_error_level(self):
        sarif = _make_sarif(runs=[{
            "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "rule1", "properties": {}}]}},
            "results": [{"ruleId": "rule1", "level": "error", "message": {"text": "err"}}],
        }])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(sarif, tmpdir)
            issues = parse_sarif(path)
        assert issues[0]["severity_score"] == 7.0

    def test_fallback_severity_warning_level(self):
        sarif = _make_sarif(runs=[{
            "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "rule1", "properties": {}}]}},
            "results": [{"ruleId": "rule1", "level": "warning", "message": {"text": "warn"}}],
        }])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(sarif, tmpdir)
            issues = parse_sarif(path)
        assert issues[0]["severity_score"] == 4.0

    def test_partial_fingerprints_preserved(self):
        sarif = _make_sarif(runs=[{
            "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "r1", "properties": {}}]}},
            "results": [{
                "ruleId": "r1",
                "message": {"text": "msg"},
                "partialFingerprints": {"primaryLocationLineHash": "abc123"},
            }],
        }])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(sarif, tmpdir)
            issues = parse_sarif(path)
        assert issues[0]["partial_fingerprints"]["primaryLocationLineHash"] == "abc123"

    def test_rule_help_truncated(self):
        long_help = "x" * 2000
        sarif = _make_sarif(runs=[{
            "tool": {"driver": {"name": "CodeQL", "rules": [{
                "id": "r1",
                "help": {"text": long_help},
                "properties": {},
            }]}},
            "results": [{"ruleId": "r1", "message": {"text": "msg"}}],
        }])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(sarif, tmpdir)
            issues = parse_sarif(path)
        assert len(issues[0]["rule_help"]) == 1000


class TestDeduplicateIssues:
    def _issue(self, rule_id="r1", file="a.js", line=10):
        return {
            "rule_id": rule_id,
            "locations": [{"file": file, "start_line": line}],
            "severity_score": 7.0,
            "severity_tier": "high",
            "cwe_family": "injection",
        }

    def test_removes_exact_duplicates(self):
        issues = [self._issue(), self._issue()]
        result = deduplicate_issues(issues)
        assert len(result) == 1

    def test_keeps_different_rules(self):
        issues = [self._issue(rule_id="r1"), self._issue(rule_id="r2")]
        result = deduplicate_issues(issues)
        assert len(result) == 2

    def test_keeps_different_locations(self):
        issues = [self._issue(line=10), self._issue(line=20)]
        result = deduplicate_issues(issues)
        assert len(result) == 2

    def test_keeps_different_files(self):
        issues = [self._issue(file="a.js"), self._issue(file="b.js")]
        result = deduplicate_issues(issues)
        assert len(result) == 2

    def test_empty_input(self):
        assert deduplicate_issues([]) == []

    def test_single_issue(self):
        result = deduplicate_issues([self._issue()])
        assert len(result) == 1

    def test_preserves_order(self):
        issues = [
            self._issue(rule_id="r1", file="a.js"),
            self._issue(rule_id="r2", file="b.js"),
            self._issue(rule_id="r1", file="a.js"),
        ]
        result = deduplicate_issues(issues)
        assert len(result) == 2
        assert result[0]["rule_id"] == "r1"
        assert result[1]["rule_id"] == "r2"


class TestPrioritizeIssues:
    def _issue(self, score=7.0, tier="high", family="injection"):
        return {
            "severity_score": score,
            "severity_tier": tier,
            "cwe_family": family,
        }

    def test_filter_by_critical_threshold(self):
        issues = [
            self._issue(9.5, "critical"),
            self._issue(7.5, "high"),
            self._issue(5.0, "medium"),
            self._issue(2.0, "low"),
        ]
        result = prioritize_issues(issues, "critical")
        assert len(result) == 1
        assert result[0]["severity_tier"] == "critical"

    def test_filter_by_high_threshold(self):
        issues = [
            self._issue(9.5, "critical"),
            self._issue(7.5, "high"),
            self._issue(5.0, "medium"),
            self._issue(2.0, "low"),
        ]
        result = prioritize_issues(issues, "high")
        assert len(result) == 2

    def test_filter_by_medium_threshold(self):
        issues = [
            self._issue(9.5, "critical"),
            self._issue(7.5, "high"),
            self._issue(5.0, "medium"),
            self._issue(2.0, "low"),
        ]
        result = prioritize_issues(issues, "medium")
        assert len(result) == 3

    def test_filter_by_low_threshold_keeps_all(self):
        issues = [
            self._issue(9.5, "critical"),
            self._issue(7.5, "high"),
            self._issue(5.0, "medium"),
            self._issue(2.0, "low"),
        ]
        result = prioritize_issues(issues, "low")
        assert len(result) == 4

    def test_sort_by_descending_severity(self):
        issues = [
            self._issue(2.0, "low"),
            self._issue(9.5, "critical"),
            self._issue(5.0, "medium"),
        ]
        result = prioritize_issues(issues, "low")
        assert result[0]["severity_score"] == 9.5
        assert result[1]["severity_score"] == 5.0
        assert result[2]["severity_score"] == 2.0

    def test_secondary_sort_by_cwe_family(self):
        issues = [
            self._issue(7.0, "high", "xss"),
            self._issue(7.0, "high", "auth"),
        ]
        result = prioritize_issues(issues, "low")
        assert result[0]["cwe_family"] == "auth"
        assert result[1]["cwe_family"] == "xss"

    def test_empty_input(self):
        assert prioritize_issues([], "low") == []

    def test_none_tier_excluded_by_low(self):
        issues = [self._issue(0.0, "none")]
        result = prioritize_issues(issues, "low")
        assert len(result) == 0


class TestBatchIssues:
    def _issue(self, family="injection", score=7.0, tier="high"):
        return {
            "cwe_family": family,
            "severity_score": score,
            "severity_tier": tier,
            "locations": [{"file": "a.js"}],
        }

    def test_groups_by_family(self):
        issues = [
            self._issue("injection"),
            self._issue("injection"),
            self._issue("xss"),
        ]
        batches = batch_issues(issues, batch_size=10, max_batches=10)
        families = {b["cwe_family"] for b in batches}
        assert "injection" in families
        assert "xss" in families

    def test_batch_size_splitting(self):
        issues = [self._issue("injection") for _ in range(7)]
        batches = batch_issues(issues, batch_size=3, max_batches=10)
        injection_batches = [b for b in batches if b["cwe_family"] == "injection"]
        assert len(injection_batches) == 3
        assert injection_batches[0]["issue_count"] == 3
        assert injection_batches[1]["issue_count"] == 3
        assert injection_batches[2]["issue_count"] == 1

    def test_max_batches_cap(self):
        issues = [self._issue("injection") for _ in range(20)]
        batches = batch_issues(issues, batch_size=2, max_batches=3)
        assert len(batches) == 3

    def test_empty_input(self):
        assert batch_issues([], batch_size=5, max_batches=10) == []

    def test_batch_ids_sequential(self):
        issues = [
            self._issue("injection", score=9.0, tier="critical"),
            self._issue("xss", score=7.0, tier="high"),
        ]
        batches = batch_issues(issues, batch_size=10, max_batches=10)
        ids = [b["batch_id"] for b in batches]
        assert ids == [1, 2]

    def test_highest_severity_family_first(self):
        issues = [
            self._issue("xss", score=5.0, tier="medium"),
            self._issue("injection", score=9.5, tier="critical"),
        ]
        batches = batch_issues(issues, batch_size=10, max_batches=10)
        assert batches[0]["cwe_family"] == "injection"

    def test_file_count_in_batch(self):
        issues = [
            {
                "cwe_family": "injection",
                "severity_score": 7.0,
                "severity_tier": "high",
                "locations": [{"file": "a.js"}, {"file": "b.js"}],
            },
            {
                "cwe_family": "injection",
                "severity_score": 7.0,
                "severity_tier": "high",
                "locations": [{"file": "a.js"}],
            },
        ]
        batches = batch_issues(issues, batch_size=10, max_batches=10)
        assert batches[0]["file_count"] == 2

    def test_severity_tier_reflects_max(self):
        issues = [
            self._issue("injection", score=5.0, tier="medium"),
            self._issue("injection", score=9.0, tier="critical"),
        ]
        batches = batch_issues(issues, batch_size=10, max_batches=10)
        assert batches[0]["severity_tier"] == "critical"
        assert batches[0]["max_severity_score"] == 9.0


class TestFileProximity:
    def _issue(self, files, score=7.0):
        return {
            "cwe_family": "injection",
            "severity_score": score,
            "severity_tier": "high",
            "locations": [{"file": f} for f in files],
        }

    def test_get_issue_files(self):
        issue = self._issue(["src/a.js", "src/b.js"])
        assert _get_issue_files(issue) == {"src/a.js", "src/b.js"}

    def test_get_issue_files_empty_file(self):
        issue = {"locations": [{"file": ""}]}
        assert _get_issue_files(issue) == set()

    def test_get_issue_dirs(self):
        issue = self._issue(["src/a.js", "lib/b.js"])
        dirs = _get_issue_dirs(issue)
        assert "src" in dirs
        assert "lib" in dirs

    def test_proximity_same_file(self):
        a = self._issue(["src/a.js"])
        b = self._issue(["src/a.js"])
        assert _file_proximity_score(a, b) == 1.0

    def test_proximity_same_dir(self):
        a = self._issue(["src/a.js"])
        b = self._issue(["src/b.js"])
        assert _file_proximity_score(a, b) == 0.5

    def test_proximity_different_dir(self):
        a = self._issue(["src/a.js"])
        b = self._issue(["lib/b.js"])
        assert _file_proximity_score(a, b) == 0.0

    def test_sort_empty(self):
        assert _sort_by_file_proximity([]) == []

    def test_sort_single(self):
        issue = self._issue(["src/a.js"])
        assert _sort_by_file_proximity([issue]) == [issue]

    def test_sort_groups_same_file(self):
        a = self._issue(["src/a.js"], score=5.0)
        b = self._issue(["lib/x.js"], score=5.0)
        c = self._issue(["src/a.js"], score=5.0)
        result = _sort_by_file_proximity([a, b, c])
        assert result[0] is a
        assert result[1] is c

    def test_sort_groups_same_dir(self):
        a = self._issue(["src/a.js"], score=5.0)
        b = self._issue(["lib/x.js"], score=5.0)
        c = self._issue(["src/b.js"], score=5.0)
        result = _sort_by_file_proximity([a, b, c])
        assert result[0] is a
        assert result[1] is c

    def test_batch_issues_uses_proximity(self):
        issues = [
            self._issue(["src/a.js"], score=7.0),
            self._issue(["lib/x.js"], score=7.0),
            self._issue(["src/a.js"], score=7.0),
        ]
        batches = batch_issues(issues, batch_size=10, max_batches=10)
        batch_issues_list = batches[0]["issues"]
        assert batch_issues_list[0] is issues[0]
        assert batch_issues_list[1] is issues[2]


class TestAssignIssueIds:
    def test_assigns_sequential_ids(self):
        issues = [
            {"rule_id": "r1", "locations": [{"file": "a.js", "start_line": 1}], "message": "m1"},
            {"rule_id": "r2", "locations": [{"file": "b.js", "start_line": 2}], "message": "m2"},
        ]
        result = assign_issue_ids(issues, "42")
        assert result[0]["id"] == "CQLF-R42-0001"
        assert result[1]["id"] == "CQLF-R42-0002"
        assert "fingerprint" in result[0]

    def test_no_run_number(self):
        issues = [{"rule_id": "r1", "locations": [], "message": "m"}]
        result = assign_issue_ids(issues, "")
        assert result[0]["id"] == "CQLF-0001"


class TestGenerateSummary:
    def test_summary_contains_key_sections(self):
        issues = [
            {"severity_tier": "critical", "cwe_family": "injection"},
            {"severity_tier": "high", "cwe_family": "xss"},
        ]
        batches = [
            {"batch_id": 1, "cwe_family": "injection", "severity_tier": "critical",
             "issue_count": 1, "file_count": 1},
        ]
        summary = generate_summary(issues, batches, total_raw=3, dedup_removed=1)
        assert "# CodeQL Analysis Summary" in summary
        assert "CRITICAL" in summary
        assert "HIGH" in summary
        assert "injection" in summary
        assert "Batches Created: 1" in summary
