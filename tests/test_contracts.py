"""Contract tests for data format conformance.

Covers:
- SARIF v2.1.0 schema conformance: validate parse_sarif handles required fields
- Devin API contract: verify request payloads match expected schema
"""

import json
import os
import sys
import tempfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.parse_sarif import parse_sarif
from scripts.dispatch_devin import create_devin_session

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class TestSarifSchemaConformance:
    """Verify parse_sarif correctly handles SARIF v2.1.0 required fields."""

    def test_handles_version_field(self):
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.sarif")
            with open(path, "w") as f:
                json.dump(sarif, f)
            issues = parse_sarif(path)
        assert issues == []

    def test_handles_runs_with_tool_driver(self):
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "version": "2.15.0",
                        "semanticVersion": "2.15.0",
                        "rules": [],
                    }
                },
                "results": [],
            }],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.sarif")
            with open(path, "w") as f:
                json.dump(sarif, f)
            issues = parse_sarif(path)
        assert issues == []

    def test_handles_result_with_all_sarif_fields(self):
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [{
                            "id": "js/sql-injection",
                            "name": "SqlInjection",
                            "shortDescription": {"text": "SQL injection"},
                            "fullDescription": {"text": "Full description of SQL injection"},
                            "help": {"text": "Use parameterized queries."},
                            "properties": {
                                "tags": ["security", "external/cwe/cwe-89"],
                                "security-severity": "9.8",
                                "precision": "high",
                                "kind": "path-problem",
                            },
                        }],
                    }
                },
                "results": [{
                    "ruleId": "js/sql-injection",
                    "ruleIndex": 0,
                    "level": "error",
                    "message": {"text": "Tainted data flows to query."},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "src/db.js",
                                "uriBaseId": "%SRCROOT%",
                                "index": 0,
                            },
                            "region": {
                                "startLine": 42,
                                "startColumn": 5,
                                "endLine": 42,
                                "endColumn": 30,
                            },
                        }
                    }],
                    "partialFingerprints": {
                        "primaryLocationLineHash": "abc123",
                        "primaryLocationStartColumnFingerprint": "5",
                    },
                    "codeFlows": [],
                    "relatedLocations": [],
                }],
            }],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.sarif")
            with open(path, "w") as f:
                json.dump(sarif, f)
            issues = parse_sarif(path)
        assert len(issues) == 1
        issue = issues[0]
        assert issue["rule_id"] == "js/sql-injection"
        assert issue["severity_score"] == 9.8
        assert issue["cwes"] == ["cwe-89"]
        assert issue["locations"][0]["file"] == "src/db.js"
        assert issue["locations"][0]["start_line"] == 42
        assert issue["locations"][0]["end_line"] == 42
        assert issue["locations"][0]["start_column"] == 5
        assert issue["partial_fingerprints"]["primaryLocationLineHash"] == "abc123"

    def test_handles_extensions_rules(self):
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {"name": "CodeQL", "rules": []},
                    "extensions": [{
                        "name": "codeql/javascript-queries",
                        "version": "0.5.0",
                        "rules": [{
                            "id": "js/xss",
                            "name": "Xss",
                            "properties": {
                                "tags": ["external/cwe/cwe-79"],
                                "security-severity": "7.5",
                            },
                        }],
                    }],
                },
                "results": [{
                    "ruleId": "js/xss",
                    "level": "error",
                    "message": {"text": "XSS"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "view.js"},
                            "region": {"startLine": 10},
                        },
                    }],
                }],
            }],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.sarif")
            with open(path, "w") as f:
                json.dump(sarif, f)
            issues = parse_sarif(path)
        assert len(issues) == 1
        assert issues[0]["severity_score"] == 7.5
        assert issues[0]["cwes"] == ["cwe-79"]

    def test_handles_missing_optional_sarif_fields(self):
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "r1",
                    "message": {"text": "msg"},
                }],
            }],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.sarif")
            with open(path, "w") as f:
                json.dump(sarif, f)
            issues = parse_sarif(path)
        assert len(issues) == 1
        assert issues[0]["rule_id"] == "r1"
        assert issues[0]["locations"] == []
        assert issues[0]["cwes"] == []
        assert issues[0]["severity_score"] == 0.0

    def test_handles_no_runs_key(self):
        sarif = {"version": "2.1.0"}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.sarif")
            with open(path, "w") as f:
                json.dump(sarif, f)
            issues = parse_sarif(path)
        assert issues == []


class TestDevinApiContract:
    """Verify create_devin_session sends payloads matching expected API schema."""

    @patch("scripts.dispatch_devin.requests.post")
    def test_payload_has_required_fields(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "s1", "url": "u1"}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        batch = {
            "batch_id": 1,
            "cwe_family": "injection",
            "severity_tier": "critical",
            "issues": [{"id": "CQLF-R1-0001"}],
        }
        create_devin_session("api-key", "fix these issues", batch)

        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")

        assert "prompt" in payload
        assert isinstance(payload["prompt"], str)
        assert len(payload["prompt"]) > 0

        assert "idempotent" in payload
        assert payload["idempotent"] is True

        assert "tags" in payload
        assert isinstance(payload["tags"], list)
        assert all(isinstance(t, str) for t in payload["tags"])

        assert "title" in payload
        assert isinstance(payload["title"], str)

    @patch("scripts.dispatch_devin.requests.post")
    def test_payload_tags_contain_required_metadata(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "s1", "url": "u1"}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        batch = {
            "batch_id": 3,
            "cwe_family": "xss",
            "severity_tier": "high",
            "issues": [{"id": "CQLF-R2-0005"}, {"id": "CQLF-R2-0006"}],
        }
        os.environ["RUN_NUMBER"] = "42"
        os.environ["RUN_ID"] = "run-abc"
        try:
            create_devin_session("key", "prompt", batch)
        finally:
            os.environ.pop("RUN_NUMBER", None)
            os.environ.pop("RUN_ID", None)

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        tags = payload["tags"]
        assert "codeql-fix" in tags
        assert "severity-high" in tags
        assert "cwe-xss" in tags
        assert "batch-3" in tags
        assert "run-42" in tags
        assert "run-id-run-abc" in tags
        assert "CQLF-R2-0005" in tags
        assert "CQLF-R2-0006" in tags

    @patch("scripts.dispatch_devin.requests.post")
    def test_payload_with_max_acu(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "s1", "url": "u1"}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        batch = {"batch_id": 1, "cwe_family": "xss", "severity_tier": "high", "issues": []}
        create_devin_session("key", "prompt", batch, max_acu=100)

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert payload["max_acu_limit"] == 100

    @patch("scripts.dispatch_devin.requests.post")
    def test_payload_without_max_acu(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "s1", "url": "u1"}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        batch = {"batch_id": 1, "cwe_family": "xss", "severity_tier": "high", "issues": []}
        create_devin_session("key", "prompt", batch, max_acu=None)

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "max_acu_limit" not in payload

    @patch("scripts.dispatch_devin.requests.post")
    def test_auth_header_format(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "s1", "url": "u1"}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        batch = {"batch_id": 1, "cwe_family": "xss", "severity_tier": "high", "issues": []}
        create_devin_session("my-secret-key", "prompt", batch)

        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert headers["Authorization"] == "Bearer my-secret-key"
        assert headers["Content-Type"] == "application/json"

    @patch("scripts.dispatch_devin.requests.post")
    def test_api_endpoint_url(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "s1", "url": "u1"}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        batch = {"batch_id": 1, "cwe_family": "xss", "severity_tier": "high", "issues": []}
        create_devin_session("key", "prompt", batch)

        call_args = mock_post.call_args
        url = call_args.args[0] if call_args.args else call_args[0][0]
        assert url == "https://api.devin.ai/v1/sessions"
