"""Unit tests for playbook_manager.py module."""

import os
import sys
import tempfile

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.playbook_manager import (
    Playbook,
    PlaybookManager,
    PlaybookStep,
    _parse_playbook,
    _playbook_to_dict,
    parse_improvement_suggestions,
)


def _write_playbook(directory: str, name: str, data: dict) -> str:
    path = os.path.join(directory, f"{name}.yaml")
    with open(path, "w") as fh:
        yaml.dump(data, fh, default_flow_style=False, sort_keys=False)
    return path


def _minimal_playbook_data(name: str = "injection") -> dict:
    return {
        "name": name,
        "version": 1,
        "description": f"Fix pattern for {name}.",
        "steps": [
            {
                "id": "identify_entry_points",
                "title": "Identify all entry points for tainted data",
                "instructions": "Trace data flow backwards.\n",
            },
            {
                "id": "apply_fix",
                "title": "Apply the canonical fix pattern",
                "instructions": "Use parameterized queries.\n",
            },
            {
                "id": "run_tests",
                "title": "Run the existing test suite",
                "instructions": "Run pytest or equivalent.\n",
            },
            {
                "id": "add_test",
                "title": "Add a test case",
                "instructions": "Write a test for the vulnerability.\n",
            },
        ],
        "improvement_log": [],
    }


class TestParsePlaybook:
    def test_parses_minimal_playbook(self):
        data = _minimal_playbook_data()
        pb = _parse_playbook(data)
        assert pb.name == "injection"
        assert pb.version == 1
        assert len(pb.steps) == 4
        assert pb.steps[0].id == "identify_entry_points"

    def test_preserves_step_order(self):
        data = _minimal_playbook_data()
        pb = _parse_playbook(data)
        ids = [s.id for s in pb.steps]
        assert ids == ["identify_entry_points", "apply_fix", "run_tests", "add_test"]

    def test_strips_trailing_whitespace_from_instructions(self):
        data = _minimal_playbook_data()
        data["steps"][0]["instructions"] = "some text\n\n  \n"
        pb = _parse_playbook(data)
        assert not pb.steps[0].instructions.endswith("\n")

    def test_defaults_version_when_missing(self):
        data = _minimal_playbook_data()
        del data["version"]
        pb = _parse_playbook(data)
        assert pb.version == 1

    def test_defaults_description_when_missing(self):
        data = _minimal_playbook_data()
        del data["description"]
        pb = _parse_playbook(data)
        assert pb.description == ""

    def test_source_path_stored(self):
        data = _minimal_playbook_data()
        pb = _parse_playbook(data, source_path="/tmp/test.yaml")
        assert pb.source_path == "/tmp/test.yaml"

    def test_empty_improvement_log(self):
        data = _minimal_playbook_data()
        pb = _parse_playbook(data)
        assert pb.improvement_log == []

    def test_existing_improvement_log_preserved(self):
        data = _minimal_playbook_data()
        data["improvement_log"] = [{"step_id": "apply_fix", "suggestion": "be specific"}]
        pb = _parse_playbook(data)
        assert len(pb.improvement_log) == 1


class TestPlaybookToDict:
    def test_round_trip(self):
        data = _minimal_playbook_data()
        pb = _parse_playbook(data)
        result = _playbook_to_dict(pb)
        assert result["name"] == "injection"
        assert result["version"] == 1
        assert len(result["steps"]) == 4
        assert result["steps"][0]["id"] == "identify_entry_points"

    def test_improvement_log_deep_copied(self):
        data = _minimal_playbook_data()
        pb = _parse_playbook(data)
        pb.improvement_log.append({"step_id": "apply_fix", "suggestion": "test"})
        result = _playbook_to_dict(pb)
        result["improvement_log"].clear()
        assert len(pb.improvement_log) == 1


class TestPlaybookManager:
    def test_loads_from_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_playbook(tmpdir, "injection", _minimal_playbook_data("injection"))
            _write_playbook(tmpdir, "xss", _minimal_playbook_data("xss"))
            pm = PlaybookManager(tmpdir)
            assert "injection" in pm.available_families
            assert "xss" in pm.available_families

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PlaybookManager(tmpdir)
            assert pm.available_families == []

    def test_nonexistent_directory(self):
        pm = PlaybookManager("/nonexistent/path")
        assert pm.available_families == []

    def test_skips_non_yaml_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_playbook(tmpdir, "injection", _minimal_playbook_data())
            with open(os.path.join(tmpdir, "readme.txt"), "w") as f:
                f.write("not a playbook")
            pm = PlaybookManager(tmpdir)
            assert pm.available_families == ["injection"]

    def test_skips_invalid_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "bad.yaml"), "w") as f:
                f.write(": : : invalid yaml {{{}}")
            _write_playbook(tmpdir, "injection", _minimal_playbook_data())
            pm = PlaybookManager(tmpdir)
            assert pm.available_families == ["injection"]

    def test_skips_yaml_without_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "noname.yaml"), "w") as f:
                yaml.dump({"version": 1, "steps": []}, f)
            pm = PlaybookManager(tmpdir)
            assert pm.available_families == []

    def test_get_playbook_existing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_playbook(tmpdir, "injection", _minimal_playbook_data())
            pm = PlaybookManager(tmpdir)
            pb = pm.get_playbook("injection")
            assert pb is not None
            assert pb.name == "injection"

    def test_get_playbook_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PlaybookManager(tmpdir)
            assert pm.get_playbook("injection") is None

    def test_format_for_prompt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_playbook(tmpdir, "injection", _minimal_playbook_data())
            pm = PlaybookManager(tmpdir)
            pb = pm.get_playbook("injection")
            prompt = pm.format_for_prompt(pb)
            assert "## Playbook: injection (v1)" in prompt
            assert "Step 1:" in prompt
            assert "Step 2:" in prompt
            assert "Step 3:" in prompt
            assert "Step 4:" in prompt
            assert "Identify all entry points" in prompt
            assert "Apply the canonical fix" in prompt

    def test_format_improvement_request(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_playbook(tmpdir, "injection", _minimal_playbook_data())
            pm = PlaybookManager(tmpdir)
            pb = pm.get_playbook("injection")
            text = pm.format_improvement_request(pb)
            assert "Playbook Improvement Request" in text
            assert "injection" in text
            assert "STEP:" in text
            assert "SUGGESTION:" in text

    def test_apply_improvement_valid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_playbook(tmpdir, "injection", _minimal_playbook_data())
            pm = PlaybookManager(tmpdir)
            result = pm.apply_improvement(
                "injection", "apply_fix", "Add ORM-specific examples", "sess-1"
            )
            assert result is True
            pb = pm.get_playbook("injection")
            assert len(pb.improvement_log) == 1
            assert pb.improvement_log[0]["step_id"] == "apply_fix"
            assert pb.improvement_log[0]["session_id"] == "sess-1"

    def test_apply_improvement_unknown_family(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PlaybookManager(tmpdir)
            assert pm.apply_improvement("unknown", "step1", "suggestion") is False

    def test_apply_improvement_unknown_step(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_playbook(tmpdir, "injection", _minimal_playbook_data())
            pm = PlaybookManager(tmpdir)
            assert pm.apply_improvement("injection", "nonexistent_step", "x") is False

    def test_save_playbook(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_playbook(tmpdir, "injection", _minimal_playbook_data())
            pm = PlaybookManager(tmpdir)
            pm.apply_improvement("injection", "apply_fix", "new tip", "sess-2")
            assert pm.save_playbook("injection") is True

            pm2 = PlaybookManager(tmpdir)
            pb = pm2.get_playbook("injection")
            assert len(pb.improvement_log) == 1
            assert pb.improvement_log[0]["suggestion"] == "new tip"

    def test_save_playbook_unknown_family(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PlaybookManager(tmpdir)
            assert pm.save_playbook("unknown") is False

    def test_loads_yml_extension(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "xss.yml")
            with open(path, "w") as fh:
                yaml.dump(_minimal_playbook_data("xss"), fh)
            pm = PlaybookManager(tmpdir)
            assert "xss" in pm.available_families


class TestParseImprovementSuggestions:
    def test_parses_single_suggestion(self):
        body = (
            "## Playbook Improvements\n"
            "```\n"
            "STEP: apply_fix\n"
            "SUGGESTION: Add Django ORM examples\n"
            "```\n"
        )
        result = parse_improvement_suggestions(body)
        assert len(result) == 1
        assert result[0]["step_id"] == "apply_fix"
        assert "Django ORM" in result[0]["suggestion"]

    def test_parses_multiple_suggestions(self):
        body = (
            "STEP: identify_entry_points\n"
            "SUGGESTION: Include WebSocket inputs\n"
            "\n"
            "STEP: add_test\n"
            "SUGGESTION: Add parameterized test examples\n"
        )
        result = parse_improvement_suggestions(body)
        assert len(result) == 2
        assert result[0]["step_id"] == "identify_entry_points"
        assert result[1]["step_id"] == "add_test"

    def test_empty_body(self):
        assert parse_improvement_suggestions("") == []

    def test_no_suggestions_in_body(self):
        body = "This PR fixes SQL injection issues by using parameterized queries."
        assert parse_improvement_suggestions(body) == []

    def test_multiline_suggestion(self):
        body = (
            "STEP: apply_fix\n"
            "SUGGESTION: For SQLAlchemy use text() with bindparams.\n"
            "Also consider using the ORM query builder.\n"
        )
        result = parse_improvement_suggestions(body)
        assert len(result) == 1
        assert "SQLAlchemy" in result[0]["suggestion"]
        assert "ORM query builder" in result[0]["suggestion"]

    def test_case_insensitive_keywords(self):
        body = (
            "step: apply_fix\n"
            "suggestion: Use prepared statements\n"
        )
        result = parse_improvement_suggestions(body)
        assert len(result) == 1


class TestSyncToDevinApi:
    def test_sync_creates_playbooks(self):
        from unittest.mock import patch, MagicMock
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_playbook(tmpdir, "injection", _minimal_playbook_data("injection"))
            pm = PlaybookManager(tmpdir)

            mock_list_resp = MagicMock()
            mock_list_resp.json.return_value = []
            mock_list_resp.raise_for_status.return_value = None

            mock_create_resp = MagicMock()
            mock_create_resp.json.return_value = {"playbook_id": "pb-123"}
            mock_create_resp.raise_for_status.return_value = None

            with patch("scripts.playbook_manager.requests.get", return_value=mock_list_resp) as mock_get, \
                 patch("scripts.playbook_manager.requests.post", return_value=mock_create_resp) as mock_post:
                result = pm.sync_to_devin_api("fake-key")

            assert result == {"injection": "pb-123"}
            assert pm.get_devin_playbook_id("injection") == "pb-123"
            mock_get.assert_called_once()
            mock_post.assert_called_once()

    def test_sync_updates_existing_playbooks(self):
        from unittest.mock import patch, MagicMock
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_playbook(tmpdir, "injection", _minimal_playbook_data("injection"))
            pm = PlaybookManager(tmpdir)

            mock_list_resp = MagicMock()
            mock_list_resp.json.return_value = [
                {"title": "codeql-fix-injection", "playbook_id": "pb-existing"},
            ]
            mock_list_resp.raise_for_status.return_value = None

            mock_put_resp = MagicMock()
            mock_put_resp.raise_for_status.return_value = None

            with patch("scripts.playbook_manager.requests.get", return_value=mock_list_resp), \
                 patch("scripts.playbook_manager.requests.put", return_value=mock_put_resp) as mock_put:
                result = pm.sync_to_devin_api("fake-key")

            assert result == {"injection": "pb-existing"}
            assert pm.get_devin_playbook_id("injection") == "pb-existing"
            mock_put.assert_called_once()

    def test_sync_empty_api_key_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_playbook(tmpdir, "injection", _minimal_playbook_data("injection"))
            pm = PlaybookManager(tmpdir)
            assert pm.sync_to_devin_api("") == {}

    def test_sync_api_failure_returns_empty(self):
        import requests as req
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_playbook(tmpdir, "injection", _minimal_playbook_data("injection"))
            pm = PlaybookManager(tmpdir)
            with patch("scripts.playbook_manager.requests.get", side_effect=req.exceptions.ConnectionError("fail")):
                assert pm.sync_to_devin_api("fake-key") == {}

    def test_get_devin_playbook_id_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PlaybookManager(tmpdir)
            assert pm.get_devin_playbook_id("injection") == ""


class TestBuiltInPlaybooks:
    def test_injection_playbook_loads(self):
        playbooks_dir = os.path.join(
            os.path.dirname(__file__), "..", "playbooks"
        )
        pm = PlaybookManager(playbooks_dir)
        pb = pm.get_playbook("injection")
        assert pb is not None
        assert len(pb.steps) == 4
        step_ids = [s.id for s in pb.steps]
        assert "identify_entry_points" in step_ids
        assert "apply_fix" in step_ids
        assert "run_tests" in step_ids
        assert "add_test" in step_ids

    def test_xss_playbook_loads(self):
        playbooks_dir = os.path.join(
            os.path.dirname(__file__), "..", "playbooks"
        )
        pm = PlaybookManager(playbooks_dir)
        pb = pm.get_playbook("xss")
        assert pb is not None
        assert len(pb.steps) == 4

    def test_path_traversal_playbook_loads(self):
        playbooks_dir = os.path.join(
            os.path.dirname(__file__), "..", "playbooks"
        )
        pm = PlaybookManager(playbooks_dir)
        pb = pm.get_playbook("path-traversal")
        assert pb is not None
        assert len(pb.steps) == 4

    def test_all_playbooks_have_required_steps(self):
        playbooks_dir = os.path.join(
            os.path.dirname(__file__), "..", "playbooks"
        )
        pm = PlaybookManager(playbooks_dir)
        required_step_ids = {
            "identify_entry_points", "apply_fix", "run_tests", "add_test"
        }
        for family in pm.available_families:
            pb = pm.get_playbook(family)
            step_ids = {s.id for s in pb.steps}
            assert required_step_ids.issubset(step_ids), (
                f"Playbook '{family}' missing steps: "
                f"{required_step_ids - step_ids}"
            )

    def test_all_playbooks_format_for_prompt(self):
        playbooks_dir = os.path.join(
            os.path.dirname(__file__), "..", "playbooks"
        )
        pm = PlaybookManager(playbooks_dir)
        for family in pm.available_families:
            pb = pm.get_playbook(family)
            prompt = pm.format_for_prompt(pb)
            assert f"## Playbook: {family}" in prompt
            assert "Step 1:" in prompt
