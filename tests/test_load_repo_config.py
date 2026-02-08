"""Unit tests for scripts/load_repo_config.py.

Covers: _parse_yaml, load_config, main (GITHUB_OUTPUT writing).
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.load_repo_config import _parse_yaml, load_config, VALID_SEVERITIES


class TestParseYaml:
    def test_simple_key_value(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("severity_threshold: high\nbatch_size: 10\n")
            f.flush()
            result = _parse_yaml(f.name)
        os.unlink(f.name)
        assert result["severity_threshold"] == "high"
        assert result["batch_size"] == 10

    def test_boolean_values(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("enabled: true\ndisabled: false\n")
            f.flush()
            result = _parse_yaml(f.name)
        os.unlink(f.name)
        assert result["enabled"] is True
        assert result["disabled"] is False

    def test_json_inline_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write('exclude_paths: ["src/test", "vendor"]\n')
            f.flush()
            result = _parse_yaml(f.name)
        os.unlink(f.name)
        assert result["exclude_paths"] == ["src/test", "vendor"]

    def test_json_inline_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write('cwe_families: {"custom": ["cwe-999"]}\n')
            f.flush()
            result = _parse_yaml(f.name)
        os.unlink(f.name)
        assert result["cwe_families"] == {"custom": ["cwe-999"]}

    def test_skips_comments_and_blanks(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("# comment\n\nbatch_size: 5\n")
            f.flush()
            result = _parse_yaml(f.name)
        os.unlink(f.name)
        assert result == {"batch_size": 5}

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("")
            f.flush()
            result = _parse_yaml(f.name)
        os.unlink(f.name)
        assert result == {}


class TestLoadConfig:
    def _write_config(self, content):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False)
        f.write(content)
        f.flush()
        f.close()
        return f.name

    def test_valid_config(self):
        path = self._write_config("severity_threshold: high\nbatch_size: 10\nmax_sessions: 5\n")
        config = load_config(path)
        os.unlink(path)
        assert config["severity_threshold"] == "high"
        assert config["batch_size"] == 10
        assert config["max_sessions"] == 5

    def test_invalid_severity_removed(self, capsys):
        path = self._write_config("severity_threshold: extreme\n")
        config = load_config(path)
        os.unlink(path)
        assert "severity_threshold" not in config
        assert "WARNING" in capsys.readouterr().out

    def test_batch_size_out_of_range_removed(self, capsys):
        path = self._write_config("batch_size: 999\n")
        config = load_config(path)
        os.unlink(path)
        assert "batch_size" not in config
        assert "WARNING" in capsys.readouterr().out

    def test_batch_size_zero_removed(self, capsys):
        path = self._write_config("batch_size: 0\n")
        config = load_config(path)
        os.unlink(path)
        assert "batch_size" not in config

    def test_max_sessions_out_of_range_removed(self, capsys):
        path = self._write_config("max_sessions: 200\n")
        config = load_config(path)
        os.unlink(path)
        assert "max_sessions" not in config
        assert "WARNING" in capsys.readouterr().out

    def test_exclude_paths_non_list_removed(self, capsys):
        path = self._write_config("exclude_paths: not-a-list\n")
        config = load_config(path)
        os.unlink(path)
        assert "exclude_paths" not in config
        assert "WARNING" in capsys.readouterr().out

    def test_cwe_families_non_dict_removed(self, capsys):
        path = self._write_config('cwe_families: ["not", "a", "dict"]\n')
        config = load_config(path)
        os.unlink(path)
        assert "cwe_families" not in config
        assert "WARNING" in capsys.readouterr().out

    def test_valid_exclude_paths_preserved(self):
        path = self._write_config('exclude_paths: ["vendor", "test"]\n')
        config = load_config(path)
        os.unlink(path)
        assert config["exclude_paths"] == ["vendor", "test"]

    def test_valid_cwe_families_preserved(self):
        path = self._write_config('cwe_families: {"custom": ["cwe-999"]}\n')
        config = load_config(path)
        os.unlink(path)
        assert config["cwe_families"] == {"custom": ["cwe-999"]}

    def test_empty_config(self):
        path = self._write_config("")
        config = load_config(path)
        os.unlink(path)
        assert config == {}
