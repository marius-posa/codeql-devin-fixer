"""Unit tests for machine_config.py."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.machine_config import (
    MACHINE_HEAVY,
    MACHINE_LIGHT,
    MACHINE_STANDARD,
    list_machines,
    resolve_machine_acu,
    select_machine_type,
    _estimate_repo_size,
)


class TestListMachines:
    def test_returns_three_tiers(self):
        machines = list_machines()
        assert len(machines) == 3

    def test_names(self):
        names = [m.name for m in list_machines()]
        assert names == ["light", "standard", "heavy"]

    def test_acu_ordering(self):
        machines = list_machines()
        assert machines[0].max_acu < machines[1].max_acu < machines[2].max_acu


class TestEstimateRepoSize:
    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            assert _estimate_repo_size(tmpdir) == 0

    def test_counts_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(10):
                open(os.path.join(tmpdir, f"file{i}.py"), "w").close()
            assert _estimate_repo_size(tmpdir) == 10

    def test_skips_git_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            git_dir = os.path.join(tmpdir, ".git")
            os.makedirs(git_dir)
            open(os.path.join(git_dir, "HEAD"), "w").close()
            open(os.path.join(tmpdir, "src.py"), "w").close()
            assert _estimate_repo_size(tmpdir) == 1

    def test_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nm = os.path.join(tmpdir, "node_modules")
            os.makedirs(nm)
            open(os.path.join(nm, "pkg.js"), "w").close()
            open(os.path.join(tmpdir, "index.js"), "w").close()
            assert _estimate_repo_size(tmpdir) == 1

    def test_nonexistent_dir(self):
        assert _estimate_repo_size("/nonexistent/path") == 0

    def test_empty_string(self):
        assert _estimate_repo_size("") == 0


class TestSelectMachineType:
    def test_defaults_to_light(self):
        mt = select_machine_type()
        assert mt == MACHINE_LIGHT

    def test_many_issues_bumps_to_standard(self):
        mt = select_machine_type(issue_count=8, file_count=5)
        assert mt.max_acu >= MACHINE_STANDARD.max_acu

    def test_high_severity_contributes(self):
        mt = select_machine_type(
            issue_count=4, severity_tier="critical", file_count=5,
        )
        assert mt.max_acu >= MACHINE_STANDARD.max_acu

    def test_cross_family_contributes(self):
        mt = select_machine_type(
            issue_count=4, cross_family=True, file_count=5,
        )
        assert mt.max_acu >= MACHINE_STANDARD.max_acu

    def test_compiled_language_contributes(self):
        mt = select_machine_type(
            issue_count=4, file_count=5, languages=["java"],
        )
        assert mt.max_acu >= MACHINE_STANDARD.max_acu

    def test_large_repo_bumps_score(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(5001):
                open(os.path.join(tmpdir, f"f{i}.py"), "w").close()
            mt = select_machine_type(
                target_dir=tmpdir, issue_count=4, file_count=5,
            )
            assert mt == MACHINE_HEAVY

    def test_everything_heavy(self):
        mt = select_machine_type(
            issue_count=10,
            file_count=15,
            severity_tier="critical",
            cross_family=True,
            languages=["java"],
        )
        assert mt == MACHINE_HEAVY


class TestResolveMachineAcu:
    def test_explicit_max_acu_takes_precedence(self):
        result = resolve_machine_acu(explicit_max_acu=42)
        assert result == 42

    def test_explicit_machine_type_name(self):
        result = resolve_machine_acu(machine_type_name="heavy")
        assert result == MACHINE_HEAVY.max_acu

    def test_unknown_machine_type_falls_back(self):
        result = resolve_machine_acu(machine_type_name="unknown_tier")
        assert result is not None

    def test_auto_selection(self):
        result = resolve_machine_acu(issue_count=1)
        assert result == MACHINE_LIGHT.max_acu

    def test_explicit_acu_overrides_machine_type(self):
        result = resolve_machine_acu(
            explicit_max_acu=99, machine_type_name="light",
        )
        assert result == 99

    def test_zero_acu_triggers_auto(self):
        result = resolve_machine_acu(explicit_max_acu=0)
        assert result is not None
        assert result != 0
