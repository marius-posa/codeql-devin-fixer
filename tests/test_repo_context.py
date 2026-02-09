"""Unit tests for repo_context.py module."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.repo_context import (
    RepoContext,
    analyze_repo,
    _extract_npm_deps,
    _extract_pip_deps,
    _detect_test_frameworks,
    _detect_style_configs,
)


class TestRepoContext:
    def test_empty_context(self):
        ctx = RepoContext()
        assert ctx.is_empty()
        assert ctx.to_prompt_section() == ""

    def test_non_empty_with_deps(self):
        ctx = RepoContext(dependencies={"npm": ["express", "lodash"]})
        assert not ctx.is_empty()
        section = ctx.to_prompt_section()
        assert "Dependencies:" in section
        assert "npm: express, lodash" in section

    def test_non_empty_with_test_frameworks(self):
        ctx = RepoContext(test_frameworks=["jest"])
        assert not ctx.is_empty()
        section = ctx.to_prompt_section()
        assert "Testing framework(s): jest" in section

    def test_non_empty_with_style_configs(self):
        ctx = RepoContext(style_configs=[".eslintrc.json", ".prettierrc"])
        assert not ctx.is_empty()
        section = ctx.to_prompt_section()
        assert "Code style config: .eslintrc.json, .prettierrc" in section

    def test_full_context(self):
        ctx = RepoContext(
            dependencies={"npm": ["react"], "pip": ["flask"]},
            test_frameworks=["jest", "pytest"],
            style_configs=[".eslintrc"],
        )
        section = ctx.to_prompt_section()
        assert "Repository context:" in section
        assert "npm: react" in section
        assert "pip: flask" in section
        assert "jest, pytest" in section
        assert ".eslintrc" in section

    def test_deps_without_names(self):
        ctx = RepoContext(dependencies={"cargo": []})
        section = ctx.to_prompt_section()
        assert "cargo: (manifest found)" in section


class TestExtractNpmDeps:
    def test_extracts_deps_and_devdeps(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = {
                "dependencies": {"express": "^4.0.0", "lodash": "^4.17.0"},
                "devDependencies": {"jest": "^29.0.0"},
            }
            with open(os.path.join(tmpdir, "package.json"), "w") as f:
                json.dump(pkg, f)
            deps = _extract_npm_deps(tmpdir)
            assert "express" in deps
            assert "lodash" in deps
            assert "jest" in deps

    def test_no_package_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            assert _extract_npm_deps(tmpdir) == []

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "package.json"), "w") as f:
                f.write("not json")
            assert _extract_npm_deps(tmpdir) == []


class TestExtractPipDeps:
    def test_extracts_requirements(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "requirements.txt"), "w") as f:
                f.write("flask>=2.0\nrequests==2.28.0\npytest\n")
            deps = _extract_pip_deps(tmpdir)
            assert "flask" in deps
            assert "requests" in deps
            assert "pytest" in deps

    def test_skips_flags(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "requirements.txt"), "w") as f:
                f.write("-r base.txt\nflask\n")
            deps = _extract_pip_deps(tmpdir)
            assert "flask" in deps
            assert len(deps) == 1

    def test_no_requirements_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            assert _extract_pip_deps(tmpdir) == []


class TestDetectTestFrameworks:
    def test_jest_from_package_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = {"devDependencies": {"jest": "^29.0.0"}}
            with open(os.path.join(tmpdir, "package.json"), "w") as f:
                json.dump(pkg, f)
            fws = _detect_test_frameworks(tmpdir)
            assert "jest" in fws

    def test_vitest_from_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "vitest.config.ts"), "w") as f:
                f.write("export default {}")
            fws = _detect_test_frameworks(tmpdir)
            assert "vitest" in fws

    def test_pytest_from_conftest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "conftest.py"), "w") as f:
                f.write("")
            fws = _detect_test_frameworks(tmpdir)
            assert "pytest" in fws

    def test_pytest_from_pyproject_toml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "pyproject.toml"), "w") as f:
                f.write("[tool.pytest.ini_options]\ntestpaths = ['tests']\n")
            fws = _detect_test_frameworks(tmpdir)
            assert "pytest" in fws

    def test_go_test_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "go.mod"), "w") as f:
                f.write("module example.com/foo")
            with open(os.path.join(tmpdir, "main_test.go"), "w") as f:
                f.write("package main")
            fws = _detect_test_frameworks(tmpdir)
            assert "go test" in fws

    def test_cargo_test_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "Cargo.toml"), "w") as f:
                f.write("[package]\nname = \"foo\"")
            fws = _detect_test_frameworks(tmpdir)
            assert "cargo test" in fws

    def test_no_frameworks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fws = _detect_test_frameworks(tmpdir)
            assert fws == []

    def test_mocha_from_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, ".mocharc.yml"), "w") as f:
                f.write("timeout: 5000")
            fws = _detect_test_frameworks(tmpdir)
            assert "mocha" in fws


class TestDetectStyleConfigs:
    def test_eslint_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, ".eslintrc.json"), "w") as f:
                f.write("{}")
            configs = _detect_style_configs(tmpdir)
            assert ".eslintrc.json" in configs

    def test_prettier_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, ".prettierrc"), "w") as f:
                f.write("{}")
            configs = _detect_style_configs(tmpdir)
            assert ".prettierrc" in configs

    def test_editorconfig_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, ".editorconfig"), "w") as f:
                f.write("root = true")
            configs = _detect_style_configs(tmpdir)
            assert ".editorconfig" in configs

    def test_pyproject_toml_with_ruff(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "pyproject.toml"), "w") as f:
                f.write("[tool.ruff]\nline-length = 88\n")
            configs = _detect_style_configs(tmpdir)
            assert "pyproject.toml" in configs

    def test_pyproject_toml_without_style(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "pyproject.toml"), "w") as f:
                f.write("[project]\nname = \"foo\"\n")
            configs = _detect_style_configs(tmpdir)
            assert "pyproject.toml" not in configs

    def test_no_configs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            configs = _detect_style_configs(tmpdir)
            assert configs == []


class TestAnalyzeRepo:
    def test_nonexistent_dir(self):
        ctx = analyze_repo("/nonexistent/path")
        assert ctx.is_empty()

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = analyze_repo(tmpdir)
            assert ctx.is_empty()

    def test_npm_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = {
                "dependencies": {"express": "^4.0.0"},
                "devDependencies": {"jest": "^29.0.0"},
                "scripts": {"test": "jest"},
            }
            with open(os.path.join(tmpdir, "package.json"), "w") as f:
                json.dump(pkg, f)
            with open(os.path.join(tmpdir, ".eslintrc.json"), "w") as f:
                f.write("{}")
            ctx = analyze_repo(tmpdir)
            assert "npm" in ctx.dependencies
            assert "express" in ctx.dependencies["npm"]
            assert "jest" in ctx.test_frameworks
            assert ".eslintrc.json" in ctx.style_configs

    def test_python_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "requirements.txt"), "w") as f:
                f.write("flask>=2.0\npytest\n")
            with open(os.path.join(tmpdir, "conftest.py"), "w") as f:
                f.write("")
            with open(os.path.join(tmpdir, "pyproject.toml"), "w") as f:
                f.write("[tool.ruff]\nline-length = 88\n")
            ctx = analyze_repo(tmpdir)
            assert "pip" in ctx.dependencies
            assert "flask" in ctx.dependencies["pip"]
            assert "pytest" in ctx.test_frameworks
            assert "pyproject.toml" in ctx.style_configs

    def test_empty_string_dir(self):
        ctx = analyze_repo("")
        assert ctx.is_empty()

    def test_full_prompt_section(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = {
                "dependencies": {"react": "^18.0.0"},
                "devDependencies": {"jest": "^29.0.0"},
            }
            with open(os.path.join(tmpdir, "package.json"), "w") as f:
                json.dump(pkg, f)
            ctx = analyze_repo(tmpdir)
            section = ctx.to_prompt_section()
            assert "Repository context:" in section
            assert "npm:" in section
