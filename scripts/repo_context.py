"""Analyze a target repository to extract context for Devin prompts.

Before dispatching fix sessions, this module inspects the cloned repo to
discover:

* **Dependencies** -- from manifest files such as ``package.json``,
  ``requirements.txt``, ``Cargo.toml``, etc.
* **Testing framework** -- inferred from dev-dependencies, config files,
  or test directory conventions (jest, pytest, mocha, etc.).
* **Code style configuration** -- from linter/formatter config files
  (``.eslintrc``, ``.prettierrc``, ``.editorconfig``, etc.).

The extracted context is included in Devin prompts so the AI can produce
fixes that conform to the project's tooling and conventions.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


DEPENDENCY_MANIFESTS: dict[str, str] = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "Pipfile": "pipenv",
    "pyproject.toml": "python",
    "setup.py": "python",
    "setup.cfg": "python",
    "Cargo.toml": "cargo",
    "go.mod": "go",
    "Gemfile": "bundler",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "composer.json": "composer",
    "Package.swift": "swift-pm",
}

TEST_FRAMEWORK_SIGNALS: dict[str, list[str]] = {
    "jest": ["jest.config.js", "jest.config.ts", "jest.config.mjs", "jest.config.cjs"],
    "mocha": [".mocharc.yml", ".mocharc.yaml", ".mocharc.json", ".mocharc.js"],
    "vitest": ["vitest.config.ts", "vitest.config.js", "vitest.config.mts"],
    "pytest": ["pytest.ini", "pyproject.toml", "setup.cfg", "conftest.py"],
    "unittest": [],
    "rspec": [".rspec", "spec/spec_helper.rb"],
    "minitest": [],
    "go test": [],
    "cargo test": [],
    "junit": [],
}

STYLE_CONFIG_FILES: list[str] = [
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".eslintrc.json",
    ".eslintrc.yml",
    ".eslintrc.yaml",
    "eslint.config.js",
    "eslint.config.mjs",
    ".prettierrc",
    ".prettierrc.js",
    ".prettierrc.json",
    ".prettierrc.yml",
    ".prettierrc.yaml",
    "prettier.config.js",
    ".editorconfig",
    ".stylelintrc",
    ".stylelintrc.json",
    "pyproject.toml",
    "setup.cfg",
    ".flake8",
    ".pylintrc",
    "tox.ini",
    ".rubocop.yml",
    ".clang-format",
    ".clang-tidy",
    "rustfmt.toml",
    ".golangci.yml",
    ".golangci.yaml",
    "biome.json",
]

MAX_DEPENDENCY_NAMES = 40


@dataclass
class RepoContext:
    dependencies: dict[str, list[str]] = field(default_factory=dict)
    test_frameworks: list[str] = field(default_factory=list)
    style_configs: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.dependencies and not self.test_frameworks and not self.style_configs

    def to_prompt_section(self) -> str:
        if self.is_empty():
            return ""
        parts: list[str] = ["Repository context:"]
        if self.dependencies:
            parts.append("")
            parts.append("Dependencies:")
            for manager, deps in self.dependencies.items():
                if deps:
                    shown = deps[:MAX_DEPENDENCY_NAMES]
                    dep_str = ", ".join(shown)
                    if len(deps) > MAX_DEPENDENCY_NAMES:
                        dep_str += f" (and {len(deps) - MAX_DEPENDENCY_NAMES} more)"
                    parts.append(f"  {manager}: {dep_str}")
                else:
                    parts.append(f"  {manager}: (manifest found)")
        if self.test_frameworks:
            parts.append("")
            parts.append(f"Testing framework(s): {', '.join(self.test_frameworks)}")
        if self.style_configs:
            parts.append("")
            parts.append(f"Code style config: {', '.join(self.style_configs)}")
        return "\n".join(parts)


def _read_json_safe(path: str) -> dict | list | None:
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _read_lines_safe(path: str, max_lines: int = 200) -> list[str]:
    try:
        with open(path, errors="replace") as f:
            lines = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    lines.append(stripped)
            return lines
    except OSError:
        return []


def _extract_npm_deps(target_dir: str) -> list[str]:
    pkg_path = os.path.join(target_dir, "package.json")
    data = _read_json_safe(pkg_path)
    if not isinstance(data, dict):
        return []
    deps: list[str] = []
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            deps.extend(section.keys())
    return sorted(set(deps))


def _extract_pip_deps(target_dir: str) -> list[str]:
    req_path = os.path.join(target_dir, "requirements.txt")
    lines = _read_lines_safe(req_path)
    deps: list[str] = []
    for line in lines:
        if line.startswith("-"):
            continue
        name = line.split("==")[0].split(">=")[0].split("<=")[0].split("~=")[0].split("!=")[0].split("[")[0].strip()
        if name:
            deps.append(name)
    return sorted(set(deps))


def _detect_test_framework_from_package_json(target_dir: str) -> list[str]:
    pkg_path = os.path.join(target_dir, "package.json")
    data = _read_json_safe(pkg_path)
    if not isinstance(data, dict):
        return []
    frameworks: list[str] = []
    dev_deps = data.get("devDependencies", {})
    all_deps = {**data.get("dependencies", {}), **dev_deps}
    scripts = data.get("scripts", {})
    test_script = scripts.get("test", "")
    if "jest" in all_deps or "jest" in test_script:
        frameworks.append("jest")
    if "vitest" in all_deps or "vitest" in test_script:
        frameworks.append("vitest")
    if "mocha" in all_deps or "mocha" in test_script:
        frameworks.append("mocha")
    if "jasmine" in all_deps or "jasmine" in test_script:
        frameworks.append("jasmine")
    if "ava" in all_deps or "ava" in test_script:
        frameworks.append("ava")
    if "tap" in all_deps or "tap" in test_script:
        frameworks.append("tap")
    return frameworks


def _detect_test_frameworks(target_dir: str) -> list[str]:
    frameworks: list[str] = []
    js_frameworks = _detect_test_framework_from_package_json(target_dir)
    frameworks.extend(js_frameworks)

    for fw, config_files in TEST_FRAMEWORK_SIGNALS.items():
        if fw in frameworks:
            continue
        for cf in config_files:
            if os.path.isfile(os.path.join(target_dir, cf)):
                detected = False
                if fw == "pytest":
                    if cf == "pyproject.toml":
                        data = _read_lines_safe(os.path.join(target_dir, cf))
                        if any("[tool.pytest" in line for line in data):
                            detected = True
                    elif cf == "setup.cfg":
                        data = _read_lines_safe(os.path.join(target_dir, cf))
                        if any("[tool:pytest]" in line for line in data):
                            detected = True
                    else:
                        detected = True
                else:
                    detected = True
                if detected:
                    frameworks.append(fw)
                    break

    if os.path.isfile(os.path.join(target_dir, "go.mod")) and "go test" not in frameworks:
        if os.path.isdir(os.path.join(target_dir, "test")) or any(
            f.endswith("_test.go")
            for f in os.listdir(target_dir)
            if os.path.isfile(os.path.join(target_dir, f))
        ):
            frameworks.append("go test")

    if os.path.isfile(os.path.join(target_dir, "Cargo.toml")) and "cargo test" not in frameworks:
        frameworks.append("cargo test")

    return sorted(set(frameworks))


def _detect_style_configs(target_dir: str) -> list[str]:
    found: list[str] = []
    for cfg in STYLE_CONFIG_FILES:
        if os.path.isfile(os.path.join(target_dir, cfg)):
            if cfg == "pyproject.toml":
                data = _read_lines_safe(os.path.join(target_dir, cfg))
                style_sections = [
                    "[tool.black]", "[tool.ruff]", "[tool.isort]",
                    "[tool.mypy]", "[tool.flake8]",
                ]
                if any(section in line for line in data for section in style_sections):
                    found.append(cfg)
            elif cfg in ("setup.cfg", "tox.ini"):
                data = _read_lines_safe(os.path.join(target_dir, cfg))
                style_sections = ["[flake8]", "[isort]", "[mypy]", "[pylint"]
                if any(section in line for line in data for section in style_sections):
                    found.append(cfg)
            else:
                found.append(cfg)
    return found


def analyze_repo(target_dir: str) -> RepoContext:
    """Analyze *target_dir* and return a :class:`RepoContext` with discovered metadata."""
    if not target_dir or not os.path.isdir(target_dir):
        return RepoContext()

    dependencies: dict[str, list[str]] = {}
    for manifest, manager in DEPENDENCY_MANIFESTS.items():
        manifest_path = os.path.join(target_dir, manifest)
        if not os.path.isfile(manifest_path):
            continue
        if manager == "npm":
            deps = _extract_npm_deps(target_dir)
            dependencies["npm"] = deps
        elif manager == "pip":
            deps = _extract_pip_deps(target_dir)
            dependencies["pip"] = deps
        elif manager not in dependencies:
            dependencies[manager] = []

    test_frameworks = _detect_test_frameworks(target_dir)
    style_configs = _detect_style_configs(target_dir)

    return RepoContext(
        dependencies=dependencies,
        test_frameworks=test_frameworks,
        style_configs=style_configs,
    )
