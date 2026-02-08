#!/usr/bin/env python3
"""Load per-repo configuration from a .codeql-fixer.yml file.

Target repositories can include a ``.codeql-fixer.yml`` (or ``.yaml``)
file at their root to override default action settings without modifying
the workflow dispatch inputs.  This allows per-repo customisation of
severity thresholds, batch sizes, excluded paths, and CWE-to-family
mappings.

The script reads the YAML config file, validates its contents, and
writes the resolved values to ``$GITHUB_OUTPUT`` so subsequent action
steps can use them.

Supported config keys
---------------------
severity_threshold : str
    Minimum severity tier (critical, high, medium, low).
batch_size : int
    Maximum issues per Devin session.
max_sessions : int
    Maximum number of Devin sessions to create.
exclude_paths : list[str]
    Glob patterns to exclude from analysis.
cwe_families : dict[str, list[str]]
    Custom CWE-to-family mappings that extend the built-in families.
"""

import json
import os
import sys

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _parse_yaml(path: str) -> dict:
    with open(path) as f:
        content = f.read()

    if yaml is not None:
        return yaml.safe_load(content) or {}

    result: dict = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if value.startswith("[") or value.startswith("{"):
                try:
                    result[key] = json.loads(value)
                except json.JSONDecodeError:
                    result[key] = value
            elif value.isdigit():
                result[key] = int(value)
            elif value.lower() in ("true", "false"):
                result[key] = value.lower() == "true"
            elif value:
                result[key] = value
    return result


def load_config(path: str) -> dict:
    config = _parse_yaml(path)

    if not isinstance(config, dict):
        print(f"WARNING: {path} did not parse as a mapping; ignoring")
        return {}

    severity = config.get("severity_threshold", "")
    if severity and severity not in VALID_SEVERITIES:
        print(f"WARNING: invalid severity_threshold '{severity}' in {path}; ignoring")
        config.pop("severity_threshold", None)

    batch_size = config.get("batch_size")
    if batch_size is not None:
        try:
            batch_size = int(batch_size)
            if batch_size < 1 or batch_size > 50:
                print(f"WARNING: batch_size {batch_size} out of range [1,50]; ignoring")
                config.pop("batch_size", None)
        except (ValueError, TypeError):
            print(f"WARNING: invalid batch_size '{batch_size}' in {path}; ignoring")
            config.pop("batch_size", None)

    max_sessions = config.get("max_sessions")
    if max_sessions is not None:
        try:
            max_sessions = int(max_sessions)
            if max_sessions < 1 or max_sessions > 100:
                print(f"WARNING: max_sessions {max_sessions} out of range [1,100]; ignoring")
                config.pop("max_sessions", None)
        except (ValueError, TypeError):
            print(f"WARNING: invalid max_sessions '{max_sessions}' in {path}; ignoring")
            config.pop("max_sessions", None)

    exclude_paths = config.get("exclude_paths")
    if exclude_paths is not None and not isinstance(exclude_paths, list):
        print(f"WARNING: exclude_paths must be a list in {path}; ignoring")
        config.pop("exclude_paths", None)

    cwe_families = config.get("cwe_families")
    if cwe_families is not None and not isinstance(cwe_families, dict):
        print(f"WARNING: cwe_families must be a mapping in {path}; ignoring")
        config.pop("cwe_families", None)

    return config


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: load_repo_config.py <config_path>")
        sys.exit(1)

    config_path = sys.argv[1]
    if not os.path.isfile(config_path):
        print(f"Config file not found: {config_path}")
        sys.exit(1)

    config = load_config(config_path)
    print(f"Loaded config from {config_path}: {json.dumps(config, indent=2)}")

    github_output = os.environ.get("GITHUB_OUTPUT", "")
    if not github_output:
        return

    env_batch_size = os.environ.get("INPUT_BATCH_SIZE", "5")
    env_max_sessions = os.environ.get("INPUT_MAX_SESSIONS", "25")
    env_severity = os.environ.get("INPUT_SEVERITY_THRESHOLD", "low")
    env_exclude = os.environ.get("INPUT_EXCLUDE_PATHS", "")

    with open(github_output, "a") as f:
        f.write(f"batch_size={config.get('batch_size', env_batch_size)}\n")
        f.write(f"max_sessions={config.get('max_sessions', env_max_sessions)}\n")
        f.write(f"severity_threshold={config.get('severity_threshold', env_severity)}\n")

        exclude = config.get("exclude_paths")
        if exclude and isinstance(exclude, list):
            f.write(f"exclude_paths={','.join(exclude)}\n")
        else:
            f.write(f"exclude_paths={env_exclude}\n")

        cwe_families = config.get("cwe_families")
        if cwe_families and isinstance(cwe_families, dict):
            f.write(f"custom_cwe_families={json.dumps(cwe_families)}\n")
        else:
            f.write("custom_cwe_families=\n")


if __name__ == "__main__":
    main()
