# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Per-repo configuration**: Target repos can include a `.codeql-fixer.yml` file to override severity thresholds, batch sizes, excluded paths, and CWE-to-family mappings without modifying workflow inputs.
- **Custom prompt templates**: Organizations can provide Jinja2 templates to customize Devin session prompts via the `prompt_template` input.
- **Webhook integration**: Configurable webhook URL receives signed notifications for `scan_started`, `scan_completed`, and `session_created` lifecycle events.
- **Docker support for telemetry**: `Dockerfile` and `docker-compose.yml` for deploying the telemetry dashboard with `docker compose up`.
- **Helm chart**: Kubernetes deployment via `charts/telemetry/` with configurable values.
- **One-click setup script**: `setup.sh` creates the workflow file, prompts for secrets, and runs a dry-run verification.
- **Example telemetry data**: `telemetry/sample_data/` with sample run files; the Flask app loads these automatically when no real data exists.
- **Architecture diagram**: Visual flow diagram in `docs/architecture.md`.
- **Contributing guide**: `CONTRIBUTING.md` with dev environment setup, testing, and PR guidelines.
- **Action branding**: Shield icon and purple color for professional appearance in GitHub Actions UI.

## [0.1.0] - 2026-02-07

### Added
- Initial release of the CodeQL Devin Fixer action.
- CodeQL security analysis with auto-detected language support.
- SARIF parsing with CVSS-based severity tiers and CWE family grouping.
- Devin session dispatch with context-rich prompts including code snippets and fix hints.
- Fork management for isolated scanning.
- Log persistence to fork repositories.
- Centralized telemetry dashboard (Flask) with per-repo views, issue tracking, and session polling.
- Historical fix rate learning via `fix_learning.py`.
- Prompt injection defense via `sanitize_prompt_text()`.
- Exponential backoff retries for all API calls.
- Configurable failure rate threshold for session dispatch.
