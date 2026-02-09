# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Solution Review V5**: Comprehensive review covering security, UI, orchestrator, telemetry, Devin API usage, and enterprise readiness (MP-68).
- **Updated README**: Restructured with Devin API Integration section, architecture diagram, database schema, deployment guide, and DeepWiki link.

## [0.5.0] - 2026-02-09

### Added
- **Devin Knowledge API integration** (MP-62): `scripts/knowledge.py` with full CRUD operations for storing and retrieving fix patterns. `build_knowledge_context()` enriches prompts with historical fix data. Gated by `enable_knowledge` action input.
- **Devin Send Message API** (MP-63): `scripts/retry_feedback.py` for retry-with-feedback loops. Sends verification results back to active sessions; creates follow-up sessions for ended ones. Gated by `enable_retry_feedback` input.
- **Structured output schema** (MP-64): `STRUCTURED_OUTPUT_SCHEMA` in `pipeline_config.py` defining expected JSON structure for Devin session progress updates. Enables real-time issue-level tracking in the dashboard.
- **Devin Playbooks API sync** (MP-65): `sync_to_devin_api()` in `playbook_manager.py` pushes CWE-specific playbooks to the Devin Playbooks API for native integration.
- **Shared Devin API utilities**: `scripts/devin_api.py` with centralized base URL, `request_with_retry()`, `TERMINAL_STATUSES`, and `clean_session_id()`.

### Changed
- **Flask Blueprint modularization** (MP-56): Decomposed monolithic `app.py` into 5 Blueprints under `telemetry/routes/` (api, orchestrator, registry, demo, oauth). Extracted shared utilities to `helpers.py`.
- **Server-side sessions** (MP-57): Replaced client-side cookie storage with `flask-session` using `FileSystemCache` backend. Session cookies now have `HttpOnly`, `Secure`, and `SameSite=Lax` attributes.
- **CORS restriction** (MP-58): CORS origins now configurable via `CORS_ORIGINS` environment variable (defaults to localhost only). Replaced permissive `*` origin.
- **Rate limiting** (MP-59): Added `flask-limiter` with tiered limits: 120/min default, 10/min for dispatch, 5/min for orchestrator actions. Configured via `extensions.py`.

### Security
- Server-side session storage prevents OAuth token exposure in client-side cookies.
- Security headers added: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, HSTS on secure requests.
- Rate limiting mitigates API abuse and DoS vectors.
- CORS restriction prevents unauthorized cross-origin requests.

## [0.4.0] - 2026-02-08

### Added
- **Orchestrator decomposition** (MP-48): Split monolithic orchestrator into 5 modules under `scripts/orchestrator/` (cli, dispatcher, scanner, state, alerts).
- **Structured JSON logging** (MP-49): `logging_config.py` with structured log format for all pipeline scripts.
- **TypedDict configurations** (MP-50): `pipeline_config.py` with typed configuration classes replacing loose dictionaries.
- **Wave-based dispatch** (MP-51): Severity-tiered wave dispatch with fix-rate gating between waves.
- **Audit logging** (MP-52): `audit_log` table in SQLite with action/user/timestamp/details tracking for all mutating operations.
- **Chart.js dashboard** (MP-53): Migrated Overview tab charts from hand-rolled SVG to Chart.js with dark/light theme support.
- **Tabbed dashboard UI** (MP-54): 6-tab layout (Overview, Repositories, Issues, Activity, Orchestrator, Settings) with lazy-loading.
- **Demo data system** (MP-55): Load/clear/regenerate/edit demo data for demos without real scan data.

## [0.3.0] - 2026-02-08

### Added
- **Multi-repo orchestrator engine**: Centralized scan scheduling and dispatch across repository fleet with priority-based dispatch.
- **GitHub App**: Webhook-driven automation with HMAC signature verification, JWT auth, and scan-on-push.
- **SQLite telemetry database**: Migration from JSON files to SQLite with FTS5 full-text search.
- **Fix verification loop**: `verify_results.py` re-runs CodeQL on PR branches and compares fingerprints.
- **CWE-specific playbooks**: YAML playbooks for injection, XSS, and path-traversal remediation.
- **Repository context enrichment**: `repo_context.py` analyzes target repos for dependencies, test frameworks, and code style.
- **Fix learning**: `fix_learning.py` for historical fix rate analysis by CWE family.

## [0.2.0] - 2026-02-07

### Added
- **Exponential backoff retries**: `retry_utils.py` for resilient API calls.
- **Flask telemetry dashboard**: Centralized web UI for aggregating metrics across repos.
- **Shared utilities**: Common helpers for GitHub API, logging, and configuration.
- **Per-repo configuration**: `.codeql-fixer.yml` support for target repos.
- **Custom prompt templates**: Jinja2 templates for Devin session prompts.
- **Webhook integration**: Signed notifications for scan lifecycle events.
- **Docker and Helm support**: Container and Kubernetes deployment for the dashboard.
- **Setup script**: `setup.sh` for guided configuration.
- **Architecture documentation**: `docs/architecture.md` with flow diagrams.
- **Contributing guide**: `CONTRIBUTING.md` with dev environment setup.

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
