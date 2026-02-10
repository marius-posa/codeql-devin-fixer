# Contributing to CodeQL Devin Fixer

This guide covers how to set up the development environment, run tests, and submit changes.

## Development Environment

### Prerequisites

- Python 3.11+
- Git
- A GitHub Personal Access Token (PAT) with `repo` scope (for integration tests)
- A [Devin API key](https://docs.devin.ai/api-reference/overview) (only needed for live session tests)

### Setup

```bash
git clone https://github.com/YOUR_USERNAME/codeql-devin-fixer.git
cd codeql-devin-fixer

python -m venv .venv
source .venv/bin/activate

pip install -r telemetry/requirements.txt
pip install pytest requests jinja2 pyyaml
```

### Telemetry Dashboard

```bash
cd telemetry
cp .env.example .env
# Edit .env with your credentials
python app.py
```

Open `http://localhost:5000` to view the dashboard.

### Docker

```bash
cd telemetry
docker compose up --build
```

## Project Structure

```
action.yml                       # Composite GitHub Action definition
.github/workflows/               # GitHub Actions workflows
scripts/                         # Pipeline scripts
  parse_sarif.py                 # SARIF parsing, severity scoring, batching
  dispatch_devin.py              # Devin session creation with wave dispatch
  fork_repo.py                   # Fork management and sync
  persist_logs.py                # Log persistence to fork repos
  persist_telemetry.py           # Telemetry record storage to SQLite
  verify_results.py              # Fix verification via fingerprint comparison
  pipeline_config.py             # Centralized config with TypedDicts
  devin_api.py                   # Shared Devin API utilities
  knowledge.py                   # Devin Knowledge API client
  retry_feedback.py              # Send Message API for retry-with-feedback
  playbook_manager.py            # CWE-specific playbooks + Devin Playbooks API
  orchestrator/                  # Multi-repo orchestrator package
    cli.py                       # Command routing (scan, dispatch, cycle, plan, status)
    dispatcher.py                # Session dispatch with rate limiting
    scanner.py                   # Scan triggering and SARIF retrieval
    state.py                     # State persistence and cooldown
    alerts.py                    # Alert processing and delivery
    agent.py                     # Orchestrator agent mode
telemetry/                       # Flask dashboard backend
  app.py                         # Flask entry point (Blueprint registration)
  routes/                        # Modular route Blueprints
    api.py                       # Core API (runs, sessions, PRs, issues, stats)
    orchestrator.py              # Orchestrator controls
    registry.py                  # Repo registry CRUD
    demo.py                      # Demo data management
  database.py                    # SQLite schema, queries, migrations
  helpers.py                     # Shared auth, pagination, audit utilities
github_app/                      # GitHub App for webhook automation
playbooks/                       # CWE-specific fix instructions (YAML)
charts/telemetry/                # Helm chart for Kubernetes deployment
docs/                            # GitHub Pages static site + documentation
tests/                           # Test suite (32 files, ~11,400 lines)
```

See [docs/architecture.md](docs/architecture.md) for detailed flow diagrams and [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md) for the complete configuration reference.

## Running Tests

```bash
python -m pytest tests/ -v
```

To run a specific test file:

```bash
python -m pytest tests/test_parse_sarif.py -v
```

### Test Categories

| File | What it tests |
|---|---|
| `test_parse_sarif.py` | SARIF parsing, severity classification, batching |
| `test_dispatch_devin.py` | Prompt generation, session creation, wave dispatch |
| `test_contracts.py` | Data format contracts between pipeline stages |
| `test_fork_repo.py` | Fork creation and sync logic |
| `test_resilience.py` | Retry and error handling |
| `test_orchestrator.py` | Orchestrator scheduling, priority scoring, dispatch logic |
| `test_telemetry_app.py` | Flask API endpoints and Blueprint routing |
| `test_telemetry_auth.py` | API key and OAuth authentication |
| `test_database.py` | SQLite schema, queries, and migrations |
| `test_verification.py` | Fix verification and fingerprint comparison |
| `test_webhook.py` | Webhook delivery and HMAC signing |
| `test_playbook_manager.py` | CWE playbook loading and Devin API sync |

## Making Changes

### Branch Naming

Use descriptive branch names:

```
feature/per-repo-config
fix/sarif-parsing-edge-case
docs/architecture-diagram
```

### Code Style

- Follow existing patterns in the file you're editing
- Use type annotations on public function signatures
- Keep functions focused and under ~50 lines where practical
- Use the existing utility modules (`github_utils.py`, `retry_utils.py`, `pipeline_config.py`, `devin_api.py`)

### Commit Messages

Use conventional commit format:

```
feat(parse): add support for custom CWE family mappings
fix(dispatch): handle empty batch list gracefully
docs: update architecture diagram
test: add coverage for webhook delivery
```

### Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear, focused commits
3. Run the test suite: `python -m pytest tests/ -v`
4. Push your branch and open a PR against `main`
5. Describe what your PR changes and why
6. Link any relevant issues or tickets

### Adding New Pipeline Scripts

If you add a new script to `scripts/`:

1. Follow the existing pattern of using `PipelineConfig` for environment variables
2. Add appropriate error handling with informative messages
3. Write tests in `tests/`
4. Update `action.yml` if the script is invoked as a step

### Adding New API Endpoints

If you add endpoints to the telemetry dashboard:

1. Add routes to the appropriate Blueprint in `telemetry/routes/`
2. Use the existing `_paginate()` helper for list endpoints
3. Gate mutating endpoints behind `@require_api_key`
4. Add tests to `tests/test_telemetry_app.py`

## Per-Repo Configuration

Target repositories can include a `.codeql-fixer.yml` file to customize behavior. See `.codeql-fixer.example.yml` for a template and [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md) for the full option reference.

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps and relevant log output
- For security vulnerabilities, please report privately via GitHub Security Advisories
