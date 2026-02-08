# Contributing to CodeQL Devin Fixer

Thank you for your interest in contributing! This guide covers how to set up the development environment, run tests, and submit changes.

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
pip install pytest requests jinja2
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
action.yml                 # Composite action definition
scripts/                   # Pipeline scripts (parsing, dispatch, telemetry)
telemetry/                 # Flask dashboard backend
  app.py                   # Main Flask application
  templates/               # Server-rendered HTML templates
docs/                      # Static frontend dashboard
tests/                     # Test suite
```

See `docs/architecture.md` for a detailed flow diagram.

## Running Tests

```bash
python -m pytest tests/ -v
```

To run a specific test file:

```bash
python -m pytest tests/test_parse_sarif.py -v
```

### Test Categories

| Directory/File | What it tests |
|---|---|
| `tests/test_parse_sarif.py` | SARIF parsing, severity classification, batching |
| `tests/test_dispatch_devin.py` | Prompt generation, session creation |
| `tests/test_contracts.py` | Data format contracts between pipeline stages |
| `tests/test_fork_repo.py` | Fork creation and sync logic |
| `tests/test_resilience.py` | Retry and error handling |
| `tests/test_services.py` | Telemetry service integrations |
| `tests/test_telemetry_app.py` | Flask API endpoints |

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
- Use the existing utility modules (`github_utils.py`, `retry_utils.py`, `pipeline_config.py`)

### Commit Messages

Use conventional commit format:

```
feat(parse): add support for custom CWE family mappings
fix(dispatch): handle empty batch list gracefully
docs: add architecture diagram
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

If you add endpoints to `telemetry/app.py`:

1. Use the existing `_paginate()` helper for list endpoints
2. Gate mutating endpoints behind `@require_api_key`
3. Add tests to `tests/test_telemetry_app.py`

## Per-Repo Configuration

Target repositories can include a `.codeql-fixer.yml` file to customize behavior. See the example in `.codeql-fixer.example.yml` for available options.

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps and relevant log output
- For security vulnerabilities, please report privately via GitHub Security Advisories
