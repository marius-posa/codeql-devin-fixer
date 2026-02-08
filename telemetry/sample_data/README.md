# Sample Telemetry Data

This directory contains example telemetry run files that demonstrate the data format produced by the CodeQL Devin Fixer pipeline.

The telemetry Flask app automatically loads these files when the `runs/` directory is empty, providing a working dashboard out of the box for new installations.

## File Format

Each JSON file represents one pipeline run and contains:

| Field | Type | Description |
|---|---|---|
| `target_repo` | string | GitHub URL of the scanned repository |
| `fork_url` | string | Fork URL used for scanning |
| `run_number` | int | GitHub Actions run number |
| `run_label` | string | Human-readable run identifier |
| `timestamp` | string | ISO 8601 timestamp of the run |
| `issues_found` | int | Total security issues found by CodeQL |
| `severity_breakdown` | object | Issue counts by severity tier |
| `category_breakdown` | object | Issue counts by CWE family |
| `batches_created` | int | Number of issue batches created |
| `sessions` | array | Devin sessions created for this run |

## Using Your Own Data

Once you have real pipeline runs, telemetry data is stored in `telemetry/runs/`. The sample data will no longer be loaded once real run files exist.
