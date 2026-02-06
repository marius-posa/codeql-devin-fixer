# CodeQL Devin Fixer

A GitHub Action that runs CodeQL security analysis on any repository, prioritizes vulnerabilities by severity, groups them into batches, and creates [Devin](https://devin.ai) sessions to fix each batch with a pull request.

## How It Works

1. **Clone** the target repository
2. **Analyze** with CodeQL (auto-detects languages)
3. **Parse** SARIF results and extract security issues
4. **Prioritize** by CVSS severity score (adversary perspective)
5. **Batch** by vulnerability family (e.g., all XSS together, all SQLi together)
6. **Dispatch** a Devin session per batch, each creating a fix PR

## Prioritization

Issues are ranked from an adversary's perspective -- which vulnerabilities are easiest to exploit with the highest impact:

| Tier | CVSS Score | Examples |
|------|-----------|----------|
| Critical | 9.0 - 10.0 | SQL injection, command injection, code injection, path traversal |
| High | 7.0 - 8.9 | XSS, SSRF, deserialization, authentication bypass |
| Medium | 4.0 - 6.9 | Information disclosure, open redirect, weak crypto, CSRF |
| Low | 0.1 - 3.9 | Minor info leaks, code quality issues |

## Quick Start

### 1. As a Reusable Action

Reference this action in your workflow:

```yaml
name: Fix Security Issues
on:
  workflow_dispatch:
    inputs:
      target_repo:
        description: "Repository URL to analyze"
        required: true
        type: string

jobs:
  fix:
    runs-on: ubuntu-latest
    steps:
      - uses: marius-posa/codeql-devin-fixer@main
        with:
          target_repo: ${{ inputs.target_repo }}
          devin_api_key: ${{ secrets.DEVIN_API_KEY }}
```

### 2. Run from This Repo

1. Fork or clone this repo
2. Add your `DEVIN_API_KEY` as a repository secret
3. Go to **Actions** > **CodeQL Devin Fixer** > **Run workflow**
4. Enter the target repository URL and configure options
5. The action will analyze the repo and create Devin sessions

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `target_repo` | Yes | - | GitHub repo URL to analyze |
| `languages` | No | auto-detect | Comma-separated CodeQL languages (javascript, python, java, go, ruby, csharp, cpp, swift) |
| `batch_size` | No | `5` | Max issues per Devin session |
| `max_sessions` | No | `10` | Max Devin sessions to create |
| `severity_threshold` | No | `low` | Minimum severity: `critical`, `high`, `medium`, `low` |
| `queries` | No | `security-extended` | CodeQL query suite (`security-extended`, `security-and-quality`) |
| `include_paths` | No | `` | Newline/comma-separated globs to include (narrows analysis) |
| `exclude_paths` | No | `` | Newline/comma-separated globs to exclude |
| `devin_api_key` | Yes | - | Devin API key (use a repository secret) |
| `max_acu_per_session` | No | - | ACU limit per Devin session |
| `dry_run` | No | `false` | Generate prompts without creating sessions |
| `default_branch` | No | `main` | Default branch of the target repo |
| `wait_for_sessions` | No | `false` | Wait for Devin sessions to finish and collect outcomes |
| `poll_timeout` | No | `60` | Polling timeout (minutes) |
| `poll_interval` | No | `30` | Polling interval (seconds) |

## Outputs

| Output | Description |
|--------|-------------|
| `total_issues` | Number of security issues found |
| `total_batches` | Number of batches created |
| `sessions_created` | Number of Devin sessions dispatched |
| `session_urls` | Comma-separated Devin session URLs |
| `sessions_finished` | Number of Devin sessions that finished (if waited) |
| `sessions_with_pr` | Number of sessions that produced a PR (if waited) |
| `issues_addressed` | Proxy: sum of issues in finished sessions that produced a PR (if waited) |

## Batching Strategy

Issues are grouped by CWE vulnerability family:

- **injection** -- SQLi, command injection, code injection (CWE-78, 89, 94, ...)
- **xss** -- Cross-site scripting (CWE-79, 80)
- **path-traversal** -- Directory traversal (CWE-22, 23, 36)
- **ssrf** -- Server-side request forgery (CWE-918)
- **deserialization** -- Insecure deserialization (CWE-502)
- **auth** -- Authentication/authorization issues (CWE-287, 306, 862, 863)
- **crypto** -- Weak cryptography (CWE-327, 328, 330, 338)
- **info-disclosure** -- Information leaks (CWE-200, 209, 532)
- **redirect** -- Open redirect (CWE-601)
- **xxe** -- XML external entity (CWE-611)
- **csrf** -- Cross-site request forgery (CWE-352)
- **prototype-pollution** -- Prototype pollution (CWE-1321)
- **regex-dos** -- Regular expression DoS (CWE-1333, 730)

Highest-severity batches are dispatched first.

## Example: Analyzing juice-shop

```yaml
- uses: marius-posa/codeql-devin-fixer@main
  with:
    target_repo: "https://github.com/juice-shop/juice-shop"
    languages: "javascript"
    batch_size: 5
    max_sessions: 10
    severity_threshold: "medium"
    devin_api_key: ${{ secrets.DEVIN_API_KEY }}
```

## Notes

- ACU usage is not reported with the public v1 API; enterprise APIs expose ACU via different auth.
- "Issues addressed" is a proxy: sum of issues in batches where a session finished and produced a PR (does not re-run CodeQL on PRs).

## Dry Run Mode

Test without creating Devin sessions:

```yaml
- uses: marius-posa/codeql-devin-fixer@main
  with:
    target_repo: "https://github.com/juice-shop/juice-shop"
    devin_api_key: "not-needed-for-dry-run"
    dry_run: "true"
```

This generates all analysis artifacts (SARIF, batches, prompts) without calling the Devin API. Check the uploaded artifacts for the generated prompts.

## Artifacts

Every run uploads these artifacts:

- `issues.json` -- All parsed issues with severity and CWE data
- `batches.json` -- Grouped batches ready for dispatch
- `summary.md` -- Human-readable analysis summary
- `sessions.json` -- Created Devin session details
- `outcomes.json` -- Session outcomes (status, PR URLs) when waiting is enabled
- `prompt_batch_N.txt` -- The exact prompt sent to each Devin session
- SARIF results from CodeQL

## Requirements

- GitHub Actions runner (ubuntu-latest)
- [Devin API key](https://docs.devin.ai/api-reference/overview) with session creation permissions
- Target repository must be accessible (public or with appropriate credentials)

## Architecture

```
workflow_dispatch (target_repo, options)
    |
    v
Clone target repo
    |
    v
CodeQL: database create + analyze -> SARIF
    |
    v
parse_sarif.py: parse -> prioritize -> batch
    |
    v
dispatch_devin.py: create Devin session per batch (optionally wait + collect outcomes)
    |
    v
Each Devin session: clone repo -> fix issues -> create PR
```
