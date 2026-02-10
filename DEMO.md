# CodeQL Devin Fixer — Demo Narrative & Highlights

Full-stack security remediation platform that automates the end‑to‑end flow from finding vulnerabilities to shipping verified fixes. Combines:
- CodeQL static analysis (finding issues)
- Devin AI agents (fixing issues via PRs)
- Multi-repo orchestrator (prioritization, batching, scheduling)
- Closed-loop verification (re‑scan PRs to confirm fixes)
- Centralized telemetry (Flask dashboard + SQLite)

Why this repo is special
- End‑to‑end automation: scanning → batching → AI fix PRs → verification → telemetry.
- Deep Devin integration: 8 API endpoints including Knowledge API, Send Message API, Playbooks API, structured output, idempotent sessions, rich tagging, CWE‑aware playbooks, wave‑based dispatch, and prompt‑injection sanitization.
- Multi‑repo at scale: the orchestrator plans across many repos, prioritizing by CVSS severity and batching by CWE family.
- Closed‑loop quality: verification re‑runs CodeQL on PR branches, compares fingerprints, and feeds results back via retry-with-feedback and Knowledge API.

High‑level architecture

```
┌──────────────┐      ┌──────────┐      ┌──────────────────┐      ┌────────────┐
│  Repos Fleet │ ───▶ │  CodeQL  │ ───▶ │  SARIF Parsing   │ ───▶ │  Batching  │
└──────────────┘      └──────────┘      └──────────────────┘      └────────────┘
                                                                    │ by CWE /   │
                                                                    │ Severity   │
                                                                    └─────┬──────┘
                                                                          │
                                                                          ▼
                                                                   ┌────────────┐
                                                                   │ Devin AI   │
                                                                   │ Sessions   │
                                                                   └─────┬──────┘
                                                                         │ PRs
                                                                         ▼
┌────────────────┐      re‑scan PR branch      ┌─────────────────┐      ┌─────────────┐
│ Verification   │ ◀────────────────────────── │  CodeQL on PR   │ ───▶ │  Telemetry  │
│ (fingerprints) │                              └─────────────────┘      │  + Dashboard│
└────────────────┘                                                     └─────────────┘
```

Key components (where to look)
- action.yml — Composite GitHub Action that runs CodeQL, parses SARIF, and dispatches Devin sessions
- scripts/
  - dispatch_devin.py — Builds Devin prompts, tags sessions, defends against prompt injection, creates sessions (idempotent)
  - orchestrator/ — Multi‑repo scheduling package: scanner, dispatcher, state management, alerts, agent mode
  - verify_results.py — Re‑runs CodeQL on PR branches, compares fingerprints to confirm fixes
  - knowledge.py — Devin Knowledge API client for storing/retrieving fix patterns
  - retry_feedback.py — Send Message API for retry-with-feedback loop
  - playbook_manager.py — CWE playbooks + Devin Playbooks API sync
  - repo_context.py — Gathers repo signals (pkg managers, tests, style) to enrich prompts
- playbooks/ — CWE‑specific playbooks that guide Devin with structured, auditable instructions
- telemetry/ — Flask dashboard (5 Blueprints) + SQLite to track runs, sessions, PRs, fix rates
- docs/ — Architecture docs, config reference, and GitHub Pages static site

How Devin is used here
- Prompts are CWE‑aware, include precise locations and diffs to change, and instruct Devin to create PRs on forks (not upstream) using consistent naming.
- Sessions are tagged with severity tier, batch ID, CWE family, issue IDs for traceability.
- Sessions are idempotent, so retries don’t duplicate work.
- Fix‑learning closes the loop by analyzing historical fix rates across CWE families and feeding that into dispatch and prompting.

Demo flow (suggested script)
1) Quickstart (Basic Mode)
   - Trigger the workflow (`.github/workflows/codeql-fixer.yml`) on a target repo with `mode: basic`.
   - Watch Action logs as CodeQL runs and SARIF is parsed.
   - Observe Devin sessions created (tags include repo, CWE, severity, batch).
   - Show the resulting PRs created by Devin (titles follow the playbook conventions).

2) Orchestrator Mode
   - Run `python -m scripts.orchestrator.cli cycle` against a repo set (`repo_registry.json`).
   - Highlight prioritization (CVSS), CWE batching, and wave‑based dispatch with fix‑rate gating.
   - Emphasize cost/control benefits and better fix coherence.

3) Verification Loop
   - On a Devin PR, run `scripts/verify_results.py` (or let PR workflow trigger).
   - Show how fingerprints are compared to confirm targeted issues are gone.
   - Note labels/status in telemetry to mark verified fixes.

4) Telemetry Dashboard (optional)
   - Launch Flask app (telemetry/app.py) to show runs, sessions, PRs, fix‑rates.
   - Screenshot the overview and a specific run/session breakdown.

Standout features (talking points)
- CWE playbooks: Clear, reviewable instructions per vulnerability family → improves consistency, auditability, and governance.
- Repository context enrichment: Prompts reference real repo signals (pkg managers, frameworks, tests, code style) → safer, idiomatic fixes.
- Wave‑based dispatch: Stop after each wave if fix‑rate dips below threshold → avoids wasting sessions; focuses on high‑yield families first.
- Prompt‑injection defense: Sanitization of inbound text before prompting.
- Idempotency + retry: Stable, resilient execution.
- Verification by fingerprints: Objective success criteria beyond “it builds”.
- Central telemetry: Single source of truth for outcomes and trends.

Expanded standout features + how to demo in UI

- CWE playbooks
  - What to say: Each CWE family has a reviewed playbook (playbooks/*.yaml) with precise, auditable guidance. This yields consistent fixes and governance.
  - How to demo: Open playbooks/ in the repo, show a representative file, and point out the actionable steps and guardrails. Tie back to telemetry by highlighting improved fix rates for those CWE families over time.

- Repository context enrichment
  - What to say: We parse package managers, frameworks, tests, style rules (scripts/repo_context.py) and inject them into prompts so fixes match project conventions.
  - How to demo: Show scripts/repo_context.py and a snippet of its collected signals. In Action logs, point out where these signals appear in the prompt payload (if logs are enabled) or reference the session tags.

- Wave-based dispatch with gating
  - What to say: We dispatch by severity tiers in waves; if fix-rate drops below threshold, we halt further waves to save cost and redirect effort.
  - How to demo: Open `scripts/orchestrator/dispatcher.py` and point to the wave logic. In telemetry, filter by a run and talk through the phases/waves and resulting PRs.

- Prompt-injection defense
  - What to say: We sanitize inbound text before prompting (scripts/dispatch_devin.py: sanitize_prompt_text) to defend against injection.
  - How to demo: Show the sanitize function in scripts/dispatch_devin.py. Call out examples of what gets stripped.

- Idempotency + retry + knowledge assist
  - What to say: Sessions are created with idempotent semantics. The Knowledge API (`scripts/knowledge.py`) stores successful fix patterns, and the retry-with-feedback pipeline (`scripts/retry_feedback.py`) sends targeted guidance to Devin sessions that need rework.
  - How to demo: Show `scripts/knowledge.py` and `scripts/retry_feedback.py`. Point to `dispatch_devin.py` where idempotency is set. In telemetry, highlight improvements in fix-rate for those CWEs.

- Fingerprint-based verification
  - What to say: We re-run CodeQL on PR branches and compare stable fingerprints—objective proof that the target issue is actually gone.
  - How to demo: Open scripts/verify_results.py and show fingerprint comparison. In telemetry, locate a PR marked verified and narrate the before/after.

- Central telemetry dashboard
  - What to say: Single pane of glass with 6 tabs: Overview, Repositories, Issues, Activity, Orchestrator, Settings. Dark/light theme, Chart.js charts, PDF reports.
  - How to demo: Launch `telemetry/app.py`. Walk:
    1) Overview tab: total runs, sessions, verified PRs, fix-rate trend charts
    2) Repositories tab: per-repo metrics with drill-down
    3) Issues tab: fingerprint-based tracking with SLA status
    4) Activity tab: sessions and PRs with status filters
    5) Orchestrator tab: plan preview, scan/dispatch controls, fix rates by CWE
    6) Settings tab: configuration and audit log

Screenshots to include (optional)
- GitHub Actions run (CodeQL + dispatch step)
- Devin session detail (tags visible) — link to example session if available
- Telemetry dashboard overview (runs, sessions, PR status)
- Verification result on a PR (issues resolved)

How to run a minimal demo locally
- Python 3.11+, Node (if required by targets), CodeQL CLI installed
- Create a GitHub token with repo permissions (and Devin API token)
- Use `.codeql-fixer.example.yml` as a template to configure inputs
- For telemetry: `pip install -r telemetry/requirements.txt` then `python telemetry/app.py`

References
- [Architecture](docs/architecture.md)
- [Configuration Reference](docs/CONFIG_REFERENCE.md)
- [Live Dashboard](https://marius-posa.github.io/codeql-devin-fixer/)

Notes
- This file is meant for presentations and demos. Keep it updated as capabilities evolve.
