"""Demo seed data generator for the telemetry dashboard.

Generates realistic sample data covering multiple repositories with temporal
spread that tells a narrative of improving security posture:
- Fix rates improve over time
- New vulnerabilities are quickly flagged and fixed
- Devin is used more efficiently by the orchestrator over time
- The orchestrator + Devin manage security vulnerability entropy
"""

import hashlib
import json
import pathlib
import random
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from database import get_connection, init_db, insert_run, upsert_pr

DEMO_DATA_DIR = pathlib.Path(__file__).parent / "demo_data"
DEMO_MARKER_KEY = "demo_data_loaded"

REPOS = [
    {
        "url": "https://github.com/acme-corp/web-platform",
        "fork": "https://github.com/acme-corp-forks/web-platform",
        "importance": "critical",
        "languages": ["javascript", "python"],
    },
    {
        "url": "https://github.com/acme-corp/api-gateway",
        "fork": "https://github.com/acme-corp-forks/api-gateway",
        "importance": "high",
        "languages": ["python"],
    },
    {
        "url": "https://github.com/acme-corp/mobile-backend",
        "fork": "https://github.com/acme-corp-forks/mobile-backend",
        "importance": "high",
        "languages": ["java"],
    },
    {
        "url": "https://github.com/acme-corp/data-pipeline",
        "fork": "https://github.com/acme-corp-forks/data-pipeline",
        "importance": "medium",
        "languages": ["python"],
    },
    {
        "url": "https://github.com/acme-corp/internal-tools",
        "fork": "https://github.com/acme-corp-forks/internal-tools",
        "importance": "medium",
        "languages": ["javascript"],
    },
]

SEVERITY_TIERS = ["critical", "high", "medium", "low"]

CWE_FAMILIES = [
    "injection",
    "xss",
    "path-traversal",
    "crypto",
    "info-disclosure",
    "auth-bypass",
    "ssrf",
    "insecure-deserialization",
]

RULE_IDS = {
    "injection": [
        "js/sql-injection",
        "py/sql-injection",
        "java/sql-injection",
        "py/command-injection",
    ],
    "xss": [
        "js/xss",
        "js/reflected-xss",
        "js/stored-xss",
    ],
    "path-traversal": [
        "js/path-injection",
        "py/path-injection",
        "java/path-injection",
    ],
    "crypto": [
        "py/weak-crypto",
        "js/weak-crypto",
        "java/weak-crypto",
    ],
    "info-disclosure": [
        "py/stack-trace-exposure",
        "js/information-exposure",
        "java/information-exposure",
    ],
    "auth-bypass": [
        "py/insecure-auth",
        "js/missing-auth-check",
    ],
    "ssrf": [
        "py/ssrf",
        "java/ssrf",
    ],
    "insecure-deserialization": [
        "py/unsafe-deserialization",
        "java/unsafe-deserialization",
    ],
}

FILE_PATHS = {
    "injection": [
        "src/api/controllers/users.py",
        "src/api/controllers/search.js",
        "src/services/QueryBuilder.java",
        "src/db/queries.py",
    ],
    "xss": [
        "src/views/components/UserProfile.jsx",
        "src/templates/comment.html",
        "src/views/dashboard.js",
    ],
    "path-traversal": [
        "src/utils/file_handler.py",
        "src/api/upload.js",
        "src/services/FileService.java",
    ],
    "crypto": [
        "src/auth/token_manager.py",
        "src/utils/encryption.js",
        "src/security/CryptoHelper.java",
    ],
    "info-disclosure": [
        "src/middleware/error_handler.py",
        "src/api/error_boundary.js",
        "src/handlers/ExceptionMapper.java",
    ],
    "auth-bypass": [
        "src/middleware/auth.py",
        "src/api/middleware/auth.js",
    ],
    "ssrf": [
        "src/services/webhook_sender.py",
        "src/services/WebhookClient.java",
    ],
    "insecure-deserialization": [
        "src/api/import_handler.py",
        "src/services/DataImporter.java",
    ],
}


def _fingerprint(repo: str, rule: str, file: str, line: int) -> str:
    raw = f"{repo}:{rule}:{file}:{line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _session_id() -> str:
    return f"devin-{uuid.uuid4().hex}"


def _pr_url(fork: str, num: int) -> str:
    return f"{fork}/pull/{num}"


def _session_url(sid: str) -> str:
    clean = sid.replace("devin-", "")
    return f"https://app.devin.ai/sessions/{clean}"


def _generate_issues_for_run(
    repo: dict,
    run_number: int,
    total_runs: int,
    existing_fingerprints: list[str],
    rng: random.Random,
) -> tuple[list[dict], dict[str, int], dict[str, int]]:
    progress = run_number / max(total_runs, 1)

    if run_number == 1:
        base_count = rng.randint(10, 18)
    else:
        prev_count = len(existing_fingerprints)
        new_found = max(1, int(rng.randint(1, 4) * (1.0 - progress * 0.6)))
        fixed_count = int(prev_count * min(0.3 + progress * 0.3, 0.7))
        base_count = max(2, prev_count - fixed_count + new_found)

    severity_weights = {
        "critical": max(0.05, 0.20 - progress * 0.15),
        "high": max(0.15, 0.35 - progress * 0.15),
        "medium": 0.30 + progress * 0.10,
        "low": 0.15 + progress * 0.20,
    }

    issues = []
    severity_breakdown: dict[str, int] = {}
    category_breakdown: dict[str, int] = {}

    reused = 0
    for fp in existing_fingerprints:
        if reused >= base_count:
            break
        keep_prob = max(0.2, 0.8 - progress * 0.5)
        if rng.random() < keep_prob:
            reused += 1

    new_count = max(1, base_count - reused)

    for i in range(new_count):
        sevs = list(severity_weights.keys())
        weights = list(severity_weights.values())
        severity = rng.choices(sevs, weights=weights, k=1)[0]
        cwe = rng.choice(CWE_FAMILIES)
        rule_options = RULE_IDS.get(cwe, ["unknown/rule"])
        rule = rng.choice(rule_options)
        file_options = FILE_PATHS.get(cwe, ["src/unknown.py"])
        file = rng.choice(file_options)
        line = rng.randint(10, 500)
        fp = _fingerprint(repo["url"], rule, file, line + i)

        issues.append({
            "id": f"ISSUE-{run_number:03d}-{i+1:03d}",
            "fingerprint": fp,
            "rule_id": rule,
            "severity_tier": severity,
            "cwe_family": cwe,
            "file": file,
            "start_line": line + i,
            "description": f"Potential {cwe.replace('-', ' ')} vulnerability in {file.split('/')[-1]}",
            "resolution": "",
            "code_churn": rng.randint(0, 3),
        })
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
        category_breakdown[cwe] = category_breakdown.get(cwe, 0) + 1

    return issues, severity_breakdown, category_breakdown


def generate_demo_runs() -> list[dict]:
    rng = random.Random(42)
    all_runs: list[dict] = []
    pr_counter = 1

    base_date = datetime(2025, 11, 1, tzinfo=timezone.utc)
    end_date = datetime(2026, 2, 1, tzinfo=timezone.utc)
    total_days = (end_date - base_date).days

    for repo in REPOS:
        if repo["importance"] == "critical":
            num_runs = rng.randint(10, 14)
        elif repo["importance"] == "high":
            num_runs = rng.randint(7, 10)
        else:
            num_runs = rng.randint(4, 7)

        run_dates = sorted([
            base_date + timedelta(
                days=rng.randint(0, total_days),
                hours=rng.randint(6, 18),
                minutes=rng.randint(0, 59),
            )
            for _ in range(num_runs)
        ])

        existing_fps: list[str] = []
        run_number_base = len(all_runs)

        for idx, run_date in enumerate(run_dates):
            run_number = run_number_base + idx + 1
            progress = idx / max(num_runs - 1, 1)

            issues, sev_bd, cat_bd = _generate_issues_for_run(
                repo, idx + 1, num_runs, existing_fps, rng,
            )
            existing_fps = [iss["fingerprint"] for iss in issues]

            if idx < 2:
                batch_size = rng.randint(4, 6)
            else:
                batch_size = rng.randint(3, 5)

            issues_count = len(issues)
            batches = max(1, (issues_count + batch_size - 1) // batch_size)

            sessions = []
            issues_per_batch = max(1, issues_count // batches)

            for b in range(batches):
                start_i = b * issues_per_batch
                end_i = min(start_i + issues_per_batch, issues_count)
                batch_issues = issues[start_i:end_i]
                if not batch_issues and b > 0:
                    continue

                sid = _session_id()

                if progress < 0.3:
                    status_weights = {"finished": 0.5, "stopped": 0.3, "error": 0.2}
                elif progress < 0.6:
                    status_weights = {"finished": 0.7, "stopped": 0.2, "error": 0.1}
                else:
                    status_weights = {"finished": 0.85, "stopped": 0.10, "error": 0.05}

                statuses = list(status_weights.keys())
                weights = list(status_weights.values())
                status = rng.choices(statuses, weights=weights, k=1)[0]

                has_pr = status == "finished" and rng.random() < (0.5 + progress * 0.4)
                pr_url = ""
                if has_pr:
                    pr_url = _pr_url(repo["fork"], pr_counter)
                    pr_counter += 1

                sessions.append({
                    "session_id": sid,
                    "session_url": _session_url(sid),
                    "batch_id": b + 1,
                    "status": status,
                    "issue_ids": [iss["id"] for iss in batch_issues],
                    "pr_url": pr_url,
                })

            run_label = (
                f"run-{run_number}-"
                f"{run_date.strftime('%Y-%m-%d-%H%M%S')}"
            )

            run_data = {
                "target_repo": repo["url"],
                "fork_url": repo["fork"],
                "run_number": run_number,
                "run_id": str(rng.randint(10000000000, 99999999999)),
                "run_url": f"https://github.com/acme-corp/codeql-devin-fixer/actions/runs/{rng.randint(10000000000, 99999999999)}",
                "run_label": run_label,
                "timestamp": run_date.isoformat(),
                "issues_found": issues_count,
                "severity_breakdown": sev_bd,
                "category_breakdown": cat_bd,
                "batches_created": batches,
                "sessions": sessions,
                "issue_fingerprints": issues,
            }
            all_runs.append(run_data)

    return all_runs


def generate_demo_prs(runs: list[dict]) -> list[dict]:
    rng = random.Random(42)
    prs: list[dict] = []
    seen_urls: set[str] = set()

    for run in runs:
        run_date = datetime.fromisoformat(run["timestamp"])
        for session in run.get("sessions", []):
            pr_url = session.get("pr_url", "")
            if not pr_url or pr_url in seen_urls:
                continue
            seen_urls.add(pr_url)

            pr_num_match = pr_url.rstrip("/").split("/")[-1]
            pr_number = int(pr_num_match) if pr_num_match.isdigit() else 0

            progress = 0.5
            for i, r in enumerate(runs):
                if r["run_label"] == run["run_label"]:
                    progress = i / max(len(runs) - 1, 1)
                    break

            if progress > 0.6:
                merge_prob = 0.8
            elif progress > 0.3:
                merge_prob = 0.55
            else:
                merge_prob = 0.35

            is_merged = rng.random() < merge_prob
            if is_merged:
                state = "closed"
            elif rng.random() < 0.3:
                state = "open"
            else:
                state = "closed"

            created_at = run_date + timedelta(minutes=rng.randint(5, 60))

            issue_ids = session.get("issue_ids", [])
            cwe_hint = ""
            if issue_ids:
                cwe_hint = rng.choice([
                    "SQL injection", "XSS", "path traversal",
                    "weak crypto", "info disclosure", "auth bypass",
                    "SSRF", "deserialization",
                ])

            prs.append({
                "pr_number": pr_number,
                "title": f"fix: resolve {cwe_hint} vulnerability" if cwe_hint else f"fix: security remediation batch",
                "html_url": pr_url,
                "state": state,
                "merged": is_merged,
                "created_at": created_at.isoformat(),
                "repo": run.get("fork_url", ""),
                "user": "devin-ai-integration[bot]",
                "session_id": session.get("session_id", ""),
                "issue_ids": issue_ids,
            })

    return prs


def generate_demo_verification_records(runs: list[dict], prs: list[dict]) -> list[dict]:
    rng = random.Random(42)
    records: list[dict] = []

    merged_pr_urls = {p["html_url"] for p in prs if p.get("merged")}

    for run in runs:
        for session in run.get("sessions", []):
            pr_url = session.get("pr_url", "")
            if not pr_url or pr_url not in merged_pr_urls:
                continue

            issue_ids = session.get("issue_ids", [])
            if not issue_ids:
                continue

            total_targeted = len(issue_ids)

            progress = 0.5
            for i, r in enumerate(runs):
                if r["run_label"] == run["run_label"]:
                    progress = i / max(len(runs) - 1, 1)
                    break

            if progress > 0.6:
                fix_ratio = rng.uniform(0.7, 1.0)
            elif progress > 0.3:
                fix_ratio = rng.uniform(0.4, 0.8)
            else:
                fix_ratio = rng.uniform(0.2, 0.6)

            fixed_count = max(1, int(total_targeted * fix_ratio))
            fixed_count = min(fixed_count, total_targeted)

            pr_num = int(pr_url.rstrip("/").split("/")[-1]) if pr_url.rstrip("/").split("/")[-1].isdigit() else 0
            run_date = datetime.fromisoformat(run["timestamp"])
            verified_at = run_date + timedelta(hours=rng.randint(1, 12))

            if fixed_count == total_targeted:
                label = "verified-fix"
            elif fixed_count > 0:
                label = "codeql-partial-fix"
            else:
                label = "codeql-needs-work"

            records.append({
                "pr_url": pr_url,
                "pr_number": pr_num,
                "session_id": session.get("session_id", ""),
                "verified_at": verified_at.isoformat(),
                "label": label,
                "summary": {
                    "total_targeted": total_targeted,
                    "fixed_count": fixed_count,
                    "still_present": total_targeted - fixed_count,
                    "fix_rate": round(fixed_count / total_targeted * 100, 1),
                },
            })

    return records


def generate_demo_orchestrator_state(runs: list[dict]) -> dict:
    rng = random.Random(42)

    last_run = max(runs, key=lambda r: r["timestamp"])
    last_date = datetime.fromisoformat(last_run["timestamp"])

    dispatch_history: dict[str, list[dict]] = {}
    for run in runs:
        for session in run.get("sessions", []):
            for issue_id in session.get("issue_ids", []):
                fp = hashlib.sha256(issue_id.encode()).hexdigest()[:32]
                if fp not in dispatch_history:
                    dispatch_history[fp] = []
                dispatch_history[fp].append({
                    "session_id": session["session_id"],
                    "session_url": session["session_url"],
                    "dispatched_at": run["timestamp"],
                    "status": session["status"],
                    "pr_url": session.get("pr_url", ""),
                })

    timestamps = []
    for run in runs[-5:]:
        for s in run.get("sessions", []):
            timestamps.append(run["timestamp"])

    scan_schedule: dict[str, dict] = {}
    for repo in REPOS:
        last_scan = last_date - timedelta(days=rng.randint(0, 7))
        next_scan = last_scan + timedelta(days=7)
        scan_schedule[repo["url"]] = {
            "last_scan": last_scan.isoformat(),
            "next_scan": next_scan.isoformat(),
            "schedule": "weekly",
        }

    return {
        "last_cycle": last_date.isoformat(),
        "rate_limiter": {
            "created_timestamps": timestamps,
        },
        "dispatch_history": dispatch_history,
        "objective_progress": [],
        "scan_schedule": scan_schedule,
    }


def build_all_demo_data() -> dict:
    runs = generate_demo_runs()
    prs = generate_demo_prs(runs)
    verification_records = generate_demo_verification_records(runs, prs)
    orchestrator_state = generate_demo_orchestrator_state(runs)

    return {
        "runs": runs,
        "prs": prs,
        "verification_records": verification_records,
        "orchestrator_state": orchestrator_state,
    }


def save_demo_data_to_files(data: dict | None = None) -> pathlib.Path:
    if data is None:
        data = build_all_demo_data()

    DEMO_DATA_DIR.mkdir(parents=True, exist_ok=True)

    for f in DEMO_DATA_DIR.glob("*.json"):
        f.unlink()

    for run in data["runs"]:
        label = run["run_label"].replace(" ", "_")
        fp = DEMO_DATA_DIR / f"{label}.json"
        fp.write_text(json.dumps(run, indent=2) + "\n")

    prs_path = DEMO_DATA_DIR / "_prs.json"
    prs_path.write_text(json.dumps(data.get("prs", []), indent=2) + "\n")

    verification_path = DEMO_DATA_DIR / "_verification.json"
    verification_path.write_text(json.dumps(data.get("verification_records", []), indent=2) + "\n")

    orch_path = DEMO_DATA_DIR / "_orchestrator_state.json"
    orch_path.write_text(json.dumps(data.get("orchestrator_state", {}), indent=2) + "\n")

    return DEMO_DATA_DIR


def load_demo_data_into_db(conn: sqlite3.Connection | None = None) -> dict:
    own_conn = conn is None
    if own_conn:
        init_db()
        conn = get_connection()

    stats = {"runs": 0, "prs": 0, "verification_records": 0, "errors": 0}

    if not DEMO_DATA_DIR.is_dir():
        data = build_all_demo_data()
        save_demo_data_to_files(data)
    else:
        data = load_demo_data_from_files()

    for run in data["runs"]:
        try:
            result = insert_run(conn, run, f"demo_{run['run_label']}.json")
            if result is not None:
                stats["runs"] += 1
        except Exception:
            stats["errors"] += 1

    for pr in data["prs"]:
        try:
            upsert_pr(conn, pr)
            stats["prs"] += 1
        except Exception:
            stats["errors"] += 1

    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        (DEMO_MARKER_KEY, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()

    if own_conn:
        conn.close()

    return stats


def clear_demo_data_from_db(conn: sqlite3.Connection | None = None) -> dict:
    own_conn = conn is None
    if own_conn:
        conn = get_connection()

    stats = {"runs_deleted": 0, "prs_deleted": 0}

    run_rows = conn.execute(
        "SELECT id FROM runs WHERE source_file LIKE 'demo_%'"
    ).fetchall()
    run_ids = [r["id"] for r in run_rows]

    if run_ids:
        placeholders = ",".join("?" * len(run_ids))
        conn.execute(f"DELETE FROM sessions WHERE run_id IN ({placeholders})", run_ids)
        conn.execute(f"DELETE FROM issues WHERE run_id IN ({placeholders})", run_ids)
        conn.execute(f"DELETE FROM runs WHERE id IN ({placeholders})", run_ids)
        stats["runs_deleted"] = len(run_ids)

    demo_prs = conn.execute(
        "SELECT id FROM prs WHERE user = 'devin-ai-integration[bot]' AND repo LIKE '%acme-corp%'"
    ).fetchall()
    pr_ids = [p["id"] for p in demo_prs]
    if pr_ids:
        placeholders = ",".join("?" * len(pr_ids))
        conn.execute(f"DELETE FROM pr_issue_ids WHERE pr_id IN ({placeholders})", pr_ids)
        conn.execute(f"DELETE FROM prs WHERE id IN ({placeholders})", pr_ids)
        stats["prs_deleted"] = len(pr_ids)

    conn.execute("DELETE FROM metadata WHERE key = ?", (DEMO_MARKER_KEY,))
    conn.commit()

    if own_conn:
        conn.close()

    return stats


def is_demo_data_loaded(conn: sqlite3.Connection | None = None) -> bool:
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
    try:
        row = conn.execute(
            "SELECT value FROM metadata WHERE key = ?", (DEMO_MARKER_KEY,)
        ).fetchone()
        return row is not None
    except Exception:
        return False
    finally:
        if own_conn:
            conn.close()


def load_demo_data_from_files() -> dict:
    data: dict = {"runs": [], "prs": [], "verification_records": [], "orchestrator_state": {}}

    if not DEMO_DATA_DIR.is_dir():
        return data

    for fp in sorted(DEMO_DATA_DIR.glob("*.json")):
        if fp.name.startswith("_"):
            continue
        try:
            with open(fp) as f:
                data["runs"].append(json.load(f))
        except (json.JSONDecodeError, OSError):
            pass

    prs_path = DEMO_DATA_DIR / "_prs.json"
    if prs_path.exists():
        try:
            with open(prs_path) as f:
                data["prs"] = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    verification_path = DEMO_DATA_DIR / "_verification.json"
    if verification_path.exists():
        try:
            with open(verification_path) as f:
                data["verification_records"] = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    orch_path = DEMO_DATA_DIR / "_orchestrator_state.json"
    if orch_path.exists():
        try:
            with open(orch_path) as f:
                data["orchestrator_state"] = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    return data


def get_demo_data_summary() -> dict:
    data = load_demo_data_from_files()
    if not data["runs"]:
        data = build_all_demo_data()
        save_demo_data_to_files(data)
        data = load_demo_data_from_files()

    repos = set()
    total_issues = 0
    total_sessions = 0
    for run in data["runs"]:
        repos.add(run.get("target_repo", ""))
        total_issues += run.get("issues_found", 0)
        total_sessions += len(run.get("sessions", []))

    dates = [r["timestamp"] for r in data["runs"] if r.get("timestamp")]
    date_range = ""
    if dates:
        dates.sort()
        start = dates[0][:10]
        end = dates[-1][:10]
        date_range = f"{start} to {end}"

    return {
        "repos": len(repos),
        "runs": len(data["runs"]),
        "prs": len(data["prs"]),
        "verification_records": len(data["verification_records"]),
        "total_issues_across_runs": total_issues,
        "total_sessions": total_sessions,
        "date_range": date_range,
    }
