def compute_sla_summary(issues: list[dict]) -> dict:
    by_status: dict[str, int] = {}
    by_severity: dict[str, dict] = {}
    ttf_by_severity: dict[str, list[float]] = {}

    for iss in issues:
        sla = iss.get("sla_status", "unknown")
        by_status[sla] = by_status.get(sla, 0) + 1

        sev = (iss.get("severity_tier") or "").lower()
        if sev:
            if sev not in by_severity:
                by_severity[sev] = {}
            by_severity[sev][sla] = by_severity[sev].get(sla, 0) + 1

        dur = iss.get("fix_duration_hours")
        if dur is not None and sev:
            if sev not in ttf_by_severity:
                ttf_by_severity[sev] = []
            ttf_by_severity[sev].append(dur)

    time_to_fix: dict[str, dict] = {}
    for sev, durations in ttf_by_severity.items():
        sorted_d = sorted(durations)
        n = len(sorted_d)
        time_to_fix[sev] = {
            "count": n,
            "min": round(sorted_d[0], 1),
            "max": round(sorted_d[-1], 1),
            "avg": round(sum(sorted_d) / n, 1),
            "median": round(
                (sorted_d[n // 2] + sorted_d[(n - 1) // 2]) / 2, 1
            ),
        }

    return {
        "by_status": by_status,
        "by_severity": by_severity,
        "time_to_fix_by_severity": time_to_fix,
        "total_breached": by_status.get("breached", 0),
        "total_at_risk": by_status.get("at-risk", 0),
        "total_on_track": by_status.get("on-track", 0),
        "total_met": by_status.get("met", 0),
    }
