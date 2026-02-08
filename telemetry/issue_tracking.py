from datetime import datetime, timezone

DEFAULT_SLA_HOURS: dict[str, int] = {
    "critical": 48,
    "high": 96,
    "medium": 168,
    "low": 336,
}

AT_RISK_THRESHOLD = 0.75


def compute_sla_status(
    severity_tier: str,
    found_at: datetime | None,
    fixed_at: datetime | None,
    sla_hours: dict[str, int] | None = None,
) -> dict:
    thresholds = sla_hours or DEFAULT_SLA_HOURS
    limit = thresholds.get(severity_tier.lower(), 0) if severity_tier else 0
    if not limit or not found_at:
        return {
            "sla_status": "unknown",
            "sla_limit_hours": limit,
            "sla_hours_elapsed": None,
            "sla_hours_remaining": None,
        }

    ref = fixed_at if fixed_at else datetime.now(timezone.utc)
    if found_at.tzinfo is None:
        found_at = found_at.replace(tzinfo=timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    elapsed = (ref - found_at).total_seconds() / 3600
    remaining = limit - elapsed

    if fixed_at:
        status = "met" if elapsed <= limit else "breached"
    else:
        if elapsed > limit:
            status = "breached"
        elif elapsed >= limit * AT_RISK_THRESHOLD:
            status = "at-risk"
        else:
            status = "on-track"

    return {
        "sla_status": status,
        "sla_limit_hours": limit,
        "sla_hours_elapsed": round(elapsed, 1),
        "sla_hours_remaining": round(remaining, 1),
    }


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None
