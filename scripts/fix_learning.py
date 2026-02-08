#!/usr/bin/env python3
"""Learn from past fix attempts to optimise future dispatch decisions.

This module analyses historical telemetry data to compute per-CWE-family
fix rates and provides recommendations for batch prioritisation and prompt
enrichment.

The telemetry data lives in ``telemetry/runs/`` as JSON files committed by
``persist_telemetry.py`` after each pipeline run.  Each file contains
``issue_fingerprints`` (with ``cwe_family`` and ``severity_tier``) and
``sessions`` (with ``status``).  By correlating session outcomes with the
CWE families they addressed, we can estimate which vulnerability types
Devin historically fixes most reliably.

Usage
-----
::

    from fix_learning import FixLearning

    fl = FixLearning.from_telemetry_dir("telemetry/runs")
    rates = fl.family_fix_rates()
    hint = fl.prompt_context_for_family("injection")
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

DEFAULT_ACU_BUDGET = 10
MIN_ACU_BUDGET = 3
MAX_ACU_BUDGET = 30
HIGH_FIX_RATE_THRESHOLD = 0.7
LOW_FIX_RATE_THRESHOLD = 0.3
MAX_FIX_EXAMPLE_DIFF_CHARS = 2000
MAX_FIX_EXAMPLES_PER_PROMPT = 3


CWE_FIX_HINTS: dict[str, str] = {
    "injection": (
        "Use parameterized queries or prepared statements instead of string "
        "concatenation.  For OS command injection, use safe APIs that accept "
        "argument lists (e.g. subprocess with shell=False)."
    ),
    "xss": (
        "Escape all user-controlled output using context-appropriate encoding "
        "(HTML entity encoding for HTML bodies, JS encoding for script blocks, "
        "URL encoding for href attributes).  Prefer framework auto-escaping."
    ),
    "path-traversal": (
        "Canonicalize file paths with os.path.realpath() and verify the result "
        "is within the expected base directory.  Reject paths containing '..' "
        "or absolute path components."
    ),
    "ssrf": (
        "Validate and allowlist target URLs/hostnames before making requests.  "
        "Block requests to internal/private IP ranges (127.0.0.0/8, 10.0.0.0/8, "
        "169.254.169.254, etc.)."
    ),
    "deserialization": (
        "Never deserialize untrusted data with pickle, yaml.load, or Java "
        "ObjectInputStream.  Use safe alternatives (json, yaml.safe_load, "
        "allowlisted type resolvers)."
    ),
    "auth": (
        "Enforce authentication checks on every protected endpoint.  Use "
        "framework-provided decorators or middleware rather than manual checks.  "
        "Ensure authorization is checked after authentication."
    ),
    "crypto": (
        "Use well-established libraries (e.g. libsodium, OpenSSL) with strong "
        "defaults.  Replace weak algorithms (MD5, SHA1, DES, RC4) with modern "
        "alternatives (SHA-256+, AES-GCM, ChaCha20-Poly1305).  Use "
        "cryptographically secure random number generators."
    ),
    "info-disclosure": (
        "Remove sensitive data from error messages, logs, and HTTP responses.  "
        "Use generic error pages in production.  Ensure stack traces and debug "
        "information are suppressed outside development mode."
    ),
    "redirect": (
        "Validate redirect targets against an allowlist of trusted domains.  "
        "Use relative paths for internal redirects.  Reject open redirect URLs "
        "pointing to external sites."
    ),
    "xxe": (
        "Disable external entity processing in XML parsers.  For Python use "
        "defusedxml; for Java set XMLConstants.FEATURE_SECURE_PROCESSING and "
        "disallow DTDs."
    ),
    "csrf": (
        "Implement anti-CSRF tokens on all state-changing endpoints.  Use "
        "framework-provided CSRF middleware.  Verify the Origin/Referer header "
        "as a defense-in-depth measure."
    ),
    "prototype-pollution": (
        "Avoid recursive object merges on user-controlled input.  Use "
        "Object.create(null) for dictionary-like objects.  Freeze prototypes "
        "where feasible, or validate keys against a blocklist (__proto__, "
        "constructor, prototype)."
    ),
    "regex-dos": (
        "Avoid nested quantifiers and overlapping alternations in regular "
        "expressions.  Use possessive quantifiers or atomic groups where "
        "supported.  Set timeouts on regex execution."
    ),
    "hardcoded-credentials": (
        "Move credentials to environment variables, secrets managers, or "
        "configuration files excluded from version control.  Use .env files "
        "with .gitignore entries."
    ),
    "file-upload": (
        "Validate file type by content inspection (magic bytes), not just "
        "extension.  Store uploads outside the web root.  Set a maximum file "
        "size limit."
    ),
    "race-condition": (
        "Use database-level locking or atomic operations for shared-state "
        "mutations.  Avoid TOCTOU patterns by combining check and use into "
        "a single atomic operation."
    ),
    "memory-safety": (
        "Use bounds-checked APIs and smart pointers.  Enable compiler "
        "sanitizers (ASan, UBSan) during testing.  Prefer safe languages or "
        "safe abstractions for new code."
    ),
}


@dataclass
class FamilyStats:
    """Aggregated fix statistics for a single CWE family."""
    total_sessions: int = 0
    finished_sessions: int = 0
    failed_sessions: int = 0
    total_issues: int = 0

    @property
    def fix_rate(self) -> float:
        if self.total_sessions == 0:
            return 0.0
        return self.finished_sessions / self.total_sessions


@dataclass
class FixLearning:
    """Analyses past telemetry to guide future dispatch decisions."""

    runs: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_telemetry_dir(cls, telemetry_dir: str) -> "FixLearning":
        runs: list[dict[str, Any]] = []
        if not os.path.isdir(telemetry_dir):
            return cls(runs=runs)
        for entry in sorted(os.listdir(telemetry_dir)):
            if not entry.endswith(".json"):
                continue
            path = os.path.join(telemetry_dir, entry)
            try:
                with open(path) as f:
                    runs.append(json.load(f))
            except (json.JSONDecodeError, OSError):
                continue
        return cls(runs=runs)

    def family_fix_rates(self) -> dict[str, FamilyStats]:
        stats: dict[str, FamilyStats] = {}
        for run in self.runs:
            sessions = run.get("sessions", [])
            for fp in run.get("issue_fingerprints", []):
                family = fp.get("cwe_family", "other")
                if family not in stats:
                    stats[family] = FamilyStats()
                stats[family].total_issues += 1

            for s in sessions:
                status = s.get("status", "")
                family = "other"
                for ifp in run.get("issue_fingerprints", []):
                    issue_id = ifp.get("id", "")
                    if issue_id in s.get("issue_ids", []):
                        family = ifp.get("cwe_family", "other")
                        break
                if family not in stats:
                    stats[family] = FamilyStats()
                stats[family].total_sessions += 1
                if status in ("finished", "stopped"):
                    stats[family].finished_sessions += 1
                elif status.startswith("error"):
                    stats[family].failed_sessions += 1
        return stats

    def prioritized_families(self) -> list[tuple[str, float]]:
        rates = self.family_fix_rates()
        result = [
            (family, s.fix_rate) for family, s in rates.items()
        ]
        result.sort(key=lambda x: -x[1])
        return result

    def should_skip_family(self, family: str, min_sessions: int = 3, max_fix_rate: float = 0.1) -> bool:
        rates = self.family_fix_rates()
        s = rates.get(family)
        if s is None or s.total_sessions < min_sessions:
            return False
        return s.fix_rate < max_fix_rate

    def prompt_context_for_family(self, family: str) -> str:
        parts: list[str] = []
        hint = CWE_FIX_HINTS.get(family)
        if hint:
            parts.append(f"Fix pattern hint: {hint}")
        rates = self.family_fix_rates()
        s = rates.get(family)
        if s and s.total_sessions > 0:
            pct = s.fix_rate * 100
            parts.append(
                f"Historical fix rate for {family}: {pct:.0f}% "
                f"({s.finished_sessions}/{s.total_sessions} sessions completed)"
            )
        return "\n".join(parts)

    def compute_acu_budget(
        self, family: str, base_budget: int | None = None,
    ) -> int:
        """Return a dynamic ACU budget for *family* based on historical fix rates.

        Families with high fix rates get a smaller budget (they resolve quickly),
        while families with low fix rates get a larger budget (Devin needs more
        time).  When no historical data is available the *base_budget* (or
        ``DEFAULT_ACU_BUDGET``) is returned unchanged.
        """
        base = base_budget if base_budget is not None else DEFAULT_ACU_BUDGET
        rates = self.family_fix_rates()
        stats = rates.get(family)
        if stats is None or stats.total_sessions == 0:
            return max(MIN_ACU_BUDGET, min(base, MAX_ACU_BUDGET))
        rate = stats.fix_rate
        if rate >= HIGH_FIX_RATE_THRESHOLD:
            budget = int(base * 0.6)
        elif rate <= LOW_FIX_RATE_THRESHOLD:
            budget = int(base * 1.8)
        else:
            scale = 1.0 + 0.8 * (0.5 - rate)
            budget = int(base * scale)
        return max(MIN_ACU_BUDGET, min(budget, MAX_ACU_BUDGET))

    def find_fix_examples(
        self, family: str, file_patterns: list[str] | None = None,
    ) -> list[dict[str, str]]:
        """Find historical fix examples for *family*, optionally filtered by file patterns.

        Returns a list of dicts with keys ``cwe_family``, ``file``, ``diff``
        from past successful sessions.  Results are ordered by relevance:
        examples matching both family and file pattern come first.
        """
        examples: list[dict[str, str]] = []
        pattern_dirs: set[str] = set()
        if file_patterns:
            for fp in file_patterns:
                pattern_dirs.add(str(PurePosixPath(fp).parent))

        for run in self.runs:
            for ex in run.get("fix_examples", []):
                if ex.get("cwe_family") != family:
                    continue
                if not ex.get("diff"):
                    continue
                examples.append(ex)

        if pattern_dirs and examples:
            def _relevance(ex: dict[str, str]) -> int:
                ex_dir = str(PurePosixPath(ex.get("file", "")).parent)
                return 0 if ex_dir in pattern_dirs else 1
            examples.sort(key=_relevance)

        return examples[:MAX_FIX_EXAMPLES_PER_PROMPT]

    def prompt_fix_examples(self, family: str, file_patterns: list[str] | None = None) -> str:
        """Return formatted fix examples for inclusion in a Devin prompt."""
        examples = self.find_fix_examples(family, file_patterns)
        if not examples:
            return ""
        parts = ["Historical fix examples for similar issues:"]
        for i, ex in enumerate(examples, 1):
            diff = ex["diff"]
            if len(diff) > MAX_FIX_EXAMPLE_DIFF_CHARS:
                diff = diff[:MAX_FIX_EXAMPLE_DIFF_CHARS] + "\n... (truncated)"
            parts.append(f"\nExample {i} ({ex.get('file', 'unknown')}):\n```diff\n{diff}\n```")
        return "\n".join(parts)
