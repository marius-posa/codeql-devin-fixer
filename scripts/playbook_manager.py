"""Load, select, and format Devin playbooks for vulnerability fix sessions.

Playbooks are structured YAML instruction sets stored in the ``playbooks/``
directory.  Each playbook targets a specific CWE family (e.g. ``injection``,
``xss``, ``path-traversal``) and contains step-by-step guidance that is
injected into the Devin session prompt.

The module also supports a *learning loop*: after a session completes, Devin
can propose improvements to a playbook.  Those improvements are appended to
the playbook's ``improvement_log`` and, when accepted, merged into the
playbook steps.

Usage
-----
::

    from playbook_manager import PlaybookManager

    pm = PlaybookManager("playbooks")
    pb = pm.get_playbook("injection")
    if pb:
        prompt_section = pm.format_for_prompt(pb)
"""

from __future__ import annotations

import copy
import logging
import os
from dataclasses import dataclass, field
from typing import Any

import requests
import yaml

try:
    from devin_api import DEVIN_API_BASE
except ImportError:
    from scripts.devin_api import DEVIN_API_BASE

logger = logging.getLogger(__name__)


PLAYBOOK_SCHEMA_VERSION = 1


@dataclass
class PlaybookStep:
    """A single step in a playbook."""

    id: str
    title: str
    instructions: str


@dataclass
class Playbook:
    """A structured fix-pattern playbook for a CWE family."""

    name: str
    version: int
    description: str
    steps: list[PlaybookStep]
    improvement_log: list[dict[str, Any]] = field(default_factory=list)
    source_path: str = ""


def _parse_playbook(data: dict[str, Any], source_path: str = "") -> Playbook:
    """Parse a raw YAML dict into a :class:`Playbook`."""
    steps: list[PlaybookStep] = []
    for raw_step in data.get("steps", []):
        steps.append(
            PlaybookStep(
                id=raw_step["id"],
                title=raw_step["title"],
                instructions=raw_step["instructions"].rstrip(),
            )
        )
    return Playbook(
        name=data["name"],
        version=data.get("version", PLAYBOOK_SCHEMA_VERSION),
        description=data.get("description", "").strip(),
        steps=steps,
        improvement_log=data.get("improvement_log") or [],
        source_path=source_path,
    )


class PlaybookManager:
    """Load and manage playbooks from a directory of YAML files."""

    def __init__(self, playbooks_dir: str) -> None:
        self._dir = playbooks_dir
        self._playbooks: dict[str, Playbook] = {}
        self._devin_ids: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.isdir(self._dir):
            return
        for entry in sorted(os.listdir(self._dir)):
            if not entry.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(self._dir, entry)
            try:
                with open(path) as fh:
                    data = yaml.safe_load(fh)
                if not isinstance(data, dict) or "name" not in data:
                    continue
                pb = _parse_playbook(data, source_path=path)
                self._playbooks[pb.name] = pb
            except (yaml.YAMLError, OSError, KeyError):
                continue

    @property
    def available_families(self) -> list[str]:
        """Return the CWE families that have playbooks."""
        return sorted(self._playbooks.keys())

    def get_playbook(self, family: str) -> Playbook | None:
        """Return the playbook for *family*, or ``None``."""
        return self._playbooks.get(family)

    def format_for_prompt(self, playbook: Playbook) -> str:
        """Render a playbook as a Markdown section for a Devin prompt."""
        parts: list[str] = [
            f"## Playbook: {playbook.name} (v{playbook.version})",
            "",
            playbook.description,
            "",
            "Follow these steps in order:",
            "",
        ]
        for idx, step in enumerate(playbook.steps, 1):
            parts.append(f"### Step {idx}: {step.title}")
            parts.append("")
            parts.append(step.instructions)
            parts.append("")
        return "\n".join(parts)

    def format_improvement_request(self, playbook: Playbook) -> str:
        """Return prompt text asking Devin to suggest playbook improvements."""
        return (
            "## Playbook Improvement Request\n"
            "\n"
            f"You used the **{playbook.name}** playbook (v{playbook.version}) "
            "to fix the issues above. Based on your experience applying it "
            "to this codebase, please suggest improvements.\n"
            "\n"
            "In your PR description, include a section titled "
            '**"Playbook Improvements"** with:\n'
            "- Any steps that were unclear or missing context\n"
            "- Additional sub-steps that would help future fixes\n"
            "- Language- or framework-specific tips you discovered\n"
            "- Steps that were unnecessary or redundant\n"
            "\n"
            "Format each suggestion as:\n"
            "```\n"
            "STEP: <step_id>\n"
            "SUGGESTION: <your improvement>\n"
            "```\n"
            "\n"
            "These suggestions will be reviewed and merged into the playbook "
            "for future sessions.\n"
        )

    def apply_improvement(
        self,
        family: str,
        step_id: str,
        suggestion: str,
        session_id: str = "",
    ) -> bool:
        """Append an improvement entry to a playbook's improvement log.

        Returns ``True`` if the improvement was recorded, ``False`` if the
        playbook or step was not found.
        """
        pb = self._playbooks.get(family)
        if pb is None:
            return False
        valid_ids = {s.id for s in pb.steps}
        if step_id not in valid_ids:
            return False
        pb.improvement_log.append({
            "step_id": step_id,
            "suggestion": suggestion,
            "session_id": session_id,
        })
        return True

    def save_playbook(self, family: str) -> bool:
        """Write the playbook back to its YAML file.

        Returns ``True`` on success, ``False`` if the playbook has no
        ``source_path`` or does not exist.
        """
        pb = self._playbooks.get(family)
        if pb is None or not pb.source_path:
            return False
        data = _playbook_to_dict(pb)
        try:
            with open(pb.source_path, "w") as fh:
                yaml.dump(data, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)
            return True
        except OSError:
            return False

    def sync_to_devin_api(self, api_key: str) -> dict[str, str]:
        """Sync local playbooks to the Devin Playbooks API.

        For each local playbook, creates or updates a corresponding
        playbook via the Devin API.  Returns a mapping of
        ``{family: playbook_id}`` for all successfully synced playbooks.
        """
        if not api_key:
            return {}

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        existing: dict[str, str] = {}
        try:
            resp = requests.get(
                f"{DEVIN_API_BASE}/playbooks",
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            for item in resp.json():
                title = item.get("title", "")
                pid = item.get("playbook_id", "")
                if title and pid:
                    existing[title] = pid
        except requests.exceptions.RequestException as exc:
            logger.warning("Failed to list Devin playbooks: %s", exc)
            return {}

        synced: dict[str, str] = {}
        for family, pb in self._playbooks.items():
            title = f"codeql-fix-{pb.name}"
            body = self.format_for_prompt(pb)
            payload = {"title": title, "body": body}

            try:
                if title in existing:
                    pid = existing[title]
                    requests.put(
                        f"{DEVIN_API_BASE}/playbooks/{pid}",
                        headers=headers,
                        json=payload,
                        timeout=15,
                    ).raise_for_status()
                    synced[family] = pid
                    logger.info("Updated Devin playbook '%s' (%s)", title, pid)
                else:
                    resp = requests.post(
                        f"{DEVIN_API_BASE}/playbooks",
                        headers=headers,
                        json=payload,
                        timeout=15,
                    )
                    resp.raise_for_status()
                    pid = resp.json().get("playbook_id", "")
                    if pid:
                        synced[family] = pid
                        logger.info("Created Devin playbook '%s' (%s)", title, pid)
            except requests.exceptions.RequestException as exc:
                logger.warning("Failed to sync playbook '%s': %s", family, exc)

        self._devin_ids.update(synced)
        return synced

    def get_devin_playbook_id(self, family: str) -> str:
        """Return the Devin API playbook ID for *family*, or empty string."""
        return self._devin_ids.get(family, "")


def _playbook_to_dict(pb: Playbook) -> dict[str, Any]:
    """Serialize a :class:`Playbook` to a plain dict for YAML output."""
    return {
        "name": pb.name,
        "version": pb.version,
        "description": pb.description,
        "steps": [
            {
                "id": s.id,
                "title": s.title,
                "instructions": s.instructions + "\n",
            }
            for s in pb.steps
        ],
        "improvement_log": copy.deepcopy(pb.improvement_log),
    }


def parse_improvement_suggestions(pr_body: str) -> list[dict[str, str]]:
    """Extract playbook improvement suggestions from a PR description.

    Looks for blocks matching the format::

        STEP: <step_id>
        SUGGESTION: <text>

    Returns a list of ``{"step_id": ..., "suggestion": ...}`` dicts.
    """
    suggestions: list[dict[str, str]] = []
    lines = pr_body.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.upper().startswith("STEP:"):
            step_id = line.split(":", 1)[1].strip()
            suggestion_lines: list[str] = []
            i += 1
            while i < len(lines):
                sline = lines[i].strip()
                if sline.upper().startswith("SUGGESTION:"):
                    suggestion_lines.append(sline.split(":", 1)[1].strip())
                    i += 1
                    while i < len(lines) and lines[i].strip() and not lines[i].strip().upper().startswith("STEP:") and lines[i].strip() != "```":
                        suggestion_lines.append(lines[i].strip())
                        i += 1
                    break
                else:
                    i += 1
            if step_id and suggestion_lines:
                suggestions.append({
                    "step_id": step_id,
                    "suggestion": " ".join(suggestion_lines),
                })
        else:
            i += 1
    return suggestions
