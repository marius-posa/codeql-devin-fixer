"""Machine type selection for Devin sessions.

Determines appropriate compute resources (expressed as ``max_acu_limit``)
for each session based on repository size, build complexity, and batch
characteristics.  This module centralises machine-selection logic so it
can be extended when a dedicated ``/v1/machines`` API endpoint becomes
available.

Machine tiers
-------------
light   -- Small repos or simple single-file fixes.
standard -- Typical multi-file fix batches.
heavy   -- Large monorepos or complex cross-family batches requiring
           significant build/test time.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Sequence

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MachineType:
    """Describes a machine configuration tier."""

    name: str
    max_acu: int
    description: str


MACHINE_LIGHT = MachineType(
    name="light",
    max_acu=5,
    description="Small repos or simple single-file fixes",
)

MACHINE_STANDARD = MachineType(
    name="standard",
    max_acu=10,
    description="Typical multi-file fix batches",
)

MACHINE_HEAVY = MachineType(
    name="heavy",
    max_acu=20,
    description="Large monorepos or complex cross-family batches",
)

MACHINE_TYPES: dict[str, MachineType] = {
    "light": MACHINE_LIGHT,
    "standard": MACHINE_STANDARD,
    "heavy": MACHINE_HEAVY,
}


def list_machines() -> list[MachineType]:
    """Return all available machine type configurations."""
    return [MACHINE_LIGHT, MACHINE_STANDARD, MACHINE_HEAVY]


def _estimate_repo_size(target_dir: str) -> int:
    """Return an approximate file count for the repository at *target_dir*.

    Only counts files in the working tree (skips ``.git``, ``node_modules``,
    and other common non-source directories).
    """
    if not target_dir or not os.path.isdir(target_dir):
        return 0

    skip_dirs = {
        ".git", "node_modules", "__pycache__", ".tox", ".mypy_cache",
        ".pytest_cache", "venv", ".venv", "dist", "build", "target",
    }
    count = 0
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        count += len(files)
    return count


def select_machine_type(
    *,
    target_dir: str = "",
    issue_count: int = 1,
    file_count: int = 0,
    severity_tier: str = "medium",
    cross_family: bool = False,
    languages: Sequence[str] = (),
) -> MachineType:
    """Select the most appropriate machine type for a session.

    The selection considers:
    * **Repository size** -- large repos (>5 000 files) need more compute.
    * **Batch complexity** -- many issues or cross-family batches are heavier.
    * **Severity** -- critical issues get more headroom.
    * **Build requirements** -- compiled languages (Java, Go, Rust, C++)
      or monorepo indicators push toward heavier machines.

    Returns a :class:`MachineType` whose ``max_acu`` can be used directly
    as the ``max_acu_limit`` on session creation.
    """
    score = 0

    repo_file_count = _estimate_repo_size(target_dir) if target_dir else 0
    if repo_file_count > 5000:
        score += 3
    elif repo_file_count > 1000:
        score += 1

    if issue_count >= 8:
        score += 2
    elif issue_count >= 4:
        score += 1

    if file_count >= 10:
        score += 2
    elif file_count >= 5:
        score += 1

    if severity_tier in ("critical", "high"):
        score += 1

    if cross_family:
        score += 1

    compiled_langs = {"java", "go", "rust", "c", "c++", "cpp", "scala", "kotlin"}
    if any(lang.lower() in compiled_langs for lang in languages):
        score += 1

    if score >= 5:
        return MACHINE_HEAVY
    if score >= 2:
        return MACHINE_STANDARD
    return MACHINE_LIGHT


def resolve_machine_acu(
    *,
    explicit_max_acu: int | None = None,
    machine_type_name: str = "",
    target_dir: str = "",
    issue_count: int = 1,
    file_count: int = 0,
    severity_tier: str = "medium",
    cross_family: bool = False,
    languages: Sequence[str] = (),
) -> int | None:
    """Determine the ``max_acu_limit`` to use for a session.

    Priority order:
    1. *explicit_max_acu* -- user-provided ``MAX_ACU_PER_SESSION`` override.
    2. *machine_type_name* -- explicit ``MACHINE_TYPE`` env var.
    3. Auto-selection via :func:`select_machine_type`.

    Returns ``None`` when no limit should be imposed (i.e. the user did
    not set any ACU configuration and auto-selection is disabled).
    """
    if explicit_max_acu is not None and explicit_max_acu > 0:
        return explicit_max_acu

    if machine_type_name:
        mt = MACHINE_TYPES.get(machine_type_name.lower())
        if mt:
            logger.info("Using explicit machine type '%s' (ACU=%d)", mt.name, mt.max_acu)
            return mt.max_acu
        logger.warning(
            "Unknown machine type '%s'; falling back to auto-selection",
            machine_type_name,
        )

    mt = select_machine_type(
        target_dir=target_dir,
        issue_count=issue_count,
        file_count=file_count,
        severity_tier=severity_tier,
        cross_family=cross_family,
        languages=languages,
    )
    logger.info("Auto-selected machine type '%s' (ACU=%d)", mt.name, mt.max_acu)
    return mt.max_acu
