"""Resolve the directory that contains audit rule YAML files."""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def _dir_has_rule_yaml(d: Path) -> bool:
    if not d.is_dir():
        return False
    try:
        return any(d.rglob("*.yaml"))
    except OSError:
        return False


def resolve_rule_pack_path(*, anchor: Path | None = None) -> Path:
    """Pick the first candidate directory under ``RULE_PACK_PATH``, repo layout, or Docker that contains ``*.yaml``.

    Falls back to the usual repo-relative ``rule_packs/v1`` (even if missing) so worker defaults stay stable in tests.
    """
    candidates: list[Path] = []
    env = os.environ.get("RULE_PACK_PATH", "").strip()
    if env:
        candidates.append(Path(env).resolve())

    if anchor is not None:
        cur = anchor.resolve().parent
        for _ in range(10):
            candidates.append((cur / "rule_packs" / "v1").resolve())
            if cur.parent == cur:
                break
            cur = cur.parent

    candidates.append(Path("/app/rule_packs/v1").resolve())

    seen: set[str] = set()
    ordered: list[Path] = []
    for p in candidates:
        key = str(p)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(p)

    for p in ordered:
        if _dir_has_rule_yaml(p):
            return p

    if env:
        p = Path(env).resolve()
        logger.warning(
            "RULE_PACK_PATH=%s has no rule YAML files; audit checks may be empty. "
            "Fix the path or unset RULE_PACK_PATH so the resolver can locate rule_packs/v1.",
            p,
        )
        return p

    for p in ordered:
        if p.is_dir():
            return p

    return ordered[0] if ordered else Path("/app/rule_packs/v1").resolve()


def sync_rule_pack_path_env(anchor: Path) -> None:
    """Ensure ``RULE_PACK_PATH`` points at a directory that contains ``*.yaml`` rules."""
    cur_raw = os.environ.get("RULE_PACK_PATH", "").strip()
    if cur_raw and _dir_has_rule_yaml(Path(cur_raw).resolve()):
        return
    effective = resolve_rule_pack_path(anchor=anchor)
    if cur_raw and Path(cur_raw).resolve() != effective:
        logger.warning(
            "RULE_PACK_PATH=%s has no usable rule YAML — using %s instead.",
            cur_raw,
            effective,
        )
    os.environ["RULE_PACK_PATH"] = str(effective)
