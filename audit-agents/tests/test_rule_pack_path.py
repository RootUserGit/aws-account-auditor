"""Tests for rule pack directory resolution."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from audit_agents.rule_pack_path import resolve_rule_pack_path, sync_rule_pack_path_env


def test_resolve_prefers_env_when_it_has_yaml(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    good = tmp_path / "pack-a"
    good.mkdir()
    (good / "r.yaml").write_text("x: 1\n", encoding="utf-8")
    other = tmp_path / "pack-b"
    other.mkdir()
    (other / "r.yaml").write_text("x: 1\n", encoding="utf-8")

    anchor = tmp_path / "audit-agents" / "audit_agents" / "graph" / "audit_graph.py"
    anchor.parent.mkdir(parents=True, exist_ok=True)
    anchor.write_text("#", encoding="utf-8")

    monkeypatch.setenv("RULE_PACK_PATH", str(good))
    assert resolve_rule_pack_path(anchor=anchor) == good.resolve()


def test_resolve_walks_from_anchor_when_env_unset(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    pack = root / "rule_packs" / "v1"
    pack.mkdir(parents=True)
    (pack / "r.yaml").write_text("x: 1\n", encoding="utf-8")

    anchor = root / "audit-agents" / "audit_agents" / "worker.py"
    anchor.parent.mkdir(parents=True, exist_ok=True)
    anchor.write_text("#", encoding="utf-8")

    old = os.environ.pop("RULE_PACK_PATH", None)
    try:
        assert resolve_rule_pack_path(anchor=anchor) == pack.resolve()
    finally:
        if old is not None:
            os.environ["RULE_PACK_PATH"] = old


def test_sync_replaces_invalid_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "repo"
    pack = root / "rule_packs" / "v1"
    pack.mkdir(parents=True)
    (pack / "r.yaml").write_text("x: 1\n", encoding="utf-8")

    fake_worker = root / "audit-agents" / "audit_agents" / "worker.py"
    fake_worker.parent.mkdir(parents=True, exist_ok=True)
    fake_worker.write_text("#", encoding="utf-8")

    bad = tmp_path / "nowhere"
    bad.mkdir()  # no yaml

    monkeypatch.setenv("RULE_PACK_PATH", str(bad))
    sync_rule_pack_path_env(fake_worker)
    assert Path(os.environ["RULE_PACK_PATH"]).resolve() == pack.resolve()
