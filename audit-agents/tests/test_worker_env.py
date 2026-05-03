"""Tests for worker env loading (.env layering + defaults)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from rq import Worker

from audit_agents.worker import WindowsSimpleWorker, _parse_dotenv_lines, _worker_class, load_worker_env


def _write_min_rule_pack(root: Path) -> None:
    pack = root / "rule_packs" / "v1"
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "_stub.yaml").write_text(
        "id: STUB\npillar: cost\nseverity: low\nevaluator: cost_zero_spend_signal\n",
        encoding="utf-8",
    )


def test_parse_dotenv_basic() -> None:
    raw = """
# comment
FOO=bar
export BAZ=qux
EMPTY=
"""
    assert _parse_dotenv_lines(raw) == {"FOO": "bar", "BAZ": "qux", "EMPTY": ""}


def test_parse_dotenv_strips_quotes() -> None:
    assert _parse_dotenv_lines('X="hello world"\n') == {"X": "hello world"}
    assert _parse_dotenv_lines("Y='single'\n") == {"Y": "single"}


def test_load_worker_env_shell_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "audit-agents" / "audit_agents").mkdir(parents=True)
    fake_worker = root / "audit-agents" / "audit_agents" / "worker.py"
    fake_worker.write_text("# stub", encoding="utf-8")
    _write_min_rule_pack(root)

    env_file = root / ".env"
    env_file.write_text("REDIS_URL=redis://from-file:6379/0\n", encoding="utf-8")

    monkeypatch.setenv("REDIS_URL", "redis://from-shell:6379/0")
    monkeypatch.delenv("RULE_PACK_PATH", raising=False)
    monkeypatch.delenv("ARTIFACTS_DIR", raising=False)

    load_worker_env(worker_file=fake_worker)

    assert os.environ["REDIS_URL"] == "redis://from-shell:6379/0"


def test_worker_class_windows_uses_timer_compat_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    cls = _worker_class()
    assert cls is WindowsSimpleWorker
    assert cls.death_penalty_class.__name__ == "TimerDeathPenalty"


def test_worker_class_unix_uses_fork_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert _worker_class() is Worker


def test_load_worker_env_audit_api_env_overrides_repo(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "repo"
    ag = root / "audit-agents" / "audit_agents"
    ag.mkdir(parents=True)
    (root / "audit-api").mkdir(parents=True)
    fake_worker = ag / "worker.py"
    fake_worker.write_text("# stub", encoding="utf-8")
    _write_min_rule_pack(root)
    (root / ".env").write_text("REDIS_URL=redis://repo:6379/0\nAWS_ACCESS_KEY_ID=from-root\n", encoding="utf-8")
    (root / "audit-api" / ".env").write_text(
        "REDIS_URL=redis://api:6379/0\nAWS_ACCESS_KEY_ID=from-api\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("RULE_PACK_PATH", raising=False)
    monkeypatch.delenv("ARTIFACTS_DIR", raising=False)

    load_worker_env(worker_file=fake_worker)

    assert os.environ["REDIS_URL"] == "redis://api:6379/0"
    assert os.environ["AWS_ACCESS_KEY_ID"] == "from-api"


def test_load_worker_env_default_redis_when_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "repo"
    ag = root / "audit-agents" / "audit_agents"
    ag.mkdir(parents=True)
    fake_worker = ag / "worker.py"
    fake_worker.write_text("# stub", encoding="utf-8")
    _write_min_rule_pack(root)

    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("RULE_PACK_PATH", raising=False)
    monkeypatch.delenv("ARTIFACTS_DIR", raising=False)

    load_worker_env(worker_file=fake_worker)

    assert os.environ["REDIS_URL"] == "redis://localhost:6379/0"
    assert Path(os.environ["RULE_PACK_PATH"]) == root / "rule_packs" / "v1"
