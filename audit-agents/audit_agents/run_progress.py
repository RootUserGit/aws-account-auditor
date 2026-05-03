"""Optional progress callbacks into the worker DB session (contextvar)."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Callable

Reporter = Callable[[dict[str, Any]], None]

_reporter: ContextVar[Reporter | None] = ContextVar("audit_run_progress_reporter", default=None)


def attach_run_progress_reporter(fn: Reporter | None) -> Any:
    """Returns a token for :func:`reset_run_progress_reporter`."""
    return _reporter.set(fn)


def reset_run_progress_reporter(token: Any) -> None:
    _reporter.reset(token)


def report_progress(update: dict[str, Any]) -> None:
    fn = _reporter.get()
    if fn:
        fn(update)
