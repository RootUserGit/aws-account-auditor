from dataclasses import dataclass, field
from typing import Any


@dataclass
class CollectorResult:
    """Result of a collector domain with partial success support."""

    bundle: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def merge_errors(self, label: str, exc: BaseException) -> None:
        self.errors.append(f"{label}: {exc.__class__.__name__}: {exc}")
