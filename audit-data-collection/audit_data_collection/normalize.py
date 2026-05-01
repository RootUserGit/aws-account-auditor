"""Merge security + cost bundles into one evidence map for the rule engine."""

from __future__ import annotations

from typing import Any


def merge_evidence(security: dict[str, Any], cost: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    merged.update({f"sec.{k}": v for k, v in security.items() if not k.startswith("_")})
    merged.update({f"cost.{k}": v for k, v in cost.items() if not k.startswith("_")})
    merged.update(security)
    for k, v in cost.items():
        if k not in merged:
            merged[k] = v
    merged["_errors"] = list(security.get("_collector_errors") or []) + list(
        cost.get("_collector_errors") or []
    )
    return merged
