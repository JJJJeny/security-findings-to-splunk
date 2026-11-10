"""Normalize step: build the canonical, SIEM-agnostic finding.

The canonical finding mirrors the Lantern schema with fixes from the
validate step applied (e.g. timestamp fallback, size cast), plus:
    dq_flags     list of data-quality flags
    finding_key  stable composite key (BUILD_LOG B2)
    input_index  position in the input file
It has no knowledge of any SIEM.
"""

from __future__ import annotations

import copy
from typing import Any

from .validate import ValidatedEvent


def finding_key(ev: dict[str, Any]) -> str:
    """event_id alone is not unique in the export, so combine the fields
    that identify one finding and never change over its life."""
    host_id = (ev.get("host") or {}).get("host_id", "")
    collection_id = (ev.get("collection") or {}).get("collection_id", "")
    return f"{ev.get('event_id', '')}|{host_id}|{collection_id}"


def _set(obj: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = obj
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def normalize(event: ValidatedEvent) -> dict[str, Any]:
    finding = copy.deepcopy(event.raw)
    for path, value in event.fixes.items():
        _set(finding, path, value)
    finding["dq_flags"] = list(event.flags)
    finding["finding_key"] = finding_key(finding)
    finding["input_index"] = event.index
    return finding


def normalize_all(events: list[ValidatedEvent]) -> list[dict[str, Any]]:
    return [normalize(e) for e in events]
