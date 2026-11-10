"""Validate step: apply data-quality rules from config/dq_rules.yaml.

Never mutates the raw input. Returns accepted events (with flags and any
fixes recorded separately) and quarantined events with reason codes.

How rules are wired (BUILD_LOG B1): each rule's *check* is implemented in
code, keyed by the rule id. The YAML decides whether a rule is active and
what happens when it fires (action, flag name, reason code). So changing
"flag" to "quarantine" for a rule is a config change; adding a brand-new
kind of check is a code change.
"""

from __future__ import annotations

import copy
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

import yaml

VALID_STATUSES = {"UNREVIEWED", "BENIGN", "MALICIOUS", "SUPPRESSED"}


@dataclass
class ValidatedEvent:
    raw: dict[str, Any]
    flags: list[str] = field(default_factory=list)
    fixes: dict[str, Any] = field(default_factory=dict)  # dotted path -> repaired value
    index: int = 0  # position in the input file, for traceability


@dataclass
class QuarantinedEvent:
    raw: dict[str, Any]
    reason_code: str
    detail: str = ""
    index: int = 0


def load_rules(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        rules = yaml.safe_load(fh)
    if "version" not in rules or "rules" not in rules:
        raise ValueError(f"{path}: dq rules need 'version' and 'rules'")
    return rules


def _get(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# --- per-event checks: return None if OK, else (fix_path, fix_value, detail) ---

def _missing_host(ev: dict[str, Any]) -> str | None:
    host = ev.get("host")
    if not isinstance(host, dict):
        return "host object missing"
    if not host.get("host_id") or not host.get("hostname"):
        return "host.host_id or host.hostname missing"
    return None


def _rule_name_missing(ev: dict[str, Any]) -> str | None:
    return None if _get(ev, "rule.name") else "rule.name missing"


def _timestamp_estimated(ev: dict[str, Any]) -> tuple[str, Any] | None:
    if ev.get("timestamp") is None:
        return ("timestamp", _get(ev, "collection.completed_at"))
    return None


def _size_type_coerced(ev: dict[str, Any]) -> tuple[str, Any] | None:
    size = _get(ev, "file.size")
    if isinstance(size, bool) or isinstance(size, int):
        return None
    try:
        return ("file.size", int(str(size).strip()))
    except (TypeError, ValueError):
        return ("file.size", None)


def _unknown_status(ev: dict[str, Any]) -> str | None:
    status = _get(ev, "disposition.status")
    return None if status in VALID_STATUSES else f"status={status!r}"


def _no_patterns(ev: dict[str, Any]) -> str | None:
    return None if ev.get("matched_patterns") else "matched_patterns empty"


def _order_violation(ev: dict[str, Any]) -> str | None:
    mtime = _parse_ts(_get(ev, "file.mtime"))
    ts = _parse_ts(ev.get("timestamp"))
    done = _parse_ts(_get(ev, "collection.completed_at"))
    if mtime is None or ts is None or done is None:
        return None  # can't evaluate; null timestamp is handled by its own rule
    return None if mtime <= ts <= done else "file.mtime <= timestamp <= completed_at broken"


FLAG_CHECKS: dict[str, Callable[[dict[str, Any]], str | None]] = {
    "rule_name_missing": _rule_name_missing,
    "unknown_status": _unknown_status,
    "no_patterns": _no_patterns,
    "order_violation": _order_violation,
}
FIX_CHECKS: dict[str, Callable[[dict[str, Any]], tuple[str, Any] | None]] = {
    "timestamp_estimated": _timestamp_estimated,
    "size_type_coerced": _size_type_coerced,
}
QUARANTINE_CHECKS: dict[str, Callable[[dict[str, Any]], str | None]] = {
    "missing_host": _missing_host,
}
CROSS_EVENT_RULES = {"duplicate_id", "hash_size_conflict"}


def _cross_event_flags(events: list[dict[str, Any]], active: set[str]) -> dict[int, list[str]]:
    """Rules that need the whole file. Evaluated over ALL input events (BUILD_LOG B4)."""
    out: dict[int, list[str]] = defaultdict(list)

    if "duplicate_id" in active:
        by_id: dict[Any, list[int]] = defaultdict(list)
        for i, ev in enumerate(events):
            by_id[ev.get("event_id")].append(i)
        for idxs in by_id.values():
            if len(idxs) > 1:
                bodies = {json.dumps(events[i], sort_keys=True) for i in idxs}
                if len(bodies) > 1:  # identical repeats are not this rule's concern
                    for i in idxs:
                        out[i].append("duplicate_id")

    if "hash_size_conflict" in active:
        sizes: dict[Any, set[Any]] = defaultdict(set)
        members: dict[Any, list[int]] = defaultdict(list)
        for i, ev in enumerate(events):
            h = _get(ev, "file.sha256")
            if not h:
                continue
            raw_size = _get(ev, "file.size")
            try:
                size = int(raw_size)
            except (TypeError, ValueError):
                size = raw_size
            sizes[h].add(size)
            members[h].append(i)
        for h, s in sizes.items():
            if len(s) > 1:
                for i in members[h]:
                    out[i].append("hash_size_conflict")
    return out


def validate(
    events: list[dict[str, Any]], rules: dict[str, Any]
) -> tuple[list[ValidatedEvent], list[QuarantinedEvent]]:
    """Apply per-event and cross-event rules. Host identity is host.host_id, not IP."""
    by_id = {r["id"]: r for r in rules["rules"]}
    unknown = set(by_id) - set(FLAG_CHECKS) - set(FIX_CHECKS) - set(QUARANTINE_CHECKS) - CROSS_EVENT_RULES
    if unknown:
        raise ValueError(f"dq rules with no implemented check: {sorted(unknown)}")

    cross = _cross_event_flags(events, set(by_id))
    accepted: list[ValidatedEvent] = []
    quarantined: list[QuarantinedEvent] = []

    for i, original in enumerate(events):
        ev = copy.deepcopy(original)  # raw input is never touched

        # 1. quarantine rules first: an event we can't attribute is not sent at all
        q_hit = None
        for rid, check in QUARANTINE_CHECKS.items():
            rule = by_id.get(rid)
            if rule and rule["action"] == "quarantine":
                detail = check(ev)
                if detail:
                    q_hit = (rule["reason_code"], detail)
                    break
        if q_hit:
            quarantined.append(QuarantinedEvent(raw=ev, reason_code=q_hit[0], detail=q_hit[1], index=i))
            continue

        v = ValidatedEvent(raw=ev, index=i)
        for rid, check in FIX_CHECKS.items():
            rule = by_id.get(rid)
            if rule:
                hit = check(ev)
                if hit:
                    v.fixes[hit[0]] = hit[1]
                    v.flags.append(rule["flag"])
        for rid, check in FLAG_CHECKS.items():
            rule = by_id.get(rid)
            if rule and check(ev):
                v.flags.append(rule["flag"])
        for rid in cross.get(i, []):
            v.flags.append(by_id[rid]["flag"])
        accepted.append(v)

    return accepted, quarantined
