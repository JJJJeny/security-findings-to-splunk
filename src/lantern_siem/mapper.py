"""Map step: turn canonical findings into SIEM events using a mapping YAML.

All field decisions live in config/mappings/*.yaml; this module only
interprets the rules: source/target, constant, cast, on_missing, and the
transforms basename, severity_bucket, multivalue.

Output shape is a Splunk HEC event payload:
    {"time": <epoch>, "host": <dest>, "source", "sourcetype", "index",
     "event": {<mapped fields>}}
Fields go in "event" (search-time JSON extraction), not indexed "fields"
(BUILD_LOG B5).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

import yaml

SUPPORTED_TRANSFORMS = {"basename", "severity_bucket", "multivalue"}


def load_mapping(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        mapping = yaml.safe_load(fh)
    for key in ("mapping_version", "fields", "splunk", "event_time"):
        if key not in mapping:
            raise ValueError(f"{path}: mapping is missing '{key}'")
    for rule in mapping["fields"]:
        t = rule.get("transform")
        if t and t not in SUPPORTED_TRANSFORMS:
            raise ValueError(f"{path}: unsupported transform {t!r} for {rule.get('target')}")
        if "source" not in rule and "constant" not in rule:
            raise ValueError(f"{path}: rule for {rule.get('target')} needs source or constant")
    return mapping


def get_path(obj: dict[str, Any], dotted: str) -> Any:
    """Read a dotted path such as 'host.hostname'; return None if absent."""
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _basename(path: Any) -> Any:
    if not isinstance(path, str):
        return None
    return re.split(r"[\\/]", path)[-1]


def _severity_bucket(value: Any, buckets: list[dict[str, Any]]) -> Any:
    if not isinstance(value, (int, float)):
        return None
    for b in buckets:
        if b["min"] <= value <= b["max"]:
            return b["value"]
    return None


def _multivalue(items: Any, fmt: str) -> list[str]:
    if not isinstance(items, list):
        return []
    return [fmt.format(**item) for item in items if isinstance(item, dict)]


def _epoch(ts: Any) -> float | None:
    if not isinstance(ts, str):
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def apply_mapping(finding: dict[str, Any], mapping: dict[str, Any], run_id: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for rule in mapping["fields"]:
        target = rule["target"]
        if "constant" in rule:
            out[target] = rule["constant"]
            continue
        value = get_path(finding, rule["source"])
        t = rule.get("transform")
        if t == "basename":
            value = _basename(value)
        elif t == "severity_bucket":
            value = _severity_bucket(value, rule["buckets"])
        elif t == "multivalue":
            value = _multivalue(value, rule["format"])
        if rule.get("cast") == "int" and value is not None:
            value = int(value)
        if value in (None, "") and "on_missing" in rule:
            value = rule["on_missing"]["value"]
        out[target] = value

    # pipeline traceability fields (BUILD_LOG B3)
    out["lantern_run_id"] = run_id
    out["lantern_mapping_version"] = mapping["mapping_version"]
    out["lantern_dq_flags"] = finding.get("dq_flags", [])
    out["lantern_finding_key"] = finding.get("finding_key")

    # event time: the validate step already applied the fallback and flagged it
    et = mapping["event_time"]
    when = _epoch(get_path(finding, et["source"])) or _epoch(get_path(finding, et["fallback"]))

    sp = mapping["splunk"]
    return {
        "time": when,
        "host": out.get("dest"),
        "source": sp["source"],
        "sourcetype": sp["sourcetype"],
        "index": sp["index"],
        "event": out,
    }
