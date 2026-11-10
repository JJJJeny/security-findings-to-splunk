"""Run log: every run writes its own folder for traceability.

runs/<run_id>/
    summary.json      run_id, mapping_version, dq_rules version, input path +
                      sha256, counts, flag counts, quarantine reason counts,
                      delivery result, reconciliation
    quarantine.jsonl  one line per quarantined event: reason_code, detail, input_index, raw
    sent.jsonl        one line per event sent (or that would be sent in --dry-run)

Reconciliation: input_count == sent_count + quarantined_count.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Run:
    run_id: str
    path: Path
    mapping_version: str
    dry_run: bool


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{secrets.token_hex(3)}"


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def start_run(runs_dir: str, mapping_version: str, input_path: str, dry_run: bool) -> Run:
    run_id = new_run_id() + ("-dry" if dry_run else "")
    path = Path(runs_dir) / run_id
    path.mkdir(parents=True, exist_ok=False)
    for name in ("quarantine.jsonl", "sent.jsonl"):
        (path / name).touch()
    return Run(run_id=run_id, path=path, mapping_version=mapping_version, dry_run=dry_run)


def append_jsonl(run: Run, filename: str, record: dict[str, Any]) -> None:
    with open(run.path / filename, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def finish_run(run: Run, summary: dict[str, Any]) -> Path:
    out = run.path / "summary.json"
    out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out
