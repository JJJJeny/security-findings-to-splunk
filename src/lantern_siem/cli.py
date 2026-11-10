"""Command-line entry point.

Dry run (no Splunk needed):
    PYTHONPATH=src python -m lantern_siem.cli run \
        --input data/raw/events.json \
        --mapping config/mappings/splunk_cim_v1.yaml \
        --dry-run

Live run reads SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN from the environment or
from a .env file in the repo root.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, mapper, normalize, runlog, validate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lantern-siem",
        description="Validate, normalize, map and deliver Lantern findings to a SIEM.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run the pipeline once; writes runs/<run_id>/.")
    run.add_argument("--input", required=True, help="Path to Lantern events.json (read-only).")
    run.add_argument("--mapping", required=True, help="Path to a mapping YAML, e.g. splunk_cim_v1.yaml.")
    run.add_argument("--dq-rules", default="config/dq_rules.yaml", help="Path to data-quality rules YAML.")
    run.add_argument("--runs-dir", default="runs", help="Directory where run folders are written.")
    run.add_argument("--dry-run", action="store_true", help="Do everything except send to the SIEM.")
    run.add_argument("--env-file", default=".env", help="Optional KEY=VALUE file for HEC settings.")
    run.add_argument("--verify-tls", action="store_true", help="Verify Splunk's TLS certificate.")
    return parser


def load_env_file(path: str) -> None:
    """Minimal .env reader; real environment variables win."""
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        # strip straight and "smart" quotes (TextEdit can insert the latter)
        value = value.strip().strip('"').strip("'").strip("\u201c\u201d\u2018\u2019")
        if value and not os.environ.get(key.strip()):
            os.environ[key.strip()] = value


def run_pipeline(args: argparse.Namespace) -> int:
    started = datetime.now(timezone.utc).isoformat()
    rules = validate.load_rules(args.dq_rules)
    mapping = mapper.load_mapping(args.mapping)
    with open(args.input, encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, list):
        print("Input must be a JSON array of events.", file=sys.stderr)
        return 2

    hec_url = hec_token = ""
    if not args.dry_run:
        # Check settings BEFORE creating a run folder, so a misconfigured run
        # leaves nothing half-written behind (BUILD_LOG B12).
        load_env_file(args.env_file)
        hec_url = os.environ.get("SPLUNK_HEC_URL", "").strip()
        hec_token = os.environ.get("SPLUNK_HEC_TOKEN", "").strip()
        missing = [k for k, v in (("SPLUNK_HEC_URL", hec_url), ("SPLUNK_HEC_TOKEN", hec_token)) if not v]
        if missing:
            env_path = Path(args.env_file).resolve()
            where = f"{env_path} (found)" if env_path.is_file() else f"{env_path} (NOT FOUND)"
            print(f"Cannot send: {', '.join(missing)} not set.", file=sys.stderr)
            print(f"  Looked in the environment and in {where}.", file=sys.stderr)
            print("  Each line should look like KEY=value with no quotes; save the file as plain text.",
                  file=sys.stderr)
            print("  Nothing was sent and no run folder was created.", file=sys.stderr)
            return 2

    run = runlog.start_run(args.runs_dir, mapping["mapping_version"], args.input, args.dry_run)

    accepted, quarantined = validate.validate(raw, rules)
    for q in quarantined:
        runlog.append_jsonl(run, "quarantine.jsonl", {
            "input_index": q.index, "event_id": q.raw.get("event_id"),
            "reason_code": q.reason_code, "detail": q.detail, "raw": q.raw,
        })

    findings = normalize.normalize_all(accepted)
    events = [mapper.apply_mapping(f, mapping, run.run_id) for f in findings]

    failed_events: list[dict] = []
    delivery: dict = {"mode": "dry_run" if args.dry_run else "splunk_hec"}
    if args.dry_run:
        sent_events = events
    else:
        from .senders.splunk_hec import SplunkHECSender

        sender = SplunkHECSender(
            url=hec_url,
            token=hec_token,
            verify_tls=args.verify_tls,
        )
        result = sender.send(events)
        sent_events, failed_events = result.sent_events, result.failed_events
        delivery.update({"endpoint": sender.url, "errors": result.errors, "verify_tls": args.verify_tls})

    for ev in sent_events:
        runlog.append_jsonl(run, "sent.jsonl", ev)
    if failed_events:
        (run.path / "failed.jsonl").touch()
        for ev in failed_events:
            runlog.append_jsonl(run, "failed.jsonl", ev)

    flag_counts = Counter(flag for f in findings for flag in f["dq_flags"])
    severity_counts = Counter(e["event"].get("severity") for e in events)
    counts = {
        "input": len(raw),
        "sent": len(sent_events),
        "failed": len(failed_events),
        "quarantined": len(quarantined),
        "flagged_events": sum(1 for f in findings if f["dq_flags"]),
    }
    balanced = counts["input"] == counts["sent"] + counts["failed"] + counts["quarantined"]
    summary = {
        "run_id": run.run_id,
        "tool_version": __version__,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "input": {"path": args.input, "sha256": runlog.file_sha256(args.input)},
        "mapping_version": mapping["mapping_version"],
        "dq_rules_version": rules["version"],
        "counts": counts,
        "flag_counts": dict(sorted(flag_counts.items())),
        "quarantine_reasons": dict(Counter(q.reason_code for q in quarantined)),
        "severity_counts": {str(k): v for k, v in sorted(severity_counts.items(), key=lambda kv: str(kv[0]))},
        "delivery": delivery,
        "reconciliation": {
            "rule": "input == sent + failed + quarantined",
            "balanced": balanced,
        },
    }
    runlog.finish_run(run, summary)

    verb = "would send" if args.dry_run else "sent"
    print(f"run {run.run_id}")
    print(f"  {counts['input']} in: {counts['sent']} {verb}, {counts['quarantined']} quarantined, "
          f"{counts['failed']} failed, {counts['flagged_events']} flagged")
    print(f"  flags: {dict(sorted(flag_counts.items()))}")
    print(f"  reconciliation: {'OK' if balanced else 'MISMATCH'}")
    print(f"  output: {run.path}/")
    if delivery.get("errors"):
        for err in delivery["errors"]:
            print(f"  error: {err}", file=sys.stderr)
    return 0 if balanced and not failed_events else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        return run_pipeline(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
