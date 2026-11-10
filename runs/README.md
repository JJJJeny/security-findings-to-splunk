# Runs

One folder per pipeline run: `runs/<run_id>/`

| File | Contents |
|---|---|
| `summary.json` | run_id, mapping_version, input path and SHA-256, dry_run, counts (input / sent / quarantined), data-quality flag counts, quarantine reason counts, reconciliation check |
| `quarantine.jsonl` | one line per quarantined event, with reason code and the untouched raw event |
| `sent.jsonl` | one line per event sent to the SIEM (or that would be sent, in `--dry-run`) |

Reconciliation: `input == sent + quarantined`. Run folders are tracked in git so results are traceable.
