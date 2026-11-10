# Build log

What was built, the implementation choices made along the way, and anything
critical still open. Product decisions are summarized in the [README](../README.md#key-decisions);
entries here are **B**uild choices and **O**pen items. Code comments cite
these IDs.

---

## 2026-11-08 · Pipeline v0.1 (dry run working)

**Built:** validate → normalize → map → run log, the Splunk HEC sender, and the
CLI that ties them together. 28 tests. Splunk itself is not running yet, so
delivery is unit-tested only (see O1).

**Verified result on the provided export** (`data/raw/events.json`, sha256
`c1a83face6d05f5cc7c8189ab315207acbe90656e2a84e6b9d2993f1f6b7e6f7`):

| | Count |
|---|---|
| Input | 200 |
| Would send | 199 |
| Quarantined | 1 (`evt-00018`, missing_host) |
| Flagged (sent with flags) | 34 |
| Reconciliation | balanced: 200 = 199 + 0 failed + 1 |

Flags: `hash_size_conflict` 25, `duplicate_id` 4, and one each of
`rule_name_missing`, `timestamp_estimated`, `size_type_coerced`,
`unknown_status`, `no_patterns`. `order_violation` fired 0 times. No event
carries more than one flag.

Severity after mapping: critical 49, high 75, medium 50, low 25. Profiling
the raw export gives critical 50; the difference is `evt-00018` (severity
94), which is quarantined and therefore not mapped.

The raw input file was byte-compared with the original after the run:
unchanged.

---

## Build choices

**B1 · Rules: checks in code, behaviour in config.**
Each rule's *check* is a Python function keyed by rule id. `dq_rules.yaml`
decides which rules exist and what they do (flag / fix_and_flag /
quarantine, flag name, reason code). The `check:` strings in the YAML are
documentation, not an executed language. Validation fails loudly if the
YAML lists a rule with no implemented check, so config and code can't
drift silently.
*Why:* a mini rule language would be over-built for a prototype.
*Trade-off:* a new kind of check needs a code change.

**B2 · Composite finding key.**
`lantern_finding_key = event_id|host_id|collection_id`, added in normalize
and sent on every event. In the export, 199 sent events have only 197
unique `event_id`s but 199 unique finding keys. The disposition search
(`splunk/searches/02`) dedups on this key. See README, Key decisions #3.
*Revisit:* when Lantern engineering fixes the duplicate IDs upstream.

**B3 · Traceability fields on every event.**
`lantern_run_id`, `lantern_mapping_version`, `lantern_dq_flags`,
`lantern_finding_key`. Every run writes `runs/<run_id>/` with
`summary.json` (input sha256, rule and mapping versions, all counts),
`quarantine.jsonl` (reason, detail, input position, full raw event) and
`sent.jsonl`. Dry runs end in `-dry`. A failed live batch also writes
`failed.jsonl`.

**B4 · Cross-event rules look at the whole input, including quarantined events.**
`duplicate_id` and `hash_size_conflict` are evaluated over all 200 events
before quarantine. Today this changes nothing (evt-00018 is in neither
group), but it means a conflict is detected even if one side is later held
back. Identical repeats of an event are not flagged as `duplicate_id`;
there are none in this export.

**B5 · Fields go in the HEC `event` body, not indexed `fields`.**
Splunk extracts JSON fields at search time, which is enough for a
prototype and keeps everything visible in the raw event. Indexed fields
would make high-volume searches faster.
*Revisit:* when volume grows or the customer's ES correlation searches
need it.

**B6 · Event time.**
HEC `time` = finding `timestamp` as epoch seconds. For `evt-00035` (null
timestamp) it uses `collection.completed_at` and flags
`timestamp_estimated`. HEC `host` = mapped `dest`.

**B7 · TLS verification off by default.**
Local Docker Splunk serves a self-signed certificate. `--verify-tls` turns
it on. This must be on for any real deployment. Called out in the README.

**B8 · Expected counts are locked in a test.**
`test_real_export_expected_counts` fails if a code or config change shifts
the 200 / 199 / 1 / 34 result, so a change can't alter the demo numbers
unnoticed.

**B9 · Sender behaviour.**
Batches of 100 events, newline-separated JSON, to `/services/collector/event`
with `Authorization: Splunk <token>`. Up to 3 retries with backoff (1s, 2s, 4s)
on 5xx and connection errors. No retry on 4xx, since a bad token or index
won't fix itself; those are counted as failed and logged. Exit code is 1 if
anything failed or reconciliation doesn't balance.

**B10 · `.env` reader.**
A minimal built-in reader, so no extra dependency. Real environment
variables take precedence over `.env`.

**B11 · `platform: linux/amd64` in docker-compose.**
The official `splunk/splunk` image has no ARM build, so on an Apple Silicon
Mac it must run under x86 emulation, and Docker needs the platform named
explicitly. Source: a Splunk Community thread
(<https://community.splunk.com/t5/Splunk-Enterprise/Splunk-Web-on-Docker-fails-to-start-using-an-M1-Mac-on-Monterey/m-p/581178>).
In that thread Splunk Web sometimes failed to start under emulation, with no
confirmed fix, so see O8.

---

## Open items

| ID | Item | How it closes |
|---|---|---|
| ~~**O1**~~ | ~~Sender never run against a live Splunk.~~ | **Closed 2026-11-08:** live run `20261108T220258Z-50b362` sent 199 events to the Splunk Cloud trial, 0 failed. |
| **O2** | Unverified: does HEC come up enabled from `SPLUNK_HEC_TOKEN` alone, is port 8088 reachable, is the `lantern` index auto-created? | Check on first start; record results here. |
| ~~**O3**~~ | ~~Saved searches not yet run against real data.~~ | **Closed 2026-11-08:** all three saved searches run in Splunk Cloud and exported to `evidence/splunk-exports/`; results match the sent data row for row (01: 25, 02: 199, 03: wldp.dll on 9 hosts). |
| **O4** | CIM alignment and the disposition-change design rest on assumptions about the customer; not yet confirmed with the customer. | Revisit the mapping if the answers change them. |
| **O5** | Severity thresholds are proposed, not validated. wldp.dll findings (all MALICIOUS) land in "medium" at severity 63. | Raise in README and video as a question for the content team. |
| **O6** | Re-sending a finding after a disposition change works via the new-event-per-change design, but the pipeline has no "only send changes since last run" checkpoint yet. | Listed under "Next" in the README (scheduled pull with checkpoint). |
| ~~**O7**~~ | ~~CIM compliance is incomplete: the Malware data model requires the tags `malware` and `attack`, which nothing sets yet. In Splunk these come from an eventtype plus `tags.conf`, not from the event body. Until then, field names match CIM but the data won't appear in the Malware data model or ES.~~ | **Closed 2026-11-08:** event type `lantern_malware_finding` (`index=lantern sourcetype="lantern:finding"`) tagged `malware`, `attack` created in Splunk Web; all 199 events carry both tags (`evidence/splunk-exports/00-all-events.csv`). Full CIM data model acceleration and the `datamodel` check were not run. |
| **O8** | Splunk under x86 emulation on Apple Silicon is a known risk: Splunk Web may not come up. | Turn on Rosetta emulation in Docker (Docker Desktop setting, or Colima with `--vz-rosetta`) and try once. If Splunk Web isn't up within ~20 minutes, switch to the Splunk Cloud trial (planned fallback). Record the outcome here. | **2026-11-08 result: failed.** Image `splunk/splunk:latest` resolved to Splunk 10.6.1.1 linux-amd64. On Jenny's Apple Silicon Mac with Rosetta, prerequisite checks passed, then `splunkd` exited while waiting for Splunk Web (`splunkd ... was not running`; `WARNING: web interface does not seem to be available!`). The Ansible task `Start Splunk via CLI` failed after 5 attempts (~6 min); total ~7.5 min. **Decision: stop debugging emulation, switch to the Splunk Cloud trial (planned fallback).** |

---

## 2026-11-08 · Local Splunk failed on Apple Silicon → Splunk Cloud trial

Local Docker Splunk did not start under x86 emulation (O8). Rather than spend
more time on an environment issue unrelated to the integration itself, the
prototype moves to the Splunk Cloud 14-day trial, the fallback planned from the
start. The pipeline code is unchanged; only `SPLUNK_HEC_URL` and the
token change. (It later turned out the trial's HEC certificate is
self-signed, so TLS verification stays off; see the next entry.) `splunk/docker-compose.yml` stays in
the repo for anyone on an Intel Mac or Linux.

---

## 2026-11-08 · First live attempt against Splunk Cloud trial

- **HEC endpoint:** `https://prd-p-amlnj.splunkcloud.com:8088/services/collector/event`.
  Splunk's docs describe the `http-inputs-` host for paid stacks; for trials,
  community posts report the stack host on port 8088 instead. The host and
  port answered.
- **TLS:** `curl` to `/services/collector/health` failed with *self signed
  certificate in certificate chain*. On the trial the HEC certificate is not
  publicly trusted, so the prototype runs with TLS verification off (B7).
  For production, use a trusted certificate and `--verify-tls`.
- **Python:** the test Mac runs Python 3.9 (Command Line Tools). The dry run
  worked on 3.9, so the README requirement is lowered from 3.11 to 3.9.
- **Dry run on the test Mac:** same result as here: 200 in, 199 would send,
  1 quarantined, 34 flagged, reconciliation OK.
- **Live run failed before sending.** `SPLUNK_HEC_URL`/`SPLUNK_HEC_TOKEN`
  were not read from `.env`. The cause is still being checked; likely the file
  wasn't saved as plain text with the values. Nothing was sent.

**B12 · Fail before starting a run when settings are missing.**
The first live attempt raised a traceback *after* creating a run folder,
leaving one with no `summary.json`. Settings are now checked first, with a
plain error saying which variable is missing and where it looked, and no run
folder is created. The `.env` reader also strips "smart" quotes, which
TextEdit can insert. Two tests cover this.

---

## 2026-11-08 · First live send to Splunk Cloud trial

- Run ID: `20261108T220258Z-50b362` (folder `runs/20261108T220258Z-50b362/`)
- Result: 200 in, 199 sent, 1 quarantined, 0 failed, 34 flagged; reconciliation OK
- Endpoint: `https://prd-p-amlnj.splunkcloud.com:8088/services/collector/event`, TLS verification off (trial certificate is self-signed; see B7)
- Splunk-side count: 199, confirmed from Splunk export (`evidence/splunk-exports/00-all-events.csv`)
- Closes: O1 (sender run against a live Splunk). Still open: O2 index/HEC details are confirmed for Cloud trial only; O3 saved searches; O7 CIM tags.
- Python on this Mac uses LibreSSL; urllib3 printed a warning about it during the live run. Delivery still completed with the expected counts. Not a blocker for the prototype.

**B13 · Saved search 01 grouped by finding key.**
`01_unreviewed_high_severity.spl` grouped by `lantern_event_id`, which would
merge the two different findings that share an ID. It now groups by
`lantern_finding_key`, like search 02. Expected results on this export:
01 = 25 findings, 02 = 199 findings, 03 = 1 hash (wldp.dll on 9 hosts).

