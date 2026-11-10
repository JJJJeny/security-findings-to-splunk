# Lantern → Splunk integration prototype

A working prototype that sends findings from Lantern, a fictional forensic collection product, into Splunk, so security analysts can triage them where they already work.

**Walkthrough video (4 min):** https://youtu.be/amAz2nue2Nk

## Overview

Lantern's users are security analysts who work in their SIEM. A major customer runs Splunk and wants Lantern findings to show up there, so they can triage them alongside everything else. This prototype takes Lantern's export (`events.json`, 200 findings), checks it for data problems, maps each finding to Splunk's Common Information Model (CIM) Malware data model, and sends it to Splunk over the HTTP Event Collector (HEC). Three saved searches then answer the questions an analyst actually asks: what to look at first, what was decided, and how far a threat has spread.

**Status:** working end to end against a Splunk Cloud trial. Live run `runs/20261108T220258Z-50b362/`: 200 in, **199 sent, 1 quarantined, 34 flagged**, reconciliation balanced. In Splunk, all 199 events arrived, every one carries the CIM tags `malware` and `attack`, and the three analyst searches return exactly what was sent. Evidence: [`evidence/splunk-exports/`](evidence/splunk-exports/).

## Architecture

```
data/raw/events.json  (never modified)
        │
        ▼
  validate  ──► quarantine (reason codes)  ──► runs/<run_id>/quarantine.jsonl
        │
        ▼
  normalize   canonical finding, SIEM-agnostic
        │
        ▼
  map         per-SIEM config (config/mappings/splunk_cim_v1.yaml)
        │
        ▼
  deliver     per-SIEM sender (Splunk HEC)  ──► runs/<run_id>/sent.jsonl
```

- **Validate** applies the rules in `config/dq_rules.yaml`. Each problem is fixed, flagged, or quarantined with a reason, so nothing reaches Splunk silently wrong.
- **Normalize** produces one canonical finding that knows nothing about any SIEM, and adds a stable `finding_key` (the export's `event_id` is not unique).
- **Map** reads a mapping file. All field decisions live in `config/mappings/splunk_cim_v1.yaml`, not in code.
- **Deliver** is a small per-SIEM sender. Splunk's sends batches to HEC with retries.

Supporting a second SIEM (for example Microsoft Sentinel or Elastic) means writing a new mapping file and a new sender. Validation, data-quality rules and run logging are reused unchanged.

## How to run

**Prerequisites:** Python 3.9+ and a Splunk instance. Verified on a **Splunk Cloud Platform trial**. A local Docker setup is included (`splunk/docker-compose.yml`) but did not start on an Apple Silicon Mac (see [Known limitations](#known-limitations)).

**1. Prepare Splunk** (Splunk Web)
- **Settings → Indexes → New Index:** name `lantern`, type Events. Set searchable retention to at least 365 days: the sample data is from June 2026, and a short retention would age it out immediately.
- **Settings → Data inputs → HTTP Event Collector → New Token:** allowed index and default index `lantern`. Copy the token value.
- **Settings → Event types → New Event Type:** name `lantern_malware_finding`, search `index=lantern sourcetype="lantern:finding"`, tags `malware, attack`. These tags are what put the events in CIM's Malware data model.

**2. Configure and install**
```
cp .env.example .env    # set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src python -m pytest -q tests      # 30 passed
```
For a Splunk Cloud trial, `SPLUNK_HEC_URL=https://<stack>.splunkcloud.com:8088`. Check it with `curl -sSk <SPLUNK_HEC_URL>/services/collector/health` (expect `HEC is healthy`).

**3. Run**
```
# dry run: everything except sending
PYTHONPATH=src python -m lantern_siem.cli run --input data/raw/events.json --mapping config/mappings/splunk_cim_v1.yaml --dry-run
# live run: same command without --dry-run
PYTHONPATH=src python -m lantern_siem.cli run --input data/raw/events.json --mapping config/mappings/splunk_cim_v1.yaml
```
Expected: `200 in: 199 sent, 1 quarantined, 0 failed, 34 flagged` and `reconciliation: OK`. Each run writes `runs/<run_id>/`. Run the live send once: running it again sends the same findings again.

TLS verification is off by default because the trial's HEC certificate is self-signed. Use `--verify-tls` with a trusted certificate.

**4. Search** (Search & Reporting, time range **All time**, since the data is from June 2026)

| Search (`splunk/searches/`) | Analyst question | Expected on this export |
|---|---|---|
| `index=lantern sourcetype="lantern:finding" \| stats count` | Did everything arrive? | 199 |
| `01_unreviewed_high_severity.spl` | What should I look at first? | 25 findings |
| `02_current_disposition_per_finding.spl` | What is the current decision on each finding? | 199 findings |
| `03_hash_seen_on_many_hosts.spl` | Is this file on one host or many? | 1 hash: `wldp.dll` on 9 hosts |

## Mapping

The full field-by-field mapping is in [`config/mappings/splunk_cim_v1.yaml`](config/mappings/splunk_cim_v1.yaml), annotated with each field's fit (clean / transform / loose / assumed / no_cim_home). Rationale for the main choices is under [Key decisions](#key-decisions).

Target fields and allowed values come from Splunk's CIM Malware data model, `Malware_Attacks` dataset ([CIM 6.0 – Malware](https://help.splunk.com/en/data-management/common-information-model/6.0/data-models/malware)). Fields prefixed `lantern_` are custom names for data CIM has no field for; they are not Splunk standards.

| Lantern field | Splunk field | Fit |
|---|---|---|
| `host.hostname` | `dest` | clean |
| `rule.name` | `signature` | clean (`unknown` if missing) |
| `file.path` | `file_path`, and `file_name` from its last segment | clean / transform |
| `file.sha256` | `file_hash` | clean |
| `severity` (0–100) | `severity` (critical / high / medium / low / informational), raw value kept as `severity_id` | transform |
| `rule.namespace` | `category` | loose |
| `file.owner` | `user` | loose |
| (constant) | `vendor_product="Lantern"`, `action="allowed"` | assumed |

Proposed severity buckets: 90–100 critical, 70–89 high, 40–69 medium, 1–39 low, 0 informational. On this export that gives critical 49, high 75, medium 50, low 25.

## Fields that could not be cleanly mapped

| Lantern field | Problem | What the prototype does |
|---|---|---|
| `disposition.*` (status, analyst, comment, updated_at) | CIM has no field for an analyst's verdict, and the verdict changes after the event is indexed | Custom `lantern_disposition_*` fields; a new event is sent when the verdict changes, and searches take the latest per finding |
| `matched_patterns[]` | Pattern IDs and byte offsets have no CIM equivalent | Multivalue `lantern_patterns`, e.g. `p1:4096` |
| `collection.*` | Forensic job context (job name, requester, completion time) has no CIM equivalent | `lantern_collection_*` |
| `host.host_id` | Stable host identity; CIM only has `dest` | `lantern_host_id`, used as the host key |
| `host.ip` | Not a Malware data model field (`dest_ip` doesn't exist there), and it changes for the same host even within one collection | `lantern_ip`; not used as identity |
| `rule.version`, `rule.author`, `file.mtime`, `file.size`, `host.os`, `host.agent_version` | No CIM field | `lantern_*` custom fields |
| `rule.namespace` → `category` | CIM's category examples are malware types (e.g. keylogger); Lantern's namespace (e.g. `webshell`, `techniques`) is close but not the same thing | Mapped, marked loose |
| `file.owner` → `user` | The file's owner is not necessarily the user involved in the event | Mapped, marked loose |
| `action` | Lantern detects; it doesn't block. CIM requires one of allowed / blocked / deferred | Set to `allowed` as an assumption |

## Data quality findings

On the provided export, 200 events in: **199 sent, 1 quarantined, 34 flagged**. Nothing is sent silently wrong: each issue is fixed, flagged (`lantern_dq_flags`), or quarantined with a reason. Rules are in `config/dq_rules.yaml`.

| Issue | Events | Handling |
|---|---|---|
| Same SHA-256, different file sizes (wldp.dll) | 25 | flag `hash_size_conflict` |
| Duplicate `event_id`, different findings | 4 (2 IDs) | flag `duplicate_id`; keyed on composite `lantern_finding_key` |
| No `host` object | 1 | quarantine `missing_host` |
| Rule has no name | 1 | flag `rule_name_missing`, `signature=unknown` |
| Null `timestamp` | 1 | use `collection.completed_at`, flag `timestamp_estimated` |
| `file.size` is a string | 1 | cast to int, flag `size_type_coerced` |
| Status `TRIAGED` not in schema | 1 | pass through, flag `unknown_status` |
| Empty `matched_patterns` | 1 | flag `no_patterns` |

The documented ordering `file.mtime ≤ timestamp ≤ collection.completed_at` held for every event that had a timestamp.

## Key decisions

Implementation choices, with the reason and revisit trigger for each, are in [`docs/BUILD_LOG.md`](docs/BUILD_LOG.md) (B1–B13).

1. **Align to CIM, keep Lantern's extra context.** Matching CIM lets existing Splunk content (and Enterprise Security, if the customer has it) use the data without custom searches. Lantern-only data stays in `lantern_*` fields instead of being dropped.
2. **Handle changing verdicts by sending a new event.** Splunk events can't be edited after indexing, but a Lantern verdict changes over time. Each change is a new event; searches take the latest per finding. This keeps history and needs no extra infrastructure. A KV Store lookup is the next step if volume grows.
3. **Key findings on a composite ID.** Two `event_id`s in the export each belong to two different findings. `lantern_finding_key` (event_id + host_id + collection_id) keeps them apart.
4. **Never send anything silently wrong.** Every data problem is fixed, flagged, or quarantined with a reason, and every run reconciles: input = sent + failed + quarantined.
5. **Mapping in config, not code.** A second SIEM is a new mapping file and sender, not a rewrite.

## Traceability

Every run writes `runs/<run_id>/`:

- `summary.json`: input path and SHA-256, mapping and rule versions, counts, flag and quarantine-reason counts, delivery result, reconciliation
- `quarantine.jsonl`: each held-back event with its reason and full raw content
- `sent.jsonl`: each event exactly as sent to Splunk (`failed.jsonl` if any batch failed)

Every event in Splunk carries `lantern_run_id`, `lantern_mapping_version`, `lantern_dq_flags` and `lantern_finding_key`, so any search result traces back to the run, the rules used and the original Lantern event. Reconciliation: `input = sent + failed + quarantined`, checked on every run and locked by a test. Implementation notes: [`docs/BUILD_LOG.md`](docs/BUILD_LOG.md).

## Next steps

| Now (this prototype) | Next (first customer) | Later (product) |
|---|---|---|
| File-based export, config-driven CIM mapping | Validate the mapping and searches with the customer's analysts | Package as a Splunk add-on (eventtypes, tags, field definitions); for Splunk Cloud this needs Splunk's app vetting |
| Data-quality rules with quarantine and flags | Pull from Lantern's export API on a schedule, sending only changes since the last run | Second SIEM via a new mapping file and sender; evaluate OCSF as the shared format |
| Reconciled, traceable runs | Trusted TLS, retries with a dead-letter queue | Near-real-time push instead of polling |
| Three analyst searches | Current verdicts via a KV Store lookup | Delivery health metrics and alerting |
| | Fix upstream data bugs with Lantern engineering: duplicate IDs, same hash with different sizes, changing IPs, `TRIAGED` status | |
| | Confirm severity thresholds with the content team | |

**How to measure it:** share of findings delivered without error; time from a Lantern match to the finding being searchable in Splunk; share of Lantern findings triaged inside Splunk.

## Assumptions

These are stated assumptions, to be confirmed with the customer:

- The customer uses (or may use) CIM-based content, so CIM alignment is worth it. If they only use plain Splunk searches, the custom fields alone would work.
- A one-time export of findings is acceptable for a first version; continuous sync is a next step.
- The integration should be a reusable product capability, not a one-off for this customer.
- Lantern detects but does not block (`action=allowed`).
- Severity thresholds are a proposal. All 25 `wldp.dll` findings are MALICIOUS but have severity 63, which lands in "medium". That is worth reviewing with the content team.
- Host identity is `host_id`, not hostname or IP.
- Event time is the finding's `timestamp`; for the one event without it, the collection's completion time is used and the event is flagged.

## Known limitations

- **Local Splunk on Apple Silicon:** the official image is Intel-only. Under emulation, Splunk's web server never came up, so the prototype moved to the Splunk Cloud trial (planned fallback). Details: BUILD_LOG O8.
- **TLS verification is off** against the trial, whose HEC certificate is self-signed.
- **Re-running a live send duplicates events.** There is no checkpoint yet (BUILD_LOG O6).
- **Fields are extracted at search time** from the JSON event body, not indexed. Fine at this volume; revisit for large customers.

## Use of AI tools

I used an AI assistant (Claude) for research and to help write and test the code. The product decisions, assumptions and trade-offs are mine, and I checked the results against the data and a live Splunk instance.

## References

Splunk documentation behind the mapping and the prototype.

| Source | Used for |
|---|---|
| [Splunk CIM 6.0 – Malware data model](https://help.splunk.com/en/data-management/common-information-model/6.0/data-models/malware) | Target fields (`dest`, `signature`, `category`, `file_*`, `user`, `vendor_product`), prescribed `action` and `severity` values, required tags `malware` and `attack`; `dest_ip` is not a field |
| [Splunk CIM – Malware (docs.splunk.com, latest)](https://docs.splunk.com/Documentation/CIM/latest/User/Malware) | Same data model, legacy docs site |
| [Overview of the Splunk Common Information Model](https://help.splunk.com/en/data-management/common-information-model) | What CIM is and how Enterprise Security uses it |
| [Use the CIM to normalize data at search time](https://help.splunk.com/en/splunk-enterprise-security-8/common-information-model/6.0/using-the-common-information-model/use-the-cim-to-normalize-data-at-search-time) | Event types, tags, aliases; packaging as an add-on (next steps) |
| [Set up and use HTTP Event Collector in Splunk Web](https://help.splunk.com/en/splunk-enterprise/get-data-in/collect-http-event-data/set-up-and-use-http-event-collector-in-splunk-web) | Enabling HEC, creating a token, port 8088 |
| [Format events for HTTP Event Collector](https://help.splunk.com/en/data-management/collect-http-event-data/use-hec-in-splunk-enterprise/format-events-for-http-event-collector) | `/services/collector/event` payload (`time`, `host`, `source`, `sourcetype`, `index`) and auth header |
| [splunk/splunk on Docker Hub](https://hub.docker.com/r/splunk/splunk) · [docker-splunk on GitHub](https://github.com/splunk/docker-splunk) | Required env vars, including `SPLUNK_GENERAL_TERMS` for 10.x images |
| [Create custom indexes](https://help.splunk.com/en/data-management/manage-splunk-enterprise-indexers/10.2/manage-indexes/create-custom-indexes) | Creating the `lantern` index |
| [stats](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/stats) · [dedup](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/dedup) | Latest disposition per finding in the saved searches |
| [Define a KV Store lookup](https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.2/use-lookups-in-splunk-web/define-a-kv-store-lookup-in-splunk-web) | Alternative disposition design (next steps) |
| [Licensing for Splunk Enterprise Security](https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.5/introduction/licensing-for-splunk-enterprise-security) | ES is a separately purchased premium app |
| [OCSF](https://ocsf.io/) | Candidate vendor-neutral format for multi-SIEM support (later) |
