# Splunk search exports

CSV exports of each check, run in Splunk Web (Search & Reporting, time range **All time**) against the Splunk Cloud trial after live run `20261108T220258Z-50b362`. These are the Splunk-side evidence that what the pipeline sent actually arrived and that the searches work. They're compared against `runs/20261108T220258Z-50b362/sent.jsonl`.

| File | Search | Expected on this export |
|---|---|---|
| `00-all-events.csv` | `index=lantern sourcetype="lantern:finding"` (all events, raw) | 199 events, each with eventtype `lantern_malware_finding` and tags `attack`, `malware` |
| `01-unreviewed-high-severity.csv` | `splunk/searches/01_unreviewed_high_severity.spl` | 25 rows |
| `02-current-disposition.csv` | `splunk/searches/02_current_disposition_per_finding.spl` | 199 rows |
| `03-hash-on-many-hosts.csv` | `splunk/searches/03_hash_seen_on_many_hosts.spl` | 1 row: `wldp.dll` on 9 hosts |

How to export: run the search, click the download arrow above the results, choose CSV. Splunk saves to the browser's Downloads folder; move the file here.

## Verification (2026-11-08)

Each export was compared with `runs/20261108T220258Z-50b362/sent.jsonl`:

| File | Result |
|---|---|
| `00-all-events.csv` | 199 events; the 199 finding keys are exactly the ones sent; all in index `lantern`, sourcetype `lantern:finding`; every event has eventtype `lantern_malware_finding` and tags `attack`, `malware` |
| `01-unreviewed-high-severity.csv` | 25 rows, exactly the set of unreviewed high/critical findings sent |
| `02-current-disposition.csv` | 199 rows; finding keys match, and every disposition status matches what was sent |
| `03-hash-on-many-hosts.csv` | 1 row: `wldp.dll` (`dc7f6660…f144`) on 9 hosts, the same 9 hosts as in the sent data |

Housekeeping: the count and tag-check exports were the same raw-event export (byte-identical), so they're kept as one file, `00-all-events.csv`, which proves both checks. The 02 and 03 exports had each other's names and were swapped back.
