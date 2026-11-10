# events.json

Lantern's native event format. A flat array of event objects, as produced by
the export API.

```json
{
  "event_id": "evt-00001",
  "event_type": "indicator_match",
  "timestamp": "2026-06-15T04:18:11Z",
  "severity": 88,
  "collection": {
    "collection_id": "col-00417",
    "job_name": "Weekly scan - all hosts",
    "requested_by": "automation-bot",
    "completed_at": "2026-06-15T05:04:11Z"
  },
  "host": {
    "host_id": "044b4a10a177",
    "hostname": "srv-lin-01.corp.example",
    "os": "LINUX",
    "ip": "10.40.1.10",
    "agent_version": "1.4"
  },
  "rule": {
    "name": "Webshell_PHP_Generic",
    "namespace": "webshell",
    "version": 2,
    "author": "content-team"
  },
  "file": {
    "path": "/var/www/html/uploads/6f3b1c9d02.php",
    "size": 8452,
    "sha256": "...",
    "mtime": "2026-06-11T22:07:19Z",
    "owner": "www-data"
  },
  "matched_patterns": [
    {"pattern_id": "p1", "offset": 4096},
    {"pattern_id": "p2", "offset": 20488}
  ],
  "disposition": {
    "status": "MALICIOUS",
    "analyst": "nvirtanen",
    "comment": "confirmed, host isolated and reimaged",
    "updated_at": "2026-06-16T03:22:47Z"
  }
}
```


## Fields

| Field | Type | Notes |
|---|---|---|
| `event_id` | string | Lantern's identifier for this finding |
| `event_type` | string | `indicator_match` throughout this export |
| `timestamp` | string | ISO 8601, when the match was produced |
| `severity` | integer | 0 to 100, from the rule that matched |
| `collection` | object | the tasked job this finding came out of |
| `host` | object | the host the file was collected from |
| `rule` | object | the rule that matched, and its version at match time |
| `file` | object | the file that matched |
| `matched_patterns` | array | which rule patterns matched, and at what byte offset |
| `disposition` | object | the analyst decision, if one has been made |

`disposition.status` is one of `UNREVIEWED`, `BENIGN`, `MALICIOUS`, or
`SUPPRESSED`. `analyst`, `comment`, and `updated_at` are null while the
status is `UNREVIEWED`.

A disposition changes over the life of a finding. The rest of the event does
not.


## Notes on the export

One file matching several rules produces one event per rule. Events from the
same collection share a `collection_id` and a `completed_at`.

For any event, `file.mtime` precedes `timestamp`, which is at or before
`collection.completed_at`. A file cannot be matched before it exists, and a
collection is not complete until its matches are in.

This export is a snapshot taken from a live system and has not been cleaned.
