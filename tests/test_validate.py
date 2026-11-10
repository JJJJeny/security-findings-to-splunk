"""Tests for the pipeline: one per data-quality rule, plus mapping and delivery.

Unit tests use small synthetic events so each rule is checked in isolation.
test_real_export_* runs the real data/raw/events.json end to end.
"""

import copy
import json
from pathlib import Path

import pytest

from lantern_siem import cli, mapper, normalize, validate
from lantern_siem.senders.splunk_hec import SplunkHECSender

ROOT = Path(__file__).resolve().parents[1]
RULES = validate.load_rules(str(ROOT / "config/dq_rules.yaml"))
MAPPING = mapper.load_mapping(str(ROOT / "config/mappings/splunk_cim_v1.yaml"))

BASE = {
    "event_id": "evt-1",
    "event_type": "indicator_match",
    "timestamp": "2026-06-15T04:18:11Z",
    "severity": 88,
    "collection": {"collection_id": "col-1", "job_name": "j", "requested_by": "bot",
                   "completed_at": "2026-06-15T05:04:11Z"},
    "host": {"host_id": "h1", "hostname": "srv-1.corp.example", "os": "LINUX",
             "ip": "10.0.0.1", "agent_version": "1.4"},
    "rule": {"name": "Webshell_PHP_Generic", "namespace": "webshell", "version": 2, "author": "content-team"},
    "file": {"path": "/var/www/a.php", "size": 100, "sha256": "aa", "mtime": "2026-06-11T22:07:19Z",
             "owner": "www-data"},
    "matched_patterns": [{"pattern_id": "p1", "offset": 4096}],
    "disposition": {"status": "UNREVIEWED", "analyst": None, "comment": None, "updated_at": None},
}


def ev(**changes):
    e = copy.deepcopy(BASE)
    for path, value in changes.items():
        cur = e
        parts = path.split("__")
        for p in parts[:-1]:
            cur = cur[p]
        cur[parts[-1]] = value
    return e


def run(events):
    accepted, quarantined = validate.validate(events, RULES)
    return accepted, quarantined


def flags_of(events):
    accepted, _ = run(events)
    return [a.flags for a in accepted]


def test_clean_event_has_no_flags():
    assert flags_of([ev()]) == [[]]


def test_duplicate_id_different_content_is_flagged():
    a, b = ev(), ev(severity=10, file__sha256="bb")
    assert flags_of([a, b]) == [["duplicate_id"], ["duplicate_id"]]


def test_identical_duplicate_is_not_flagged_as_conflict():
    assert flags_of([ev(), ev()]) == [[], []]


def test_missing_host_is_quarantined():
    e = ev()
    del e["host"]
    accepted, quarantined = run([e])
    assert accepted == [] and quarantined[0].reason_code == "missing_host"


def test_missing_rule_name_is_flagged_and_signature_unknown():
    e = ev()
    del e["rule"]["name"]
    accepted, _ = run([e])
    assert accepted[0].flags == ["rule_name_missing"]
    out = mapper.apply_mapping(normalize.normalize(accepted[0]), MAPPING, "r")
    assert out["event"]["signature"] == "unknown"


def test_null_timestamp_uses_completed_at_and_is_flagged():
    accepted, _ = run([ev(timestamp=None)])
    assert accepted[0].flags == ["timestamp_estimated"]
    finding = normalize.normalize(accepted[0])
    assert finding["timestamp"] == "2026-06-15T05:04:11Z"


def test_non_int_size_is_cast_and_flagged():
    accepted, _ = run([ev(file__size="8452")])
    assert accepted[0].flags == ["size_type_coerced"]
    out = mapper.apply_mapping(normalize.normalize(accepted[0]), MAPPING, "r")
    assert out["event"]["lantern_file_size"] == 8452


def test_unknown_status_is_flagged_and_passed_through():
    accepted, _ = run([ev(disposition__status="TRIAGED")])
    assert accepted[0].flags == ["unknown_status"]
    out = mapper.apply_mapping(normalize.normalize(accepted[0]), MAPPING, "r")
    assert out["event"]["lantern_disposition_status"] == "TRIAGED"


def test_empty_matched_patterns_is_flagged():
    assert flags_of([ev(matched_patterns=[])]) == [["no_patterns"]]


def test_same_hash_different_size_is_flagged():
    a = ev(event_id="e1", file__sha256="same", file__size=1)
    b = ev(event_id="e2", file__sha256="same", file__size=2)
    assert flags_of([a, b]) == [["hash_size_conflict"], ["hash_size_conflict"]]


def test_order_violation_is_flagged():
    assert flags_of([ev(file__mtime="2026-06-20T00:00:00Z")]) == [["order_violation"]]


def test_host_identity_uses_host_id_not_ip():
    a = ev(event_id="e1", host__ip="10.0.0.1")
    b = ev(event_id="e2", host__ip="10.0.0.99")
    findings = normalize.normalize_all(run([a, b])[0])
    assert {f["finding_key"].split("|")[1] for f in findings} == {"h1"}


def test_raw_input_is_never_mutated():
    e = ev(timestamp=None, file__size="5")
    before = json.dumps(e, sort_keys=True)
    normalize.normalize_all(run([e])[0])
    assert json.dumps(e, sort_keys=True) == before


def test_mapping_cim_fields_and_transforms():
    out = mapper.apply_mapping(normalize.normalize(run([ev(file__path="C:\\Windows\\System32\\wldp.dll")])[0][0]),
                               MAPPING, "run-1")
    e = out["event"]
    assert e["file_name"] == "wldp.dll"
    assert e["severity"] == "high" and e["severity_id"] == 88
    assert e["dest"] == "srv-1.corp.example" and out["host"] == "srv-1.corp.example"
    assert e["lantern_patterns"] == ["p1:4096"]
    assert e["lantern_run_id"] == "run-1" and e["lantern_mapping_version"] == "splunk_cim_v1"
    assert out["sourcetype"] == "lantern:finding" and out["index"] == "lantern"


@pytest.mark.parametrize("value,bucket", [(0, "informational"), (1, "low"), (39, "low"), (40, "medium"),
                                          (69, "medium"), (70, "high"), (89, "high"), (90, "critical"),
                                          (100, "critical")])
def test_severity_bucket_boundaries(value, bucket):
    out = mapper.apply_mapping(normalize.normalize(run([ev(severity=value)])[0][0]), MAPPING, "r")
    assert out["event"]["severity"] == bucket


def test_reconciliation_input_equals_sent_plus_quarantined(tmp_path):
    rc = cli.main(["run", "--input", str(ROOT / "data/raw/events.json"),
                   "--mapping", str(ROOT / "config/mappings/splunk_cim_v1.yaml"),
                   "--dq-rules", str(ROOT / "config/dq_rules.yaml"),
                   "--runs-dir", str(tmp_path), "--dry-run"])
    assert rc == 0
    summary = json.loads(next(tmp_path.glob("*/summary.json")).read_text())
    c = summary["counts"]
    assert c["input"] == c["sent"] + c["failed"] + c["quarantined"]
    assert summary["reconciliation"]["balanced"] is True


def test_real_export_expected_counts(tmp_path):
    """Locks in the verified result for the provided export (BUILD_LOG B8)."""
    cli.main(["run", "--input", str(ROOT / "data/raw/events.json"),
              "--mapping", str(ROOT / "config/mappings/splunk_cim_v1.yaml"),
              "--dq-rules", str(ROOT / "config/dq_rules.yaml"),
              "--runs-dir", str(tmp_path), "--dry-run"])
    s = json.loads(next(tmp_path.glob("*/summary.json")).read_text())
    assert s["counts"] == {"input": 200, "sent": 199, "failed": 0, "quarantined": 1, "flagged_events": 34}
    assert s["flag_counts"] == {"duplicate_id": 4, "hash_size_conflict": 25, "no_patterns": 1,
                                "rule_name_missing": 1, "size_type_coerced": 1,
                                "timestamp_estimated": 1, "unknown_status": 1}
    sent = [json.loads(line) for line in next(tmp_path.glob("*/sent.jsonl")).open()]
    keys = [e["event"]["lantern_finding_key"] for e in sent]
    assert len(set(keys)) == len(keys)  # composite key is unique even though event_id is not


# --- sender, with a fake HTTP layer (no live Splunk) -------------------------

class FakeResp:
    def __init__(self, code, text="ok"):
        self.status_code, self.text = code, text


def make_sender(responses, batch_size=2):
    calls = []

    def post(url, data, headers, verify, timeout):
        calls.append({"url": url, "data": data, "headers": headers})
        r = responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    s = SplunkHECSender("https://localhost:8088", "tok", batch_size=batch_size, max_retries=2,
                        post=post, sleep=lambda _: None)
    return s, calls


def test_sender_batches_and_auth_header():
    s, calls = make_sender([FakeResp(200), FakeResp(200)])
    res = s.send([{"event": i} for i in range(3)])
    assert res.sent == 3 and res.failed == 0 and len(calls) == 2
    assert calls[0]["url"] == "https://localhost:8088/services/collector/event"
    assert calls[0]["headers"]["Authorization"] == "Splunk tok"
    assert calls[0]["data"].decode().count("\n") == 1  # two events, newline-separated


def test_sender_retries_on_5xx_then_succeeds():
    s, calls = make_sender([FakeResp(503), ConnectionError("down"), FakeResp(200)])
    res = s.send([{"event": 1}])
    assert res.sent == 1 and len(calls) == 3


def test_sender_does_not_retry_on_4xx():
    s, calls = make_sender([FakeResp(403, "Invalid token")])
    res = s.send([{"event": 1}])
    assert res.failed == 1 and len(calls) == 1 and "403" in res.errors[0]


def test_live_run_without_settings_fails_cleanly(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)
    rc = cli.main(["run", "--input", str(ROOT / "data/raw/events.json"),
                   "--mapping", str(ROOT / "config/mappings/splunk_cim_v1.yaml"),
                   "--dq-rules", str(ROOT / "config/dq_rules.yaml"),
                   "--runs-dir", str(tmp_path / "runs"), "--env-file", str(tmp_path / "missing.env")])
    assert rc == 2
    assert not (tmp_path / "runs").exists()  # no half-written run folder
    assert "SPLUNK_HEC_URL" in capsys.readouterr().err


def test_env_file_strips_smart_quotes(tmp_path, monkeypatch):
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    env = tmp_path / ".env"
    env.write_text("SPLUNK_HEC_URL=\u201chttps://example:8088\u201d\n", encoding="utf-8")
    cli.load_env_file(str(env))
    import os
    assert os.environ["SPLUNK_HEC_URL"] == "https://example:8088"
