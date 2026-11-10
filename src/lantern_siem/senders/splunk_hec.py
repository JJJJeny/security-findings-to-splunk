"""Splunk HTTP Event Collector sender.

POSTs batches of events to <SPLUNK_HEC_URL>/services/collector/event with
header 'Authorization: Splunk <SPLUNK_HEC_TOKEN>'. A batch body is the JSON
events concatenated with newlines, which HEC accepts on this endpoint.

Behaviour:
    - retries with exponential backoff on 5xx and connection errors
    - no retry on 4xx (bad token, bad index, bad payload): counted as failed
    - TLS verification off by default because local Docker Splunk uses a
      self-signed certificate (BUILD_LOG B7). Turn it on for anything real.

Status: unit-tested with a fake HTTP layer; NOT yet run against a live
Splunk (BUILD_LOG open item O1).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

HEC_PATH = "/services/collector/event"


@dataclass
class SendResult:
    sent: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)
    sent_events: list[dict[str, Any]] = field(default_factory=list)
    failed_events: list[dict[str, Any]] = field(default_factory=list)


class SplunkHECSender:
    def __init__(
        self,
        url: str,
        token: str,
        batch_size: int = 100,
        max_retries: int = 3,
        verify_tls: bool = False,
        post: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not url or not token:
            raise ValueError("SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN are required to send")
        self.url = url.rstrip("/") + HEC_PATH
        self.token = token
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.verify_tls = verify_tls
        self._sleep = sleep
        if post is None:
            import requests

            if not verify_tls:
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            post = requests.post
        self._post = post

    def send(self, events: list[dict[str, Any]]) -> SendResult:
        result = SendResult()
        for start in range(0, len(events), self.batch_size):
            batch = events[start : start + self.batch_size]
            error = self._post_batch(batch)
            if error is None:
                result.sent += len(batch)
                result.sent_events.extend(batch)
            else:
                result.failed += len(batch)
                result.failed_events.extend(batch)
                result.errors.append(f"batch starting at {start}: {error}")
        return result

    def _post_batch(self, batch: list[dict[str, Any]]) -> str | None:
        """Return None on success, else an error description."""
        body = "\n".join(json.dumps(ev, ensure_ascii=False) for ev in batch)
        headers = {"Authorization": f"Splunk {self.token}"}
        last = "unknown error"
        for attempt in range(self.max_retries + 1):
            try:
                resp = self._post(self.url, data=body.encode("utf-8"), headers=headers,
                                  verify=self.verify_tls, timeout=30)
            except Exception as exc:  # connection refused, timeout, TLS error
                last = f"connection error: {exc}"
            else:
                if 200 <= resp.status_code < 300:
                    return None
                last = f"HTTP {resp.status_code}: {resp.text[:300]}"
                if 400 <= resp.status_code < 500:
                    return last  # client error: retrying won't help
            if attempt < self.max_retries:
                self._sleep(2 ** attempt)
        return last
