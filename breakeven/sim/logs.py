"""Structured Loki logging for the live simulator."""

from __future__ import annotations

import base64
import json
import logging
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.request import Request, urlopen

from breakeven.secrets import get_secret

LOKI_PUSH_URL = "https://logs-prod-028.grafana.net/loki/api/v1/push"
LOKI_BASIC_USERNAME = "1705303"
LOGS_SECRET_NAME = "grafana-logs-write-token"


@dataclass(frozen=True)
class LogEntry:
    """One structured error line destined for Loki."""

    timestamp_ns: int
    level: str
    service: str
    channel_id: str
    region: str
    vast_error_code: str
    creative_id: str
    advertiser_id: str
    ladder_rung: str
    message: str
    trace_id: str


class LokiWriter:
    """Send structured log batches to Loki without stopping the live simulator."""

    def __init__(
        self,
        *,
        send: Callable[[bytes], None] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._send = send or self._send_remote
        self._logger = logger or logging.getLogger(__name__)

    def write(self, entries: Iterable[LogEntry]) -> None:
        """Write an iterable of log entries, logging and swallowing transport failures."""
        batch = tuple(entries)
        if not batch:
            return
        for entry in batch:
            _validate_trace_id(entry.trace_id)
        try:
            self._send(_encode_payload(batch))
        except Exception:
            self._logger.exception("Loki push failed; continuing live emission")

    @staticmethod
    def _send_remote(payload: bytes) -> None:
        token = get_secret(LOGS_SECRET_NAME)
        credentials = base64.b64encode(
            f"{LOKI_BASIC_USERNAME}:{token}".encode("utf-8")
        ).decode("ascii")
        _post(payload, {"Authorization": f"Basic {credentials}"})


def _encode_payload(entries: tuple[LogEntry, ...]) -> bytes:
    streams: dict[tuple[str, str, str, str], list[list[str]]] = defaultdict(list)
    for entry in entries:
        labels = (entry.service, entry.channel_id, entry.region, entry.level)
        streams[labels].append(
            [str(entry.timestamp_ns), json.dumps(_line(entry), separators=(",", ":"))]
        )
    payload = {
        "streams": [
            {
                "stream": {
                    "service": service,
                    "channel": channel_id,
                    "region": region,
                    "level": level,
                },
                "values": values,
            }
            for (service, channel_id, region, level), values in streams.items()
        ]
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _line(entry: LogEntry) -> dict[str, str]:
    return {
        "ts": datetime.fromtimestamp(entry.timestamp_ns / 1_000_000_000, UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "level": entry.level,
        "service": entry.service,
        "channel_id": entry.channel_id,
        "region": entry.region,
        "vast_error_code": entry.vast_error_code,
        "creative_id": entry.creative_id,
        "advertiser_id": entry.advertiser_id,
        "ladder_rung": entry.ladder_rung,
        "message": entry.message,
        "trace_id": entry.trace_id,
    }


def _post(payload: bytes, headers: dict[str, str]) -> None:
    request = Request(
        LOKI_PUSH_URL,
        data=payload,
        headers={
            **headers,
            "Content-Type": "application/json",
            "User-Agent": "breakeven-simulator/1",
        },
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        response.read()


def _validate_trace_id(trace_id: str) -> None:
    if len(trace_id) != 32 or any(
        character not in "0123456789abcdef" for character in trace_id
    ):
        raise ValueError("trace_id must be a 32-character lowercase hex string")
