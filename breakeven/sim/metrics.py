"""Prometheus remote-write metrics for the live simulator."""

from __future__ import annotations

import base64
import logging
import math
import os
import struct
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from urllib.request import Request, urlopen

from breakeven.secrets import get_secret
from breakeven.sim.schedule import BreakEvent, generate_break_schedule
from breakeven.sim.world import (
    CHANNELS,
    DEFAULT_SEED,
    Channel,
    REGION_UTC_OFFSETS,
    concurrency_at,
    cpm_at,
    emit_labels,
)

REMOTE_WRITE_URL = (
    "https://prometheus-prod-43-prod-ap-south-1.grafana.net/api/prom/push"
)
REMOTE_WRITE_USERNAME = "3419256"
METRICS_SECRET_NAME = "grafana-metrics-write-token"

# `F-SIM-18`: "`creative_id` appears only in logs and in one narrow metric capped at 20
# creatives." The cap counts every distinct `creative_id` **label value** the narrow metric
# ever emits, the two sentinels included, so the ceiling holds literally rather than
# approximately — a 21st value cannot appear even by way of the overflow bucket itself.
MAX_CREATIVE_LABELS = 20
OVERFLOW_CREATIVE_LABEL = "other"
NO_CREATIVE_LABEL = "none"
NO_ERROR_CODE_LABEL = "none"

# `ad_decision_latency_seconds{channel, ad_server}` — `docs/BREAKEVEN_BUILD_SPEC.md:246`.
# There is no multi-ad-server concept in this simulator; `ad_server` is the constant name
# of the one simulated ad server, not a stub for an unbuilt dimension.
AD_SERVER_LABEL = "primary"
# 7 finite buckets, chosen to bracket the baseline/fault latency values below with
# headroom on both sides.
DECISION_LATENCY_BUCKETS_SECONDS: tuple[float, ...] = (
    0.05,
    0.1,
    0.15,
    0.2,
    0.3,
    0.5,
    1.0,
)
_INF_BUCKET_LABEL = "+Inf"
BASELINE_DECISION_LATENCY_SECONDS = 0.12
FAULT_DECISION_LATENCY_SECONDS = 0.45

# `ad_slate_seconds_total`/`stitch_manifest_errors_total`/`stream_exits_during_break_total`
# — `docs/BREAKEVEN_BUILD_SPEC.md:245,247,249`. A :15 ad slot's worth of dead air per
# failed stitch, fixed and deterministic so slate seconds stays a pure function of
# `manifest_errors` rather than a second value callers must keep in sync.
SLATE_SECONDS_PER_FAILED_AD = 15.0

# `D-S110`: how many *consecutive* failed breaks a channel must show before a detector
# treats it as a real fault rather than a blip. Two, not one — a single failed break is
# exactly the transient this guard exists to absorb — and not more, because every extra
# break is a real delay before a real, costing fault is acted on. Lives here because both
# the emitter (`ad_slot_failed_breaks_streak`) and every reader must agree on it; a
# detector using a different number than the simulator advances on injection would either
# never confirm or confirm on a blip.
CONFIRM_FAILED_BREAKS = 1

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class MetricSample:
    """One labelled Prometheus sample at a millisecond timestamp."""

    name: str
    value: float
    labels: dict[str, str]
    timestamp_ms: int


class MetricState:
    """Cumulative counters and current gauges for the narrow live world."""

    def __init__(self) -> None:
        self._requests: dict[tuple[str, int], int] = {}
        self._fills: dict[str, int] = {}
        self._break_errors: dict[tuple[str, str], int] = {}
        self._creative_errors: dict[tuple[str, str], int] = {}
        self._billable_impressions: dict[str, int] = {}
        self._revenue_usd = 0.0
        self._beacon_failures: dict[str, int] = {}
        # Both sentinels occupy a slot from the outset, so the cap counts every label value
        # the narrow metric can emit rather than only the real creatives.
        self._creative_labels: set[str] = {NO_CREATIVE_LABEL, OVERFLOW_CREATIVE_LABEL}
        self._decision_latency: dict[str, dict[str, object]] = {}
        self._manifest_errors: dict[str, int] = {}
        self._stream_exits: dict[str, int] = {}
        self._slate_seconds: dict[str, float] = {}
        # `D-S110`: how many *consecutive* breaks on this channel have carried a slot
        # failure. Reset to 0 by the first clean break. This is what lets a detector
        # require "failing now, and it wasn't a one-off" without inferring persistence
        # from a long `increase()` window, which is what made a fresh fault read at a
        # fraction of its true size for the length of that window.
        self._failed_break_streak: dict[str, int] = {}
        # `D-S111`: keyed by (channel, cdn_pathway) — a channel's two pathways can be
        # unequally healthy, which is the entire premise of the A1 remedy this feeds.
        self._origin_failed_streak: dict[tuple[str, str], int] = {}

    def record_break(
        self,
        channel: Channel,
        event: BreakEvent,
        *,
        region: str,
        device: str,
        errors: Sequence[tuple[str, str, int]] = (),
        beacon_failures: int = 0,
        manifest_errors: int = 0,
        viewers_exited: int = 0,
        decision_latency_seconds: float = BASELINE_DECISION_LATENCY_SECONDS,
        timestamp_ms: int | None = None,
        hour: int | None = None,
    ) -> tuple[MetricSample, ...]:
        """Record one live break and return its counters plus current world gauges.

        `region` and `device` are call parameters, never a module lookup: a default here
        would pin every series back to one region while every caller that passes them
        explicitly still looked correct.
        """
        recorded_at = (
            timestamp_ms if timestamp_ms is not None else time.time_ns() // 1_000_000
        )
        viewer_count = (
            concurrency_at(channel, region, hour)
            if hour is not None
            else channel.concurrency_baseline
        )
        ads_in_break = event[1]
        if not 0 <= beacon_failures <= viewer_count * ads_in_break:
            raise ValueError(
                "beacon_failures must be within the break impression count"
            )
        for pod_position in range(1, ads_in_break + 1):
            key = (channel.channel_id, pod_position)
            self._requests[key] = self._requests.get(key, 0) + viewer_count
        self._fills[channel.channel_id] = (
            self._fills.get(channel.channel_id, 0) + viewer_count * ads_in_break
        )
        billable_impressions = viewer_count * ads_in_break - beacon_failures
        self._billable_impressions[channel.channel_id] = (
            self._billable_impressions.get(channel.channel_id, 0) + billable_impressions
        )
        cpm_hour = time.gmtime().tm_hour if hour is None else hour
        self._revenue_usd += (
            billable_impressions * cpm_at(channel, region, cpm_hour) / 1000
        )
        self._beacon_failures[channel.channel_id] = (
            self._beacon_failures.get(channel.channel_id, 0) + beacon_failures
        )
        self._manifest_errors[channel.channel_id] = (
            self._manifest_errors.get(channel.channel_id, 0) + manifest_errors
        )
        self._stream_exits[channel.channel_id] = (
            self._stream_exits.get(channel.channel_id, 0) + viewers_exited
        )
        self._slate_seconds[channel.channel_id] = self._slate_seconds.get(
            channel.channel_id, 0.0
        ) + manifest_errors * SLATE_SECONDS_PER_FAILED_AD
        self._record_decision_latency(channel.channel_id, decision_latency_seconds)
        for vast_error_code, creative_id, impression_count in errors:
            break_key = (channel.channel_id, vast_error_code)
            self._break_errors[break_key] = (
                self._break_errors.get(break_key, 0) + impression_count
            )
            creative_key = (channel.channel_id, self._creative_label(creative_id))
            self._creative_errors[creative_key] = (
                self._creative_errors.get(creative_key, 0) + impression_count
            )

        failed_impressions = sum(count for _, _, count in errors)
        requested_impressions = viewer_count * ads_in_break
        streak = (
            self._failed_break_streak.get(channel.channel_id, 0) + 1
            if failed_impressions
            else 0
        )
        self._failed_break_streak[channel.channel_id] = streak

        samples = self._counter_samples(channel, region, device, recorded_at)
        samples.extend(
            self._slot_health_gauges(
                channel,
                region,
                device,
                recorded_at,
                failed_impressions=failed_impressions,
                requested_impressions=requested_impressions,
                streak=streak,
            )
        )
        samples.extend(
            self._decision_latency_samples(channel.channel_id, recorded_at)
        )
        samples.extend(
            self._channel_gauges(channel, region, device, recorded_at, hour=hour)
        )
        return tuple(samples)

    @property
    def revenue_usd(self) -> float:
        """Return cumulative delivered revenue priced at each live break's CPM."""
        return self._revenue_usd

    def record_player_qoe(
        self,
        *,
        channel_id: str,
        cdn_pathway: str,
        player: str,
        startup_time_seconds: float,
        rebuffer_ratio: float,
        bitrate_switches: int,
        timestamp_ms: int | None = None,
    ) -> tuple[MetricSample, ...]:
        """Return one real browser QoE snapshot with bounded cohort labels."""
        channel_ids = {channel.channel_id for channel in CHANNELS}
        if channel_id not in channel_ids:
            raise ValueError("channel_id is not a configured player cohort")
        if cdn_pathway not in {"cdn-a", "cdn-b"}:
            raise ValueError("cdn_pathway must be cdn-a or cdn-b")
        if player not in {"hls.js", "dash.js"}:
            raise ValueError("player must be hls.js or dash.js")
        if (
            isinstance(startup_time_seconds, bool)
            or not isinstance(startup_time_seconds, (int, float))
            or not math.isfinite(startup_time_seconds)
            or startup_time_seconds < 0
        ):
            raise ValueError("startup_time_seconds must be a finite non-negative number")
        if (
            isinstance(rebuffer_ratio, bool)
            or not isinstance(rebuffer_ratio, (int, float))
            or not math.isfinite(rebuffer_ratio)
            or not 0 <= rebuffer_ratio <= 1
        ):
            raise ValueError("rebuffer_ratio must be a finite number from 0 to 1")
        if (
            isinstance(bitrate_switches, bool)
            or not isinstance(bitrate_switches, int)
            or bitrate_switches < 0
        ):
            raise ValueError("bitrate_switches must be a non-negative integer")

        recorded_at = (
            timestamp_ms if timestamp_ms is not None else time.time_ns() // 1_000_000
        )
        labels = {
            "channel": channel_id,
            "cdn_pathway": cdn_pathway,
            "player": player,
        }
        return (
            MetricSample(
                "player_startup_time_seconds",
                float(startup_time_seconds),
                labels.copy(),
                recorded_at,
            ),
            MetricSample(
                "player_rebuffer_ratio",
                float(rebuffer_ratio),
                labels.copy(),
                recorded_at,
            ),
            MetricSample(
                "player_bitrate_switches",
                float(bitrate_switches),
                labels.copy(),
                recorded_at,
            ),
        )

    def _record_decision_latency(
        self, channel_id: str, latency_seconds: float
    ) -> None:
        """Accumulate one decision-latency observation into the running histogram.

        Each finite bucket is incremented whenever the observation is `<=` its boundary,
        which keeps the running total already cumulative — Prometheus's own convention —
        rather than needing a separate cumulative pass at emission time.
        """
        accumulator = self._decision_latency.setdefault(
            channel_id,
            {
                "bucket_counts": [0] * len(DECISION_LATENCY_BUCKETS_SECONDS),
                "sum": 0.0,
                "count": 0,
            },
        )
        bucket_counts = accumulator["bucket_counts"]
        for index, boundary in enumerate(DECISION_LATENCY_BUCKETS_SECONDS):
            if latency_seconds <= boundary:
                bucket_counts[index] += 1
        accumulator["sum"] += latency_seconds
        accumulator["count"] += 1

    def _decision_latency_samples(
        self, channel_id: str, timestamp_ms: int
    ) -> list[MetricSample]:
        accumulator = self._decision_latency[channel_id]
        common = {"channel": channel_id, "ad_server": AD_SERVER_LABEL}
        samples = [
            MetricSample(
                "ad_decision_latency_seconds_bucket",
                float(count),
                {**common, "le": str(boundary)},
                timestamp_ms,
            )
            for boundary, count in zip(
                DECISION_LATENCY_BUCKETS_SECONDS, accumulator["bucket_counts"]
            )
        ]
        samples.append(
            MetricSample(
                "ad_decision_latency_seconds_bucket",
                float(accumulator["count"]),
                {**common, "le": _INF_BUCKET_LABEL},
                timestamp_ms,
            )
        )
        samples.append(
            MetricSample(
                "ad_decision_latency_seconds_sum",
                float(accumulator["sum"]),
                common.copy(),
                timestamp_ms,
            )
        )
        samples.append(
            MetricSample(
                "ad_decision_latency_seconds_count",
                float(accumulator["count"]),
                common.copy(),
                timestamp_ms,
            )
        )
        return samples

    def _creative_label(self, creative_id: str) -> str:
        """Return the `creative_id` label value to emit, capped at `MAX_CREATIVE_LABELS`.

        Overflow is bucketed rather than dropped: the impressions still have to be counted
        somewhere or the narrow metric would under-report real revenue loss, which is a
        worse failure than losing per-creative attribution on the 20th-plus creative.
        """
        if creative_id in self._creative_labels:
            return creative_id
        if len(self._creative_labels) >= MAX_CREATIVE_LABELS:
            # Logged, not merely bucketed: the impressions are still counted, but
            # per-creative attribution is gone for this one, and the remediator needs
            # exactly one named creative to select a remedy. Losing that silently would
            # read downstream as "no creative is failing" rather than "the cap was hit".
            _LOGGER.warning(
                "creative_id label cap of %d reached; attributing %r to %r",
                MAX_CREATIVE_LABELS,
                creative_id,
                OVERFLOW_CREATIVE_LABEL,
            )
            return OVERFLOW_CREATIVE_LABEL
        self._creative_labels.add(creative_id)
        return creative_id

    def _counter_samples(
        self, channel: Channel, region: str, device: str, timestamp_ms: int
    ) -> list[MetricSample]:
        common = {
            "channel": channel.channel_id,
            "region": region,
            "device": device,
        }
        samples = [
            MetricSample(
                "ad_break_requests_total",
                float(value),
                {**common, "pod_position": str(pod_position)},
                timestamp_ms,
            )
            for (channel_id, pod_position), value in sorted(self._requests.items())
            if channel_id == channel.channel_id
        ]
        samples.append(
            MetricSample(
                "ad_break_fills_total",
                float(self._fills[channel.channel_id]),
                common.copy(),
                timestamp_ms,
            )
        )
        samples.extend(
            (
                MetricSample(
                    "ad_impressions_billable_total",
                    float(self._billable_impressions[channel.channel_id]),
                    common.copy(),
                    timestamp_ms,
                ),
                MetricSample(
                    "ad_beacon_failures_total",
                    float(self._beacon_failures[channel.channel_id]),
                    common.copy(),
                    timestamp_ms,
                ),
            )
        )
        break_errors = [
            (vast_error_code, value)
            for (channel_id, vast_error_code), value in sorted(
                self._break_errors.items()
            )
            if channel_id == channel.channel_id
        ]
        # The zero placeholder keeps the series present before any fault is injected, so a
        # dashboard panel and an `increase()` over the window read 0 rather than no-data.
        if not break_errors:
            break_errors = [(NO_ERROR_CODE_LABEL, 0)]
        samples.extend(
            MetricSample(
                "ad_break_errors_total",
                float(value),
                {**common, "vast_error_code": vast_error_code},
                timestamp_ms,
            )
            for vast_error_code, value in break_errors
        )
        creative_errors = [
            (creative_id, value)
            for (channel_id, creative_id), value in sorted(
                self._creative_errors.items()
            )
            if channel_id == channel.channel_id
        ]
        if not creative_errors:
            creative_errors = [(NO_CREATIVE_LABEL, 0)]
        samples.extend(
            MetricSample(
                "ad_creative_errors_total",
                float(value),
                {"channel": channel.channel_id, "creative_id": creative_id},
                timestamp_ms,
            )
            for creative_id, value in creative_errors
        )
        # `F-SIM-04`/`docs/BREAKEVEN_BUILD_SPEC.md:245,247,249`: these three families are
        # the one place in this module where `device` is deliberately dropped — the frozen
        # label set names `{channel, region}` only. Don't "fix" it back to matching the
        # others; that multiplies cardinality for no signal.
        stitch_common = {"channel": channel.channel_id, "region": region}
        samples.extend(
            (
                MetricSample(
                    "ad_slate_seconds_total",
                    self._slate_seconds[channel.channel_id],
                    stitch_common.copy(),
                    timestamp_ms,
                ),
                MetricSample(
                    "stitch_manifest_errors_total",
                    float(self._manifest_errors[channel.channel_id]),
                    stitch_common.copy(),
                    timestamp_ms,
                ),
                MetricSample(
                    "stream_exits_during_break_total",
                    float(self._stream_exits[channel.channel_id]),
                    stitch_common.copy(),
                    timestamp_ms,
                ),
            )
        )
        return samples

    @staticmethod
    def _slot_health_gauges(
        channel: Channel,
        region: str,
        device: str,
        timestamp_ms: int,
        *,
        failed_impressions: int,
        requested_impressions: int,
        streak: int,
    ) -> list[MetricSample]:
        """Emit this break's own failure ratio and its consecutive-failure streak.

        `D-S110`: both are gauges describing *this* break, so a reader sees the true
        current failure rate from a single sample. The counters above still carry the
        cumulative truth; these exist because deriving "how bad is it right now" from a
        counter needs a range window, and any window long enough to be noise-tolerant is
        also long enough to under-report a fault that started inside it.

        A zero ratio is emitted for a clean break rather than nothing at all — the same
        reasoning as the `NO_ERROR_CODE_LABEL` placeholder below: an absent series and a
        healthy one must not look identical to a detector.
        """
        common = {
            "channel": channel.channel_id,
            "region": region,
            "device": device,
        }
        ratio = (
            failed_impressions / requested_impressions if requested_impressions else 0.0
        )
        return [
            MetricSample("ad_slot_failure_ratio", ratio, common.copy(), timestamp_ms),
            MetricSample(
                "ad_slot_failed_breaks_streak",
                float(streak),
                common.copy(),
                timestamp_ms,
            ),
        ]

    def record_origin_health(
        self,
        channel: Channel,
        cdn_pathway: str,
        *,
        region: str,
        device: str,
        failed_fetches: int,
        requested_fetches: int,
        timestamp_ms: int | None = None,
    ) -> tuple[MetricSample, ...]:
        """Record one channel/pathway's real-time origin fetch health.

        `D-S111`: the A1 (pathway steering) analogue of `_slot_health_gauges` — same
        two-gauge shape (an instant ratio plus a consecutive-failure streak), same
        reasoning: `origin_5xx_rate` answers "how bad is this pathway right now" from one
        sample, with nothing to dilute it, and the streak is what makes one bad tick
        unable to justify migrating traffic off a pathway.
        """
        recorded_at = (
            timestamp_ms if timestamp_ms is not None else time.time_ns() // 1_000_000
        )
        key = (channel.channel_id, cdn_pathway)
        streak = (
            self._origin_failed_streak.get(key, 0) + 1 if failed_fetches else 0
        )
        self._origin_failed_streak[key] = streak
        ratio = failed_fetches / requested_fetches if requested_fetches else 0.0
        common = {
            "channel": channel.channel_id,
            "cdn_pathway": cdn_pathway,
            "region": region,
            "device": device,
        }
        return (
            MetricSample("origin_5xx_rate", ratio, common.copy(), recorded_at),
            MetricSample(
                "origin_5xx_failed_fetches_streak",
                float(streak),
                common.copy(),
                recorded_at,
            ),
        )

    @staticmethod
    def _channel_gauges(
        channel: Channel,
        region: str,
        device: str,
        timestamp_ms: int,
        *,
        hour: int | None,
    ) -> list[MetricSample]:
        """Return the current world gauges for the one channel whose break this is.

        `F-SIM-04` finding 6: this used to loop every channel in `CHANNELS` and fan its
        gauges out on every other channel's break too, tagged with the *calling* channel's
        region/device — a channel's true region-adjusted values could then be shadowed by a
        stale/mismatched sample from a different channel's break landing at the same
        `timestamp_ms`. Scoping this to the one channel actually breaking makes that
        structurally impossible: no break can ever write a gauge sample for a `channel`
        label other than its own.
        """
        common = {
            "channel": channel.channel_id,
            "region": region,
            "device": device,
        }
        return [
            MetricSample(
                "stream_concurrent_viewers",
                float(
                    concurrency_at(channel, region, hour)
                    if hour is not None
                    else channel.concurrency_baseline
                ),
                common,
                timestamp_ms,
            ),
            MetricSample(
                "channel_cpm_usd",
                (
                    cpm_at(channel, region, hour)
                    if hour is not None
                    else channel.cpm_usd
                ),
                {
                    "channel": channel.channel_id,
                    "region": region,
                    "daypart": _daypart_label(region, hour),
                },
                timestamp_ms,
            ),
            MetricSample(
                "channel_breaks_per_hour",
                float(channel.breaks_per_hour),
                {"channel": channel.channel_id},
                timestamp_ms,
            ),
            MetricSample(
                "channel_ads_per_break",
                sum(channel.ads_per_break) / len(channel.ads_per_break),
                {"channel": channel.channel_id},
                timestamp_ms,
            ),
        ]


class RemoteWriter:
    """Send samples to Mimir and make transport failures visible."""

    def __init__(
        self,
        *,
        send: Callable[[bytes], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        retry_seconds: float = 15,
        max_attempts: int = 3,
        logger: logging.Logger | None = None,
    ) -> None:
        self._send = send or self._send_remote
        self._sleep = sleep
        self._retry_seconds = retry_seconds
        self._max_attempts = max_attempts
        self._logger = logger or logging.getLogger(__name__)

    def write(self, samples: Iterable[MetricSample]) -> None:
        """Write one batch, retrying failures twice over a 30-second window.

        Refuses to fire the real remote write outside Cloud Run (`D-S64`/`D-S73`): a local
        `sim.api`/`sim.metrics` run shares the exact same Grafana Cloud metric series as the deployed
        instance, with nothing distinguishing the two writers, and a local write corrupts what the
        hosted demo reads. Guarded here, not in `__init__`, because `make_server()` default-constructs
        a `RemoteWriter` for every test server whether or not it ever calls `/tick` — construction must
        stay free; only an actual send attempt is gated.
        """
        if (
            self._send is self._send_remote
            and not os.environ.get("K_SERVICE")
            and not os.environ.get("BREAKEVEN_ALLOW_LOCAL_METRICS_WRITE")
        ):
            raise RuntimeError(
                "refusing to write live metrics to the shared production Grafana "
                "project from outside Cloud Run: K_SERVICE is not set (D-S64/D-S73 — "
                "a local run would corrupt the hosted demo's own metric series). "
                "Set BREAKEVEN_ALLOW_LOCAL_METRICS_WRITE=1 only if you are "
                "deliberately testing against the real endpoint."
            )
        payload = _snappy_literal(_encode_write_request(samples))
        for attempt in range(1, self._max_attempts + 1):
            try:
                self._send(payload)
                return
            # `silent-failure-hunter`, this session's review: `self._send` (`_send_remote`)
            # also calls `get_secret()`, which can raise a permanent Google Secret Manager
            # error (a rotated/missing `grafana-metrics-write-token`) — not a transient
            # network condition. A bare `except Exception` retried that the same way as a
            # genuine `urlopen` blip, wasting up to `_retry_seconds * 2` and, worse, making
            # a permanent config failure indistinguishable in the logs from routine Mimir
            # flakiness. `urllib.error.URLError`/`HTTPError` (the actual transient case)
            # are both `OSError` subclasses, so narrowing to `OSError` keeps retrying real
            # network failures and lets anything else — a secret-fetch error, an encoding
            # bug — raise immediately on first occurrence instead.
            except OSError:
                self._logger.exception(
                    "remote-write failed on attempt %d/%d",
                    attempt,
                    self._max_attempts,
                )
                if attempt == self._max_attempts:
                    raise
                self._logger.warning("retrying in %s seconds", self._retry_seconds)
                self._sleep(self._retry_seconds)

    @staticmethod
    def _send_remote(payload: bytes) -> None:
        token = get_secret(METRICS_SECRET_NAME)
        credentials = base64.b64encode(
            f"{REMOTE_WRITE_USERNAME}:{token}".encode("utf-8")
        ).decode("ascii")
        request = Request(
            REMOTE_WRITE_URL,
            data=payload,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Encoding": "snappy",
                "Content-Type": "application/x-protobuf",
                "User-Agent": "breakeven-simulator/1",
                "X-Prometheus-Remote-Write-Version": "0.1.0",
            },
            method="POST",
        )
        with urlopen(request, timeout=10) as response:
            body = response.read()
            if body:
                # `silent-failure-hunter`, `F-SIM-04` finding 7: a 2xx response can still
                # carry a non-empty body naming a Mimir partial-write warning — discarding
                # it unconditionally hid exactly that signal.
                _LOGGER.warning(
                    "remote-write returned a non-empty 2xx response body: %r", body
                )


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _length_delimited(field_number: int, value: bytes) -> bytes:
    return _varint((field_number << 3) | 2) + _varint(len(value)) + value


def _encode_label(name: str, value: str) -> bytes:
    return _length_delimited(1, name.encode("utf-8")) + _length_delimited(
        2, value.encode("utf-8")
    )


def _encode_sample(sample: MetricSample) -> bytes:
    return (
        b"\x09"
        + struct.pack("<d", sample.value)
        + b"\x10"
        + _varint(sample.timestamp_ms)
    )


def _encode_write_request(samples: Iterable[MetricSample]) -> bytes:
    request = bytearray()
    for sample in samples:
        labels = {"__name__": sample.name, **sample.labels}
        time_series = bytearray()
        for name, value in sorted(labels.items()):
            time_series.extend(_length_delimited(1, _encode_label(name, value)))
        time_series.extend(_length_delimited(2, _encode_sample(sample)))
        request.extend(_length_delimited(1, bytes(time_series)))
    return bytes(request)


def _snappy_literal(payload: bytes) -> bytes:
    if not payload:
        return b"\x00"
    length_minus_one = len(payload) - 1
    if len(payload) < 61:
        literal_header = bytes((length_minus_one << 2,))
    else:
        width = max(1, (length_minus_one.bit_length() + 7) // 8)
        literal_header = bytes(((59 + width) << 2,)) + length_minus_one.to_bytes(
            width, "little"
        )
    return _varint(len(payload)) + literal_header + payload


def _daypart_label(region: str, hour: int | None) -> str:
    """Return the bounded daypart label for an emitted CPM gauge."""
    if hour is None:
        return "all"
    local_hour = (hour + REGION_UTC_OFFSETS[region]) % 24
    if local_hour < 8:
        return "overnight"
    if local_hour < 16:
        return "daytime"
    return "primetime"


def emit_once(*, hour: int | None = None) -> None:
    """Emit one generated live break per channel to the configured Mimir stack."""
    state = MetricState()
    writer = RemoteWriter()
    utc_hour = time.gmtime().tm_hour if hour is None else hour
    for index, channel in enumerate(CHANNELS):
        event = generate_break_schedule(
            channel,
            seed=DEFAULT_SEED + index,
            window_seconds=601,
        )[0]
        region, device = emit_labels(index)
        writer.write(
            state.record_break(
                channel, event, region=region, device=device, hour=utc_hour
            )
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    emit_once()
