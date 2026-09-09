"""In-memory fault injection for the live simulator."""

from __future__ import annotations

import threading
from uuid import uuid4

from breakeven.sim.world import CHANNELS, CREATIVE_IDS, concurrency_at

VAST_TRANSCODE_ERROR = "900"
# `F-SIM-12`/`F-SIM-04`: a fixed, deterministic fraction of viewers on a failed ad slot
# exit the stream — not `random`, so `stitch_failures_for` stays exactly testable. Small
# enough that a fault at `failure_rate=1.0` across a 3-ad break stays well under the
# break's own viewer count.
STITCH_EXIT_RATE = 0.02

# `D-S111`: the two real CDN pathway names `origins.py`'s own origin pair already uses
# (`origin_name`/`partner_name`). Origin-degradation faults are scoped to one of these
# per channel — the whole point of the A1 remedy is choosing to move a channel's traffic
# off whichever one is degraded.
CDN_PATHWAYS = ("cdn-a", "cdn-b")


class FaultRegistry:
    """Apply creative-transcode and beacon-delivery faults to ad slots."""

    def __init__(self, *, seed: int) -> None:
        del seed
        self._faults: dict[str, tuple[str, str, float]] = {}
        self._by_request: dict[tuple[str, str, float], str] = {}
        self._beacon_faults: dict[str, tuple[str, float]] = {}
        self._beacon_by_request: dict[tuple[str, float], str] = {}
        self._stitch_faults: dict[str, tuple[str, float]] = {}
        self._stitch_by_request: dict[tuple[str, float], str] = {}
        self._origin_faults: dict[str, tuple[str, str, float]] = {}
        self._origin_by_request: dict[tuple[str, str, float], str] = {}
        self._lock = threading.Lock()

    def create(self, *, creative_id: str, channel_id: str, failure_rate: float) -> str:
        """Register a fault, returning its stable ID when already active."""
        self._validate(creative_id, channel_id, failure_rate)
        request = (creative_id, channel_id, failure_rate)
        with self._lock:
            existing = self._by_request.get(request)
            if existing is not None:
                return existing
            fault_id = str(uuid4())
            self._faults[fault_id] = request
            self._by_request[request] = fault_id
            return fault_id

    def create_delivery_loss(self, *, channel_id: str, failure_rate: float) -> str:
        """Register a channel-scoped beacon loss fault idempotently."""
        self._validate_channel_rate(channel_id, failure_rate)
        request = (channel_id, failure_rate)
        with self._lock:
            existing = self._beacon_by_request.get(request)
            if existing is not None:
                return existing
            fault_id = str(uuid4())
            self._beacon_faults[fault_id] = request
            self._beacon_by_request[request] = fault_id
            return fault_id

    def create_stitch_corruption(self, *, channel_id: str, failure_rate: float) -> str:
        """Register a channel-scoped manifest-stitch corruption fault idempotently."""
        self._validate_channel_rate(channel_id, failure_rate)
        request = (channel_id, failure_rate)
        with self._lock:
            existing = self._stitch_by_request.get(request)
            if existing is not None:
                return existing
            fault_id = str(uuid4())
            self._stitch_faults[fault_id] = request
            self._stitch_by_request[request] = fault_id
            return fault_id

    def create_origin_degradation(
        self, *, channel_id: str, cdn_pathway: str, failure_rate: float
    ) -> str:
        """Register a channel+pathway-scoped origin delivery fault idempotently."""
        self._validate_channel_rate(channel_id, failure_rate)
        if cdn_pathway not in CDN_PATHWAYS:
            raise ValueError(f"unknown cdn_pathway {cdn_pathway!r}")
        request = (channel_id, cdn_pathway, failure_rate)
        with self._lock:
            existing = self._origin_by_request.get(request)
            if existing is not None:
                return existing
            fault_id = str(uuid4())
            self._origin_faults[fault_id] = request
            self._origin_by_request[request] = fault_id
            return fault_id

    def delete(self, fault_id: str) -> bool:
        """Remove a fault and report whether it was active."""
        with self._lock:
            fault = self._faults.pop(fault_id, None)
            if fault is not None:
                del self._by_request[fault]
                return True
            beacon_fault = self._beacon_faults.pop(fault_id, None)
            if beacon_fault is not None:
                del self._beacon_by_request[beacon_fault]
                return True
            stitch_fault = self._stitch_faults.pop(fault_id, None)
            if stitch_fault is not None:
                del self._stitch_by_request[stitch_fault]
                return True
            origin_fault = self._origin_faults.pop(fault_id, None)
            if origin_fault is None:
                return False
            del self._origin_by_request[origin_fault]
            return True

    def errors_for(
        self,
        channel_id: str,
        slots: int,
        eligible_creatives: tuple[str, ...],
        *,
        region: str | None = None,
        hour: int | None = None,
    ) -> tuple[tuple[str, str, int], ...]:
        """Return per-fault failed viewer-request counts for the next ad pod."""
        with self._lock:
            active_faults = [
                (creative_id, failure_rate)
                for creative_id, fault_channel_id, failure_rate in self._faults.values()
                if fault_channel_id == channel_id and creative_id in eligible_creatives
            ]
            channel = next(
                channel for channel in CHANNELS if channel.channel_id == channel_id
            )
            viewer_count = (
                concurrency_at(channel, region, hour)
                if region is not None and hour is not None
                else channel.concurrency_baseline
            )
            remaining_rate = 1.0
            remaining_requests = viewer_count * slots
            errors: list[tuple[str, str, int]] = []
            for creative_id, failure_rate in active_faults:
                effective_rate = min(failure_rate, remaining_rate)
                impression_count = min(
                    round(viewer_count * slots * effective_rate), remaining_requests
                )
                errors.append((VAST_TRANSCODE_ERROR, creative_id, impression_count))
                remaining_rate -= effective_rate
            return tuple(errors)

    def delivery_losses_for(
        self,
        channel_id: str,
        slots: int,
        *,
        region: str | None = None,
        hour: int | None = None,
    ) -> int:
        """Return the beacon confirmations lost for the next channel ad pod."""
        with self._lock:
            failure_rate = min(
                1.0,
                sum(
                    rate
                    for fault_channel_id, rate in self._beacon_faults.values()
                    if fault_channel_id == channel_id
                ),
            )
            channel = next(
                channel for channel in CHANNELS if channel.channel_id == channel_id
            )
            viewer_count = (
                concurrency_at(channel, region, hour)
                if region is not None and hour is not None
                else channel.concurrency_baseline
            )
            return round(viewer_count * slots * failure_rate)

    def stitch_failures_for(
        self,
        channel_id: str,
        slots: int,
        *,
        region: str | None = None,
        hour: int | None = None,
    ) -> tuple[int, int]:
        """Return (failed_ad_slots, viewers_exited) for the next channel ad pod."""
        with self._lock:
            failure_rate = min(
                1.0,
                sum(
                    rate
                    for fault_channel_id, rate in self._stitch_faults.values()
                    if fault_channel_id == channel_id
                ),
            )
            channel = next(
                channel for channel in CHANNELS if channel.channel_id == channel_id
            )
            viewer_count = (
                concurrency_at(channel, region, hour)
                if region is not None and hour is not None
                else channel.concurrency_baseline
            )
            failed_slots = round(slots * failure_rate)
            viewers_exited = round(viewer_count * failed_slots * STITCH_EXIT_RATE)
            return failed_slots, viewers_exited

    def origin_errors_for(self, channel_id: str, cdn_pathway: str, requests: int) -> int:
        """Return how many of `requests` origin fetches fail on `cdn_pathway` for this
        channel — the CDN-cohort analogue of `delivery_losses_for`. Scoped by pathway
        (not summed across faults the way beacon/stitch are) because A1's whole premise
        is that pathways can be unequally healthy; collapsing them would erase the exact
        signal `steer_pathway` needs to justify moving traffic off one specific one.
        """
        with self._lock:
            failure_rate = next(
                (
                    rate
                    for fault_channel_id, fault_pathway, rate in self._origin_faults.values()
                    if fault_channel_id == channel_id and fault_pathway == cdn_pathway
                ),
                0.0,
            )
            return round(requests * failure_rate)

    @staticmethod
    def _validate(creative_id: str, channel_id: str, failure_rate: float) -> None:
        if creative_id not in CREATIVE_IDS:
            raise ValueError("unknown creative_id")
        FaultRegistry._validate_channel_rate(channel_id, failure_rate)

    @staticmethod
    def _validate_channel_rate(channel_id: str, failure_rate: float) -> None:
        if channel_id not in {channel.channel_id for channel in CHANNELS}:
            raise ValueError("unknown channel_id")
        if (
            isinstance(failure_rate, bool)
            or not isinstance(failure_rate, (int, float))
            or not 0.0 <= failure_rate <= 1.0
        ):
            raise ValueError("failure_rate must be between 0.0 and 1.0")
