"""In-memory blocklist and active-pathway control for the live simulator."""

from __future__ import annotations

import threading

from breakeven.sim.faults import CDN_PATHWAYS
from breakeven.sim.world import CHANNELS, CREATIVE_IDS

# `D-S115`: the pathway a channel is actually served from by default, before any real A1
# migration has ever run. `CDN_PATHWAYS[0]` ("cdn-a") rather than an arbitrary pick — it is
# also the pathway `origins.py`'s own fault-injection story has always demoed faults on.
_DEFAULT_ACTIVE_PATHWAY = CDN_PATHWAYS[0]


class ControlRegistry:
    """Track creative blocks and each channel's active CDN pathway."""

    def __init__(self) -> None:
        self._blocked: set[tuple[str, str]] = set()
        self._active_pathway: dict[str, str] = {}
        self._lock = threading.Lock()

    def block(self, channel_id: str, creative_id: str) -> None:
        """Block a known creative on a known channel."""
        self._validate(channel_id, creative_id)
        with self._lock:
            self._blocked.add((channel_id, creative_id))

    def unblock(self, channel_id: str, creative_id: str) -> bool:
        """Remove a known block and report whether it was active."""
        self._validate(channel_id, creative_id)
        with self._lock:
            pair = (channel_id, creative_id)
            if pair not in self._blocked:
                return False
            self._blocked.remove(pair)
            return True

    def active_pairs(self) -> tuple[tuple[str, str], ...]:
        """Return the active channel/creative pairs in stable order."""
        with self._lock:
            return tuple(sorted(self._blocked))

    def eligible_creatives(self, channel_id: str) -> tuple[str, ...]:
        """Return the channel's rotation after its blocks are removed."""
        self._validate(channel_id, CREATIVE_IDS[0])
        with self._lock:
            return tuple(
                creative_id
                for creative_id in CREATIVE_IDS
                if (channel_id, creative_id) not in self._blocked
            )

    def active_pathway(self, channel_id: str) -> str:
        """Return the CDN pathway this channel is really being served from right now.

        `D-S115`: real, mutable, HTTP-exposed state — the missing link that makes A1's
        `steer_pathway` remedy causally connect to anything. Before this existed,
        `steer_pathway`'s only mutation was a local file on the orchestrator's own
        machine, which the simulator (a separate deployment) could never see or act on.
        """
        self._validate_channel(channel_id)
        with self._lock:
            return self._active_pathway.get(channel_id, _DEFAULT_ACTIVE_PATHWAY)

    def set_active_pathway(self, channel_id: str, cdn_pathway: str) -> None:
        """Really migrate a channel onto `cdn_pathway` — the one real effect
        `steer_pathway`'s remedy has once it completes."""
        self._validate_channel(channel_id)
        if cdn_pathway not in CDN_PATHWAYS:
            raise ValueError(f"unknown cdn_pathway {cdn_pathway!r}")
        with self._lock:
            self._active_pathway[channel_id] = cdn_pathway

    @staticmethod
    def _validate_channel(channel_id: str) -> None:
        if channel_id not in {channel.channel_id for channel in CHANNELS}:
            raise ValueError("unknown channel_id")

    @staticmethod
    def _validate(channel_id: str, creative_id: str) -> None:
        if channel_id not in {channel.channel_id for channel in CHANNELS}:
            raise ValueError("unknown channel_id")
        if creative_id not in CREATIVE_IDS:
            raise ValueError("unknown creative_id")
