"""Fixed rendition ladders for the simulator's channels."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from breakeven.sim.world import CHANNELS


@dataclass(frozen=True)
class Rendition:
    """One selectable video rendition and its accessibility signalling."""

    rendition_id: str
    bitrate_kbps: int
    carries_captions: bool
    carries_audio_description: bool


# One ladder shape per tier, and the single rung on each that carries accessibility
# signalling. Derived rather than written out eight times: applied to the pre-widening
# roster these reproduce `ch_flagship_01`'s 1080/720/540/360 ladder (accessibility on
# `ch_flagship_01_1080p`, the rung `docs/FEATURES.md:138` names) and `ch_niche_07`'s
# 720/540/360 ladder (accessibility on `ch_niche_07_540p`) byte for byte —
# `tests/test_sim_renditions.py` pins both so this derivation cannot drift off them.
_RUNGS_BY_TIER: Mapping[str, tuple[tuple[int, int], ...]] = {
    "flagship": ((1080, 6_000), (720, 3_000), (540, 1_500), (360, 800)),
    "mid": ((720, 3_000), (540, 1_500), (360, 800)),
    "niche": ((720, 3_000), (540, 1_500), (360, 800)),
}
_ACCESSIBILITY_HEIGHT_BY_TIER: Mapping[str, int] = {
    "flagship": 1080,
    "mid": 720,
    "niche": 540,
}


def _ladder(channel_id: str, tier: str) -> tuple[Rendition, ...]:
    accessible_height = _ACCESSIBILITY_HEIGHT_BY_TIER[tier]
    return tuple(
        Rendition(
            f"{channel_id}_{height}p",
            bitrate_kbps,
            height == accessible_height,
            height == accessible_height,
        )
        for height, bitrate_kbps in _RUNGS_BY_TIER[tier]
    )


LADDER_BY_CHANNEL: Mapping[str, tuple[Rendition, ...]] = {
    channel.channel_id: _ladder(channel.channel_id, channel.tier)
    for channel in CHANNELS
}
