"""F-ACT-04 channel business metadata lookup."""

from __future__ import annotations

import breakeven.sim.world as world  # pylint: disable=consider-using-from-import


def get_channel_business_metadata(channel_id: str) -> dict:
    """Return configured commercial metadata for one known channel."""
    for channel in world.CHANNELS:
        if channel.channel_id == channel_id:
            return {
                "channel_id": channel.channel_id,
                "cpm_usd": channel.cpm_usd,
                "breaks_per_hour": channel.breaks_per_hour,
                "ads_per_break": list(channel.ads_per_break),
                "advertiser_commitments": [],
            }
    raise ValueError(f"unknown channel_id: {channel_id}")
