"""Deterministic world model for the live ad-stack simulator."""

from __future__ import annotations

import math
from dataclasses import dataclass

DEFAULT_SEED = 20260803
# `us-east` and `ctv` stay first: `ch_flagship_01` is assigned index 0 in `CHANNELS`, so
# the deployed instance's live series and the two real Grafana alert rules scoped to it
# keep the exact `{region="us-east",device="ctv"}` label pair they already carry.
REGIONS = ("us-east", "us-west", "eu-west", "apac-south")
REGION_UTC_OFFSETS = {
    "us-east": 0,
    "us-west": -3,
    "eu-west": 2,
    "apac-south": 5,
}
DEVICE_CLASSES = ("ctv", "mobile", "web")
CREATIVE_IDS = (
    "cr_premiere_trailer",
    "cr_summer_sale",
    "cr_new_series",
    "cr_stream_bundle",
)


@dataclass(frozen=True)
class Channel:
    """Fixed economics and ad-pod configuration for one channel."""

    channel_id: str
    name: str
    tier: str
    cpm_usd: float
    concurrency_baseline: int
    breaks_per_hour: int
    ads_per_break: tuple[int, int]


# `ch_flagship_01` and `ch_niche_07` are byte-identical to this file at commit 760e12e and
# must stay that way: they are load-bearing outside this repository (the deployed Cloud Run
# instance's live metric series, and the two real Grafana alert rules `F-AGT-19` created).
# The other six are additions.
#
# EXCEPTION, `D-S102`: `ch_flagship_01.cpm_usd` was deliberately changed from `24.0` to `1250.0`
# to make `F-SIM-08`'s scenario reachable at any hour. `channel_id`/`region`/`device` labels are
# untouched, so `F-AGT-19`'s alert rules and the live label pairing above are unaffected — only
# the `channel_cpm_usd` gauge VALUE and derived revenue arithmetic change, which is the point.
#
# Every `ads_per_break` upper bound is <= 4 — `RESEARCH.md` §2 prices the `pod_position`
# label on `ad_break_requests_total` at <= 4 values per channel, and a wider pod would
# breach that budget silently.
#
# Every channel is 6 breaks/hour, inside `F-SIM-03`'s configured 4-8 range. Not variety for
# its own sake: `test_sim_schedule.py`'s cadence assertion measures a 600 s window against
# `breaks_per_hour * (10/60)` within 5%, which only any single-event cadence can satisfy at
# exactly 6/hour, and its pod-range test needs >= 100 events in 60,000 s. Cadence variety is
# a real feature, but it needs the schedule tests reshaped and belongs to `F-SIM-03`, not to
# this task — widening the roster must not weaken an assertion that already passes.
CHANNELS = (
    Channel(
        channel_id="ch_flagship_01",
        name="Prime Movies 24/7",
        tier="flagship",
        # 1250.0, not the original 24.0: F-SIM-08's frozen scenario (<3% aggregate error while
        # revenue-at-risk exceeds $1,500/min) must hold at any hour a fault is injected, not just
        # a chosen demo window — F-SIM-02's required real daypart swing means revenue-at-risk
        # varies ~11x across the day at a fixed CPM, so no realistic CPM clears $1,500/min at the
        # worst hour (UTC 09) at a share-safe failure rate. D-S102 has the full derivation.
        cpm_usd=1250.0,
        concurrency_baseline=850000,
        breaks_per_hour=6,
        ads_per_break=(2, 4),
    ),
    Channel(
        channel_id="ch_flagship_02",
        name="Blockbuster Cinema One",
        tier="flagship",
        cpm_usd=21.5,
        concurrency_baseline=610000,
        breaks_per_hour=6,
        ads_per_break=(2, 4),
    ),
    Channel(
        channel_id="ch_mid_03",
        name="Comedy Classics Rerun",
        tier="mid",
        cpm_usd=15.5,
        concurrency_baseline=92000,
        breaks_per_hour=6,
        ads_per_break=(2, 4),
    ),
    Channel(
        channel_id="ch_mid_04",
        name="True Crime Files",
        tier="mid",
        cpm_usd=14.0,
        concurrency_baseline=64000,
        breaks_per_hour=6,
        ads_per_break=(2, 3),
    ),
    Channel(
        channel_id="ch_mid_05",
        name="Sports Archive Live",
        tier="mid",
        cpm_usd=13.0,
        concurrency_baseline=78000,
        breaks_per_hour=6,
        ads_per_break=(3, 4),
    ),
    Channel(
        channel_id="ch_mid_06",
        name="Home & Garden Daily",
        tier="mid",
        cpm_usd=11.0,
        concurrency_baseline=41000,
        breaks_per_hour=6,
        ads_per_break=(2, 3),
    ),
    Channel(
        channel_id="ch_niche_07",
        name="Retro Anime Vault",
        tier="niche",
        cpm_usd=9.0,
        concurrency_baseline=1800,
        breaks_per_hour=6,
        ads_per_break=(2, 3),
    ),
    Channel(
        channel_id="ch_niche_08",
        name="Vintage Motorsport",
        tier="niche",
        cpm_usd=7.5,
        concurrency_baseline=1200,
        breaks_per_hour=6,
        ads_per_break=(2, 3),
    ),
)


def _daypart_multiplier(region: str, hour: int) -> float:
    """Return the smooth local viewing-intensity multiplier for one UTC hour."""
    local_hour = (hour + REGION_UTC_OFFSETS[region]) % 24
    primetime = (math.cos((local_hour - 21) * math.tau / 24) + 1) / 2
    return 0.15 + 0.85 * primetime**3


def concurrency_at(channel: Channel, region: str, hour: int) -> int:
    """Return a channel's region-adjusted concurrent viewers at a UTC hour."""
    return round(channel.concurrency_baseline * _daypart_multiplier(region, hour))


def cpm_at(channel: Channel, region: str, hour: int) -> float:
    """Return a channel's region-adjusted CPM at a UTC hour."""
    return channel.cpm_usd * (0.6 + 0.8 * _daypart_multiplier(region, hour))


def emit_labels(channel_index: int) -> tuple[str, str]:
    """Return the ``(region, device)`` label pair one channel emits under.

    A fixed per-channel assignment, not a per-cycle rotation. Every
    ``(channel, region, device)`` series therefore receives a sample on **every** emit
    cycle, which is what keeps ``increase()`` over the 600 s window meaningful: a rotating
    assignment would leave each series with one or two points in the window, and
    ``sum by (channel) (increase(...))`` would silently read low against a dense
    ``ad_creative_errors_total`` in the same expression (`F-AGT-19`'s alert rule divides
    one by the other). Index 0 maps to ``us-east``/``ctv``, preserving `ch_flagship_01`.
    """
    return (
        REGIONS[channel_index % len(REGIONS)],
        DEVICE_CLASSES[channel_index % len(DEVICE_CLASSES)],
    )


def world_payload() -> dict[str, object]:
    """Return the stable JSON-compatible payload served by ``GET /world``."""
    return {
        "seed": DEFAULT_SEED,
        "regions": list(REGIONS),
        "device_classes": list(DEVICE_CLASSES),
        "creative_ids": list(CREATIVE_IDS),
        "channels": [
            {
                "channel_id": channel.channel_id,
                "name": channel.name,
                "tier": channel.tier,
                "cpm_usd": channel.cpm_usd,
                "concurrency_baseline": channel.concurrency_baseline,
                "breaks_per_hour": channel.breaks_per_hour,
                "ads_per_break": list(channel.ads_per_break),
            }
            for channel in CHANNELS
        ],
    }
