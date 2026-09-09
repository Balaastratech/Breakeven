"""Deterministic ad-pod schedules with an injectable live clock."""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Iterable

from breakeven.sim.world import Channel

BreakEvent = tuple[float, int]


def generate_break_schedule(
    channel: Channel,
    seed: int,
    window_seconds: float,
) -> list[BreakEvent]:
    """Generate ordered ``(start_offset_seconds, ads_in_break)`` events."""
    rng = random.Random(seed)
    interval = 3600.0 / channel.breaks_per_hour
    nominal_start = interval / 2
    events: list[BreakEvent] = []
    while nominal_start < window_seconds:
        start = nominal_start + rng.uniform(-60.0, 60.0)
        ads = rng.randint(*channel.ads_per_break)
        events.append((start, ads))
        nominal_start += interval
    return events


def run_schedule_live(
    events: Iterable[BreakEvent],
    emit: Callable[[BreakEvent], None],
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Emit scheduled break events as their offsets arrive on the supplied clock."""
    started_at = clock()
    for event in events:
        remaining = started_at + event[0] - clock()
        if remaining > 0:
            sleep(remaining)
        emit(event)
