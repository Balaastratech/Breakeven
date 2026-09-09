"""Accessibility-safe A2 ladder-rung actions."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import timedelta
from pathlib import Path

from breakeven.actions import executor
from breakeven.policy import engine
from breakeven.sim.renditions import LADDER_BY_CHANNEL

# Keep the action layer independent of the simulator it acts upon; this mirrors the
# literal policy ceilings in engine.py. A second class is a one-word data change.
DEVICE_STEERING_CAPABLE: frozenset[str] = frozenset({"ctv"})


class AccessibilityReject(Exception):
    """Raised when a requested rung carries caption or audio-description signalling."""


AccessibilityRefusal = AccessibilityReject


class UnsupportedDeviceClass(Exception):
    """Raised before an action reaches the policy engine for an ineligible device."""


def require_device_capable(device_class: str) -> None:
    """Reject device classes that cannot use Plane A steering."""
    if device_class not in DEVICE_STEERING_CAPABLE:
        raise UnsupportedDeviceClass(f"unsupported device class: {device_class}")


def set_ladder_rungs(
    cohort: engine.Cohort,
    disable: frozenset[str],
    *,
    device_class: str,
    telemetry: Mapping[str, int],
    escalate: Callable[[str], None],
    state_dir: Path,
    action_id_prefix: str,
    ttl: timedelta,
) -> None:
    """Disable named non-accessibility rungs through the existing A2 executor path."""
    require_device_capable(device_class)
    if cohort.channels == engine.WILDCARD:
        raise ValueError("set_ladder_rungs requires named channels")

    candidates: dict[str, frozenset[str]] = {}
    protected: dict[str, frozenset[str]] = {}
    known_ids: set[str] = set()
    for channel_id in cohort.channels:
        try:
            ladder = LADDER_BY_CHANNEL[channel_id]
        except KeyError as error:
            raise ValueError(f"no rendition ladder for channel {channel_id!r}") from error
        protected_ids = frozenset(
            rendition.rendition_id
            for rendition in ladder
            if rendition.carries_captions or rendition.carries_audio_description
        )
        channel_ids = frozenset(rendition.rendition_id for rendition in ladder)
        candidates[channel_id] = channel_ids - protected_ids
        protected[channel_id] = protected_ids
        known_ids.update(channel_ids)

    unknown_ids = disable - known_ids
    if unknown_ids:
        raise ValueError(f"unknown rendition id: {sorted(unknown_ids)[0]}")

    for channel_id in sorted(cohort.channels):
        refused_ids = disable & protected[channel_id]
        if refused_ids:
            rung_id = sorted(refused_ids)[0]
            message = f"refusing to disable accessibility rung {rung_id} on {channel_id}"
            escalate(message)
            raise AccessibilityRefusal(message)

    applied_actions: list[engine.ActionResult] = []
    try:
        for channel_id in sorted(cohort.channels):
            channel_cohort = engine.Cohort(
                channels=frozenset({channel_id}),
                regions=cohort.regions,
                devices=cohort.devices,
                cdn_pathways=cohort.cdn_pathways,
            )
            action = engine.ActionResult(
                action_id=f"{action_id_prefix}-{channel_id}",
                reversible=True,
                blast_radius=channel_cohort,
                predicted_effect="disable selected non-accessibility ladder rungs",
                verification_query=f"disabled_ladder_rungs{{channel_id={channel_id!r}}}",
                ttl=ttl,
            )
            disabled_ids = disable & candidates[channel_id]
            target_path = state_dir / f"rungs_{channel_id}.json"
            value = json.dumps(sorted(disabled_ids))
            # Record before executing: executor mutates before watchdog spawn.
            # suppress(ValueError) makes a never-executed action safe to revert.
            applied_actions.append(action)
            engine.execute(
                engine.ActionType.A2,
                action,
                telemetry,
                lambda action, target_path=target_path, value=value: executor.execute_action(
                    action,
                    state_dir=state_dir,
                    target_path=target_path,
                    new_value=value,
                ),
            )
    except BaseException:
        for applied_action in applied_actions:
            with suppress(ValueError):
                executor.revert_action(applied_action.action_id, state_dir=state_dir)
        raise
