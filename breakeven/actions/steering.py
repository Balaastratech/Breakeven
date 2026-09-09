"""Bounded, hash-split pathway migration for content steering."""

from __future__ import annotations

import hashlib
import json
import random
import time
from contextlib import suppress
from collections.abc import Callable, Mapping, Sequence
from datetime import timedelta
from pathlib import Path

from breakeven.actions import audit, executor, flap_suppression, verification
from breakeven.policy import engine

RAMP_PCT = 0.10
_STEPS = 10


def in_ramp(channel_id: str, session_id: str, fraction: float) -> bool:
    """Return deterministic membership of one session in a ramp fraction."""
    bucket = int(
        hashlib.sha256(f"{channel_id}:{session_id}".encode()).hexdigest(), 16
    ) % 100
    return bucket < fraction * 100


def steer_pathway(
    cohort: engine.Cohort,
    target_priority: Sequence[str],
    ttl: float,
    *,
    telemetry: Mapping[str, int],
    baseline_5xx_rate: float,
    observe_5xx_rate: Callable[[], float],
    escalate: Callable[[str], None],
    state_dir: Path,
    log_path: Path,
    action_id_prefix: str,
    last_good_priority: Sequence[str],
    wait: Callable[[float], None] = time.sleep,
) -> str:
    """Migrate a cohort in ten hash-stable increments or restore it on a 5xx rise.

    The argument list is the established action entry point; the local state mirrors the
    one action per channel that owns the ramp's independent executor watchdog.
    """
    if ttl <= 0:
        raise ValueError("ttl must be positive")
    if not target_priority or not last_good_priority:
        raise ValueError("target_priority and last_good_priority must be non-empty")
    if cohort.channels == engine.WILDCARD:
        raise ValueError("steer_pathway requires named channels")

    target = tuple(target_priority)
    last_good = tuple(last_good_priority)
    # The executor's TTL must cover all bounded ramp/settlement waits. Its watchdog remains
    # the sole revert owner; this loop never schedules a second revert.
    action_ttl = timedelta(seconds=ttl * _STEPS * 3)

    actions: dict[str, engine.ActionResult] = {}
    target_paths: dict[str, Path] = {}
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
            predicted_effect="pathway migration keeps origin 5xx rate at baseline",
            verification_query=f"origin_5xx_rate{{channel_id={channel_id!r}}}",
            ttl=action_ttl,
        )
        target_path = state_dir / f"steer_{channel_id}.json"
        value = json.dumps(
            {
                "last_good_priority": list(last_good),
                "target_priority": list(target),
                "ramp_percent": RAMP_PCT,
            }
        )
        engine.execute(
            engine.ActionType.A1,
            action,
            telemetry,
            lambda action, target_path=target_path, value=value: executor.execute_action(
                action, state_dir=state_dir, target_path=target_path, new_value=value
            ),
        )
        actions[channel_id] = action
        target_paths[channel_id] = target_path

    for step in range(1, _STEPS + 1):
        fraction = round(step * RAMP_PCT, 1)
        for channel_id in sorted(cohort.channels):
            action = actions[channel_id]
            target_path = target_paths[channel_id]
            if step > 1:
                target_path.write_text(
                    json.dumps(
                        {
                            "last_good_priority": list(last_good),
                            "target_priority": list(target),
                            "ramp_percent": fraction,
                        }
                    ),
                    encoding="utf-8",
                )
            jittered_ttl = ttl * random.uniform(0.8, 1.2)
            wait(jittered_ttl * 1.5)
            proposal = verification.Proposal(
                action=action,
                threshold=3 * baseline_5xx_rate,
                direction=verification.ThresholdDirection.AT_MOST,
                agent_identity="steer_pathway",
            )
            try:
                entry = verification.settle(
                    proposal,
                    measure=lambda _query: observe_5xx_rate(),
                    escalate=escalate,
                    state_dir=state_dir,
                    log_path=log_path,
                )
            # `settle` intentionally re-raises BaseException after recording an audit
            # entry, including on an interrupt during measurement. The already-applied
            # action must still be reverted before this ramp returns.
            # pylint: disable=broad-exception-caught
            except BaseException:
                for other_action in actions.values():
                    with suppress(ValueError):
                        executor.revert_action(other_action.action_id, state_dir=state_dir)
                    flap_suppression.record_revert_if_it_happened(
                        other_action.action_id, state_dir=state_dir
                    )
                return "ABORTED"
            # `GAPS.md` #6: `settle()` may have already reverted `action` itself (e.g. on
            # `UNVERIFIED_REVERTED_AND_ESCALATED`) before returning `entry` — feed the
            # account-wide breaker here, the same way `remediator.remediate()` does right
            # after its own `settle()` call, so a pathway revert counts toward it too. A
            # no-op read when nothing was actually reverted.
            flap_suppression.record_revert_if_it_happened(
                action.action_id, state_dir=state_dir
            )
            if entry.result is audit.ActionOutcome.VERIFIED:
                continue
            for other_channel_id, other_action in actions.items():
                if other_channel_id != channel_id:
                    with suppress(ValueError):
                        executor.revert_action(other_action.action_id, state_dir=state_dir)
                    flap_suppression.record_revert_if_it_happened(
                        other_action.action_id, state_dir=state_dir
                    )
            if entry.result is not audit.ActionOutcome.UNVERIFIED_REVERTED_AND_ESCALATED:
                with suppress(ValueError):
                    executor.revert_action(action.action_id, state_dir=state_dir)
                flap_suppression.record_revert_if_it_happened(
                    action.action_id, state_dir=state_dir
                )
            return "ABORTED"

    return "COMPLETE"
