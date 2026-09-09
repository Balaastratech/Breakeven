"""Flap suppression — F-ACT-27, F-VER-08.

`docs/PRODUCTION_ACTION_LAYER.md` §5.12: steering back and forth between pathways is
worse than either endpoint, and is the classic control-loop failure. Four independent
defences, each with its own small persisted record, plain typed Python (`INV-S02`, no
model anywhere in this module):

* **per-action-type cooldown** — an action type that just ran must wait
  :data:`COOLDOWN_SECONDS` before it may run again, regardless of cohort.
* **hysteresis** — :func:`hysteresis_revert_threshold` widens the bar a verification must
  clear to be judged "held" so it is never the same value as the trigger threshold that
  caused the action to be proposed. A metric hovering right at the trigger line would
  otherwise flap the action on and off every settlement cycle.
* **a per-cohort hourly cap** — at most :data:`HOURLY_CAP_PER_COHORT` actions may execute
  against one cohort within :data:`HOURLY_CAP_WINDOW_SECONDS`, regardless of action type.
* **a circuit breaker** — :data:`BREAKER_TRIP_AFTER_K_REVERTS` reverts within
  :data:`BREAKER_WINDOW_SECONDS`, counted account-wide, suspends autonomy entirely.

**`INV-S01`, restated because it is the invariant that actually matters here:** nothing
in this module schedules, cancels, delays, or reroutes a revert. Every function here only
ever reads or appends to its own bookkeeping records. The breaker's only effect is on
:func:`suspension_reason`'s return value, which a caller (`breakeven.agents.remediator`)
reads to decide whether the *next* action needs a human's approval before it runs — an
already-armed TTL watchdog `executor.execute_action` spawned keeps running, unaided, on
its own schedule, exactly as if this module did not exist.

**Design decision, stated per this task's own prompt (§2):** `executor.py`'s per-action
state record has no execution-timestamp field — only `deadline_epoch` (an absolute future
expiry) and `reverted_at_epoch`. Rather than reconstruct one from `executor.py`'s state
(coupling this module to a record shape task 10 owns and did not design for this purpose)
or read `AuditEntry.timestamp` (stamped at settlement, a different moment from execution),
this module keeps its own small, explicit event records — `record_cooldown_trigger` and
`record_hourly_execution` are called once, by the caller, at the moment an action actually
executes. This is the same shape task 10's own idempotency claim files already use: one
small file per live fact, not a shared index.

A corrupted or unreadable record fails toward **denying** autonomy, never granting it —
`silent-failure-hunter`, this task: a record this module cannot read is exactly the
situation that must not be mistaken for "no defence is active".
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from enum import Enum, auto
from pathlib import Path

from breakeven.actions.executor import _locked, _write_text_atomic
from breakeven.actions.verification import RevertStatus, ThresholdDirection, revert_status_of
from breakeven.policy.engine import WILDCARD, ActionType, Cohort

_LOGGER = logging.getLogger(__name__)

# `K` in `PRODUCTION_ACTION_LAYER.md` §5.12's own words — named here, never a magic number
# at a call site (task 9 Assertion 6).
COOLDOWN_SECONDS: float = 300.0
HOURLY_CAP_PER_COHORT: int = 3
HOURLY_CAP_WINDOW_SECONDS: float = 3600.0
BREAKER_TRIP_AFTER_K_REVERTS: int = 3
BREAKER_WINDOW_SECONDS: float = 3600.0

# The fraction of the trigger threshold's own magnitude the revert threshold is offset
# by. Proportional rather than a fixed absolute unit because this module has no idea what
# scale a given `verification_query` measures (a viewer count in the thousands, a ratio
# between 0 and 1) — a fixed absolute band would be enormous for one and meaningless for
# the other.
HYSTERESIS_BAND: float = 0.1

# ponytail: guards `trigger_threshold == 0.0`, where a proportional band computes to zero
# and would silently defeat "the revert threshold is never the same value as the trigger"
# (task 9 Assertion 2). Add a per-metric absolute override if a real `verification_query`
# threshold is ever legitimately zero and this floor is not enough margin for it.
_HYSTERESIS_MIN_ABSOLUTE_BAND: float = 1e-9


class SuspensionReason(Enum):
    """Why :func:`suspension_reason` says the next action needs a human, ordered the way
    a human reading an escalation would find most actionable: account-wide first, then
    the narrower cohort scope, then the narrowest type scope."""

    BREAKER_TRIPPED = auto()
    HOURLY_CAP_REACHED = auto()
    COOLDOWN_ACTIVE = auto()


class _CorruptFlapRecord(ValueError):
    """A flap-suppression record exists but could not be read as one."""


def hysteresis_revert_threshold(
    trigger_threshold: float,
    direction: ThresholdDirection,
    *,
    band: float = HYSTERESIS_BAND,
) -> float:
    """Return the threshold a verification should use to decide whether an action's
    effect *held*, offset from ``trigger_threshold`` so the two are never equal —
    task 9 Assertion 2.

    ``direction`` decides which way the bar moves. :attr:`ThresholdDirection.AT_MOST`
    (verification holds when ``observed <= threshold`` — e.g. an error rate that must
    stay low) widens the bar **upward**: the revert threshold tolerates a somewhat higher
    observed value than the raw trigger before judging the effect not to have held.
    :attr:`ThresholdDirection.AT_LEAST` (holds when ``observed >= threshold`` — e.g. a
    fill rate that must stay high) widens it **downward**, tolerating a somewhat lower
    observed value. Either way the bar to *revert* is more forgiving than the bar that
    caused the action to be proposed in the first place — a metric sitting exactly at the
    trigger line no longer flaps the action on and off every settlement cycle.

    A single shared threshold (calling this a no-op, or omitting it and passing
    ``trigger_threshold`` straight through) would silently defeat hysteresis's whole
    purpose — task 9 Assertion 2 exists specifically to catch that.
    """
    delta = abs(trigger_threshold) * band
    if delta == 0:
        delta = _HYSTERESIS_MIN_ABSOLUTE_BAND
    if direction is ThresholdDirection.AT_MOST:
        return trigger_threshold + delta
    return trigger_threshold - delta


def _flap_dir(state_dir: Path) -> Path:
    """Path only — never creates it. A read-only check (`cooldown_active`,
    `hourly_cap_reached`, `breaker_tripped`) must not create `state_dir` as a side effect
    of merely being asked a question; `tests/test_remediator.py::
    test_over_scoped_proposal_is_rejected_before_the_executor_runs` asserts exactly that
    for a rejected proposal. The write functions below still work without this creating
    anything: `_locked` already creates its lock file's parent directory before writing.
    """
    return state_dir / "flap"


def _cohort_key(cohort: Cohort) -> str:
    """A stable digest of ``cohort``'s content, ignoring which action type or failure
    caused it — the hourly cap is scoped to the cohort alone (task 9 Assertion 7).

    Same construction as `breakeven.policy.engine.idempotency_key`'s cohort payload:
    every dimension's members sorted, so two structurally-equal cohorts built in
    different orders collide on the same key, and hashed so the result is safe as a
    filename component.
    """
    payload = json.dumps(
        {
            "channels": (
                WILDCARD if cohort.channels == WILDCARD else sorted(cohort.channels)
            ),
            "regions": (
                WILDCARD if cohort.regions == WILDCARD else sorted(cohort.regions)
            ),
            "devices": (
                WILDCARD if cohort.devices == WILDCARD else sorted(cohort.devices)
            ),
            "cdn_pathways": (
                WILDCARD
                if cohort.cdn_pathways == WILDCARD
                else sorted(cohort.cdn_pathways)
            ),
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _cooldown_path(state_dir: Path, action_type: ActionType) -> Path:
    return _flap_dir(state_dir) / f"cooldown_{action_type.value}.json"


def _hourly_path(state_dir: Path, cohort: Cohort) -> Path:
    return _flap_dir(state_dir) / f"hourly_{_cohort_key(cohort)}.json"


def _breaker_path(state_dir: Path) -> Path:
    return _flap_dir(state_dir) / "breaker.json"


def _lock_path(record_path: Path) -> Path:
    return record_path.with_suffix(record_path.suffix + ".lock")


def _read_record(
    path: Path, *, required_key: str, value_type: type | tuple[type, ...]
) -> dict | None:
    """Return ``path``'s parsed, shape-checked record, or ``None`` if it does not exist yet.

    Raises :class:`_CorruptFlapRecord` if the file exists but could not be read as one —
    every caller of this function treats that as "the defence is active", never as
    "the defence has no record yet", per this module's own stated fail-safe direction.
    ``silent-failure-hunter``, this task: a bare ``PermissionError`` or a torn read (any
    ``OSError`` other than "the file does not exist") must fail the same way a malformed
    JSON body does — only :class:`FileNotFoundError` means "no record", every other
    reason this call could not produce trustworthy content means "cannot be trusted".

    **Also raised for well-formed JSON that is not this record's shape** — a bare
    ``null``, a list, or a ``dict`` missing ``required_key`` (or carrying the wrong type
    for it) — the same residual gap `cohort_lease._read_record` closed for its own record
    shape, found on this file during the batched Task 6-10 review: without this,
    ``json.loads("null")`` returns ``None``, indistinguishable from "the file does not
    exist" to every caller, so a syntactically-valid-but-empty record would have been read
    as *no defence active* — the exact permissive direction this module's own fail-safe
    rule forbids. A ``dict`` missing the key would instead reach a bare, uncaught
    ``KeyError`` from inside `cooldown_active`/`hourly_cap_reached`/`breaker_tripped`,
    not a graceful "treat as active" deny.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as unreadable:
        raise _CorruptFlapRecord(f"{path}: {unreadable}") from unreadable
    try:
        record = json.loads(text)
    except json.JSONDecodeError as malformed:
        raise _CorruptFlapRecord(f"{path}: {malformed}") from malformed
    value = record.get(required_key) if isinstance(record, dict) else None
    if (
        not isinstance(record, dict)
        or not isinstance(value, value_type)
        or isinstance(value, bool)
    ):
        raise _CorruptFlapRecord(f"{path}: not a flap-suppression record: {record!r}")
    return record


def cooldown_active(action_type: ActionType, *, state_dir: Path, now: float) -> bool:
    """``True`` if ``action_type`` executed within the last :data:`COOLDOWN_SECONDS`,
    scoped only by type — never by cohort (task 9 Assertion 7).

    An unreadable record is treated as an active cooldown, not an absent one — a record
    this function cannot trust must never be read as permission to proceed.
    """
    path = _cooldown_path(state_dir, action_type)
    try:
        record = _read_record(
            path, required_key="last_executed_epoch", value_type=(int, float)
        )
    except _CorruptFlapRecord as corrupt:
        _LOGGER.warning("treating cooldown as active: %s", corrupt)
        return True
    if record is None:
        return False
    return (now - record["last_executed_epoch"]) < COOLDOWN_SECONDS


def record_cooldown_trigger(
    action_type: ActionType, *, state_dir: Path, now: float
) -> None:
    """Record that ``action_type`` executed at ``now``, starting its cooldown window."""
    path = _cooldown_path(state_dir, action_type)
    with _locked(_lock_path(path)):
        _write_text_atomic(path, json.dumps({"last_executed_epoch": now}))


def hourly_cap_reached(cohort: Cohort, *, state_dir: Path, now: float) -> bool:
    """``True`` if :data:`HOURLY_CAP_PER_COHORT` actions have already executed against
    ``cohort`` within the trailing :data:`HOURLY_CAP_WINDOW_SECONDS`, scoped only by
    cohort — never by action type, so two different types against the same cohort share
    one cap (task 9 Assertion 7).

    An unreadable record is treated as the cap being reached, for the same fail-safe
    reason as :func:`cooldown_active`.
    """
    path = _hourly_path(state_dir, cohort)
    try:
        record = _read_record(path, required_key="executed_epochs", value_type=list)
    except _CorruptFlapRecord as corrupt:
        _LOGGER.warning("treating hourly cap as reached: %s", corrupt)
        return True
    if record is None:
        return False
    live = [
        epoch
        for epoch in record["executed_epochs"]
        if now - epoch < HOURLY_CAP_WINDOW_SECONDS
    ]
    return len(live) >= HOURLY_CAP_PER_COHORT


def record_hourly_execution(cohort: Cohort, *, state_dir: Path, now: float) -> None:
    """Record that an action executed against ``cohort`` at ``now``, pruning any
    timestamp that has already aged out of the trailing window."""
    path = _hourly_path(state_dir, cohort)
    with _locked(_lock_path(path)):
        try:
            record = _read_record(path, required_key="executed_epochs", value_type=list)
        except _CorruptFlapRecord:
            # A corrupted record blocks reads (`hourly_cap_reached` above), but this is a
            # write: the honest content going forward is what this call itself knows, not
            # a history this function can no longer trust either way.
            record = None
        live = (
            []
            if record is None
            else [
                epoch
                for epoch in record["executed_epochs"]
                if now - epoch < HOURLY_CAP_WINDOW_SECONDS
            ]
        )
        live.append(now)
        _write_text_atomic(path, json.dumps({"executed_epochs": live}))


def breaker_tripped(*, state_dir: Path, now: float) -> bool:
    """``True`` if :data:`BREAKER_TRIP_AFTER_K_REVERTS` reverts have landed within the
    trailing :data:`BREAKER_WINDOW_SECONDS`, counted account-wide — `PRODUCTION_ACTION_
    LAYER.md` §5.12 says the breaker "suspends autonomous action entirely", not one type
    or one cohort's worth.

    An unreadable record is treated as tripped, for the same fail-safe reason as
    :func:`cooldown_active`.
    """
    path = _breaker_path(state_dir)
    try:
        record = _read_record(path, required_key="revert_epochs", value_type=list)
    except _CorruptFlapRecord as corrupt:
        _LOGGER.warning("treating breaker as tripped: %s", corrupt)
        return True
    if record is None:
        return False
    live = [
        epoch
        for epoch in record["revert_epochs"]
        if now - epoch < BREAKER_WINDOW_SECONDS
    ]
    return len(live) >= BREAKER_TRIP_AFTER_K_REVERTS


def record_revert(*, state_dir: Path, now: float) -> None:
    """Record that a revert landed at ``now``, for the account-wide breaker's count.

    Called after `executor.revert_action` (directly, or via `verification.settle`'s own
    call to it) has already completed — this is bookkeeping about a revert that already
    happened, never a trigger for one (`INV-S01`)."""
    path = _breaker_path(state_dir)
    with _locked(_lock_path(path)):
        try:
            record = _read_record(path, required_key="revert_epochs", value_type=list)
        except _CorruptFlapRecord:
            record = None
        live = (
            []
            if record is None
            else [
                epoch
                for epoch in record["revert_epochs"]
                if now - epoch < BREAKER_WINDOW_SECONDS
            ]
        )
        live.append(now)
        _write_text_atomic(path, json.dumps({"revert_epochs": live}))


def record_revert_if_it_happened(action_id: str, *, state_dir: Path) -> None:
    """Feed the account-wide breaker's revert count from the executor's own state
    record — the single source of truth :func:`revert_status_of` already reads.

    `GAPS.md` #6: this used to live only inside `remediator.remediate()` (as a private
    `_record_revert_if_it_happened`), called once after every A3/A4 `settle()`. A1's own
    remedy (`actions.steering.steer_pathway`) has its own independent revert loop and
    never went through `remediate()`, so a pathway revert was never counted toward this
    breaker at all — moved here, package-level, so both callers share one implementation
    instead of the gap reappearing the next time a third remedy shape is added.

    Never raises: a bookkeeping read failing here must not replace whatever exception or
    return value the caller is already propagating.
    """
    try:
        reverted = revert_status_of(action_id, state_dir=state_dir) is RevertStatus.REVERTED
    except (ValueError, OSError):
        _LOGGER.exception(
            "could not determine revert status of action %s for flap-suppression "
            "bookkeeping; the breaker's revert count may undercount this one",
            action_id,
        )
        return
    if reverted:
        record_revert(state_dir=state_dir, now=time.time())


def suspension_reason(
    action_type: ActionType,
    cohort: Cohort,
    *,
    state_dir: Path,
    now: float,
) -> SuspensionReason | None:
    """Return why ``action_type`` on ``cohort`` must be held for a human's approval right
    now, or ``None`` if none of the three stateful defences are active (hysteresis is not
    one of these — it changes what "held" means during verification, not whether a new
    action may start).

    Checked account-wide first, then per-cohort, then per-type — the broadest defence a
    human would need to clear first.

    ponytail: this decision and the caller's later `record_execution` are not one atomic
    step — a second caller can read `None` here before the first caller's own execution
    is recorded, and both proceed. Safe under this slice's single-remediation-worker
    shape (`breakeven.agents.remediator.remediate` is called sequentially, never
    concurrently, in every caller in this codebase today); add a lock spanning
    decide-through-record, keyed by `(action_type, cohort)`, if a concurrent remediator
    is ever introduced.
    """
    if breaker_tripped(state_dir=state_dir, now=now):
        return SuspensionReason.BREAKER_TRIPPED
    if hourly_cap_reached(cohort, state_dir=state_dir, now=now):
        return SuspensionReason.HOURLY_CAP_REACHED
    if cooldown_active(action_type, state_dir=state_dir, now=now):
        return SuspensionReason.COOLDOWN_ACTIVE
    return None


def record_execution(
    action_type: ActionType, cohort: Cohort, *, state_dir: Path, now: float
) -> None:
    """Record that an action of ``action_type`` executed against ``cohort`` at ``now`` —
    both the cooldown and the hourly-cap records in one call, since every real execution
    feeds both.

    ponytail: the two writes are each individually atomic (`_write_text_atomic`) but not
    atomic as a pair — a crash between them leaves one recorded and the other silently
    not. That failure direction is the permissive one (an execution that happened
    becomes invisible to whichever record missed its write), the opposite of this
    module's stated "fail toward denying" rule elsewhere. Narrow window (a `SIGKILL`
    between two already-fast local writes); combine the two into one record keyed by
    ``(action_type, cohort)`` under a single lock if this ever needs closing.
    """
    record_cooldown_trigger(action_type, state_dir=state_dir, now=now)
    record_hourly_execution(cohort, state_dir=state_dir, now=now)
