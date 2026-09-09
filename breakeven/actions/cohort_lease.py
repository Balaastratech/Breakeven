"""Single-writer cohort lease — F-ACT-26.

`docs/PRODUCTION_ACTION_LAYER.md` §5.13: two actions targeting overlapping cohorts can
interfere with each other, and their verifications become uninterpretable. Defence: a
single-writer lock per cohort — an action holds a lease over its cohort for the duration
of its verification window, and a conflicting action is rejected with a stated reason.

Time-windowed-read shape, same as `flap_suppression.py`'s four defences and for the same
reason (`INV-S01`, restated here because it is the invariant that actually matters):
nothing in this module schedules, cancels, delays, or reroutes a revert — the lease's only
effect is on whether a *new, conflicting* action gets to start at all, never on an
already-armed TTL watchdog.

**Design decision** (task 10's own prompt §2): a lease record carries its own
``expires_at_epoch`` — the same absolute clock `executor.execute_action` derives its own
``deadline_epoch`` from (``now + action.ttl.total_seconds()``), since the action's own TTL
already bounds the whole verification window worst-case. :func:`lease_held` and
:func:`lease_conflict_reason` read "is there a live, unexpired lease" rather than a
boolean some caller must remember to flip off — no code path requires the agent loop to
run again for the lease to end, which is what satisfies task 10 Assertion 3 (a crashed or
killed agent does not hold a lease forever) by construction, without a second
subprocess-and-watchdog mechanism duplicating `executor.py`'s own.

:func:`acquire_lease` is itself atomic — the live-holder re-check happens under the same
lock as the write, so two genuinely concurrent direct callers for one cohort can never
both be granted a lease. What is *not* atomic, and cannot be made so by this module alone,
is `breakeven.agents.remediator.remediate`'s own calling pattern: it reads
:func:`lease_conflict_reason` before `engine.execute` runs (so a foreseeable conflict is
caught before anything is mutated), but only calls :func:`acquire_lease` once the action
has genuinely executed — the same check-then-record split, and the same acknowledged race,
`flap_suppression.suspension_reason`/`record_execution` already carry. A second caller can
read "free" from the pre-execution check before the first caller's own post-execution
`acquire_lease` lands, and both mutate. Safe under this slice's single-remediation-worker
shape (`remediate` is called sequentially, never concurrently, in every caller in this
codebase today); acquiring the lease *before* `engine.execute` would close this fully, at
the cost of a lease held (until its own expiry) against an action that then fails policy
or mutation — a real tradeoff, not a bug, deferred the same way `remediate`'s own
docstring defers its sibling races until a concurrent remediator is introduced.

`INV-S02`: plain typed Python comparisons against stored state, no model call anywhere in
this module.

A corrupted or unreadable lease record fails toward **denying** the new action — treating
the cohort as leased, never as free — same fail-safe direction `flap_suppression.py`'s own
four defences already use (`silent-failure-hunter`, this task).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from breakeven.actions.executor import _locked, _write_text_atomic
from breakeven.actions.flap_suppression import _cohort_key
from breakeven.policy.engine import Cohort

_LOGGER = logging.getLogger(__name__)


class _CorruptLeaseRecord(ValueError):
    """A lease record exists but could not be read as one."""


def _lease_dir(state_dir: Path) -> Path:
    """Path only — never creates it. A read-only check (`lease_held`,
    `lease_conflict_reason`) must not create `state_dir` as a side effect of merely being
    asked a question, same reasoning as `flap_suppression._flap_dir`.
    """
    return state_dir / "lease"


def _lease_path(state_dir: Path, cohort: Cohort) -> Path:
    return _lease_dir(state_dir) / f"cohort_{_cohort_key(cohort)}.json"


def _lock_path(record_path: Path) -> Path:
    return record_path.with_suffix(record_path.suffix + ".lock")


def _read_record(path: Path) -> dict | None:
    """Return ``path``'s parsed, shape-checked lease record, or ``None`` if it does not
    exist yet.

    Raises :class:`_CorruptLeaseRecord` if the file exists but could not be read as one.
    Every caller treats that as "the cohort is leased", never as "the cohort is free" —
    ``silent-failure-hunter``, this task: a bare ``PermissionError`` or a torn read (any
    ``OSError`` other than "the file does not exist") must fail the same way a malformed
    JSON body does, exactly the fail-safe shape `flap_suppression._read_record` already
    uses.

    **Also raised for well-formed JSON that is not a lease record** — a bare ``null``, a
    list, or a ``dict`` missing ``holder_action_id``/``expires_at_epoch`` (or carrying the
    wrong type for either). ``silent-failure-hunter``, this task's own review: without
    this check, ``json.loads("null")`` returns ``None`` — indistinguishable from "the file
    does not exist" to every caller — so a syntactically-valid-but-semantically-empty
    record would have been read as *free*, precisely the direction this module's own
    fail-safe rule forbids. A ``dict`` missing a key would instead have reached
    :func:`_live_holder`'s subscript and raised a bare, uncaught ``KeyError`` from inside
    `remediator.remediate`'s post-execution `acquire_lease` call — after the action had
    already mutated production — which is not a graceful deny, it is an unguarded crash
    exactly where `remediate`'s own docstring says every check must not become one.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as unreadable:
        raise _CorruptLeaseRecord(f"{path}: {unreadable}") from unreadable
    try:
        record = json.loads(text)
    except json.JSONDecodeError as malformed:
        raise _CorruptLeaseRecord(f"{path}: {malformed}") from malformed
    if (
        not isinstance(record, dict)
        or not isinstance(record.get("holder_action_id"), str)
        or not record["holder_action_id"]
        or not isinstance(record.get("expires_at_epoch"), (int, float))
        or isinstance(record.get("expires_at_epoch"), bool)
    ):
        raise _CorruptLeaseRecord(f"{path}: not a lease record: {record!r}")
    return record


def _live_holder(record: dict | None, *, now: float) -> str | None:
    """Return the ``holder_action_id`` a live (unexpired) ``record`` names, or ``None`` if
    there is no record or its hold has already aged out."""
    if record is None:
        return None
    if now >= record["expires_at_epoch"]:
        return None
    return record["holder_action_id"]


def lease_held(cohort: Cohort, *, state_dir: Path, now: float) -> bool:
    """``True`` if ``cohort`` is currently held by a live, unexpired lease.

    Read-only, same as `flap_suppression`'s own read functions — an unreadable record is
    treated as held, never as free.
    """
    path = _lease_path(state_dir, cohort)
    try:
        record = _read_record(path)
    except _CorruptLeaseRecord as corrupt:
        _LOGGER.warning("treating cohort lease as held: %s", corrupt)
        return True
    return _live_holder(record, now=now) is not None


def lease_conflict_reason(cohort: Cohort, *, state_dir: Path, now: float) -> str | None:
    """Return why a new action against ``cohort`` must be refused right now, or ``None``
    if the cohort is free.

    The reason is always a real, human-readable string — F-ACT-26's own "conflicts queue
    or are rejected with a stated reason", never a bare ``False``/``None`` masquerading as
    one.
    """
    path = _lease_path(state_dir, cohort)
    try:
        record = _read_record(path)
    except _CorruptLeaseRecord as corrupt:
        _LOGGER.warning("treating cohort lease as held: %s", corrupt)
        return (
            f"cohort lease record at {path} is unreadable ({corrupt}); refusing to "
            "start a new action against a cohort that cannot be proven free"
        )
    holder = _live_holder(record, now=now)
    if holder is None:
        return None
    return (
        f"cohort is already leased by action {holder!r} for its own verification "
        "window; queue or retry once it settles"
    )


def acquire_lease(
    cohort: Cohort,
    *,
    holder_action_id: str,
    state_dir: Path,
    now: float,
    expires_at_epoch: float,
) -> str | None:
    """Record that ``holder_action_id`` holds ``cohort``'s lease until
    ``expires_at_epoch``.

    Returns ``None`` once the record is written. Returns a human-readable reason instead
    of writing anything, the same shape :func:`lease_conflict_reason` returns, if the
    cohort cannot be granted: the existing record is corrupted/unreadable (a caller must
    never be granted a lease over a cohort it cannot prove is actually free), or a
    *different* live lease already holds it. Re-checking the live holder here, under the
    same lock the write itself takes, makes **this function** atomic against another
    concurrent call to itself — see this module's own top-level docstring for the
    narrower race that remains in `remediator.remediate`'s own calling pattern, which no
    amount of atomicity inside this one function can close on its own.

    Called again for the same ``holder_action_id`` before ``expires_at_epoch`` (a retry
    of the same action), this refreshes the existing hold rather than conflicting with
    itself.
    """
    path = _lease_path(state_dir, cohort)
    with _locked(_lock_path(path)):
        try:
            record = _read_record(path)
        except _CorruptLeaseRecord as corrupt:
            _LOGGER.warning(
                "refusing to acquire cohort lease over an unreadable record: %s",
                corrupt,
            )
            return (
                f"cohort lease record at {path} is unreadable ({corrupt}); refusing to "
                "grant a new lease over a cohort that cannot be proven free"
            )
        holder = _live_holder(record, now=now)
        if holder is not None and holder != holder_action_id:
            return (
                f"cohort is already leased by action {holder!r} for its own "
                "verification window; queue or retry once it settles"
            )
        _write_text_atomic(
            path,
            json.dumps(
                {
                    "holder_action_id": holder_action_id,
                    "expires_at_epoch": expires_at_epoch,
                }
            ),
        )
        return None
