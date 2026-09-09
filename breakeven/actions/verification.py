"""Pre-registered verification and settlement — F-ACT-22.

`PRODUCTION_ACTION_LAYER.md` §4.1: *every autonomous action is an experiment with a
deadline.* An action declares, **at proposal time**, what effect it predicts, the query
that will check it, and the threshold that query must meet. Within the verification window
the predicted effect must be demonstrated; if it is not, the action is reverted and a human
is escalated to, and both facts are written to the append-only audit log (`F-ACT-29`).

Three boundaries this module deliberately does not cross:

* **It owns no timer.** `INV-S01` gives the revert exactly one owner — task 10's executor
  and the detached watchdog it spawns. :func:`settle` *calls* `revert_action`; it never
  schedules, sleeps, or spawns. When to call it is the caller's decision, and the upper
  bound is already enforced elsewhere: at TTL expiry the watchdog reverts regardless, and
  :func:`settle` then refuses to record a verdict at all (see its docstring).
* **It runs no model.** `INV-S02` — the threshold comparison is one Python operator, in
  :meth:`ThresholdDirection.holds`. Nothing here can be argued with.
* **It does not extend `breakeven.policy.engine`.** The threshold lives on
  :class:`Proposal` because `ActionResult` is task 9's reviewed six-field contract; a
  proposal is the pairing of that contract with the bar its verification must clear.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from breakeven.actions.audit import (
    ActionOutcome,
    AuditEntry,
    RevertStatus,
    append_entry,
    now_stamp,
)

# `_state_path` is imported rather than reimplemented on purpose: `executor._action_file`
# is documented as the one place any per-action path is built, and therefore the one place
# `action_id` is validated as a filename component. Rebuilding the path here would be a
# second, unguarded construction site for attacker-influenced data (task 13 lets a model
# populate `action_id`).
from breakeven.actions.executor import _state_path, revert_action
from breakeven.policy.engine import WILDCARD, ActionResult, Cohort

_REVERT_STATUS_BY_RECORD_STATUS: Mapping[str, RevertStatus] = {
    "executed": RevertStatus.NOT_REVERTED,
    "reverting": RevertStatus.REVERTING,
    "reverted": RevertStatus.REVERTED,
}


class ThresholdDirection(Enum):
    """Which side of the threshold the observed value has to be on.

    Both directions are real in this domain and neither is a default: rebuffer ratio and
    error rate must come down (``AT_MOST``), fill rate and revenue must come up
    (``AT_LEAST``). A single hardcoded direction would silently invert verification for
    half of `PRODUCTION_ACTION_LAYER.md` §3's catalog.
    """

    AT_MOST = "at_most"
    AT_LEAST = "at_least"

    def holds(self, observed: float, threshold: float) -> bool:
        """The whole decision, in one Python comparison (`INV-S02`)."""
        if self is ThresholdDirection.AT_MOST:
            return observed <= threshold
        return observed >= threshold


@dataclass(frozen=True)
class Proposal:
    """An action plus the bar its verification must clear, declared before it runs.

    Frozen: a threshold that can be lowered after the measurement is not a
    pre-registration, it is a rationalisation.
    """

    action: ActionResult
    threshold: float
    direction: ThresholdDirection
    agent_identity: str

    def __post_init__(self) -> None:
        if not isinstance(self.action, ActionResult):
            raise ValueError(
                f"Proposal.action must be an ActionResult, got {self.action!r}"
            )
        # Re-checked here, not merely inherited from `ActionResult.__post_init__`.
        # F-ACT-22's assertion is that the *proposal* is rejected, and from task 13 the
        # proposal is the trust boundary where a model's output enters the safety kernel.
        for name in ("predicted_effect", "verification_query"):
            if not str(getattr(self.action, name) or "").strip():
                raise ValueError(
                    f"Proposal requires action.{name}; an action with no {name} cannot "
                    "be verified, so it must not be proposed"
                )
        if not self.agent_identity.strip():
            raise ValueError(
                "Proposal.agent_identity is required; an audit entry with no author "
                "cannot be followed up"
            )
        if not isinstance(self.direction, ThresholdDirection):
            raise ValueError(
                "Proposal.direction must be a ThresholdDirection, got "
                f"{self.direction!r}"
            )
        self._require_usable_threshold()

    def _require_usable_threshold(self) -> None:
        """``nan`` compares false against everything, so every action would fail
        verification and revert; ``inf`` compares true in one direction, so none ever
        would. Both are silent, and they fail in opposite directions."""
        if self.threshold is None or isinstance(self.threshold, bool):
            raise ValueError(
                f"Proposal.threshold is required as a number, got {self.threshold!r}"
            )
        if not isinstance(self.threshold, (int, float)):
            raise ValueError(
                f"Proposal.threshold must be a number, got {self.threshold!r}"
            )
        if not math.isfinite(self.threshold):
            raise ValueError(
                f"Proposal.threshold must be finite, got {self.threshold!r}"
            )


def revert_status_of(action_id: str, *, state_dir: Path) -> RevertStatus:
    """Read where ``action_id`` stands from the executor's own state record.

    Never inferred, never remembered: the record is the single writer of revert state
    (`D-S34`, `D-S36`), and an audit entry that guessed would eventually disagree with it.

    Raises :class:`ValueError` naming ``action_id`` if no record exists, and again if the
    record carries a status this mapping does not know — a fourth status added to the
    executor one day must break loudly here rather than map silently onto "no revert
    happened".
    """
    state_path = _state_path(state_dir, action_id)
    if not state_path.exists():
        raise ValueError(
            f"action {action_id!r} was never executed; it has no revert status"
        )
    try:
        status = json.loads(state_path.read_text(encoding="utf-8"))["status"]
    except (json.JSONDecodeError, KeyError, TypeError) as unreadable:
        raise ValueError(
            f"action {action_id!r} has an unreadable revert-status record: "
            f"{unreadable!r}"
        ) from unreadable
    try:
        return _REVERT_STATUS_BY_RECORD_STATUS[status]
    # `TypeError` alongside `KeyError`: a mapping whose `"status"` *value* is itself
    # unhashable (a `list`, a `dict`) reaches this lookup fine — the subscript above
    # already succeeded — and fails here instead, on the dict lookup rather than the
    # dict access. Same fix shape as the subscript's own `except` tuple above.
    except (KeyError, TypeError) as unknown_status:
        raise ValueError(
            f"action {action_id!r} has unrecognised record status {status!r}; refusing "
            "to guess a revert status"
        ) from unknown_status


def settle(
    proposal: Proposal,
    *,
    measure: Callable[[str], float],
    escalate: Callable[[str], None],
    state_dir: Path,
    log_path: Path,
) -> AuditEntry:
    """Run the verification query, compare it to the threshold, and settle the action.

    Verified: nothing is touched, and one audit entry records that it held. Unverified:
    the action is reverted through task 10's :func:`revert_action` — never a second
    scheduling path (`INV-S01`) — a human is escalated to, and one audit entry records
    both before this function returns.

    **Exactly one entry is written on every path, including a `measure` call that raises**,
    or a path where the revert or the escalation itself fails. A `measure` failure becomes
    :attr:`ActionOutcome.UNVERIFIED_MEASUREMENT_FAILED` — no verdict was ever reached, so it
    is never recorded as :attr:`ActionOutcome.UNVERIFIED_SETTLEMENT_FAILED`, which presumes a
    verdict ("did not hold") was already computed before settlement itself failed. Both
    become an evidence-chain entry with the error, and the exception is re-raised
    afterwards — so a failed measurement or a failed settlement can neither be mistaken for
    a successful one nor disappear.

    Raises :class:`ValueError` if the action has no state record, or if its record is
    already ``"reverting"``/``"reverted"``. The second case is the one that matters: once
    the watchdog has fired, the query would be measuring a world that has already been put
    back, and recording ``VERIFIED`` against it would be a false green about the one thing
    this system exists to be honest about.

    **One deliberate ceiling, stated rather than implied.** This function never waits:
    calling it before the predicted effect has had time to appear will measure too early and
    revert a working action. Timing belongs to the caller, because a timer here would be a
    second owner of `INV-S01`. (A `measure` failure is no longer a silent ceiling — see
    above; the TTL watchdog still owns the eventual revert either way.)
    """
    action = proposal.action
    status = revert_status_of(action.action_id, state_dir=state_dir)
    if status is not RevertStatus.NOT_REVERTED:
        raise ValueError(
            f"action {action.action_id!r} is already {status.value}; its verification "
            "window is over and its outcome cannot be recorded now"
        )

    evidence: list[Mapping[str, object]] = []
    outcome = ActionOutcome.VERIFIED
    settlement_error: BaseException | None = None
    try:
        observed = measure(action.verification_query)
    # By this point `engine.execute` has already mutated production (this is the same
    # ordering `remediate`'s own `wait`/`settle` chaining fix already protects one call up
    # the stack). A `measure` failure here — a real Grafana/metrics round trip failing in
    # production — must not skip the audit write the way the sibling `wait()` gap once did.
    # `BaseException`, not `Exception`, for the same reason as the `not holds` branch below:
    # a Ctrl-C landing mid-measurement is exactly when the trace matters most.
    # pylint: disable=broad-exception-caught
    except BaseException as error:
        settlement_error = error
        outcome = ActionOutcome.UNVERIFIED_MEASUREMENT_FAILED
        evidence.append(
            {
                "query": action.verification_query,
                "measurement_error": _describe(error),
            }
        )
    else:
        holds = math.isfinite(observed) and proposal.direction.holds(
            observed, proposal.threshold
        )
        evidence.append(_measurement_evidence(proposal, observed, holds))

        if not holds:
            try:
                revert_action(action.action_id, state_dir=state_dir)
                escalate(_escalation_message(proposal, observed))
                outcome = ActionOutcome.UNVERIFIED_REVERTED_AND_ESCALATED
            # Nothing is swallowed here: the error is recorded, then re-raised below. The
            # point of catching it at all is that the audit entry must exist *before* the
            # exception leaves this function, or a failed revert or a failed page leaves no
            # trace of an action that is still applied. `BaseException` rather than
            # `Exception` because a Ctrl-C landing mid-revert is exactly when the trace
            # matters most, and re-raising keeps it fatal.
            # pylint: disable=broad-exception-caught
            except BaseException as error:
                settlement_error = error
                outcome = ActionOutcome.UNVERIFIED_SETTLEMENT_FAILED
                evidence.append({"settlement_error": _describe(error)})

    # The status is re-read rather than assumed: on the reverted path the record moved,
    # and on the verified path the watchdog may have fired during `measure`. That read can
    # fail too (a vanished `state_dir`), and when it does the entry must still be written —
    # losing the whole audit record to a follow-up lookup would be the larger failure.
    # `status` then keeps the last value actually observed, the reason is recorded, and an
    # earlier settlement error keeps precedence so this one cannot mask it.
    try:
        status = revert_status_of(action.action_id, state_dir=state_dir)
    except (ValueError, OSError) as error:
        evidence.append({"revert_status_error": _describe(error)})
        if settlement_error is None:
            settlement_error = error
    else:
        # `outcome` was fixed from `holds` before this read happened. If the world held
        # (`outcome` still `VERIFIED`) but the record has since moved off `NOT_REVERTED`,
        # the TTL watchdog fired *during* `measure` — the measurement describes a world
        # that no longer exists. This is not the `if not holds:` case above (that is a
        # verdict the effect did not hold); it is the honest absence of any verdict, and
        # `settle` must not become a second owner of the revert (`INV-S01`) to record it —
        # only read what the watchdog already did and say so.
        if (
            outcome is ActionOutcome.VERIFIED
            and status is not RevertStatus.NOT_REVERTED
        ):
            # `D-S40`: `REVERTED` and `REVERTING` are no longer treated alike.
            # `REVERTED` means the watchdog finished; nothing more to do. `REVERTING`
            # means the watchdog started and died before recording completion
            # (`D-S36`) — `settle` completes it, the one circumstance
            # `revert_action`'s own docstring names ("a later watchdog, an operator
            # tool"). This completes an already-scheduled revert; it does not
            # schedule a second one (`INV-S01`).
            completed_by_settle = status is RevertStatus.REVERTING
            try:
                if completed_by_settle:
                    revert_action(action.action_id, state_dir=state_dir)
                    # Re-read rather than assumed — the module's own stated
                    # principle, "never inferred, never remembered". But `revert_action`
                    # above already succeeded (no exception reached this line), so if
                    # *this* read itself fails — a vanished `state_dir`, a transient
                    # `OSError` — `status` must not be left holding the stale pre-revert
                    # value the outer read produced two blocks up. That would write a
                    # permanent audit entry claiming `REVERTING` for an action that is,
                    # in reality, genuinely reverted (K-item-G). The real state is known
                    # here regardless of whether the confirmation read succeeds, so it is
                    # asserted directly, and the read failure is recorded as evidence
                    # rather than discarded.
                    try:
                        status = revert_status_of(action.action_id, state_dir=state_dir)
                    except (ValueError, OSError) as reread_error:
                        status = RevertStatus.REVERTED
                        evidence.append(
                            {
                                "revert_confirmation_reread_error": _describe(
                                    reread_error
                                )
                            }
                        )
                evidence.append(
                    {
                        "reverted_by_ttl_during_measurement": status.value,
                        "completed_by_settle": completed_by_settle,
                    }
                )
                escalate(
                    _ttl_race_escalation_message(proposal, status, completed_by_settle)
                )
                outcome = ActionOutcome.UNVERIFIED_REVERTED_BY_TTL
            # Same reasoning as the `if not holds:` branch above: nothing on this path
            # may disappear silently, so it is caught, recorded, and re-raised.
            # pylint: disable=broad-exception-caught
            except BaseException as error:
                settlement_error = error
                outcome = ActionOutcome.UNVERIFIED_SETTLEMENT_FAILED
                evidence.append({"settlement_error": _describe(error)})

    entry = AuditEntry(
        agent_identity=proposal.agent_identity,
        timestamp=now_stamp(),
        arguments=_arguments(proposal),
        evidence_chain=tuple(evidence),
        result=outcome,
        revert_status=status,
    )
    try:
        append_entry(entry, log_path=log_path)
    # `K-R02`: `audit.append_entry`'s `json.dumps` now passes `allow_nan=False`
    # (`K-P06-11`), a new `ValueError` mode this guard did not catch — the two
    # `remediator.py` call sites into `append_entry` already catch `(OSError,
    # ValueError)`; widened here to match, so this chokepoint does not depend on every
    # caller pre-sanitising, exactly `K-P06-11`'s own stated purpose.
    except (OSError, ValueError) as error:
        # There is nowhere left to record anything, so this one propagates — but it must
        # not become the only thing the caller hears about. Chaining the settlement error
        # underneath keeps both in the traceback.
        if settlement_error is None:
            raise
        raise error from settlement_error

    if settlement_error is not None:
        raise settlement_error
    return entry


def _describe(error: BaseException) -> str:
    """``repr(error)`` where possible, the exception's type name where it is not.

    An exception's own ``__repr__`` can raise — task 10's review found exactly that costing
    a failure record. Here it would cost the audit entry, so the description is built
    defensively: the class name always survives, and it is the part that identifies what
    went wrong.
    """
    try:
        return repr(error)
    # pylint: disable=broad-exception-caught
    except BaseException:
        return type(error).__name__


def _measurement_evidence(
    proposal: Proposal, observed: float, holds: bool
) -> dict[str, object]:
    """The evidence chain's first item: the raw measurement plus the verdict against it.

    `nan` compares false against everything and `inf` compares true in one direction
    (the same hazard `Proposal._require_usable_threshold` already rejects on the
    threshold side), so a non-finite ``observed`` is marked explicitly rather than left
    to an accidental side effect of Python's comparison semantics — and stored as a
    JSON-safe string (`"inf"`/`"nan"`) rather than the raw float, so `json.dumps` is
    never asked to serialise `Infinity`/`NaN`, non-standard tokens a strict JSON consumer
    rejects, defeating `F-ACT-29`'s "Exportable" claim for this entry.
    """
    is_finite = math.isfinite(observed)
    item: dict[str, object] = {
        "query": proposal.action.verification_query,
        "observed": observed if is_finite else repr(observed),
        "threshold": proposal.threshold,
        "direction": proposal.direction.value,
        "holds": holds,
    }
    if not is_finite:
        item["observed_non_finite"] = True
    return item


def _escalation_message(proposal: Proposal, observed: float) -> str:
    action = proposal.action
    if not math.isfinite(observed):
        # Distinct content, not just a different value slotted into the same sentence:
        # the human reading this needs to know it is a measurement problem, not a real
        # regression the predicted effect failed to demonstrate.
        return (
            f"action {action.action_id!r} was reverted: predicted effect "
            f"{action.predicted_effect!r} could not be verified — "
            f"{action.verification_query} returned a non-finite value ({observed!r}), "
            "not a usable measurement, so no verdict on the threshold could be made"
        )
    return (
        f"action {action.action_id!r} was reverted: predicted effect "
        f"{action.predicted_effect!r} was not demonstrated — "
        f"{action.verification_query} returned {observed}, required "
        f"{proposal.direction.value} {proposal.threshold}"
    )


def _ttl_race_escalation_message(
    proposal: Proposal, status: RevertStatus, completed_by_settle: bool
) -> str:
    action = proposal.action
    if completed_by_settle:
        what_happened = (
            f"action {action.action_id!r} had its TTL watchdog begin reverting it "
            "during verification but did not finish; settle completed the revert"
        )
    else:
        what_happened = (
            f"action {action.action_id!r} was reverted by its TTL watchdog during "
            "verification, not by settle"
        )
    return (
        f"{what_happened}; the measurement describes a world that no longer "
        "exists, so no verdict on the predicted effect is available (record "
        f"status observed: {status.value})"
    )


def _arguments(proposal: Proposal) -> dict[str, object]:
    """The action's declared arguments, as `F-ACT-29`'s ``arguments`` field.

    Everything a human needs to reconstruct what was asked for, without holding a
    reference to a live object: `PRODUCTION_ACTION_LAYER.md` §4.4's envelope, minus the
    fields Slice 1 has no source for yet (cost of inaction, revert settle time).
    """
    action = proposal.action
    return {
        "action_id": action.action_id,
        "predicted_effect": action.predicted_effect,
        "verification_query": action.verification_query,
        "threshold": proposal.threshold,
        "direction": proposal.direction.value,
        "ttl_seconds": action.ttl.total_seconds(),
        "reversible": action.reversible,
        "blast_radius": _cohort_record(action.blast_radius),
    }


def _cohort_record(cohort: Cohort) -> dict[str, object]:
    """The cohort as JSON: ``"*"`` stays a string, a named set becomes a sorted list so
    two records of the same cohort compare equal."""
    return {
        name: WILDCARD if value == WILDCARD else sorted(value)
        for name, value in (
            ("channels", cohort.channels),
            ("regions", cohort.regions),
            ("devices", cohort.devices),
            ("cdn_pathways", cohort.cdn_pathways),
        )
    }
