"""Remediator: remedy selection, policy gate, post-action verification.

F-AGT-13, F-AGT-14, F-AGT-15. This is the piece that connects task 15's diagnosis to
task 12's action and task 9/22's policy gate and settlement — nothing in `src/` called
any of those together before this module existed.

`INV-S02` — no model call anywhere in this module's decision path. `select_remedy` maps
the literal Grafana evidence `Incident.evidence` already carries (never the model's claim
prose) to this slice's one implemented remedy, and `autonomy_eligible` is a plain typed
predicate. Where a model *is* legitimately involved is upstream, in Forensics' own claim
generation (`INV-S02`'s stated carve-out) — this module only ever reads that output.

`INV-S01` — this module never schedules a revert itself. `remediate`'s `wait` is a
verification convenience, not the safety guarantee: the TTL watchdog `execute_action`
already spawned is what saves the platform if this process dies mid-wait.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from breakeven.actions import cohort_lease, executor, flap_suppression
from breakeven.actions.audit import (
    ActionOutcome,
    AuditEntry,
    RevertStatus,
    append_entry,
    now_stamp,
)
from breakeven.actions.blocklist import DuplicateBlocklistCallError, blocklist_creative

# `_state_path` imported rather than reimplemented, same reason `verification.py`
# imports it: `executor._action_file` is the one validated construction site for a
# per-action path.
from breakeven.actions.executor import _state_path
from breakeven.actions.verification import (
    Proposal,
    ThresholdDirection,
    revert_status_of,
    settle,
)
from breakeven.agents.incident import Evidence, Incident
from breakeven.policy import engine
from breakeven.policy.engine import ActionResult, ActionType, Cohort

VAST_TRANSCODE_ERROR = "900"
_LOGGER = logging.getLogger(__name__)

# The one axis this slice tunes: how many grounded root-cause claims a diagnosis needs
# before this action type may run without a human approving it first.
# `PRODUCTION_ACTION_LAYER.md` §4's other axes (`cooldown_elapsed`,
# `no_conflicting_action_active`) are out of scope for task 16 — see `autonomy_eligible`.
MIN_EVIDENCE_CLAIMS_FOR_AUTONOMY = 2

# How much of `action.ttl` is reserved so `settle()` — measure, and on failure revert and
# escalate — finishes before the TTL watchdog's own revert fires. See
# `settle_window_seconds`.
SETTLE_MARGIN_SECONDS = 60.0


class RemedyNotFound(ValueError):
    """No deterministic remedy exists for this incident's cited evidence.

    This slice implements exactly one fault-to-remedy mapping (a creative-transcode
    fault → `blocklist_creative`). Anything else is a real mechanism gap, not something
    to paper over with a heuristic on the model's claim prose. Raising here keeps
    remedy selection's wrong-remedy rate at zero rather than guessing.
    """


class HumanApprovalRequired(Exception):
    """Raised instead of executing, so a human-gated action can never fall through to
    auto-execution by a caller that forgot to check a return value — same reasoning as
    `engine.PolicyRejection`. Carries the action a human would need to approve."""

    def __init__(self, action: ActionResult) -> None:
        super().__init__(
            f"{action.action_id} is not autonomy-eligible; a human must approve it "
            "before it can execute"
        )
        self.action = action


class CohortLeaseConflict(ValueError):
    """Raised instead of executing when another action already holds the target cohort's
    lease for its own verification window — F-ACT-26, task 10.

    F-ACT-26's own words are *"conflicts queue or are rejected with a stated reason"*;
    this implementation rejects rather than queues. Unlike `HumanApprovalRequired`, this
    is never bypassed by ``human_approved`` — a human approving the action does not make
    two concurrent verifications over the same cohort interpretable, so this check runs
    unconditionally, same reasoning `flap_suppression`'s breaker uses for the account-wide
    axis.
    """

    def __init__(self, action: ActionResult, reason: str) -> None:
        super().__init__(f"{action.action_id} was refused: {reason}")
        self.action = action
        self.reason = reason


@dataclass(frozen=True)
class Remedy:
    """The concrete, typed remedy `select_remedy` produced for one incident."""

    action_type: ActionType
    action: ActionResult
    creative_id: str


def _series(evidence: Evidence, *, label: str) -> list[tuple[dict[str, object], float]]:
    """Return the (metric-labels, value) pairs from one Prometheus instant-vector
    result whose metric carries ``label``, or an empty list if the payload is not that
    shape. Mirrors `forensics._is_none_sentinel`'s defensive parse — the only other
    place this kernel reads raw Prometheus JSON evidence.
    """
    try:
        payload = json.loads(evidence.result)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, list):
        return []
    series: list[tuple[dict[str, object], float]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        metric = item.get("metric")
        value = item.get("value")
        if not isinstance(metric, dict) or label not in metric:
            continue
        if not isinstance(value, list) or len(value) != 2:
            continue
        # `bool` is a `float`-convertible subtype of `int`; a JSON `true`/`false` sample
        # would otherwise silently read as `1.0`/`0.0` instead of being rejected as the
        # malformed sample it is (real Grafana MCP responses always encode the value as
        # a string, per the Prometheus wire format — same guard shape as
        # `verification.Proposal._require_usable_threshold`).
        if isinstance(value[1], bool):
            continue
        try:
            observed = float(value[1])
        except (TypeError, ValueError):
            continue
        series.append((metric, observed))
    return series


# The one metric `diagnose()`'s fixed queries ever group by `vast_error_code` or
# `creative_id` (`forensics._queries`). Scoping to it is what makes the two independent
# scans below name the *same* fault rather than two coincidentally-true facts about
# unrelated metrics — silent-failure-hunter review, this session: without it, any
# evidence entry merely carrying a `creative_id` label (from an unrelated query) could
# supply the blocklist target for a `900` seen on a completely different series.
_ERROR_METRIC = "ad_break_errors_total"

# `D-S89`, 2026-08-20: at 8 channels x 4 regions x 3 devices the crossed
# `ad_break_errors_total{…,creative_id}` reaches ~5,760 series against `F-SIM-18`'s 3,000
# ceiling, so `creative_id` moved off it onto its own narrow
# `ad_creative_errors_total{channel, creative_id}`. The two signals therefore now live on
# two metrics, and each is pinned to exactly the one it is emitted on — the anti-conflation
# property below is unchanged in strength: neither label may be read from an arbitrary
# query, only from its own designated metric. `forensics._queries` emits both.
_CREATIVE_ERROR_METRIC = "ad_creative_errors_total"


def _metric_name_pattern(metric: str) -> re.Pattern[str]:
    """Match `metric` as a whole PromQL metric name, never as a substring.

    S6 Tier-A review, 2026-08-10: `_ERROR_METRIC in evidence.query` was substring
    containment, so a differently-named metric that merely *contains* the text (e.g.
    `other_ad_break_errors_total_v2`) would pass the scope check too — reopening the
    exact unjoined-evidence-correlation gap the substring check was meant to close.
    PromQL metric-name characters are `[A-Za-z0-9_]`; anchoring on non-identifier
    characters either side is what makes this match the metric itself, not a substring
    of an unrelated one, while still matching every real shape (`…_total{`,
    `…_total[600s]`, a bare trailing name).
    """
    return re.compile(rf"(?<![A-Za-z0-9_]){re.escape(metric)}(?![A-Za-z0-9_])")


_ERROR_METRIC_PATTERN = _metric_name_pattern(_ERROR_METRIC)
_CREATIVE_ERROR_METRIC_PATTERN = _metric_name_pattern(_CREATIVE_ERROR_METRIC)


def _error_series(
    incident: Incident, *, label: str, pattern: re.Pattern[str]
) -> list[tuple[dict[str, object], float]]:
    """Return `_series` results, restricted to evidence whose query is literally about the
    one metric that carries `label` — the metrics this slice's fault-to-remedy mapping
    reasons over.

    `pattern` is required, with no default: silent-failure-hunter, this session. Now that
    the two signals live on two metrics, a default would let a future caller read
    `creative_id` off `ad_break_errors_total` evidence and reopen exactly the
    unjoined-evidence-correlation gap the anchored match exists to close — and it would do
    so by omission, which no test would flag.
    """
    return [
        pair
        for evidence in incident.evidence
        if pattern.search(evidence.query)
        for pair in _series(evidence, label=label)
    ]


def _creative_transcode_fault(incident: Incident) -> str | None:
    """Return the failing `creative_id` if `incident.evidence` deterministically names a
    creative-transcode fault (`vast_error_code=900`), else `None`.

    Reads only the literal PromQL evidence `diagnose()` cited — never the model's claim
    prose — so this stays a typed lookup over structured data, not a heuristic over free
    text (task 16 DO NOT #1). Each signal is read only from the metric that actually
    carries it — `vast_error_code` from `_ERROR_METRIC`, `creative_id` from
    `_CREATIVE_ERROR_METRIC` — so a `900` and a failing `creative_id` from two unrelated
    metrics can never be combined into a confidently-wrong remedy target.
    """
    has_transcode_error = any(
        metric.get("vast_error_code") == VAST_TRANSCODE_ERROR and observed > 0
        for metric, observed in _error_series(
            incident, label="vast_error_code", pattern=_ERROR_METRIC_PATTERN
        )
    )
    if not has_transcode_error:
        return None
    failing_creatives = {
        metric["creative_id"]
        for metric, observed in _error_series(
            incident, label="creative_id", pattern=_CREATIVE_ERROR_METRIC_PATTERN
        )
        if observed > 0 and metric.get("creative_id") not in (None, "none")
    }
    if len(failing_creatives) != 1:
        return None
    return next(iter(failing_creatives))


_ORIGIN_STREAK_METRIC = "origin_5xx_failed_fetches_streak"
_ORIGIN_STREAK_METRIC_PATTERN = _metric_name_pattern(_ORIGIN_STREAK_METRIC)

# `D-S112`: the three metrics `watchtower/agent.py`'s own `beacon_check` already reads to
# evaluate the identity `billable_impressions >= fills and beacon_failures == 0`.
# Re-derived here from Forensics' own cited evidence — never trusted from the model's
# claim prose — the same determinism contract every other detector in this module holds.
_BEACON_FAILURES_METRIC = "ad_beacon_failures_total"
_BEACON_FAILURES_METRIC_PATTERN = _metric_name_pattern(_BEACON_FAILURES_METRIC)
_BILLABLE_IMPRESSIONS_METRIC = "ad_impressions_billable_total"
_BILLABLE_IMPRESSIONS_METRIC_PATTERN = _metric_name_pattern(_BILLABLE_IMPRESSIONS_METRIC)
_FILLS_METRIC = "ad_break_fills_total"
_FILLS_METRIC_PATTERN = _metric_name_pattern(_FILLS_METRIC)

# `D-S111`: how many consecutive origin-fetch failures a pathway must show before it is
# named degraded — same reasoning as `sim.metrics.CONFIRM_FAILED_BREAKS`: refuses to act
# on a single blip. Kept as its own constant, not imported from `sim.metrics`, because
# this module (`remediator.py`) reads only `incident.evidence`, never the simulator
# directly (`INV-S02`'s own boundary) — importing a simulator constant here would blur
# that line even though the numeric value is deliberately kept equal.
ORIGIN_DEGRADATION_STREAK_FLOOR = 2


def _origin_degradation_fault(incident: Incident) -> tuple[str, str] | None:
    """Return `(degraded_pathway, healthy_pathway)` if `incident.evidence` deterministically
    names exactly one CDN pathway as degraded while its sibling reads clean, else `None`.

    Mirrors `_creative_transcode_fault`'s determinism contract: reads only the literal
    PromQL evidence `diagnose()` cited (never the model's claim prose), and refuses
    rather than guesses whenever the evidence does not name exactly one bad pathway
    against exactly one healthy one — the same "wrong-remedy rate zero" property `A3`'s
    detector holds.
    """
    streaks = _error_series(
        incident, label="cdn_pathway", pattern=_ORIGIN_STREAK_METRIC_PATTERN
    )
    by_pathway: dict[str, float] = {}
    for metric, observed in streaks:
        pathway = metric.get("cdn_pathway")
        if isinstance(pathway, str):
            by_pathway[pathway] = observed
    degraded = {
        pathway
        for pathway, streak in by_pathway.items()
        if streak >= ORIGIN_DEGRADATION_STREAK_FLOOR
    }
    healthy = {pathway for pathway, streak in by_pathway.items() if streak == 0}
    if len(degraded) != 1 or len(healthy) != 1:
        return None
    return next(iter(degraded)), next(iter(healthy))


def select_pathway_remedy(incident: Incident) -> tuple[str, str] | None:
    """Return `(degraded_pathway, healthy_pathway)` for `incident`, or `None` if its
    evidence does not deterministically name an origin-pathway degradation.

    Deliberately not folded into `select_remedy`/`Remedy`: A1's real executor
    (`actions.steering.steer_pathway`) is a multi-step ramp with its own verification
    and revert loop, not a single `ActionResult` `remediate()` can execute — folding it
    in would mean reshaping `remediate()`'s already multiply-reviewed pipeline (`K-S01`,
    `NEW-1`, `F-ACT-26/27/29`) around a second, incompatible shape. Kept as an
    independent, parallel entry point instead, the same way this module's own docstring
    already separates upstream model involvement from this module's deterministic
    lookups.
    """
    if not incident.root_cause_claims:
        return None
    return _origin_degradation_fault(incident)


def _channel_scalar(incident: Incident, *, pattern: re.Pattern[str]) -> float | None:
    """Return this incident's channel's single cited value for the metric `pattern`
    names, or `None` if no evidence citing that metric survived to `incident.evidence`.
    """
    for metric, observed in _error_series(incident, label="channel", pattern=pattern):
        if metric.get("channel") == incident.channel:
            return observed
    return None


def _conservation_violation_fault(incident: Incident) -> bool:
    """Return whether `incident.evidence` deterministically shows a real
    impression-conservation violation on this incident's channel.

    Re-derives `watchtower/agent.py`'s own `beacon_check` identity
    (`billable_impressions >= fills and beacon_failures == 0`) from Forensics' cited
    evidence rather than trusting the model's claim prose. Either cited signal alone is
    sufficient — `sim/metrics.py::record_break` computes
    `billable_impressions = viewer_count * ads_in_break - beacon_failures`, so the two
    are not independent facts requiring both to be cited; a beacon fault that produced
    only one of the two citable claims must not be missed for want of the other.
    """
    beacon_failures = _channel_scalar(
        incident, pattern=_BEACON_FAILURES_METRIC_PATTERN
    )
    if beacon_failures is not None and beacon_failures > 0:
        return True
    fills = _channel_scalar(incident, pattern=_FILLS_METRIC_PATTERN)
    billable = _channel_scalar(incident, pattern=_BILLABLE_IMPRESSIONS_METRIC_PATTERN)
    if fills is not None and billable is not None:
        return billable < fills
    return False


def select_conservation_remedy(incident: Incident) -> str | None:
    """Return the channel name if `incident.evidence` deterministically shows a real
    impression-conservation violation, else `None`.

    `D-S112`: returns a channel, not a creative — `sim/faults.py::create_delivery_loss`
    (the fault this detects) is channel-scoped, with no creative to name, so naming one
    would invent attribution the real fault doesn't have. Deliberately not folded into
    `select_remedy`/`Remedy` for the same reason `select_pathway_remedy` (`D-S111`)
    isn't: this remedy's shape (blocklist every eligible creative on a channel) differs
    from A3's single-creative `Remedy`, and reshaping `remediate()`'s already
    multiply-reviewed pipeline around a third shape is exactly what `D-S111` already
    declined to do for A1.
    """
    if not incident.root_cause_claims:
        return None
    if _conservation_violation_fault(incident):
        return incident.channel
    return None


def select_remedy(incident: Incident, *, action_id: str, ttl: timedelta) -> Remedy:
    """Map `incident.root_cause_claims`'s grounded evidence to this slice's one
    implemented remedy — `blocklist_creative` for a creative-transcode fault.

    Raises `RemedyNotFound` for every other input. A slice with one scenario earns
    "wrong-remedy rate zero" (task 16 Assertion 1) by refusing everything it cannot
    deterministically name, not by guessing.
    """
    if not incident.root_cause_claims:
        raise RemedyNotFound(
            f"incident {incident.id!r} has no root-cause claims; nothing to remediate"
        )
    creative_id = _creative_transcode_fault(incident)
    if creative_id is None:
        raise RemedyNotFound(
            f"incident {incident.id!r}'s evidence does not deterministically name a "
            "creative-transcode fault (vast_error_code=900); this slice implements no "
            "other remedy mapping"
        )
    cohort = Cohort(
        channels=frozenset({incident.channel}),
        regions=frozenset({incident.region}),
        devices=frozenset({"ctv"}),
        cdn_pathways=frozenset({"cdn-a"}),
    )
    window_seconds = int(ttl.total_seconds() - SETTLE_MARGIN_SECONDS)
    if window_seconds <= 0:
        raise ValueError(
            f"action {action_id!r} has ttl {ttl!r}, too short for the "
            f"{SETTLE_MARGIN_SECONDS}s settle margin; settle() would have no room to "
            "run before the TTL watchdog's own revert fires"
        )
    action = ActionResult(
        action_id=action_id,
        reversible=True,
        blast_radius=cohort,
        predicted_effect=(
            f"ad_creative_errors_total for creative {creative_id!r} on channel "
            f"{incident.channel!r} falls to zero"
        ),
        verification_query=(
            f"sum(increase({_CREATIVE_ERROR_METRIC}"
            f'{{channel="{incident.channel}",creative_id="{creative_id}"}}'
            f"[{window_seconds}s]))"
        ),
        ttl=ttl,
    )
    return Remedy(action_type=ActionType.A3, action=action, creative_id=creative_id)


def autonomy_eligible(action: ActionResult, incident: Incident) -> bool:
    """Whether `action` may run without a human approving it first.

    Plain typed Python, no model call anywhere in this function's call graph
    (`INV-S02`, task 16 Assertion 3). This slice measures exactly two of
    `PRODUCTION_ACTION_LAYER.md` §4's five axes: reversibility (`action.reversible`,
    already on task 9's reviewed contract) and evidence strength (the number of
    grounded root-cause claims Forensics produced). `cooldown_elapsed` and
    `no_conflicting_action_active` are out of scope for task 16 (DO NOT #3) — this
    function simply does not claim to evaluate them, rather than assuming either holds.
    `cooldown_elapsed` (per action type) and its own sibling axes (a per-cohort hourly
    cap, an account-wide revert breaker) are now evaluated separately by task 9's
    `flap_suppression.suspension_reason`, called by `remediate` alongside this function
    rather than folded into it — this function's existing two-axis contract and its own
    unit tests stay exactly as task 16 left them.
    """
    return (
        action.reversible
        and len(incident.root_cause_claims) >= MIN_EVIDENCE_CLAIMS_FOR_AUTONOMY
    )


def settle_window_seconds(
    action: ActionResult, *, margin: float = SETTLE_MARGIN_SECONDS
) -> float:
    """Return how long to wait before calling `settle()` — derived from `action.ttl`
    minus `margin`, never a bare literal unconnected to the action's own TTL (task 16
    Assertion 6).

    The margin leaves room for `settle()` itself to run: measuring, and on a failed
    verification, reverting and escalating — all before the TTL watchdog's own revert
    fires. Without it, waiting the full TTL would systematically race the watchdog and
    land `settle()` on `verification.py`'s `UNVERIFIED_REVERTED_BY_TTL` edge case on
    every call instead of a real verdict, defeating the point of calling it explicitly.

    Raises `ValueError` naming `action.action_id` if `margin` leaves no room at all —
    a TTL that short cannot be verified by this function before the watchdog reverts it.
    """
    seconds = action.ttl.total_seconds() - margin
    if seconds <= 0:
        raise ValueError(
            f"action {action.action_id!r} has ttl {action.ttl!r}, too short for the "
            f"{margin}s settle margin; settle() would have no room to run before the "
            "TTL watchdog's own revert fires"
        )
    return seconds


def remediate(  # pylint: disable=too-many-arguments,too-many-locals,too-many-branches,too-many-statements
    incident: Incident,
    telemetry: Mapping[str, int],
    *,
    action_id: str,
    ttl: timedelta,
    threshold: float,
    direction: ThresholdDirection,
    agent_identity: str,
    base_url: str,
    measure: Callable[[str], float],
    escalate: Callable[[str], None],
    state_dir: Path,
    log_path: Path,
    wait: Callable[[float], None] = time.sleep,
    settle_margin: float = SETTLE_MARGIN_SECONDS,
    human_approved: bool = False,
    on_executed: Callable[[ActionResult], None] | None = None,
) -> AuditEntry:
    """Select a remedy for `incident`, gate it through the policy engine, execute it,
    wait out its settle window, and record the verified-or-escalated outcome.

    Ties together, in this order: `select_remedy` → `autonomy_eligible` (raises
    `HumanApprovalRequired` before anything is executed if the action is not
    autonomy-eligible) → `flap_suppression.suspension_reason` (task 9, `F-ACT-27`: raises
    the same `HumanApprovalRequired` if an account-wide breaker trip, a per-cohort hourly
    cap, or this action type's cooldown is active — checked in that order, before
    anything is mutated) → build the `Proposal`, using `flap_suppression.
    hysteresis_revert_threshold` rather than `threshold` verbatim, so the bar `settle()`
    verifies against is never the same value as the one that justified proposing the
    action → the settle window (both pure functions of arguments already in hand, so a
    caller error here — a non-finite `threshold`, a `ttl` too short for `settle_margin` —
    is caught before anything is mutated, not after) → `cohort_lease.
    lease_conflict_reason` (task 10, `F-ACT-26`: raises `CohortLeaseConflict`, always,
    even if `human_approved` — a human approving the action does not make two overlapping
    verifications interpretable) → `policy.engine.execute` (raises `PolicyRejection`
    before the executor runs if the action is over-scoped) → `blocklist_creative` (which
    calls task 10's `execute_action`) → `flap_suppression.record_execution` (task 9: the
    cooldown and hourly-cap clocks start only once the action has genuinely executed) →
    `cohort_lease.acquire_lease` (task 10: the lease is recorded for the same window,
    keyed to the same `now`/`expires_at_epoch` pair the executor's own watchdog derives
    its `deadline_epoch` from) → `wait(settle_seconds)` → `verification.settle` →
    `flap_suppression.record_revert` if `settle` reverted the action (task 9: feeds the
    breaker's own count; never touches the revert itself, which by this point has already
    completed — `INV-S01`).

    That ordering is load-bearing (`silent-failure-hunter` review, this session): the
    watchdog `execute_action` spawns only ever calls `revert_action`, never
    `audit.append_entry` — so a caller-input error raised *after* `engine.execute` had
    already mutated the world would leave a real, executed action with no audit entry
    ever written for it, not merely one delayed until TTL. Validating both before the
    executor runs closes that gap the same way `autonomy_eligible`'s own pre-execution
    check does. **`F-ACT-29` fix, this session:** validating inputs first closes the
    caller-input class of gap, but not a genuine process crash between `engine.execute`
    succeeding and `settle()` running — no amount of pre-validation can. Immediately
    after execution, this function now writes its own provisional
    `ActionOutcome.EXECUTED_AWAITING_SETTLEMENT` audit entry (best-effort, same pattern as
    `flap_suppression.record_execution`/`cohort_lease.acquire_lease` below), so an action
    that is executed and never settled still has one entry on disk, not zero.

    A `wait` failure gets the same protection (S6 Tier-A review, 2026-08-10): `settle()`
    is still called even if `wait` raises, so the action is never left with zero audit
    entry just because the process never reached `settle()` on the happy path. The
    measurement this produces may be premature — the predicted effect might not have had
    time to appear yet — but a premature, honestly-recorded verdict is strictly better
    than no record at all. `wait`'s own error still reaches the caller afterwards, so
    the failure itself is not swallowed.
    """
    remedy = select_remedy(incident, action_id=action_id, ttl=ttl)
    if not human_approved and not autonomy_eligible(remedy.action, incident):
        raise HumanApprovalRequired(remedy.action)
    if not human_approved and (
        flap_suppression.suspension_reason(
            remedy.action_type,
            remedy.action.blast_radius,
            state_dir=state_dir,
            now=time.time(),
        )
        is not None
    ):
        raise HumanApprovalRequired(remedy.action)

    settle_seconds = settle_window_seconds(remedy.action, margin=settle_margin)
    proposal = Proposal(
        action=remedy.action,
        threshold=flap_suppression.hysteresis_revert_threshold(threshold, direction),
        direction=direction,
        agent_identity=agent_identity,
    )

    # `F-ACT-26`, unconditional (never gated by `human_approved` — see `CohortLeaseConflict`'s
    # own docstring): the lease's own expiry mirrors `executor.execute_action`'s
    # `deadline_epoch` (`now + action.ttl.total_seconds()`), so the lease frees itself no
    # later than the watchdog's own worst-case revert, without a second timer.
    lease_now = time.time()
    lease_expires_at_epoch = lease_now + remedy.action.ttl.total_seconds()
    lease_conflict = cohort_lease.lease_conflict_reason(
        remedy.action.blast_radius, state_dir=state_dir, now=lease_now
    )
    if lease_conflict is not None:
        raise CohortLeaseConflict(remedy.action, lease_conflict)

    def _execute(action: ActionResult) -> None:
        blocklist_creative(
            action,
            creative_id=remedy.creative_id,
            cohort=action.blast_radius,
            base_url=base_url,
            state_dir=state_dir,
            escalate=escalate,
        )

    try:
        engine.execute(remedy.action_type, remedy.action, telemetry, _execute)
    # A watchdog-spawn failure occurs after the mutation and its durable "executed"
    # record exist, but before the executor can arrange its normal TTL revert. Reuse the
    # executor's idempotent revert path synchronously in that one case; never add an
    # agent-owned timer (`INV-S01`).
    # pylint: disable=broad-exception-caught
    except BaseException as execution_error:
        # `NEW-1` (S6 Tier-A review of `09765c2`, live-reproduced): a duplicate
        # `blocklist_creative` call for an `action_id` that already holds a live,
        # correct, still-TTL-armed action is a harmless collision, not a genuine
        # execution failure — the durable record this exception's `action_id` names
        # belongs to that *other*, still-active action, not to this call. Forcing a
        # compensating revert here would be exactly the corruption `K-S01` was opened to
        # close, reached one layer up through this handler instead of through
        # `blocklist_creative`'s own (already-fixed) internal rollback path.
        # `DuplicateBlocklistCallError` is raised nowhere else, so recognising it by type
        # is unambiguous; `execute_action`'s own separate "already executed" guard
        # (`executor.py:580-581`) still raises a bare `ValueError` for its own scenario
        # and is untouched by this check. Handled by not forcing a revert and not writing
        # an audit entry describing a revert that never happened — but every *other*
        # exception path through this handler still ends up telling a human (directly, or
        # via `_force_compensating_revert_after_execution_failure`'s own unconditional
        # `escalate`), and `blocklist_creative`'s guard fires for *any* existing record —
        # not only a still-live, correct action, but also one whose own earlier
        # `remediate()` call crashed before reaching `settle()` and is stuck, unrevertable
        # by anything but the eventual TTL watchdog, which "never escalates ... it is a
        # safety net, not a 'tell a human' mechanism" (this module's own words, below). A
        # human is still owed that signal here (`silent-failure-hunter`, this session) —
        # re-raising alone would silently drop it, the same "loud in every case" reasoning
        # `_rollback_and_raise`'s own escalate-if-available handling already uses.
        if isinstance(execution_error, DuplicateBlocklistCallError):
            message = (
                f"action {remedy.action.action_id}: {execution_error} — a duplicate "
                "remediate() call collided with an existing durable record for this "
                "action_id; no compensating revert was forced (forcing one here risks "
                "reverting a different action that legitimately holds the same id) — a "
                "human should confirm this action_id's real state"
            )
            _LOGGER.warning(message)
            try:
                escalate(message)
            # An unavailable escalation channel must be visible in logs, never mask the
            # collision itself or block the re-raise below.
            except Exception:  # noqa: BLE001 # pylint: disable=broad-exception-caught
                _LOGGER.exception(
                    "failed to escalate the duplicate-call collision for action %s",
                    remedy.action.action_id,
                )
            raise
        record_existed = False
        revert_failed = False
        # `_force_compensating_revert_after_execution_failure` (below) resolves "does a
        # state record exist at all" internally now, returning `False` rather than
        # raising when it cannot tell (a malformed `action_id`, an unreadable
        # `state_dir`) — `silent-failure-hunter`, this session: an earlier version of
        # this fix left that determination outside the helper's own guard, so a raised
        # exception there landed here and was wrongly read as "the action executed".
        # The only exception this call can still raise is `execution_error` itself,
        # chained to a genuine revert failure as its `__cause__` — caught here only so
        # the receipt below still gets written on that path too; the `raise` at the end
        # of this block re-raises the exact same object, `__cause__` intact.
        try:
            record_existed = _force_compensating_revert_after_execution_failure(
                remedy.action.action_id,
                state_dir=state_dir,
                escalate=escalate,
                execution_error=execution_error,
            )
        # pylint: disable=broad-exception-caught
        except BaseException as helper_error:
            record_existed = True
            revert_failed = True
            # `K-R03`: the helper's own contract (its docstring above) says it only
            # ever raises `execution_error` itself, chained to a revert failure — never
            # a different exception. `record_existed`/`revert_failed` default safely to
            # `True` regardless (the loud direction, same as every other ambiguous case
            # in this file), but a genuinely different exception here means that
            # contract broke, which is worth knowing rather than silently trusting.
            if helper_error is not execution_error:
                _LOGGER.critical(
                    "compensating-revert helper for action %s raised %r instead of "
                    "chaining execution_error %r as its own docstring guarantees; "
                    "its contract may have changed without this caller being updated",
                    remedy.action.action_id,
                    helper_error,
                    execution_error,
                )
        # `K-P06-9`: a state record existing means the action genuinely executed (the
        # same "no record → never executed" reading `revert_status_of` already uses),
        # so it is owed a receipt here — `settle()`'s own final entry is never reached
        # on this path (the `raise` below skips straight past `wait`/`settle`). No
        # record means the mutation itself never took effect (`executor.execute_action`
        # removes the record on a failed mutation before this is ever reached), so
        # there is nothing an "action" audit entry would honestly describe.
        if record_existed:
            try:
                revert_status = revert_status_of(
                    remedy.action.action_id, state_dir=state_dir
                )
            except (ValueError, OSError):
                _LOGGER.exception(
                    "could not re-read action %s's revert status for its forced "
                    "compensating-revert audit entry; recording NOT_REVERTED",
                    remedy.action.action_id,
                )
                revert_status = RevertStatus.NOT_REVERTED
            try:
                append_entry(
                    AuditEntry(
                        agent_identity=agent_identity,
                        timestamp=now_stamp(),
                        arguments={
                            "action_id": remedy.action.action_id,
                            "predicted_effect": remedy.action.predicted_effect,
                            "verification_query": remedy.action.verification_query,
                        },
                        evidence_chain=(
                            {
                                "execution": (
                                    "the normal post-execution path failed; a "
                                    "synchronous compensating revert was forced"
                                )
                            },
                        ),
                        # `silent-failure-hunter`, this session: a revert that itself
                        # raised (`revert_failed`) must never be recorded under the same
                        # outcome as one that actually completed — the same distinction
                        # `settle()` already draws between these two exact outcomes.
                        result=(
                            ActionOutcome.UNVERIFIED_SETTLEMENT_FAILED
                            if revert_failed
                            else ActionOutcome.UNVERIFIED_REVERTED_AND_ESCALATED
                        ),
                        revert_status=revert_status,
                    ),
                    log_path=log_path,
                )
            except (OSError, ValueError):
                _LOGGER.exception(
                    "audit entry for action %s's forced compensating revert could "
                    "not be written",
                    remedy.action.action_id,
                )
        raise
    # `F-ACT-29`: a provisional audit entry, written now, before `wait`/`settle` — the
    # only record that survives if the process dies (crash, kill -9) anywhere between
    # here and `settle()`'s own final entry below. `settle()` always writes its own entry
    # on every path *it* can reach (its own docstring's guarantee); what this closes is
    # the one path `settle()` cannot help with — never reaching `settle()` at all. The log
    # is append-only (`audit.py`'s own docstring), so this never rewrites anything; a
    # settled action legitimately ends up with two entries, this receipt and the verdict.
    # Best-effort like the two bookkeeping calls below: a write failure here must not skip
    # `wait`/`settle` and cost the action its real, final audit entry too.
    # `silent-failure-hunter`, this session: `AuditEntry(...)` is constructed inside this
    # `try`, so its own `ValueError` (blank `agent_identity`, empty `evidence_chain`, a bad
    # timestamp) is caught here too, not just `append_entry`'s `OSError` — `agent_identity`
    # is validated non-blank by `Proposal.__post_init__` above, `evidence_chain` is a
    # non-empty literal, and `timestamp`/`result`/`revert_status` cannot be malformed here,
    # so this is currently unreachable, but catching both is what keeps it unreachable if
    # this write is ever moved earlier or reused before that validation has run.
    try:
        append_entry(
            AuditEntry(
                agent_identity=agent_identity,
                timestamp=now_stamp(),
                arguments={
                    "action_id": remedy.action.action_id,
                    "predicted_effect": remedy.action.predicted_effect,
                    "verification_query": remedy.action.verification_query,
                },
                evidence_chain=(
                    {
                        "execution": (
                            "action applied; verification/settlement not yet run"
                        )
                    },
                ),
                result=ActionOutcome.EXECUTED_AWAITING_SETTLEMENT,
                revert_status=RevertStatus.NOT_REVERTED,
            ),
            log_path=log_path,
        )
    except (OSError, ValueError):
        _LOGGER.exception(
            "provisional audit entry could not be written for action %s; "
            "remediation continues",
            remedy.action.action_id,
        )

    # `silent-failure-hunter`, this session: not allowed to propagate unguarded — by this
    # point the action has genuinely executed, and this docstring's own opening paragraph
    # explains why every check before `engine.execute` exists to prevent exactly "a real,
    # executed action with no audit entry ever written for it". An `OSError` here (lock
    # contention, a full disk) must not skip `wait`/`settle` and reopen that same gap for
    # a bookkeeping failure — logged and continued, same pattern as `on_executed` below.
    try:
        flap_suppression.record_execution(
            remedy.action_type,
            remedy.action.blast_radius,
            state_dir=state_dir,
            now=time.time(),
        )
    except OSError:
        _LOGGER.exception(
            "flap-suppression bookkeeping failed to record execution of action %s; "
            "remediation continues",
            remedy.action.action_id,
        )
    # `silent-failure-hunter`, this task: the same reasoning as the `flap_suppression.
    # record_execution` call immediately above — the action has genuinely executed by
    # this point, so a bookkeeping failure here must not skip `wait`/`settle` and reopen
    # the "executed action with no audit entry" gap those checks already exist to close.
    # A failure to record the lease is logged and continued, never raised: the cohort
    # simply reads free again sooner than it should for the remainder of this run, which
    # is the same direction `flap_suppression`'s own write-failure handling already
    # accepts, not the "silently grant a contested cohort" direction that must never
    # happen.
    try:
        lease_refusal = cohort_lease.acquire_lease(
            remedy.action.blast_radius,
            holder_action_id=remedy.action.action_id,
            state_dir=state_dir,
            now=lease_now,
            expires_at_epoch=lease_expires_at_epoch,
        )
        if lease_refusal is not None:
            _LOGGER.warning(
                "cohort lease could not be recorded for action %s after it already "
                "executed: %s",
                remedy.action.action_id,
                lease_refusal,
            )
    except OSError:
        _LOGGER.exception(
            "cohort-lease bookkeeping failed to record action %s; remediation continues",
            remedy.action.action_id,
        )
    if on_executed is not None:
        try:
            on_executed(remedy.action)
        except Exception:  # pylint: disable=broad-exception-caught
            _LOGGER.exception(
                "post-execution observer failed for action %s; remediation continues",
                remedy.action.action_id,
            )

    wait_error: BaseException | None = None
    try:
        wait(settle_seconds)
    # `BaseException`, not `Exception`: a Ctrl-C landing mid-wait is exactly when the
    # audit trail matters most, and it must not skip `settle()` any more than an
    # ordinary exception would. Re-raised below, once the entry is written.
    # pylint: disable=broad-exception-caught
    except BaseException as error:
        wait_error = error

    try:
        entry = settle(
            proposal,
            measure=measure,
            escalate=escalate,
            state_dir=state_dir,
            log_path=log_path,
        )
    except BaseException as settle_error:
        # `settle()` already wrote its own audit entry before raising (its own
        # docstring's guarantee), so nothing about the record is lost here — only the
        # exception a caller sees. `silent-failure-hunter`, this session: several of
        # `settle()`'s own raising paths (an `escalate` failure, a failed re-read) happen
        # *after* the world was genuinely reverted — `entry` is never bound here, but the
        # revert already happened and must still reach the breaker's count.
        flap_suppression.record_revert_if_it_happened(remedy.action.action_id, state_dir=state_dir)
        # Chaining `wait_error` as the cause keeps both failures visible instead of the
        # wait failure disappearing silently the one time both fail: without this,
        # `settle_error` alone would propagate and a caller inspecting the traceback
        # would never learn `wait` failed too.
        # pylint: disable=broad-exception-caught
        if wait_error is not None:
            raise settle_error from wait_error
        raise

    # Bookkeeping only, after the fact — `settle()`/the TTL watchdog have already
    # completed any revert by this point (`INV-S01`). This is what feeds the
    # account-wide breaker's own count (task 9, `F-ACT-27`).
    flap_suppression.record_revert_if_it_happened(remedy.action.action_id, state_dir=state_dir)

    if wait_error is not None:
        raise wait_error
    return entry


def _force_compensating_revert_after_execution_failure(
    action_id: str,
    *,
    state_dir: Path,
    escalate: Callable[[str], None],
    execution_error: BaseException,
) -> bool:
    """Revert an executed action when its normal post-execution path failed.

    Returns whether a state record existed for ``action_id`` — i.e. whether the action
    had genuinely executed and the caller is therefore owed an audit receipt, never
    whether *this call* personally performed a revert. Raises only when a compensating
    revert was attempted and itself failed, chaining ``execution_error`` to the revert
    failure — every other outcome (no record, already reverted, a corrupt record forced
    through the revert-and-escalate path) returns normally.

    `revert_status_of` raises the identical `ValueError` for two unlike situations: no
    record at all (the state write precedes the mutation, so this is correctly nothing
    to revert) and a record that exists but is corrupt or carries an unrecognised status
    (a real mutation whose only revert path would otherwise be lost silently). The two
    are told apart by checking the record's existence first, mirroring
    `verification.py`'s own guard — a corrupt or unreadable record forces the same
    revert-and-escalate treatment as a confirmed `NOT_REVERTED`, on the assumption that a
    record existing at all means the action likely executed. An `OSError` from the same
    read gets identical treatment, never left to propagate and replace
    ``execution_error``.

    `silent-failure-hunter`, this session: the record-existence check itself can raise —
    a malformed ``action_id`` fails `_state_path`'s own filename-safety check with a
    fresh `ValueError`, and `Path.exists()` can raise a raw `OSError` `pathlib` does not
    suppress — and an earlier version of this fix left that call unguarded, so the
    exception escaped to the caller and was wrongly read there as "the action executed".
    Guarded here for the same reason the read below already is: this determination can
    fail without meaning a mutation happened.
    """
    try:
        record_exists = _state_path(state_dir, action_id).exists()
    except (ValueError, OSError):
        _LOGGER.exception(
            "could not determine whether action %s has a state record at all; "
            "treating as never executed (nothing to revert)",
            action_id,
        )
        return False
    if not record_exists:
        return False
    try:
        needs_compensating_revert = (
            revert_status_of(action_id, state_dir=state_dir)
            is RevertStatus.NOT_REVERTED
        )
    except (ValueError, OSError) as unreadable:
        _LOGGER.exception(
            "action %s has a state record that could not be read to decide a "
            "compensating revert (%s); forcing a revert anyway because the record's "
            "existence means the action likely executed",
            action_id,
            unreadable,
        )
        needs_compensating_revert = True

    revert_error: BaseException | None = None
    if needs_compensating_revert:
        try:
            executor.revert_action(action_id, state_dir=state_dir)
        # The mutation failure is still the error a caller needs to see; preserve a
        # compensating-revert failure as its explicit cause instead of masking it.
        # pylint: disable=broad-exception-caught
        except BaseException as error:
            revert_error = error
    # Escalated unconditionally once a record exists, not only when this call itself
    # performed a revert: `needs_compensating_revert` being `False` means the action was
    # *already* reverted by the time this ran (the TTL watchdog winning a race against
    # this synchronous path is the one realistic way that happens) — `silent-failure-
    # hunter`, this session: the TTL watchdog itself never escalates (it is a safety net,
    # not a "tell a human" mechanism), so skipping this call here would mean the original
    # `execution_error` that triggered this whole path is never told to anyone at all.
    try:
        escalate(
            f"action {action_id}'s normal post-execution path failed; a human should "
            "confirm its final state"
        )
    # `silent-failure-hunter`, this session (round 2): an escalate failure used to be
    # only logged, never surfaced to the caller — the audit receipt then still claimed
    # `UNVERIFIED_REVERTED_AND_ESCALATED` even though no human was ever told, the exact
    # "or the escalation did" clause `ActionOutcome.UNVERIFIED_SETTLEMENT_FAILED`'s own
    # docstring names. Folded onto `revert_error` (first failure keeps precedence,
    # `verification.settle`'s own established pattern for this identical revert+escalate
    # pair) so either failure alone is enough for the caller to record it honestly.
    # pylint: disable=broad-exception-caught
    except BaseException as error:
        _LOGGER.exception(
            "failed to escalate forced synchronous compensating revert for action %s",
            action_id,
        )
        if revert_error is None:
            revert_error = error
    if revert_error is not None:
        raise execution_error from revert_error
    return True
