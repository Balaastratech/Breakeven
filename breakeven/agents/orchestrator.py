"""One unattended Watchtower → Forensics → Remediator cycle."""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from urllib.parse import urlencode
from hashlib import sha256
from inspect import Parameter, signature
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from breakeven.actions.audit import ActionOutcome, AuditEntry, RevertStatus, append_entry
from breakeven.actions.audit import export as audit_export
from breakeven.actions.blocklist import blocklist_creative
from breakeven.actions.steering import steer_pathway
from breakeven.agents.escalation_email import console_url, send_alert, send_best_effort
from breakeven.agents.forensics import diagnose
from breakeven.agents.incident import (
    AUTO_REMEDIATION_FLOOR_PER_MINUTE,
    Incident,
    SystemHealthAssertion,
)
from breakeven.agents.scribe.agent import (
    add_incident_activity,
    annotate_incident_detected,
    annotate_remediation_settled,
    alert_rule_url,
    close_incident as _close_grafana_incident,
    create_incident,
    dashboard_deeplink,
    ensure_revenue_alert_rule,
    incident_url,
)
from breakeven.agents.remediator import (
    HumanApprovalRequired,
    Remedy,
    RemedyNotFound,
    autonomy_eligible,
    remediate,
    select_conservation_remedy,
    select_pathway_remedy,
    select_remedy,
    settle_window_seconds,
)
from breakeven.agents.watchtower.agent import WINDOW_SECONDS, query_scalar, run_cycle
from breakeven.actions.verification import ThresholdDirection
from breakeven.policy import engine
from breakeven.policy.engine import ActionResult, ActionType, Cohort, PolicyRejection
from breakeven.sim.world import CHANNELS, CREATIVE_IDS, REGIONS
from breakeven.ui.app import serve
from breakeven.ui.controls import ControlPlane
from breakeven.ui.events import (
    RESULT_SUMMARY_LIMIT,
    EventBus,
    McpCallRecorder,
    publish_brief,
    publish_evidence,
)

INCIDENT_FLOOR_PER_MINUTE = AUTO_REMEDIATION_FLOOR_PER_MINUTE
DEFAULT_SIMULATOR_URL = "https://breakeven-simulator-452209142932.asia-south1.run.app"
# The Grafana MCP server's own URL — genuinely distinct from `DEFAULT_SIMULATOR_URL` above,
# which `_live_remediation`'s `base_url` uses for the simulator's control HTTP API. Same
# default `watchtower.agent._query` already reads from `BREAKEVEN_MCP_ENDPOINT`. Scribe's
# annotation writes previously received the simulator's `base_url` by mistake because both
# were passed under one shared name — see `scribe.agent.annotate_incident_detected`'s
# docstring for the incident this default and its distinct parameter name now prevent.
DEFAULT_MCP_ENDPOINT = "http://localhost:8000/mcp"
# The loss projection uses the same ten-minute observation window the Watchtower just
# evaluated, rather than inventing another ungrounded time horizon.
PROJECTED_LOSS_HORIZON_MINUTES = WINDOW_SECONDS / 60
# ponytail: calibration knob; tune against real incident-handling duration.
CLAIM_RECLAIM_MINUTES = 30
_CHANNEL_NAMES = {channel.channel_id: channel.name for channel in CHANNELS}
logger = logging.getLogger(__name__)

StagePublisher = Callable[[str, str, str], None]


def _active_incident_path(state_dir: Path, failure_signature: str) -> Path:
    """Return the durable, filename-safe record for one active signature."""
    digest = sha256(failure_signature.encode("utf-8")).hexdigest()
    return state_dir / f"incident-{digest}.json"


def _claim_failure_signature(
    state_dir: Path, failure_signature: str, *, claimed_at: datetime
) -> bool:
    """Atomically claim a signature until its Grafana incident is resolved."""
    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        with _active_incident_path(state_dir, failure_signature).open(
            "x", encoding="utf-8"
        ) as state_file:
            json.dump(
                {
                    "failure_signature": failure_signature,
                    "claimed_at": claimed_at.timestamp(),
                },
                state_file,
            )
    except FileExistsError:
        return False
    return True


def close_incident(
    incident: Incident, *, state_dir: Path | None, mcp_endpoint: str
) -> None:
    """Resolve a Grafana incident and release its durable suppression record."""
    if incident.grafana_incident_id is None:
        raise ValueError("An incident without a Grafana ID cannot be closed")
    _close_grafana_incident(incident.grafana_incident_id, mcp_endpoint=mcp_endpoint)
    if state_dir is not None:
        _active_incident_path(state_dir, incident.failure_signature).unlink(
            missing_ok=True
        )


def open_incident(
    assertion: SystemHealthAssertion,
    *,
    state_dir: Path | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> Incident | None:
    """Open the highest-risk failed health check above F-AGT-06's $50/min floor."""
    candidates = [
        check
        for check in assertion.checks
        if check.held is False
        and assertion.revenue_at_risk_per_min.get(check.channel, 0.0)
        > INCIDENT_FLOOR_PER_MINUTE
    ]
    if state_dir is not None:
        current_time = now()

        def has_active_claim(failure_signature: str) -> bool:
            claim_path = _active_incident_path(state_dir, failure_signature)
            if not claim_path.exists():
                return False
            try:
                claim = json.loads(claim_path.read_text(encoding="utf-8"))
            # `K-P06-15`: `json.JSONDecodeError` is a `ValueError` subclass, and so is
            # `UnicodeDecodeError` (invalid UTF-8 in the file) — widening to `ValueError`
            # catches both with the one clause, matching `verification.revert_status_of`'s
            # own guard shape for the same "unreadable record" situation.
            except (ValueError, OSError):
                logger.warning(
                    "Reclaiming unreadable incident suppression claim for %s",
                    failure_signature,
                )
                claim_path.unlink(missing_ok=True)
                return False
            # `K-P06-15`: valid JSON that isn't an object (`null`, `[]`, `5`, `"x"`) reached
            # `claim.get(...)` uncaught, raising `AttributeError` past every guard here and
            # failing the whole health-check assertion's detect stage — reclaim it exactly
            # like an unreadable claim rather than let a malformed shape crash the caller.
            if not isinstance(claim, dict):
                logger.warning(
                    "Reclaiming malformed (non-object) incident suppression claim for %s",
                    failure_signature,
                )
                claim_path.unlink(missing_ok=True)
                return False
            claimed_at_epoch = claim.get("claimed_at")
            if not isinstance(claimed_at_epoch, (int, float)):
                claimed_at_epoch = claim_path.stat().st_mtime
            elapsed = current_time - datetime.fromtimestamp(
                claimed_at_epoch, tz=timezone.utc
            )
            if elapsed <= timedelta(minutes=CLAIM_RECLAIM_MINUTES):
                return True
            logger.warning(
                "Reclaiming stale incident suppression claim for %s after %.1f minutes",
                failure_signature,
                elapsed.total_seconds() / 60,
            )
            claim_path.unlink(missing_ok=True)
            return False

        candidates = [
            check
            for check in candidates
            if not has_active_claim(f"{check.invariant}:{check.channel}")
        ]
    if not candidates:
        return None
    check = max(
        candidates,
        key=lambda candidate: assertion.revenue_at_risk_per_min[candidate.channel],
    )
    risk = assertion.revenue_at_risk_per_min[check.channel]
    region = check.region or REGIONS[0]
    incident = Incident(
        id=f"incident-{uuid4()}",
        detected_at=assertion.emitted_at,
        channel=check.channel,
        region=region,
        revenue_at_risk_per_min=risk,
        projected_loss_if_unaddressed=risk * PROJECTED_LOSS_HORIZON_MINUTES,
        failure_signature=f"{check.invariant}:{check.channel}",
    )
    if state_dir is not None and not _claim_failure_signature(
        state_dir, incident.failure_signature, claimed_at=current_time
    ):
        return None
    return incident


def _publish_stage(bus: EventBus, stage: str, status: str, detail: str) -> None:
    bus.publish("stage", {"stage": stage, "status": status, "detail": detail})


def _escalate_via_email(message: str) -> None:
    """The real `escalate` wiring for all three remedy types (`GAPS.md` #11) — replaces
    the `escalate=print` this used to be, whose text went to a spawned child process's
    discarded stdout that no code ever read. Deliberately loud: called only from inside
    `verification.settle()`'s own exception handling, which already distinguishes a
    completed revert (`UNVERIFIED_REVERTED_AND_ESCALATED`) from one whose escalation itself
    failed (`UNVERIFIED_SETTLEMENT_FAILED`) — swallowing a failure here would quietly
    re-break that exact honesty distinction.
    """
    send_alert(
        "BreakEven ALERT: a fix was reverted and needs attention",
        f"{message}\n\nOperator console: {console_url()}",
    )


def _narrate(bus: EventBus, text: str) -> None:
    bus.publish("narration", {"text": text})


def _display_region(region: str) -> str:
    return "US-" + region[3:].title() if region.startswith("us-") else region.title()


def _narrate_incident(bus: EventBus, incident: Incident) -> None:
    channel = _CHANNEL_NAMES.get(incident.channel, incident.channel)
    region = _display_region(incident.region)
    _narrate(
        bus,
        f"Found a problem on {channel} ({region}) — ads are failing to load for viewers.",
    )
    _narrate(
        bus,
        f"This is costing ${incident.revenue_at_risk_per_min:,.2f} per minute, and would "
        f"reach ${incident.projected_loss_if_unaddressed:,.2f} if left alone.",
    )
    send_best_effort(
        f"BreakEven: fault detected on {channel}",
        _format_alert(
            "Ads are failing to load for viewers — investigating now.",
            {
                "Channel": f"{channel} ({region})",
                "Revenue at risk": f"${incident.revenue_at_risk_per_min:,.2f} per minute",
                "Projected loss if unaddressed": (
                    f"${incident.projected_loss_if_unaddressed:,.2f}"
                ),
            },
        ),
    )


def _narrate_remedy(bus: EventBus, incident: Incident, remedy: Remedy) -> None:
    channel = _CHANNEL_NAMES.get(incident.channel, incident.channel)
    region = _display_region(incident.region)
    _narrate(
        bus, f"Found it: the video ad {remedy.creative_id} is broken and won't play."
    )
    send_best_effort(
        f"BreakEven: cause found on {channel}",
        _format_alert(
            "Root cause identified.",
            {
                "Channel": f"{channel} ({region})",
                "Cause": f"video ad {remedy.creative_id} is broken and won't play",
            },
        ),
    )
    if autonomy_eligible(remedy.action, incident):
        channel_count = len(remedy.action.blast_radius.channels)
        replacement = _replacement_creative(remedy.creative_id)
        _narrate(
            bus,
            f"Decision: block ad {remedy.creative_id} on {channel}. The channel will "
            f"serve {replacement} next from its configured rotation; no house ad is "
            f"invented. Safe — it affects {channel_count} of {len(CHANNELS)} channels, "
            f"{region} only, and can be undone.",
        )
        _narrate_applying(bus, remedy)
    else:
        _narrate(
            bus,
            "I need a human to approve this before I touch anything because the "
            "available evidence is not strong enough for an automatic change.",
        )


def _narrate_applying(bus: EventBus, remedy: Remedy) -> None:
    """Narrate execution only after autonomy or a human has actually authorised it."""
    replacement = _replacement_creative(remedy.creative_id)
    _narrate(
        bus,
        f"Applying the fix now: block {remedy.creative_id}; route {replacement} "
        "into that ad slot.",
    )
    minutes = settle_window_seconds(remedy.action) / 60
    _narrate(bus, f"Watching for {minutes:g} minutes to confirm ads recover…")


def _replacement_creative(creative_id: str) -> str:
    """Name the deterministic next creative the simulator rotates into the slot."""
    try:
        index = CREATIVE_IDS.index(creative_id)
    except ValueError:
        return "the next eligible creative"
    return CREATIVE_IDS[(index + 1) % len(CREATIVE_IDS)]


_FIXED_OUTCOMES = frozenset(
    {ActionOutcome.VERIFIED, ActionOutcome.EXECUTED_AWAITING_SETTLEMENT}
)


def _email_outcome(incident: Incident, entry: AuditEntry, message: str) -> None:
    """`GAPS.md` #11 buckets 4 (problem) and 5 (fixed) — the single funnel every remedy
    type's settled `AuditEntry` already passes through, so one call site covers A1/A3/A4.

    Reuses the same real, already-computed fields the audit entry and console narration
    carry (`predicted_effect`, `action_id`, `revert_status`) — nothing here is invented to
    fill the email body.
    """
    action_id = entry.arguments.get("action_id", "unknown")
    predicted_effect = entry.arguments.get("predicted_effect", "unknown")
    if entry.result in _FIXED_OUTCOMES:
        subject = f"BreakEven: fix applied on {incident.channel}"
        body = (
            f"{message}\n\n"
            f"What was changed: {predicted_effect}\n"
            f"Action id: {action_id}\n"
            f"Current revert status: {entry.revert_status.value}\n\n"
            "To revert this action, use the operator console's Revert control with the "
            f"action id above.\n\nOperator console: {console_url()}"
        )
    else:
        subject = f"BreakEven: problem on {incident.channel}"
        body = (
            f"{message}\n\n"
            f"What was attempted: {predicted_effect}\n"
            f"Action id: {action_id}\n"
            f"Current revert status: {entry.revert_status.value}\n\n"
            f"Operator console: {console_url()}"
        )
    send_best_effort(subject, body)


def _narrate_outcome(bus: EventBus, incident: Incident, entry: AuditEntry) -> None:
    messages = {
        ActionOutcome.VERIFIED: "Confirmed: ads are loading normally again. The fix worked.",
        ActionOutcome.UNVERIFIED_REVERTED_AND_ESCALATED: (
            "The fix did not work, so it was undone and a human was alerted."
        ),
        ActionOutcome.UNVERIFIED_SETTLEMENT_FAILED: (
            "I could not safely close out the fix. A human needs to check the platform."
        ),
        ActionOutcome.UNVERIFIED_REVERTED_BY_TTL: (
            "The safety watchdog undid the fix before it could be confirmed."
        ),
        ActionOutcome.UNVERIFIED_MEASUREMENT_FAILED: (
            "The result could not be measured, so a human needs to check the platform."
        ),
        # `D-S114`: A4's channel-wide containment (`_live_conservation_remediation`) has
        # no wait-then-remeasure step the way A3's does, so its own entry is honestly
        # `EXECUTED_AWAITING_SETTLEMENT` rather than a fabricated `VERIFIED` — this is
        # the one narration for it, not a gap in this dict.
        ActionOutcome.EXECUTED_AWAITING_SETTLEMENT: (
            "Contained: the affected creatives were blocked. This was not re-measured "
            "afterward, so a human may want to confirm it held."
        ),
    }
    message = messages[entry.result]
    _narrate(bus, message)
    _email_outcome(incident, entry, message)


def _run_stage(
    bus: EventBus,
    stage: str,
    detail: str,
    operation: Callable[[], object],
    *,
    incident: Incident | None = None,
) -> object | None:
    _publish_stage(bus, stage, "started", detail)
    try:
        result = operation()
    except (HumanApprovalRequired, PolicyRejection) as error:
        _publish_stage(bus, stage, "skipped", str(error))
        return None
    except Exception as error:  # pylint: disable=broad-exception-caught
        error_text = str(error)
        bounded_error_text = (
            error_text
            if len(error_text) <= RESULT_SUMMARY_LIMIT
            else (
                f"{error_text[:RESULT_SUMMARY_LIMIT]} "
                f"… (truncated from {len(error_text)} characters)"
            )
        )
        _narrate(
            bus,
            f"I could not complete the {stage.replace('_', ' ')} step. The failure was "
            f"recorded instead of being hidden: {bounded_error_text}",
        )
        # Yuvraj, 2026-09-09: a failed stage used to only narrate on-screen — nobody was
        # actually told. Every genuine stage failure now emails a human with exactly what
        # broke, on which channel, and the real error, the same `send_best_effort` channel
        # every other checkpoint in this file already uses.
        stage_label = stage.replace("_", " ")
        where = f" on {incident.channel!r} ({incident.region!r})" if incident else ""
        fields = {"Error": bounded_error_text}
        if incident is not None:
            fields["Channel"] = f"{incident.channel} ({incident.region})"
            fields["Revenue at risk"] = f"${incident.revenue_at_risk_per_min:,.2f}/min"
        send_best_effort(
            f"BreakEven: {stage_label} step failed{where}",
            _format_alert(
                f"The {stage_label} step failed and was not silently retried or hidden.",
                fields,
            ),
        )
        _publish_stage(bus, stage, "failed", error_text)
        return None
    _publish_stage(bus, stage, "ok", detail)
    return result


def _live_remediation(  # pylint: disable=too-many-arguments
    incident: Incident,
    *,
    base_url: str | None = None,
    state_dir: Path = Path(".breakeven-state"),
    log_path: Path = Path(".breakeven-audit.jsonl"),
    human_approved: bool = False,
    on_executed: Callable[[ActionResult], None] | None = None,
) -> AuditEntry:
    """Call the reviewed remediator with fixed simulator-owned Slice 1 inputs."""
    telemetry = {
        channel.channel_id: channel.concurrency_baseline for channel in CHANNELS
    }
    return remediate(
        incident,
        telemetry,
        action_id=f"action-{incident.id}",
        ttl=timedelta(minutes=10),
        threshold=0.02,
        direction=ThresholdDirection.AT_MOST,
        agent_identity="break-even-orchestrator",
        base_url=base_url or os.environ.get("BREAKEVEN_SIM_URL", DEFAULT_SIMULATOR_URL),
        measure=query_scalar,
        escalate=_escalate_via_email,
        state_dir=state_dir,
        log_path=log_path,
        human_approved=human_approved,
        on_executed=on_executed,
    )


def _last_entry_for_action(
    log_path: Path, action_id: str
) -> AuditEntry | None:
    """Return the most recent real audit entry written for `action_id`, or `None` if
    the log doesn't exist yet or carries none — never fabricated, only ever read back
    from what `append_entry` genuinely wrote.
    """
    try:
        entries = audit_export(log_path)
    except FileNotFoundError:
        return None
    matching = [
        entry for entry in entries if entry.arguments.get("action_id") == action_id
    ]
    return matching[-1] if matching else None


def _live_pathway_remediation(
    incident: Incident,
    degraded_pathway: str,
    healthy_pathway: str,
    *,
    base_url: str | None = None,
    state_dir: Path = Path(".breakeven-state"),
    log_path: Path = Path(".breakeven-audit.jsonl"),
) -> AuditEntry | None:
    """Call the real A1 pathway-steering remedy for a detected origin-degradation
    incident. Returns the real settled `AuditEntry` `steer_pathway`'s own internal
    `verification.settle()` calls already wrote for this channel — never a fabricated
    one — or `None` if the ramp aborted before any step reached `settle()`.

    `D-S111`: parallel to `_live_remediation`, not folded into it — `steer_pathway`
    (`actions/steering.py`) is a multi-step ramp with its own verification and revert
    loop, not a single `ActionResult` `remediate()` can execute.

    `baseline_5xx_rate` is measured **live, right now**, from the healthy pathway's own
    real current rate — never a constant. This closes `GAPS.md`'s #2 finding that a
    pinned `0.0` baseline made this remedy's success path structurally undemonstrable:
    with a real baseline, `3 × baseline` is a real, non-zero bar the ramp can actually
    clear. `observe_5xx_rate` re-measures that same pathway (the one traffic is being
    migrated *onto*) at each ramp step — verifying it does not itself degrade under the
    new load, the exact thundering-herd risk `PRODUCTION_ACTION_LAYER.md` §5.1 names.

    `D-S114`: returning `steer_pathway`'s own real settled entry (rather than its bare
    `"COMPLETE"`/`"ABORTED"` string) is what lets the A1 dispatch path in `run_thread`
    reuse the exact same Grafana-annotation/incident-timeline/operator-brief pipeline the
    A3 path already has (`select_remedy`'s `A11` bookkeeping) — real data already on
    disk, not invented to fit the shape.
    """
    channel_id = incident.channel
    telemetry = {
        channel.channel_id: channel.concurrency_baseline for channel in CHANNELS
    }
    cohort = Cohort(
        channels=frozenset({channel_id}),
        regions=frozenset({incident.region}),
        devices=frozenset({"ctv"}),
        cdn_pathways=frozenset({degraded_pathway, healthy_pathway}),
    )

    def observe_healthy_pathway_rate() -> float:
        return query_scalar(
            "max(origin_5xx_rate"
            f'{{channel="{channel_id}",cdn_pathway="{healthy_pathway}"}})'
        )

    baseline = observe_healthy_pathway_rate()
    action_id = f"action-{incident.id}-{channel_id}"
    ramp_result = steer_pathway(
        cohort,
        target_priority=(healthy_pathway, degraded_pathway),
        ttl=30.0,
        telemetry=telemetry,
        baseline_5xx_rate=baseline,
        observe_5xx_rate=observe_healthy_pathway_rate,
        escalate=_escalate_via_email,
        state_dir=state_dir,
        log_path=log_path,
        action_id_prefix=f"action-{incident.id}",
        last_good_priority=(degraded_pathway, healthy_pathway),
    )
    # `D-S115`: the one real effect this remedy has on anything outside its own audit
    # log. `steer_pathway`'s own mutation (`actions/steering.py`) is a local file on
    # this process's machine — the simulator, a separate deployment, can never see it.
    # Only on a genuine `"COMPLETE"` (never on `"ABORTED"`, which means the ramp itself
    # already reverted) is the channel really migrated, via a real HTTP call the
    # simulator's own `ControlRegistry` state actually changes from.
    if ramp_result == "COMPLETE":
        resolved_base_url = base_url or os.environ.get(
            "BREAKEVEN_SIM_URL", DEFAULT_SIMULATOR_URL
        )
        request = urllib.request.Request(
            f"{resolved_base_url}/control/pathway",
            data=json.dumps(
                {"channel_id": channel_id, "active_pathway": healthy_pathway}
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10.0):  # noqa: S310
            pass
    return _last_entry_for_action(log_path, action_id)


def _current_eligible_creatives(base_url: str, channel_id: str) -> tuple[str, ...]:
    """Read a channel's real current rotation from the simulator's own live control
    state — `CREATIVE_IDS` minus whatever `GET /control/blocklist` reports blocked for
    this channel right now, the identical derivation `ControlRegistry.eligible_creatives`
    performs server-side (`sim/control.py`), read through the one control endpoint the
    simulator already exposes rather than adding a new one.
    """
    with urllib.request.urlopen(  # noqa: S310 - fixed http(s) simulator base_url only
        f"{base_url}/control/blocklist", timeout=10.0
    ) as response:
        pairs = json.loads(response.read())
    blocked = {
        pair["creative_id"] for pair in pairs if pair["channel_id"] == channel_id
    }
    return tuple(
        creative_id for creative_id in CREATIVE_IDS if creative_id not in blocked
    )


def _live_conservation_remediation(
    incident: Incident,
    channel_id: str,
    *,
    base_url: str | None = None,
    state_dir: Path = Path(".breakeven-state"),
    log_path: Path = Path(".breakeven-audit.jsonl"),
) -> AuditEntry:
    """Call the real A4 containment remedy for a channel-wide impression-conservation
    violation: blocklist every creative currently eligible on that channel.

    `D-S112`: channel-scoped, not creative-scoped — `create_delivery_loss` (the fault
    this detects) never names a creative, so this loops the same real
    `blocklist_creative` executor `A3` already uses, once per currently-eligible
    creative, rather than inventing a new executor action or a fictional single-creative
    target. Each call goes through the real policy gate (`ActionType.A4`, its own
    `MAX_VIEWERS_BY_ACTION_TYPE` ceiling) before executing.

    `D-S114`: `blocklist_creative` writes no audit entry of its own (only `remediate()`'s
    explicit `append_entry` calls and `verification.settle()` do) — this path bypassed
    `remediate()` entirely, so before this change A4's containment left **zero** audit
    trail, a real gap against `PRODUCTION_ACTION_LAYER.md` §5.15's "every action
    attributed... in an append-only audit log" doctrine. Fixed by writing one real,
    aggregate entry for the whole channel-level action here. Its outcome is
    `EXECUTED_AWAITING_SETTLEMENT`, not `VERIFIED` — this containment has no
    wait-then-remeasure step the way `A3`'s does, and claiming a measured verification
    that never happened would violate this codebase's own "nothing is asserted that is
    not evidenced" rule (`remediator.py`'s own module docstring, `INV-S02`). Honest
    about what did happen (a real, policy-gated block, on every eligible creative) and
    what didn't (a settled re-measurement).
    """
    resolved_base_url = base_url or os.environ.get(
        "BREAKEVEN_SIM_URL", DEFAULT_SIMULATOR_URL
    )
    telemetry = {
        channel.channel_id: channel.concurrency_baseline for channel in CHANNELS
    }
    cohort = Cohort(
        channels=frozenset({channel_id}),
        regions=frozenset({incident.region}),
        devices=frozenset({"ctv"}),
        cdn_pathways=frozenset({"cdn-a"}),
    )
    eligible = _current_eligible_creatives(resolved_base_url, channel_id)
    blocked: list[str] = []
    for creative_id in eligible:
        action = ActionResult(
            action_id=f"action-{incident.id}-{creative_id}",
            reversible=True,
            blast_radius=cohort,
            predicted_effect=(
                f"ad_beacon_failures_total for channel {channel_id!r} falls to zero"
            ),
            verification_query=(
                "sum(increase(ad_beacon_failures_total"
                f'{{channel="{channel_id}"}}[600s]))'
            ),
            ttl=timedelta(minutes=10),
        )

        def _execute(action: ActionResult, creative_id: str = creative_id) -> None:
            blocklist_creative(
                action,
                creative_id=creative_id,
                cohort=action.blast_radius,
                base_url=resolved_base_url,
                state_dir=state_dir,
                escalate=_escalate_via_email,
            )

        engine.execute(ActionType.A4, action, telemetry, _execute)
        blocked.append(creative_id)
    entry = AuditEntry(
        agent_identity="break-even-orchestrator",
        timestamp=datetime.now(timezone.utc).isoformat(),
        arguments={
            "action_id": f"action-{incident.id}-{channel_id}",
            "predicted_effect": (
                f"ad_beacon_failures_total for channel {channel_id!r} falls to zero"
            ),
            "verification_query": (
                "sum(increase(ad_beacon_failures_total"
                f'{{channel="{channel_id}"}}[600s]))'
            ),
            "channel": channel_id,
            "blocked_creatives": list(blocked),
        },
        evidence_chain=(
            {
                "action": "blocklist_creative",
                "channel": channel_id,
                "creatives_blocked": len(blocked),
            },
        ),
        result=ActionOutcome.EXECUTED_AWAITING_SETTLEMENT,
        revert_status=RevertStatus.NOT_REVERTED,
    )
    append_entry(entry, log_path=log_path)
    return entry


class _ChildEventBus:  # pylint: disable=too-few-public-methods
    """Send the EventBus publish contract across a process queue."""

    def __init__(self, event_queue) -> None:
        self._event_queue = event_queue

    def publish(self, kind: str, payload) -> object:
        """Forward one event to the parent process and return a non-None receipt."""
        copied = dict(payload)
        self._event_queue.put(("event", kind, copied))
        return copied


def _format_alert(headline: str, fields: dict[str, str], *, cta: str | None = None) -> str:
    """One consistent shape for every escalation email: a plain headline sentence, then
    labeled fields a human can scan in two seconds, then an optional call-to-action link,
    then the console link every email already carried. Yuvraj, 2026-09-09: replaces the
    ad-hoc `f"...\\n...\\n\\n..."` string each call site built by hand."""
    lines = [headline, ""]
    for label, value in fields.items():
        lines.append(f"{label}: {value}")
    lines.append("")
    if cta is not None:
        lines.append(cta)
        lines.append("")
    lines.append(f"Operator console: {console_url()}")
    return "\n".join(lines)


def _decision_link(action_id: str, payload: dict[str, object]) -> str:
    """The email-clickable link to the confirm-then-click decision page (`ui/app.py`'s
    `/controls/decide`) — never a link that acts on load, see that route's own docstring."""
    query = urlencode(
        {
            "action_id": action_id,
            "proposed_action": payload["proposed_action"],
            "projected_saving": payload["projected_saving"],
            "blast_radius": payload["blast_radius"],
        }
    )
    return f"{console_url()}/controls/decide?{query}"


def _approval_payload(incident: Incident, remedy: Remedy) -> dict[str, object]:
    channel = _CHANNEL_NAMES.get(incident.channel, incident.channel)
    region = _display_region(incident.region)
    telemetry = {item.channel_id: item.concurrency_baseline for item in CHANNELS}
    viewers = remedy.action.blast_radius.viewer_count(telemetry)
    return {
        "action_id": remedy.action.action_id,
        "proposed_action": (
            f"Block video ad {remedy.creative_id} on {channel} ({region})"
        ),
        "projected_saving": (f"${incident.revenue_at_risk_per_min:,.2f} per minute"),
        "blast_radius": f"{viewers:,} viewers on one channel in {region}",
    }


def _policy_rejection_text(error: PolicyRejection) -> str:
    messages = {
        "WILDCARD_IN_TWO_DIMENSIONS": (
            "That fix reaches too many broad parts of the platform, so it was rejected."
        ),
        "OVER_BLAST_RADIUS_CEILING": (
            "That fix would affect too much of the platform, so it was rejected."
        ),
        "BLAST_RADIUS_UNMEASURABLE": (
            "The impact of that fix could not be measured, so it was rejected."
        ),
    }
    return messages[error.reason.name]


def cycle_process_main(
    event_queue,
    decision_queue,
    base_url: str,
    state_dir: Path,
    log_path: Path,
) -> bool:
    """Run one cycle in a killable process and forward every event to the web process.

    Returns whether this cycle found and fully finished a real incident — the signal
    `_AgentLoopProcess` (`ui/controls.py`) uses to know it can stop polling Grafana rather
    than continue forever after the thing it was watching for is already resolved.
    """
    bus = _ChildEventBus(event_queue)

    def action_started(action) -> None:
        event_queue.put(("action_started", action.action_id))

    def remediate_with_approval(
        incident: Incident, *, on_executed: Callable[[ActionResult], None] | None = None
    ) -> AuditEntry:
        def record_execution(action: ActionResult) -> None:
            action_started(action)
            if on_executed is not None:
                on_executed(action)

        try:
            return _live_remediation(
                incident,
                base_url=base_url,
                state_dir=state_dir,
                log_path=log_path,
                on_executed=record_execution,
            )
        except HumanApprovalRequired as approval:
            remedy = select_remedy(
                incident,
                action_id=f"action-{incident.id}",
                ttl=timedelta(minutes=10),
            )
            approval_payload = _approval_payload(incident, remedy)
            event_queue.put(("approval", approval_payload))
            send_best_effort(
                f"BreakEven: approval needed for {incident.channel}",
                _format_alert(
                    "A fix is ready but needs your approval before anything changes.",
                    {
                        "Channel": _CHANNEL_NAMES.get(incident.channel, incident.channel),
                        "Proposed action": str(approval_payload["proposed_action"]),
                        "Projected saving": str(approval_payload["projected_saving"]),
                        "Blast radius": str(approval_payload["blast_radius"]),
                    },
                    cta=(
                        "Decide now (opens a page with Approve/Reject buttons — "
                        "nothing happens until you click one): "
                        + _decision_link(
                            str(approval_payload["action_id"]), approval_payload
                        )
                    ),
                ),
            )
            decision = decision_queue.get()
            expected = remedy.action.action_id
            if decision != {"decision": "approve", "action_id": expected}:
                _narrate(
                    bus,
                    "The operator rejected this fix. The platform was left unchanged.",
                )
                send_best_effort(
                    f"BreakEven: fix rejected for {incident.channel}",
                    f"The operator rejected the proposed fix for {incident.channel!r}. "
                    "The platform was left unchanged.\n\n"
                    f"Operator console: {console_url()}",
                )
                raise HumanApprovalRequired(remedy.action) from approval
            _narrate(
                bus,
                "The operator approved this fix. The policy engine is checking it now.",
            )
            _narrate_applying(bus, remedy)
            try:
                return _live_remediation(
                    incident,
                    base_url=base_url,
                    state_dir=state_dir,
                    log_path=log_path,
                    human_approved=True,
                    on_executed=record_execution,
                )
            except PolicyRejection as error:
                _narrate(bus, _policy_rejection_text(error))
                send_best_effort(
                    f"BreakEven: fix rejected for {incident.channel}",
                    f"On {incident.channel!r}: {_policy_rejection_text(error)}\n\n"
                    f"Operator console: {console_url()}",
                )
                event_queue.put(
                    ("approval_failed", expected, _policy_rejection_text(error))
                )
                raise
        except PolicyRejection as error:
            _narrate(bus, _policy_rejection_text(error))
            send_best_effort(
                f"BreakEven: fix rejected for {incident.channel}",
                f"On {incident.channel!r}: {_policy_rejection_text(error)}\n\n"
                f"Operator console: {console_url()}",
            )
            raise

    entry = run_thread(
        bus=bus,
        base_url=base_url,
        state_dir=state_dir,
        remediate_fn=remediate_with_approval,
    )
    if entry is not None:
        event_queue.put(("result", entry.as_record()))
    return entry is not None


def run_thread(  # pylint: disable=too-many-arguments
    *,
    bus: EventBus,
    base_url: str | None = None,
    mcp_endpoint: str | None = None,
    state_dir: Path | None = None,
    detect: Callable[[], SystemHealthAssertion] = run_cycle,
    diagnose_fn: Callable[[Incident], Incident] = diagnose,
    remediate_fn: Callable[..., AuditEntry] = _live_remediation,
    select_pathway_remedy_fn: Callable[[Incident], tuple[str, str] | None] = (
        select_pathway_remedy
    ),
    pathway_remediate_fn: Callable[[Incident, str, str], str] = (
        _live_pathway_remediation
    ),
    select_conservation_remedy_fn: Callable[[Incident], str | None] = (
        select_conservation_remedy
    ),
    conservation_remediate_fn: Callable[[Incident, str], tuple[str, ...]] = (
        _live_conservation_remediation
    ),
    publish_evidence_fn: Callable[[EventBus, Incident], object] = publish_evidence,
    publish_brief_fn: Callable[..., object] = publish_brief,
) -> AuditEntry | None:
    """Run one cycle and publish every outcome immediately to the operator bus."""
    resolved_mcp_endpoint = mcp_endpoint or os.environ.get(
        "BREAKEVEN_MCP_ENDPOINT", DEFAULT_MCP_ENDPOINT
    )
    with McpCallRecorder(bus):
        _narrate(bus, "Checking all channels for ad delivery problems…")
        assertion = _run_stage(bus, "detect", "Running Watchtower detection.", detect)
        if not isinstance(assertion, SystemHealthAssertion):
            return None
        _publish_stage(
            bus, "open_incident", "started", "Evaluating the detection floor."
        )
        incident = open_incident(assertion, state_dir=state_dir)
        if incident is None:
            _publish_stage(
                bus,
                "open_incident",
                "skipped",
                "No incident opened: no failing channel exceeded $50.00/min.",
            )
            _narrate(
                bus,
                "No failing channel is losing more than $50.00 per minute, so no "
                "incident was opened.",
            )
            return None
        _publish_stage(
            bus, "open_incident", "ok", "Opened an incident above the detection floor."
        )
        _narrate_incident(bus, incident)
        # Yuvraj, 2026-09-09: the console's hero "Revenue at risk" tile used to be gated on
        # `brief` — the very last stage, minutes away. The real number already exists here,
        # the moment an incident clears the detection floor, so publish it now instead of
        # making the operator wait through diagnose/remediate/verify/close to see it.
        bus.publish(
            "risk",
            {
                "channel": incident.channel,
                "revenue_at_risk_per_min": incident.revenue_at_risk_per_min,
                "projected_loss_if_unaddressed": incident.projected_loss_if_unaddressed,
            },
        )
        if base_url is not None:
            _run_stage(
                bus,
                "annotate_incident",
                "Recording the incident on the dashboard.",
                lambda: annotate_incident_detected(
                    incident, mcp_endpoint=resolved_mcp_endpoint
                ),
                incident=incident,
            )
            created_incident_id = _run_stage(
                bus,
                "create_incident",
                "Creating the Grafana incident record.",
                lambda: create_incident(incident, mcp_endpoint=resolved_mcp_endpoint),
                incident=incident,
            )
            if isinstance(created_incident_id, str):
                incident.grafana_incident_id = created_incident_id
                _run_stage(
                    bus,
                    "incident_detected",
                    "Recording the detected incident activity.",
                    lambda: add_incident_activity(
                        created_incident_id,
                        "Detected: automated monitoring found an ad delivery failure.",
                        incident.detected_at,
                        mcp_endpoint=resolved_mcp_endpoint,
                    ),
                    incident=incident,
                )
        _narrate(bus, "Investigating the cause…")

        def diagnose_and_publish() -> Incident:
            diagnosed = diagnose_fn(incident)
            publish_evidence_fn(bus, diagnosed)
            return diagnosed

        diagnosed = _run_stage(
            bus,
            "diagnose",
            "Collecting grounded diagnosis evidence.",
            diagnose_and_publish,
            incident=incident,
        )
        if not isinstance(diagnosed, Incident):
            return None
        if diagnosed.grafana_incident_id is not None:
            _run_stage(
                bus,
                "incident_diagnosed",
                "Recording the completed diagnosis activity.",
                lambda: add_incident_activity(
                    diagnosed.grafana_incident_id,
                    "Diagnosed: grounded evidence identified the likely cause.",
                    datetime.now(timezone.utc),
                    mcp_endpoint=resolved_mcp_endpoint,
                ),
                incident=diagnosed,
            )
        def _finish_incident_lifecycle(
            entry: AuditEntry, *, executed_at: datetime | None
        ) -> AuditEntry | None:
            """The Plane-C bookkeeping every settled remedy owes, regardless of which
            action type produced `entry` — `PRODUCTION_ACTION_LAYER.md` `A11`
            ("annotate, file/close incident, post timeline, write operator brief").

            `D-S114`: extracted verbatim from the A3 path's own existing tail (byte-
            identical behavior, confirmed by the untouched A3 test suite) so A1
            (`D-S111`) and A4 (`D-S112`) reuse the exact same real Grafana-annotation /
            incident-timeline / operator-brief pipeline instead of returning `None`
            straight after their own remedy narration, which is what they did before
            this decision — a real incident handled by A1 or A4 previously never got
            its `incident_acted`/`annotate_settlement`/`incident_verified`/
            `close_incident`/brief steps at all.
            """
            if diagnosed.grafana_incident_id is not None and executed_at is not None:
                _run_stage(
                    bus,
                    "incident_acted",
                    "Recording the actual action execution activity.",
                    lambda: add_incident_activity(
                        diagnosed.grafana_incident_id,
                        "Acted: the corrective action executed.",
                        executed_at,
                        mcp_endpoint=resolved_mcp_endpoint,
                    ),
                    incident=diagnosed,
                )
            _narrate_outcome(bus, diagnosed, entry)
            if base_url is not None:
                _run_stage(
                    bus,
                    "annotate_settlement",
                    "Recording the settled outcome on the dashboard.",
                    lambda: annotate_remediation_settled(
                        entry, mcp_endpoint=resolved_mcp_endpoint
                    ),
                    incident=diagnosed,
                )
                if diagnosed.grafana_incident_id is not None:
                    verified_at = datetime.now(timezone.utc)
                    _run_stage(
                        bus,
                        "incident_verified",
                        "Recording the settled verification activity.",
                        lambda: add_incident_activity(
                            diagnosed.grafana_incident_id,
                            "Verified: remediation settled and its outcome was "
                            "recorded.",
                            verified_at,
                            mcp_endpoint=resolved_mcp_endpoint,
                        ),
                        incident=diagnosed,
                    )
                    _run_stage(
                        bus,
                        "close_incident",
                        "Resolving the confirmed Grafana incident.",
                        lambda: close_incident(
                            diagnosed,
                            state_dir=state_dir,
                            mcp_endpoint=resolved_mcp_endpoint,
                        ),
                        incident=diagnosed,
                    )
            dashboard_url = (
                _run_stage(
                    bus,
                    "dashboard_deeplink",
                    "Preparing the Grafana dashboard link.",
                    lambda: dashboard_deeplink(mcp_endpoint=resolved_mcp_endpoint),
                    incident=diagnosed,
                )
                if base_url is not None
                else None
            )
            links = {
                "dashboard_url": (
                    dashboard_url if isinstance(dashboard_url, str) else None
                ),
                "incident_url": (
                    incident_url(diagnosed.grafana_incident_id)
                    if diagnosed.grafana_incident_id is not None
                    else None
                ),
                "alert_rule_url": (
                    alert_rule_url(diagnosed.new_alert_rule_uid)
                    if diagnosed.new_alert_rule_uid is not None
                    else None
                ),
            }

            def publish_with_links() -> object:
                parameters = signature(publish_brief_fn).parameters.values()
                accepts_links = (
                    any(
                        parameter.name == "links"
                        or parameter.kind is Parameter.VAR_KEYWORD
                        or parameter.kind is Parameter.VAR_POSITIONAL
                        for parameter in parameters
                    )
                    or len(signature(publish_brief_fn).parameters) >= 4
                )
                if accepts_links:
                    return publish_brief_fn(bus, diagnosed, entry, links)
                return publish_brief_fn(bus, diagnosed, entry)

            result = _run_stage(
                bus,
                "brief",
                "Preparing the operator brief.",
                publish_with_links,
                incident=diagnosed,
            )
            if result is None:
                return None
            return entry

        # `D-S111`: checked before `select_remedy` — an origin-pathway degradation and a
        # creative-transcode fault are mutually exclusive, deterministically-named
        # shapes (`_origin_degradation_fault` / `_creative_transcode_fault` each require
        # their own distinct evidence), so trying pathway detection first never steals a
        # real A3 case; it only ever adds a case A3's own detector already refuses.
        pathway_fault = select_pathway_remedy_fn(diagnosed)
        if pathway_fault is not None:
            degraded_pathway, healthy_pathway = pathway_fault
            _narrate(
                bus,
                f"CDN pathway {degraded_pathway!r} is degraded on "
                f"{diagnosed.channel!r} while {healthy_pathway!r} is healthy. "
                "Migrating traffic onto the healthy pathway now…",
            )
            send_best_effort(
                f"BreakEven: cause found on {diagnosed.channel}",
                f"Cause identified on {diagnosed.channel!r}: CDN pathway "
                f"{degraded_pathway!r} is degraded while {healthy_pathway!r} is "
                "healthy. Migrating traffic onto the healthy pathway now.\n\n"
                f"Operator console: {console_url()}",
            )
            executed_at = datetime.now(timezone.utc)
            pathway_entry = _run_stage(
                bus,
                "remediate",
                "Steering traffic off the degraded pathway.",
                lambda: pathway_remediate_fn(
                    diagnosed, degraded_pathway, healthy_pathway
                ),
                incident=diagnosed,
            )
            if not isinstance(pathway_entry, AuditEntry):
                _narrate(
                    bus,
                    f"Pathway migration for {diagnosed.channel!r} did not complete "
                    "cleanly, or settled before any verification was recorded.",
                )
                return None
            return _finish_incident_lifecycle(pathway_entry, executed_at=executed_at)
        # `D-S112`: same reasoning as the pathway check above — a conservation
        # violation and a creative-transcode fault are mutually exclusive,
        # deterministically-named shapes, so checking this first never steals a real
        # A3 case.
        conservation_channel = select_conservation_remedy_fn(diagnosed)
        if conservation_channel is not None:
            _narrate(
                bus,
                f"A real impression-conservation violation is confirmed on "
                f"{conservation_channel!r} — ads are rendering without being billed. "
                "Blocking every active creative on this channel now to contain it…",
            )
            send_best_effort(
                f"BreakEven: cause found on {conservation_channel}",
                f"Cause identified on {conservation_channel!r}: a real "
                "impression-conservation violation — ads are rendering without being "
                "billed. Blocking every active creative on this channel now to contain it.\n\n"
                f"Operator console: {console_url()}",
            )
            executed_at = datetime.now(timezone.utc)
            conservation_entry = _run_stage(
                bus,
                "remediate",
                "Containing the conservation violation.",
                lambda: conservation_remediate_fn(diagnosed, conservation_channel),
                incident=diagnosed,
            )
            if not isinstance(conservation_entry, AuditEntry):
                _narrate(
                    bus,
                    f"Containment for {conservation_channel!r} did not complete "
                    "cleanly.",
                )
                return None
            return _finish_incident_lifecycle(
                conservation_entry, executed_at=executed_at
            )
        remedy: Remedy | None = None
        try:
            remedy = select_remedy(
                diagnosed,
                action_id=f"action-{diagnosed.id}",
                ttl=timedelta(minutes=10),
            )
        except RemedyNotFound:
            _narrate(
                bus,
                "I could not identify a safe fix from the available evidence, so I left "
                "the platform unchanged.",
            )
            send_best_effort(
                f"BreakEven: could not fix {diagnosed.channel}",
                f"On {diagnosed.channel!r}: I could not identify a safe fix from the "
                "available evidence, so I left the platform unchanged. A human should "
                "look at this incident.\n\n"
                f"Operator console: {console_url()}",
            )
        if remedy is not None:
            _narrate_remedy(bus, diagnosed, remedy)
            if base_url is not None:
                alert_rule_uid = _run_stage(
                    bus,
                    "ensure_revenue_alert_rule",
                    "Creating the revenue-at-risk recurrence alert.",
                    lambda: ensure_revenue_alert_rule(
                        diagnosed.channel,
                        remedy.creative_id,
                        mcp_endpoint=resolved_mcp_endpoint,
                    ),
                    incident=diagnosed,
                )
                if isinstance(alert_rule_uid, str):
                    diagnosed.new_alert_rule_uid = alert_rule_uid
        executed_at: datetime | None = None

        def record_execution(_action: ActionResult) -> None:
            nonlocal executed_at
            executed_at = datetime.now(timezone.utc)

        def remediate_and_observe() -> AuditEntry:
            parameters = signature(remediate_fn).parameters.values()
            if any(
                parameter.name == "on_executed"
                or parameter.kind is Parameter.VAR_KEYWORD
                for parameter in parameters
            ):
                return remediate_fn(diagnosed, on_executed=record_execution)
            return remediate_fn(diagnosed)

        entry = _run_stage(
            bus,
            "remediate",
            "Selecting and verifying a corrective action.",
            remediate_and_observe,
            incident=diagnosed,
        )
        if not isinstance(entry, AuditEntry):
            return None
        return _finish_incident_lifecycle(entry, executed_at=executed_at)


# W1: the Gemini calls resolve their backend from the environment, not from code, so a
# shell that has not exported these selects the Developer API, fails for want of an API
# key, and surfaces seven Grafana calls later as an unrelated "no token counts" error.
# Naming them here makes a misconfigured launch fail in one readable line instead.
_REQUIRED_VERTEX_ENVIRONMENT = (
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
)


def require_vertex_environment(
    environ: Mapping[str, str] | None = None,
) -> None:
    """Fail immediately, naming what is missing, rather than deep inside a cycle."""
    source = os.environ if environ is None else environ
    missing = [name for name in _REQUIRED_VERTEX_ENVIRONMENT if not source.get(name)]
    if missing:
        raise RuntimeError(
            "Vertex AI is not configured, so every model call would fail: "
            f"{', '.join(missing)} is not set. Export "
            "GOOGLE_GENAI_USE_VERTEXAI=TRUE, GOOGLE_CLOUD_PROJECT=<project> and "
            "GOOGLE_CLOUD_LOCATION=<region> before starting the agent."
        )


def main() -> None:
    """Serve the page first; Inject starts each cycle in its own child process.

    Yuvraj, 2026-09-09: `serve()`'s own default (`127.0.0.1:8081`) is deliberate for local
    use — `ui/app.py`'s docstring already flags this console has no authentication, so
    loopback-only is the safe default. Cloud Run always sets `PORT` and requires the
    container to bind `0.0.0.0`; that env var's presence is what distinguishes "deployed"
    from "someone's laptop" here; a bare install with `PORT` merely unset keeps the old
    loopback behavior byte-for-byte.
    """
    require_vertex_environment()
    bus = EventBus()
    controls = ControlPlane(
        bus,
        simulator_url=os.environ.get("BREAKEVEN_SIM_URL", DEFAULT_SIMULATOR_URL),
        state_dir=Path(".breakeven-state"),
        log_path=Path(".breakeven-audit.jsonl"),
    )
    deployed_port = os.environ.get("PORT")
    if deployed_port is not None:
        serve(bus, controls, host="0.0.0.0", port=int(deployed_port))  # noqa: S104
    else:
        serve(bus, controls)


if __name__ == "__main__":
    main()
