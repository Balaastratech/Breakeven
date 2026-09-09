"""Plain-language operator brief generation — F-AGT-21."""

from __future__ import annotations

import re

from breakeven.actions.audit import ActionOutcome, AuditEntry
from breakeven.agents.incident import Incident
from breakeven.sim.world import CHANNELS

_BLOCKLIST_EFFECT = re.compile(
    r"^ad_creative_errors_total for creative '([^']+)' on channel '([^']+)' falls to zero$"
)
_CHANNEL_NAMES = {channel.channel_id: channel.name for channel in CHANNELS}


def _display_region(region: str) -> str:
    return "US-" + region[3:].title() if region.startswith("us-") else region.title()


def operator_brief(incident: Incident, entry: AuditEntry) -> str:
    """Summarise an incident and its completed action without exposing internals."""
    channel = _CHANNEL_NAMES.get(incident.channel, incident.channel)
    region = _display_region(incident.region)
    return "\n\n".join(
        (
            "What broke\n" f"Advertising delivery failed in {channel} ({region}).",
            "What it cost\n"
            f"Revenue at risk was ${incident.revenue_at_risk_per_min:,.2f} per minute, "
            f"with a projected loss of ${incident.projected_loss_if_unaddressed:,.2f} "
            "if left unaddressed.",
            f"What was done\n{_action_summary(incident, entry)}",
        )
    )


def _action_summary(incident: Incident, entry: AuditEntry) -> str:
    """Describe the action outcome in operational language."""
    action = _action_description(incident, entry)
    if action is None:
        return _generic_action_summary(entry.result)
    summaries = {
        ActionOutcome.VERIFIED: (f"{action}. It was confirmed to be working."),
        ActionOutcome.UNVERIFIED_REVERTED_AND_ESCALATED: (
            f"{action}. It did not produce the expected result, so it was "
            "reversed and the issue was escalated for human follow-up."
        ),
        ActionOutcome.UNVERIFIED_SETTLEMENT_FAILED: (
            f"{action}. It could not be fully confirmed or closed out. Human "
            "follow-up is required."
        ),
        ActionOutcome.UNVERIFIED_REVERTED_BY_TTL: (
            f"{action}. It was automatically reversed before its result could "
            "be confirmed."
        ),
        ActionOutcome.UNVERIFIED_MEASUREMENT_FAILED: (
            f"{action}. Its result could not be measured. "
            "Human follow-up is required."
        ),
    }
    return summaries[entry.result]


def _action_description(incident: Incident, entry: AuditEntry) -> str | None:
    """Name a known blocklist action from its real audit arguments, or say less."""
    predicted_effect = entry.arguments.get("predicted_effect")
    if not isinstance(predicted_effect, str):
        return None
    match = _BLOCKLIST_EFFECT.fullmatch(predicted_effect)
    if match is None:
        return None
    creative_id, channel_id = match.groups()
    channel = _CHANNEL_NAMES.get(channel_id, channel_id)
    region = _display_region(incident.region)
    return f"Blocked the faulty video ad {creative_id} on {channel} ({region})"


def _generic_action_summary(outcome: ActionOutcome) -> str:
    """Retain the established honest fallback when an audit record cannot name more."""
    return {
        ActionOutcome.VERIFIED: (
            "The corrective action was applied and confirmed to be working."
        ),
        ActionOutcome.UNVERIFIED_REVERTED_AND_ESCALATED: (
            "The corrective action did not produce the expected result, so it was "
            "reversed and the issue was escalated for human follow-up."
        ),
        ActionOutcome.UNVERIFIED_SETTLEMENT_FAILED: (
            "The corrective action could not be fully confirmed or closed out. Human "
            "follow-up is required."
        ),
        ActionOutcome.UNVERIFIED_REVERTED_BY_TTL: (
            "The corrective action was automatically reversed before its result could "
            "be confirmed."
        ),
        ActionOutcome.UNVERIFIED_MEASUREMENT_FAILED: (
            "The corrective action was applied, but its result could not be measured. "
            "Human follow-up is required."
        ),
        # `D-S116`: A4's channel-wide containment has no wait-then-remeasure step, so its
        # real entry is honestly `EXECUTED_AWAITING_SETTLEMENT`, never a fabricated
        # `VERIFIED` (`D-S114`). Found missing here — a real `KeyError` — the first time
        # the full unattended A4 loop ever ran end to end against a real fault.
        ActionOutcome.EXECUTED_AWAITING_SETTLEMENT: (
            "The corrective action blocked every affected creative on the channel. "
            "This was not re-measured afterward; human confirmation is recommended."
        ),
    }[outcome]
