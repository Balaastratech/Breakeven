"""Serializable state passed between BreakEven agents."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from breakeven.policy.engine import ActionResult, Cohort

_APPROVAL_STATES = frozenset({"auto", "pending", "approved", "rejected"})
# Single source of truth for the incident-eligibility and severity floors.
AUTO_REMEDIATION_FLOOR_PER_MINUTE = 50.0


@dataclass
class Evidence:
    """A query and its observed result, recorded when evidence is collected."""

    query: str
    result: str
    taken_at: datetime


@dataclass
class HealthCheck:
    """One evidenced conservation result from a Watchtower cycle."""

    invariant: str
    channel: str
    held: bool | None
    detail: str
    evidence: Evidence
    region: str | None = None


# pylint: disable=too-many-instance-attributes
@dataclass
class SystemHealthAssertion:
    """The explicit, serialisable health conclusion emitted every cycle."""

    emitted_at: datetime
    window_seconds: int
    checks: list[HealthCheck]
    aggregate_error_rate: float | None
    revenue_at_risk_per_min: dict[str, float]
    prompt_tokens: int
    output_tokens: int
    total_tokens: int

    def to_json(self) -> str:
        """Return a deterministic, lossless JSON representation of this assertion."""
        return json.dumps(
            {
                "emitted_at": self.emitted_at.isoformat(),
                "window_seconds": self.window_seconds,
                "checks": [
                    {
                        "invariant": check.invariant,
                        "channel": check.channel,
                        "held": check.held,
                        "detail": check.detail,
                        "region": check.region,
                        "evidence": {
                            "query": check.evidence.query,
                            "result": check.evidence.result,
                            "taken_at": check.evidence.taken_at.isoformat(),
                        },
                    }
                    for check in self.checks
                ],
                "aggregate_error_rate": self.aggregate_error_rate,
                "revenue_at_risk_per_min": self.revenue_at_risk_per_min,
                "prompt_tokens": self.prompt_tokens,
                "output_tokens": self.output_tokens,
                "total_tokens": self.total_tokens,
            },
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, text: str) -> SystemHealthAssertion:
        """Restore a health assertion with its nested evidence records."""
        data = json.loads(text)
        data["emitted_at"] = datetime.fromisoformat(data["emitted_at"])
        data["checks"] = [
            HealthCheck(
                invariant=check["invariant"],
                channel=check["channel"],
                held=check["held"],
                detail=check["detail"],
                evidence=Evidence(
                    query=check["evidence"]["query"],
                    result=check["evidence"]["result"],
                    taken_at=datetime.fromisoformat(check["evidence"]["taken_at"]),
                ),
                region=check.get("region"),
            )
            for check in data["checks"]
        ]
        return cls(**data)


# pylint: disable=too-many-instance-attributes
@dataclass
class Incident:
    """The inspectable record handed between the BreakEven sub-agents."""

    id: str
    detected_at: datetime
    channel: str
    region: str
    revenue_at_risk_per_min: float
    projected_loss_if_unaddressed: float
    failure_signature: str
    root_cause: str | None = None
    root_cause_claims: list[tuple[str, str]] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    failing_span: str | None = None
    implicated_ids: dict = field(default_factory=dict)
    proposed_action: ActionResult | None = None
    approval_required: bool = False
    approval_state: str = "auto"
    action_result: str | None = None
    grafana_annotation_id: str | None = None
    grafana_incident_id: str | None = None
    new_alert_rule_uid: str | None = None
    operator_brief: str | None = None

    def __post_init__(self) -> None:
        if self.approval_state not in _APPROVAL_STATES:
            raise ValueError(f"Invalid approval_state: {self.approval_state!r}")

    def to_json(self) -> str:
        """Return a deterministic, lossless JSON representation of this incident."""
        return json.dumps(_incident_to_dict(self), sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> Incident:
        """Restore an incident and its nested policy types from JSON."""
        data = json.loads(text)
        data["detected_at"] = datetime.fromisoformat(data["detected_at"])
        data["evidence"] = [
            Evidence(
                query=evidence["query"],
                result=evidence["result"],
                taken_at=datetime.fromisoformat(evidence["taken_at"]),
            )
            for evidence in data["evidence"]
        ]
        data["root_cause_claims"] = [tuple(pair) for pair in data["root_cause_claims"]]
        if data["proposed_action"] is not None:
            data["proposed_action"] = _action_result_from_dict(data["proposed_action"])
        return cls(**data)


def _incident_to_dict(incident: Incident) -> dict:
    """Encode each field of an incident using its declared handoff representation."""
    data = asdict(incident)
    data["detected_at"] = incident.detected_at.isoformat()
    data["evidence"] = [
        {
            "query": evidence.query,
            "result": evidence.result,
            "taken_at": evidence.taken_at.isoformat(),
        }
        for evidence in incident.evidence
    ]
    data["root_cause_claims"] = [list(pair) for pair in incident.root_cause_claims]
    if incident.proposed_action is not None:
        data["proposed_action"] = _action_result_to_dict(incident.proposed_action)
    return data


def _action_result_to_dict(action: ActionResult) -> dict:
    """Encode the existing action contract without introducing a second action type."""
    return {
        "action_id": action.action_id,
        "reversible": action.reversible,
        "blast_radius": _cohort_to_dict(action.blast_radius),
        "predicted_effect": action.predicted_effect,
        "verification_query": action.verification_query,
        "ttl": action.ttl.total_seconds(),
    }


def _action_result_from_dict(data: dict) -> ActionResult:
    """Restore the existing action contract from its handoff representation."""
    return ActionResult(
        action_id=data["action_id"],
        reversible=data["reversible"],
        blast_radius=_cohort_from_dict(data["blast_radius"]),
        predicted_effect=data["predicted_effect"],
        verification_query=data["verification_query"],
        ttl=timedelta(seconds=data["ttl"]),
    )


def _cohort_to_dict(cohort: Cohort) -> dict:
    """Encode frozensets as sorted lists so handoffs remain deterministic."""
    return {
        "channels": _cohort_dimension_to_json(cohort.channels),
        "regions": _cohort_dimension_to_json(cohort.regions),
        "devices": _cohort_dimension_to_json(cohort.devices),
        "cdn_pathways": _cohort_dimension_to_json(cohort.cdn_pathways),
    }


def _cohort_dimension_to_json(value: frozenset[str] | str) -> str | list[str]:
    """Keep the wildcard literal intact; otherwise sort members for stable JSON."""
    return value if value == "*" else sorted(value)


def _cohort_from_dict(data: dict) -> Cohort:
    """Restore cohort dimensions as their original wildcard or frozenset forms."""
    return Cohort(
        channels=_cohort_dimension_from_json(data["channels"]),
        regions=_cohort_dimension_from_json(data["regions"]),
        devices=_cohort_dimension_from_json(data["devices"]),
        cdn_pathways=_cohort_dimension_from_json(data["cdn_pathways"]),
    )


def _cohort_dimension_from_json(value: str | list[str]) -> frozenset[str] | str:
    """Rebuild named cohort dimensions as frozensets rather than mutable lists."""
    return value if value == "*" else frozenset(value)
