"""A Gemini-driven investigator that chooses its own Grafana MCP evidence.

Additive and parallel to `forensics.diagnose()` — nothing on Forensics' or the
executor's frozen, live-verified call path changes unless something new calls
`investigate()`. Forensics stays exactly as `D-S111`/`D-S112`/`A11` reviewed it.

The difference from `forensics.diagnose()`: that function runs a fixed 10-query
tuple every time and only asks Gemini to summarise the results into cited claims.
Here, Gemini itself picks which queries to run, in what order, and when it has
enough evidence to stop — genuine tool choice, not a fixed script read aloud.

ponytail: the metric vocabulary is the same fixed 8-name catalog
`forensics._queries()` already emits (reused, not reinvented) — Gemini chooses
*which* of them to call, not free-form PromQL. This keeps every query in the
exact shape `remediator.select_pathway_remedy`/`select_conservation_remedy`/
`_creative_transcode_fault` already know how to read, so the safety gate below
reuses those three real, already-reviewed functions unmodified instead of a new,
untested cross-check. Add free-form query authorship only if a judge/demo
specifically needs a metric outside this catalog.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai.types import Content, GenerateContentConfig, Part

from breakeven.agents.forensics import _fetch, _fetch_loki, _queries
from breakeven.agents.incident import Evidence, Incident
from breakeven.agents.remediator import (
    _creative_transcode_fault,
    select_conservation_remedy,
    select_pathway_remedy,
)

Fetch = Callable[[str], str]
Clock = Callable[[], datetime]
RunTurn = Callable[[str], str]

MODEL = "gemini-2.5-flash"

_METRIC_NAMES = (
    "creative_errors_by_creative",
    "break_errors_by_vast_code",
    "break_requests",
    "break_fills",
    "pathway_error_rate",
    "pathway_error_streak",
    "billable_impressions",
    "beacon_failures",
)

_ALLOWED_ACTIONS = frozenset({"A1", "A3", "A4", "none"})
_MAX_TOOL_CALLS = 4

_INVESTIGATOR_INSTRUCTION = (
    "You are investigating a live ad-delivery incident. Gather only the evidence "
    "you actually need, adaptively, before diagnosing it. Respond on every turn "
    "with exactly one JSON object and nothing else — no prose, no markdown fences. "
    'To call a tool: {"tool": "query_metric", "metric_name": "<name>"} where '
    "<name> is one of: " + ", ".join(_METRIC_NAMES) + '; or {"tool": "query_logs"}. '
    f"You may call at most {_MAX_TOOL_CALLS} tools total, in whatever order and "
    "combination the incident actually calls for — never call a tool whose "
    "evidence would not change your diagnosis. A single instant reading can be a "
    "momentary blip: before recommending A1 for a pathway problem, also confirm "
    "the pathway_error_streak metric shows a sustained failure, not just a "
    "one-off spike. When you have enough evidence, "
    "respond with ONLY the final verdict: "
    '{"root_cause": "one sentence, citing only evidence you actually queried", '
    '"confidence": <float 0 to 1>, "recommended_action": "<action>"} where '
    '<action> is one of "A1" (steer traffic off a degraded CDN pathway onto its '
    'healthy sibling), "A3" (blocklist one faulty creative), "A4" (block every '
    'creative on the channel for a channel-wide impression-conservation '
    'violation), or "none" (no confident remedy). Never invent a metric value '
    "you did not observe."
)

_INVESTIGATOR_AGENT = Agent(
    name="investigator",
    model=MODEL,
    instruction=_INVESTIGATOR_INSTRUCTION,
    generate_content_config=GenerateContentConfig(
        response_mime_type="application/json"
    ),
)


@dataclass(frozen=True)
class ToolCallRecord:
    """One real Grafana MCP tool call the investigator itself chose to make."""

    tool: str
    args: dict[str, str]
    query: str
    result_summary: str


@dataclass
class InvestigationResult:
    """The investigator's structured verdict plus its full, real tool trace."""

    incident_id: str
    root_cause: str
    confidence: float
    recommended_action: str
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    gate_action: str | None = None
    accepted: bool = False


def _default_run_turn() -> RunTurn:
    """Return a callable sending one message and returning the raw reply text,
    reusing one ADK session across calls so context carries between turns."""
    sessions = InMemorySessionService()
    session = asyncio.run(
        sessions.create_session(app_name="investigator", user_id="investigator")
    )
    runner = Runner(
        app_name="investigator", agent=_INVESTIGATOR_AGENT, session_service=sessions
    )

    def run_turn(message: str) -> str:
        events = list(
            runner.run(
                user_id="investigator",
                session_id=session.id,
                new_message=Content(role="user", parts=[Part(text=message)]),
            )
        )
        # W1: same masking shape as `forensics._judge` — ADK reports a failed model
        # call on the event, not by raising.
        failures = [
            f"{event.error_code}: {event.error_message}"
            for event in events
            if event.error_code is not None or event.error_message is not None
        ]
        if failures:
            raise RuntimeError(
                "The Investigator model call failed: " + "; ".join(failures)
            )
        texts = [
            part.text
            for event in events
            if event.content is not None
            for part in event.content.parts
            if part.text is not None
        ]
        if not texts:
            raise RuntimeError("ADK returned no Investigator response")
        return texts[-1]

    return run_turn


def _summarize(result: str, *, limit: int = 400) -> str:
    """Truncate a raw MCP payload for the UI trace and the model's own context."""
    return result if len(result) <= limit else result[:limit] + "…"


def _run_tool(
    channel: str,
    call: dict,
    *,
    fetch_metric: Fetch,
    fetch_logs: Fetch,
) -> tuple[ToolCallRecord, str]:
    """Execute one investigator-chosen tool call; return its record and raw result."""
    tool = call.get("tool")
    if tool == "query_metric":
        metric_name = call.get("metric_name")
        if metric_name not in _METRIC_NAMES:
            raise RuntimeError(
                f"Investigator requested unknown metric {metric_name!r}"
            )
        query = _queries(channel)[_METRIC_NAMES.index(metric_name)]
        result = fetch_metric(query)
        args = {"metric_name": metric_name}
    elif tool == "query_logs":
        query = f'{{service="transcoder", channel="{channel}"}} | json'
        result = fetch_logs(query)
        args = {}
    else:
        raise RuntimeError(f"Investigator requested unknown tool {tool!r}")
    if not isinstance(result, str):
        raise RuntimeError("Investigator tool fetch returned a non-text result")
    record = ToolCallRecord(
        tool=tool, args=args, query=query, result_summary=_summarize(result)
    )
    return record, result


def _parse_json_object(raw: str, *, context: str) -> dict:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{context} returned non-JSON output: {raw!r}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{context} response must be a JSON object, got {parsed!r}")
    return parsed


def _gate(incident: Incident) -> str | None:
    """Independently re-derive an action from the same real evidence, using the
    real, already-reviewed deterministic selectors — never the model's own claim.

    Order matters only in the (untested-in-practice) case where two independent
    fault shapes both hold in the same evidence set; pathway/conservation/creative
    are mutually exclusive in every real fault this simulator injects.
    """
    if select_pathway_remedy(incident) is not None:
        return "A1"
    if select_conservation_remedy(incident) is not None:
        return "A4"
    if _creative_transcode_fault(incident) is not None:
        return "A3"
    return None


def _finish(
    incident: Incident, verdict: dict, tool_calls: list[ToolCallRecord]
) -> InvestigationResult:
    root_cause = verdict.get("root_cause")
    confidence = verdict.get("confidence")
    recommended_action = verdict.get("recommended_action")
    if not isinstance(root_cause, str) or not root_cause:
        raise RuntimeError(f"Investigator verdict missing root_cause: {verdict!r}")
    if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
        raise RuntimeError(
            f"Investigator verdict has an invalid confidence: {verdict!r}"
        )
    if recommended_action not in _ALLOWED_ACTIONS:
        raise RuntimeError(
            f"Investigator recommended an action outside the allowlist: {verdict!r}"
        )
    if not tool_calls:
        raise RuntimeError("Investigator reached a verdict without querying any evidence")

    incident.root_cause_claims.append((root_cause, "investigator"))
    gate_action = _gate(incident)
    accepted = (recommended_action == "none" and gate_action is None) or (
        recommended_action == gate_action
    )
    return InvestigationResult(
        incident_id=incident.id,
        root_cause=root_cause,
        confidence=float(confidence),
        recommended_action=recommended_action,
        tool_calls=tool_calls,
        gate_action=gate_action,
        accepted=accepted,
    )


def investigate(
    incident: Incident,
    *,
    fetch_metric: Fetch = _fetch,
    fetch_logs: Fetch = _fetch_loki,
    run_turn: RunTurn | None = None,
    now: Clock = lambda: datetime.now(timezone.utc),
    max_tool_calls: int = _MAX_TOOL_CALLS,
) -> InvestigationResult:
    """Let Gemini choose its own Grafana MCP evidence, then gate its verdict
    against the real deterministic remedy selectors before anything executes."""
    run_turn = run_turn or _default_run_turn()
    prompt = (
        f"Incident {incident.id} on channel {incident.channel!r}, region "
        f"{incident.region!r}: {incident.failure_signature}. Revenue at risk: "
        f"${incident.revenue_at_risk_per_min:.2f}/min."
    )
    tool_calls: list[ToolCallRecord] = []
    message = prompt
    for step in range(max_tool_calls + 1):
        raw = run_turn(message)
        parsed = _parse_json_object(raw, context="Investigator")
        if "tool" in parsed:
            if step == max_tool_calls:
                raise RuntimeError(
                    "Investigator exceeded its tool-call budget without a verdict"
                )
            record, result = _run_tool(
                incident.channel,
                parsed,
                fetch_metric=fetch_metric,
                fetch_logs=fetch_logs,
            )
            tool_calls.append(record)
            incident.evidence.append(
                Evidence(query=record.query, result=result, taken_at=now())
            )
            message = json.dumps({"tool_result": record.result_summary})
            continue
        return _finish(incident, parsed, tool_calls)
    raise RuntimeError("Investigator did not return a verdict")
