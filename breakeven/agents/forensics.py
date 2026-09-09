"""Grounded root-cause explanations for existing incidents."""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone

from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai.types import Content, GenerateContentConfig, Part

from breakeven.agents.incident import Evidence, Incident
from breakeven.agents.watchtower.agent import (
    WINDOW_SECONDS,
    _query as _watchtower_query,
)
from breakeven.mcp.client import call_tool
from breakeven.mcp.tempo import fetch_trace as _fetch_trace
from breakeven.mcp.tools import QUERY_LOKI_LOGS
from breakeven.secrets import get_secret

Fetch = Callable[[str], str]
Judge = Callable[[str], str]
Clock = Callable[[], datetime]

_LOKI_DATASOURCE_UID = "grafanacloud-logs"

_FORENSICS_INSTRUCTION = (
    "You diagnose an existing ad-break incident using only supplied evidence. "
    'Return only a JSON array. Each element must be exactly {"claim": "one sentence", '
    '"evidence_id": "eN"}. Each claim must cite exactly one supplied evidence id. '
    'A creative_id or vast_error_code of "none" with a zero value is a no-errors placeholder '
    "and must never be named as a cause. Do not calculate revenue figures. "
    "Two evidence entries report origin_5xx_rate and origin_5xx_failed_fetches_streak "
    "per cdn_pathway. If one pathway shows a nonzero streak while its sibling pathway "
    "reads zero, name that specific pathway as degraded in one claim citing that "
    "evidence id — this is a distinct fault from a creative/ad-delivery error and must "
    "not be conflated with one. Two further evidence entries report "
    "ad_impressions_billable_total and ad_beacon_failures_total for the channel. If "
    "billable impressions are lower than what fills would predict, or beacon failures "
    "are nonzero, name a channel-wide impression-conservation violation in one claim "
    "citing that evidence id — this affects the whole channel's beacon delivery, not one "
    "creative, and must not be described as a single creative's fault."
)

_FORENSICS_AGENT = Agent(
    name="forensics",
    model="gemini-2.5-pro",
    instruction=_FORENSICS_INSTRUCTION,
    generate_content_config=GenerateContentConfig(
        response_mime_type="application/json"
    ),
)


def _queries(channel: str) -> tuple[str, str, str, str, str, str, str, str]:
    """Return the fixed, ordered diagnosis queries for one incident channel.

    `D-S111` appended `e4`/`e5` (origin-pathway health). `D-S112` appends `e6`/`e7`
    (impression-conservation evidence) the same way — never interleaved with earlier
    entries, so already-established ids never move. `diagnose()`'s hardcoded Loki/trace
    ids move from `e6`/`e7` to `e8`/`e9` to make room without colliding.
    """
    window = f"{WINDOW_SECONDS}s"
    return (
        # `creative_id` lives on the narrow metric only (`D-S89`/`F-SIM-18`) — grouping
        # `ad_break_errors_total` by it after the 8x4x3 widening would return one empty
        # label and the remediator would find no failing creative, with every unit test of
        # either file still green.
        "sum by (creative_id) "
        f'(increase(ad_creative_errors_total{{channel="{channel}"}}[{window}]))',
        "sum by (vast_error_code) "
        f'(increase(ad_break_errors_total{{channel="{channel}"}}[{window}]))',
        "sum by (channel) "
        f'(increase(ad_break_requests_total{{channel="{channel}"}}[{window}]))',
        "sum by (channel) "
        f'(increase(ad_break_fills_total{{channel="{channel}"}}[{window}]))',
        # `D-S111`: instant reads, not `increase()` — same reasoning as `D-S110`'s
        # per-break gauges: `origin_5xx_rate`/`_streak` already answer "how bad, right
        # now" with nothing to dilute, so a range window would only reintroduce the lag
        # that decision already closed.
        f'max by (channel, cdn_pathway) (origin_5xx_rate{{channel="{channel}"}})',
        "max by (channel, cdn_pathway) "
        f'(origin_5xx_failed_fetches_streak{{channel="{channel}"}})',
        # `D-S112`: the impression-conservation identity `watchtower/agent.py`'s
        # `beacon_check` already evaluates to open a real incident — Forensics never
        # asked about it before now, so a real conservation-violation incident had
        # nothing citable to explain it. `increase()`, not instant: these are cumulative
        # counters, same window every other counter-backed query here already uses.
        "sum by (channel) "
        f'(increase(ad_impressions_billable_total{{channel="{channel}"}}[{window}]))',
        "sum by (channel) "
        f'(increase(ad_beacon_failures_total{{channel="{channel}"}}[{window}]))',
    )


def _fetch(query: str) -> str:
    """Issue one fixed query through Watchtower's pinned Grafana MCP path."""
    _, evidence = _watchtower_query(query)
    return evidence.result


def _fetch_loki(query: str) -> str:
    """Issue one literal LogQL query through the pinned Grafana MCP path."""
    result = call_tool(
        os.environ.get("BREAKEVEN_MCP_ENDPOINT", "http://localhost:8000/mcp"),
        get_secret("grafana-sa-token"),
        QUERY_LOKI_LOGS,
        {
            "datasourceUid": _LOKI_DATASOURCE_UID,
            "logql": query,
            "limit": 100,
            "direction": "BACKWARD",
            "endRfc3339": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        },
    )
    is_error = result.get("isError")
    if "isError" in result and not isinstance(is_error, bool):
        raise RuntimeError("Grafana MCP response has a non-boolean isError flag")
    if is_error is True:
        raise RuntimeError("Grafana MCP rejected the Forensics LogQL query")
    content = result.get("content")
    if not isinstance(content, list) or not content:
        raise RuntimeError("Grafana MCP response has no content")
    first = content[0]
    if not isinstance(first, dict) or not isinstance(first.get("text"), str):
        raise RuntimeError("Grafana MCP response has no text payload")
    return first["text"]


# Same reasoning as `watchtower._judge`: `RESOURCE_EXHAUSTED` (429) is a real
# per-minute rate limit, worth a short bounded retry — every other model failure is
# permanent and must keep failing immediately.
_RATE_LIMIT_RETRIES = 3
_RATE_LIMIT_BACKOFF_SECONDS = 2.0


def _judge(evidence_block: str) -> str:
    """Run the judgment prompt, retrying only a real rate limit."""
    for attempt in range(1, _RATE_LIMIT_RETRIES + 1):
        try:
            return _judge_once(evidence_block)
        except RuntimeError as error:
            is_rate_limited = "RESOURCE_EXHAUSTED" in str(error) or "429" in str(error)
            if not is_rate_limited or attempt == _RATE_LIMIT_RETRIES:
                raise
            time.sleep(_RATE_LIMIT_BACKOFF_SECONDS * (2 ** (attempt - 1)))
    raise AssertionError("unreachable — loop always returns or raises")


def _judge_once(evidence_block: str) -> str:
    """Return Forensics' raw JSON claim response from the ADK model runner."""
    sessions = InMemorySessionService()
    session = asyncio.run(
        sessions.create_session(app_name="forensics", user_id="forensics")
    )
    runner = Runner(
        app_name="forensics", agent=_FORENSICS_AGENT, session_service=sessions
    )
    events = runner.run(
        user_id="forensics",
        session_id=session.id,
        new_message=Content(role="user", parts=[Part(text=evidence_block)]),
    )
    collected = list(events)
    # W1: same masking shape as `watchtower._judge` — ADK reports a failed model call
    # on the event, not by raising, so "no response" hides the actual cause.
    failures = [
        f"{event.error_code}: {event.error_message}"
        for event in collected
        if event.error_code is not None or event.error_message is not None
    ]
    if failures:
        raise RuntimeError(
            "The Forensics judgment model call failed: " + "; ".join(failures)
        )
    texts = [
        part.text
        for event in collected
        if event.content is not None
        for part in event.content.parts
        if part.text is not None
    ]
    if not texts:
        raise RuntimeError("ADK returned no Forensics judge response")
    return texts[-1]


def _render(evidence_by_id: dict[str, Evidence]) -> str:
    """Render code-recorded evidence in its fixed issue order for the judge.

    `e0`-`e7` (small, already-aggregated Prometheus instant/range vectors — `D-S111` added
    `e4`/`e5` for origin-pathway health, `D-S112` added `e6`/`e7` for impression
    conservation) render verbatim. `e8`/`e9` (Loki log lines, a Tempo trace) go through a
    summarising render instead —
    `docs/BREAKEVEN_BUILD_SPEC.md:585`'s own stated principle, *"query results are
    summarised before entering agent context rather than dumped raw"* — because their raw
    payloads carry real redundant wrapper structure: a Loki entry repeats the same fields
    three ways (`line`/`structuredMetadata`/`parsed`) and a zero-match response is mostly
    Grafana MCP's own tool-assistance boilerplate (`hints`/`possibleCauses`/
    `suggestedActions`/`debug`), never diagnostic content; a Tempo trace nests every span
    under `services`/`scopes` regardless of how many actually matter. **This never touches
    `Evidence.result` on the underlying object** — only what is sent to the judge model.
    Grounding, citation, and the operator UI's evidence panel all still read the real raw
    payload every other code path in this module (and the operator UI) already depends on.
    No thinking-budget change alongside this — the model gets less to reason over, not a
    ceiling on how much it may reason.
    """
    summarisers = {"e8": _summarise_loki_for_judge, "e9": _summarise_trace_for_judge}
    return "\n".join(
        f"{evidence_id} | query={evidence.query} | "
        f"result={summarisers.get(evidence_id, lambda text: text)(evidence.result)}"
        for evidence_id, evidence in evidence_by_id.items()
    )


def _summarise_loki_for_judge(result: str) -> str:
    """One compact line per *distinct* parsed Loki log line, count-suffixed for repeats.

    Reads the same `line` field `_dominant_loki_record` already parses — this is not a
    second, competing parser, just a different rendering of the same extraction. Repeats
    are real and common (a live fault re-triggers the identical log line every tick) and
    collapsing them to a count loses no distinct information the judge could reason over,
    only the redundant copies.
    """
    if not isinstance(result, str):
        raise RuntimeError(
            f"Forensics evidence summariser requires a text result, got {type(result)!r}"
        )
    try:
        payload = json.loads(result)
    except json.JSONDecodeError:
        return result
    if not isinstance(payload, dict) or not isinstance(
        entries := payload.get("data"), list
    ):
        return result
    if not entries:
        # A genuinely empty `data` list is the only case that means "no log entries" —
        # distinct from the branch below, where entries exist but did not fit the parser.
        return "no log entries found for this channel in the query window"
    counts: dict[str, int] = {}
    order: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("line"), str):
            continue
        try:
            parsed_line = json.loads(entry["line"])
        except json.JSONDecodeError:
            parsed_line = entry["line"]
        rendered = json.dumps(parsed_line, separators=(",", ":"), sort_keys=True)
        if rendered not in counts:
            order.append(rendered)
        counts[rendered] = counts.get(rendered, 0) + 1
    if not counts:
        # `silent-failure-hunter`, this session: entries existed but none matched the
        # expected `{"line": "<json string>"}` shape — falling back to "no log entries
        # found" here would tell the judge evidence is empty when it is not. Fall back to
        # the raw payload instead, the same choice `_summarise_trace_for_judge` already
        # makes for its own "found nothing usable" case.
        return result
    # `; `, never a newline: `_render` puts one evidence entry per line, and every caller
    # (`_claims`'s own citation matching, this module's tests) assumes an evidence_id's
    # rendered text stays on the one line it started on.
    return "; ".join(
        rendered if counts[rendered] == 1 else f"{rendered} (x{counts[rendered]})"
        for rendered in order
    )


def _summarise_trace_for_judge(result: str) -> str:
    """One compact line per span: name, status, and string attributes only.

    Walks the identical `services`/`scopes`/`spans` structure `_error_span` already walks
    (not a second, competing traversal) but renders every span it finds, not only the
    first error one — the judge may reason over the trace's whole shape, not just the one
    span the code-level correlation already picked out.
    """
    if not isinstance(result, str):
        raise RuntimeError(
            f"Forensics evidence summariser requires a text result, got {type(result)!r}"
        )
    try:
        payload = json.loads(result)
    except json.JSONDecodeError:
        return result
    trace = payload.get("trace") if isinstance(payload, dict) else None
    services = trace.get("services") if isinstance(trace, dict) else None
    if not isinstance(services, list):
        return result
    lines: list[str] = []
    for service in services:
        if not isinstance(service, dict) or not isinstance(
            scopes := service.get("scopes"), list
        ):
            continue
        for scope in scopes:
            if not isinstance(scope, dict) or not isinstance(
                spans := scope.get("spans"), list
            ):
                continue
            for span in spans:
                if not isinstance(span, dict) or not isinstance(span.get("name"), str):
                    continue
                status = span.get("status")
                status_code = status.get("code") if isinstance(status, dict) else None
                attributes = span.get("attributes")
                # `silent-failure-hunter`, this session: scalar (numeric/bool) attributes
                # are kept too, stringified — a duration or a retry count is exactly the
                # kind of thing a judge may need to ground a claim, and dropping them with
                # no marker made "filtered" indistinguishable from "never existed".
                # Non-scalar values (nested objects/arrays) are still skipped — rendering
                # those flat would misrepresent their structure, not just shrink it.
                rendered_attributes = (
                    {
                        # Kept as the real Python scalar, not pre-stringified — the
                        # `json.dumps` call below serialises it once, correctly, as a JSON
                        # number/boolean/string. Pre-serialising here and again there was
                        # this fix's own first-draft bug: `8000` became the string `"8000"`.
                        key: value
                        for key, value in attributes.items()
                        if isinstance(key, str)
                        and isinstance(value, (str, int, float, bool))
                    }
                    if isinstance(attributes, dict)
                    else {}
                )
                lines.append(
                    json.dumps(
                        {
                            "span": span["name"],
                            "status": status_code,
                            **rendered_attributes,
                        },
                        separators=(",", ":"),
                    )
                )
    if not lines:
        return result
    return "; ".join(lines)  # single line — see `_summarise_loki_for_judge`'s own note


def _is_none_sentinel(evidence: Evidence) -> bool:
    """Return whether a Prometheus result is the zero-value none placeholder."""
    try:
        payload = json.loads(evidence.result)
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict) or not isinstance(
        values := payload.get("data"), list
    ):
        return False
    return bool(values) and all(
        isinstance(value, dict)
        and isinstance(metric := value.get("metric"), dict)
        and (
            metric.get("creative_id") == "none"
            or metric.get("vast_error_code") == "none"
        )
        and isinstance(sample := value.get("value"), list)
        and len(sample) == 2
        and isinstance(sample[1], (int, float, str))
        and float(sample[1]) == 0
        for value in values
    )


def _claims(
    raw_response: str, evidence_by_id: dict[str, Evidence]
) -> list[tuple[str, str]]:
    """Keep only well-formed claims cited to evidence issued in this diagnosis."""
    try:
        parsed = json.loads(raw_response)
    except json.JSONDecodeError as error:
        raise RuntimeError("Forensics judge response is not valid JSON") from error
    if not isinstance(parsed, list):
        raise RuntimeError("Forensics judge response is not a JSON array")
    return [
        (item["claim"], item["evidence_id"])
        for item in parsed
        if isinstance(item, dict)
        and isinstance(item.get("claim"), str)
        and isinstance(item.get("evidence_id"), str)
        and item["evidence_id"] in evidence_by_id
        and not _is_none_sentinel(evidence_by_id[item["evidence_id"]])
    ]


def _dominant_loki_record(result: str) -> tuple[str, str, str] | None:
    """Return the recurring error pair and one trace id from Loki log entries."""
    try:
        payload = json.loads(result)
    except json.JSONDecodeError as error:
        raise RuntimeError("Grafana MCP returned non-JSON Loki text") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise RuntimeError("Grafana MCP returned an invalid Loki payload")
    records: list[tuple[str, str, str]] = []
    for entry in payload["data"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("line"), str):
            continue
        try:
            line = json.loads(entry["line"])
        except json.JSONDecodeError:
            continue
        if not isinstance(line, dict):
            continue
        error_code = line.get("vast_error_code")
        creative_id = line.get("creative_id")
        trace_id = line.get("trace_id")
        if all(
            isinstance(item, str) and item
            for item in (error_code, creative_id, trace_id)
        ):
            records.append((error_code, creative_id, trace_id))
    if not records:
        return None
    error_code, creative_id = Counter(
        (code, creative) for code, creative, _ in records
    ).most_common(1)[0][0]
    trace_id = next(
        trace
        for code, creative, trace in records
        if (code, creative) == (error_code, creative_id)
    )
    return error_code, creative_id, trace_id


def _error_span(result: str) -> tuple[str, dict[str, str]] | None:
    """Return the first error span and its scalar OTLP attributes."""
    try:
        payload = json.loads(result)
    except json.JSONDecodeError as error:
        raise RuntimeError("Tempo returned non-JSON trace text") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("trace"), dict):
        raise RuntimeError("Tempo returned an invalid trace payload")
    services = payload["trace"].get("services")
    if not isinstance(services, list):
        raise RuntimeError("Tempo returned an invalid trace payload")
    for service in services:
        if not isinstance(service, dict) or not isinstance(service.get("scopes"), list):
            continue
        for scope in service["scopes"]:
            if not isinstance(scope, dict) or not isinstance(scope.get("spans"), list):
                continue
            for span in scope["spans"]:
                if not isinstance(span, dict) or not isinstance(span.get("name"), str):
                    continue
                status = span.get("status")
                if (
                    not isinstance(status, dict)
                    or status.get("code") != "STATUS_CODE_ERROR"
                ):
                    continue
                attributes = span.get("attributes")
                if not isinstance(attributes, dict):
                    return span["name"], {}
                return span["name"], {
                    key: value
                    for key, value in attributes.items()
                    if isinstance(key, str) and isinstance(value, str)
                }
    return None


def diagnose(
    incident: Incident,
    *,
    fetch: Fetch = _fetch,
    fetch_loki: Fetch = _fetch_loki,
    fetch_trace: Fetch = _fetch_trace,
    judge: Judge = _judge,
    now: Clock = lambda: datetime.now(timezone.utc),
) -> Incident:
    """Attach grounded explanations to an existing incident without opening one."""
    evidence_by_id: dict[str, Evidence] = {}
    for index, query in enumerate(_queries(incident.channel)):
        result = fetch(query)
        if not isinstance(result, str):
            raise RuntimeError("Forensics fetch returned a non-text result")
        evidence_by_id[f"e{index}"] = Evidence(
            query=query, result=result, taken_at=now()
        )

    loki_query = f'{{service="transcoder", channel="{incident.channel}"}} | json'
    loki_result = fetch_loki(loki_query)
    if not isinstance(loki_result, str):
        raise RuntimeError("Forensics Loki fetch returned a non-text result")
    evidence_by_id["e8"] = Evidence(
        query=loki_query, result=loki_result, taken_at=now()
    )
    record = _dominant_loki_record(loki_result)
    if record is not None:
        error_code, creative_id, trace_id = record
        trace_result = fetch_trace(trace_id)
        if not isinstance(trace_result, str):
            raise RuntimeError("Forensics trace fetch returned a non-text result")
        evidence_by_id["e9"] = Evidence(
            query=f"get-trace {trace_id}", result=trace_result, taken_at=now()
        )
        span = _error_span(trace_result)
        if span is not None:
            incident.failing_span, attributes = span
            incident.implicated_ids = {
                "creative_id": attributes.get("creative.id", creative_id),
                "vast_error_code": attributes.get("vast.error_code", error_code),
            }

    claims = _claims(judge(_render(evidence_by_id)), evidence_by_id)
    if not claims:
        return incident

    incident.root_cause = "\n".join(claim for claim, _ in claims)
    incident.root_cause_claims = claims
    cited_ids = {evidence_id for _, evidence_id in claims}
    incident.evidence.extend(
        evidence
        for evidence_id, evidence in evidence_by_id.items()
        if evidence_id in cited_ids
    )
    return incident
