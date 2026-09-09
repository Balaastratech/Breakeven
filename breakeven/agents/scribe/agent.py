"""Write incident and remediation annotations through Grafana MCP."""

from __future__ import annotations

import json
from datetime import datetime

from breakeven.actions.audit import ActionOutcome, AuditEntry
from breakeven.agents.incident import AUTO_REMEDIATION_FLOOR_PER_MINUTE, Incident
from breakeven.mcp.client import call_tool
from breakeven.mcp.tools import (
    ADD_ACTIVITY_TO_INCIDENT,
    ALERTING_MANAGE_RULES,
    CREATE_ANNOTATION,
    CREATE_INCIDENT,
    GET_INCIDENT,
    GENERATE_DEEPLINK,
    GRAFANA_API_REQUEST,
)
from breakeven.secrets import get_secret
from breakeven.sim.world import CHANNELS

_DASHBOARD_UID = "breakeven-revenue-watch"
_TOKEN_SECRET = "grafana-sa-token"
_CHANNEL_NAMES = {channel.channel_id: channel.name for channel in CHANNELS}

# Watchtower's own `WINDOW_SECONDS` (600s) exists to avoid false-positive incident
# *opens* on a brief blip — that goal wants a long window. These alert rules serve a
# different goal: showing a human (or a judge watching the live dashboard) whether a
# channel is *currently* at risk, including right after a fix lands. A 600s window there
# means a resolved fault visibly lingers for up to ten minutes after it stops, which
# reads as "the fix didn't work" — confirmed live, 2026-08-30. The Cloud Scheduler tick
# driving the deployed simulator fires once a minute (`* * * * *`), so 120s is the
# shortest window that still reliably spans at least two samples for `increase()`.
_ALERT_WINDOW_SECONDS = 120

_OUTCOME_TEXT = {
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
    # `D-S116`: A4's channel-wide containment (`_live_conservation_remediation`) has no
    # wait-then-remeasure step the way A3's/A1's do, so its real entry is honestly
    # `EXECUTED_AWAITING_SETTLEMENT` rather than a fabricated `VERIFIED` (`D-S114`).
    # Found missing here — a real `KeyError` on this exact value — the first time the
    # full unattended A4 loop ever ran end to end against a real fault.
    ActionOutcome.EXECUTED_AWAITING_SETTLEMENT: (
        "Contained: the affected creatives were blocked. This was not re-measured "
        "afterward, so a human may want to confirm it held."
    ),
}
_UPDATE_STATUS_ENDPOINT = (
    "/api/plugins/grafana-irm-app/resources/api/v1/IncidentsService.UpdateStatus"
)
_ALERT_RULES_ENDPOINT = "/api/v1/provisioning/alert-rules"
_AUTO_REMEDIATION_FLOOR_PER_MINUTE = AUTO_REMEDIATION_FLOOR_PER_MINUTE
_CRITICAL_REVENUE_AT_RISK_PER_MINUTE = 1_000.0
_ALERT_FOLDER_UID = "ffu1d9w6qr11cd"
_ALERT_RULE_GROUP = "breakeven-revenue-alerts"
_PROMETHEUS_DATASOURCE_UID = "grafanacloud-prom"
_GRAFANA_HOST = "glowingwasp1671.grafana.net"


def _milliseconds(timestamp: datetime) -> int:
    return int(timestamp.timestamp() * 1000)


def _display_region(region: str) -> str:
    return "US-" + region[3:].title() if region.startswith("us-") else region.title()


def _create_annotation(
    text: str, timestamp: datetime, tags: list[str], *, mcp_endpoint: str
) -> None:
    call_tool(
        mcp_endpoint,
        get_secret(_TOKEN_SECRET),
        CREATE_ANNOTATION,
        {
            "dashboardUid": _DASHBOARD_UID,
            "text": text,
            "time": _milliseconds(timestamp),
            "tags": tags,
        },
    )


def _tool_text(result: dict[str, object], tool_name: str) -> str:
    """The raw `content[0].text` string a Grafana MCP tool call returned, unparsed.

    Split out from :func:`_tool_value` because not every tool's `text` is JSON —
    `generate_deeplink`'s live response is a bare URL string, not a JSON object
    (`D-S82`), and needs this raw text directly rather than through a `json.loads`
    that would raise on it.
    """
    if result.get("isError"):
        raise RuntimeError(f"Grafana MCP tool {tool_name} reported an error: {result}")
    content = result.get("content")
    if not isinstance(content, list) or not content:
        raise RuntimeError(f"Grafana MCP tool {tool_name} returned no content")
    text = content[0].get("text") if isinstance(content[0], dict) else None
    if not isinstance(text, str):
        raise RuntimeError(f"Grafana MCP tool {tool_name} returned no text content")
    return text


def _tool_value(result: dict[str, object], tool_name: str) -> object:
    return json.loads(_tool_text(result, tool_name))


def _tool_content(result: dict[str, object], tool_name: str) -> dict[str, object]:
    payload = _tool_value(result, tool_name)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Grafana MCP tool {tool_name} returned non-object content")
    return payload


def dashboard_deeplink(*, mcp_endpoint: str) -> str:
    """Return Grafana's canonical deep link for the revenue-watch dashboard.

    The live server's `generate_deeplink` response is the URL itself, as a bare string
    in `content[0].text` — not a JSON object with a `url` field. Confirmed against a real
    call during the `03-review-t4-t5-batched` session (`D-S82`); reads the raw text via
    `_tool_text` rather than `_tool_content`, which would `json.loads` a non-JSON string
    and raise on every real call.
    """
    url = _tool_text(
        call_tool(
            mcp_endpoint,
            get_secret(_TOKEN_SECRET),
            GENERATE_DEEPLINK,
            {"resourceType": "dashboard", "dashboardUid": _DASHBOARD_UID},
        ),
        GENERATE_DEEPLINK,
    )
    if not url:
        raise RuntimeError("Grafana generate_deeplink response missing URL")
    return url


def incident_url(incident_id: str) -> str:
    """Return Grafana's documented incident detail path."""
    return f"https://{_GRAFANA_HOST}/a/grafana-irm-app/incidents/{incident_id}"


def alert_rule_url(rule_uid: str) -> str:
    """Return Grafana's documented managed alert-rule detail path."""
    return f"https://{_GRAFANA_HOST}/alerting/grafana/{rule_uid}/view"


def _revenue_alert_title(channel: str, creative_id: str) -> str:
    return f"BreakEven: {channel} revenue at risk ({creative_id})"


def _revenue_alert_expression(channel: str, creative_id: str) -> str:
    return (
        f'( max by (channel) (stream_concurrent_viewers{{channel="{channel}"}}) '
        f'* (max by (channel) (channel_breaks_per_hour{{channel="{channel}"}}) / 60) '
        f'* max by (channel) (channel_ads_per_break{{channel="{channel}"}}) '
        f'* (max by (channel) (channel_cpm_usd{{channel="{channel}"}}) / 1000) ) '
        f'* ( sum by (channel) (increase(ad_creative_errors_total{{channel="{channel}",creative_id="{creative_id}"}}[{_ALERT_WINDOW_SECONDS}s])) '
        f'/ sum by (channel) (increase(ad_break_requests_total{{channel="{channel}"}}[{_ALERT_WINDOW_SECONDS}s])) )'
    )


def _matching_rule_uid(rules: object, title: str) -> str | None:
    # `silent-failure-hunter`, this session's review: every other shape check in
    # `_ensure_alert_rule` (the fallback list's `status != 200`, `create`'s missing UID)
    # raises on an unexpected response rather than treating it as "no match" — this one
    # didn't, on either of its two call sites. A `rules`/`data` value that is present but
    # not a list would otherwise fall through as if the rule had never existed, reaching
    # `create` and silently provisioning a duplicate — this already happened once in
    # production (`cfv28cmclvu9sb`/`afvqx8dd94o3kb` matched nothing for a week).
    #
    # One shape is deliberately excluded from that, on the primary list's call site only:
    # a bare JSON `null` for the whole response — observed live, 2026-08-27,
    # `alerting_manage_rules(operation="list", search_rule_name=...)` matching zero rules.
    # `_ensure_alert_rule` converts that `null` to `[]` *before* calling this function, so
    # a `None` reaching here is still a genuine malformed-shape error, never that carve-out.
    if not isinstance(rules, list):
        raise RuntimeError(
            f"Grafana alert-rule list for {title!r} returned a non-list rules value: "
            f"{rules!r}"
        )
    for rule in rules:
        if isinstance(rule, dict) and rule.get("title") == title:
            rule_uid = rule.get("uid", rule.get("rule_uid"))
            if isinstance(rule_uid, str) and rule_uid:
                return rule_uid
            # `K-P06-13`: a title match with a missing or empty `uid` means the rule
            # exists but is malformed — never "safe to create a new one." Reading it as
            # "no match" is exactly how a duplicate becomes permanent drift, since
            # `_ensure_alert_rule` never rewrites an existing rule's expression.
            raise RuntimeError(
                f"Grafana alert rule titled {title!r} exists but its uid is missing "
                f"or empty: {rule!r}"
            )
    return None


def _ensure_alert_rule(
    title: str, rule_data: list[dict[str, object]], *, mcp_endpoint: str
) -> str:
    """Return an existing Grafana alert rule or create it through the MCP server."""
    listed = _tool_value(
        call_tool(
            mcp_endpoint,
            get_secret(_TOKEN_SECRET),
            ALERTING_MANAGE_RULES,
            {"operation": "list", "search_rule_name": title},
        ),
        ALERTING_MANAGE_RULES,
    )
    rules = (
        listed.get("rules", listed.get("items", listed.get("data", [])))
        if isinstance(listed, dict)
        else ([] if listed is None else listed)
    )
    # A bare JSON `null` for the whole response is converted to `[]` above — a real,
    # legitimate "matched zero rules" shape (observed live, 2026-08-27) — before
    # `_matching_rule_uid` ever sees it; every other malformed shape is `_matching_rule_uid`'s
    # own check to make (shared with the fallback call below).
    rule_uid = _matching_rule_uid(rules, title)
    if rule_uid is not None:
        return rule_uid
    listed_by_api = _tool_content(
        call_tool(
            mcp_endpoint,
            get_secret(_TOKEN_SECRET),
            GRAFANA_API_REQUEST,
            {"endpoint": _ALERT_RULES_ENDPOINT, "method": "GET"},
        ),
        GRAFANA_API_REQUEST,
    )
    if listed_by_api.get("status") != 200:
        raise RuntimeError(
            f"Grafana alert-rule fallback list returned {listed_by_api.get('status')!r}"
        )
    rule_uid = _matching_rule_uid(listed_by_api.get("data"), title)
    if rule_uid is not None:
        return rule_uid
    created = _tool_content(
        call_tool(
            mcp_endpoint,
            get_secret(_TOKEN_SECRET),
            ALERTING_MANAGE_RULES,
            {
                "operation": "create",
                "title": title,
                "condition": "B",
                "data": rule_data,
                "folder_uid": _ALERT_FOLDER_UID,
                "rule_group": _ALERT_RULE_GROUP,
                "for": "1m",
                "no_data_state": "OK",
                "exec_err_state": "Alerting",
                "org_id": 1,
            },
        ),
        ALERTING_MANAGE_RULES,
    )
    rule_uid = created.get("uid", created.get("rule_uid"))
    if not isinstance(rule_uid, str) or not rule_uid:
        raise RuntimeError("Grafana alert-rule create response missing rule UID")
    return rule_uid


def _alert_rule_data(
    expression: str, evaluator_type: str, evaluator_value: float
) -> list[dict[str, object]]:
    # Query A is a *range* query over `WINDOW_SECONDS` (`relativeTimeRange`), so Grafana
    # returns it as time-series data — a threshold condition cannot evaluate that
    # directly ("only reduced data can be alerted on"; confirmed live, 2026-08-30, the
    # rule this built sat in `Error` state on every evaluation). `R` reduces A to the
    # single most-recent point (`"last"`, not `"mean"`) before B thresholds it, so each
    # 1-minute evaluation reads the current end of the window rather than an average
    # smeared across the last `WINDOW_SECONDS` — the fastest a Grafana-managed rule can
    # reflect a real change, given the underlying `increase()` query is itself windowed.
    return [
        {
            "datasourceUid": _PROMETHEUS_DATASOURCE_UID,
            "refId": "A",
            "relativeTimeRange": {"from": _ALERT_WINDOW_SECONDS, "to": 0},
            "model": {"expr": expression},
        },
        {
            "datasourceUid": "__expr__",
            "refId": "R",
            "model": {
                "type": "reduce",
                "expression": "A",
                "reducer": "last",
            },
        },
        {
            "datasourceUid": "__expr__",
            "refId": "B",
            "model": {
                "type": "threshold",
                "expression": "R",
                "conditions": [
                    {
                        "evaluator": {
                            "type": evaluator_type,
                            "params": [evaluator_value],
                        }
                    }
                ],
            },
        },
    ]


def ensure_revenue_alert_rule(
    channel: str, creative_id: str, *, mcp_endpoint: str
) -> str:
    """Return the sole dollar-risk alert rule for one remediated failure signature."""
    return _ensure_alert_rule(
        _revenue_alert_title(channel, creative_id),
        _alert_rule_data(
            _revenue_alert_expression(channel, creative_id),
            "gt",
            AUTO_REMEDIATION_FLOOR_PER_MINUTE,
        ),
        mcp_endpoint=mcp_endpoint,
    )


def _naive_fill_rate_alert_title(channel: str) -> str:
    return f"BreakEven: {channel} naive fill rate below 80%"


def _naive_error_rate_alert_title(channel: str) -> str:
    return f"BreakEven: {channel} naive error rate above 5%"


def _naive_fill_rate_expression(channel: str) -> str:
    return (
        f'sum(increase(ad_break_fills_total{{channel="{channel}"}}[{_ALERT_WINDOW_SECONDS}s])) '
        f'/ sum(increase(ad_break_requests_total{{channel="{channel}"}}[{_ALERT_WINDOW_SECONDS}s]))'
    )


def _naive_error_rate_expression(channel: str) -> str:
    return (
        f'sum(increase(ad_break_errors_total{{channel="{channel}"}}[{_ALERT_WINDOW_SECONDS}s])) '
        f'/ sum(increase(ad_break_requests_total{{channel="{channel}"}}[{_ALERT_WINDOW_SECONDS}s]))'
    )


def ensure_naive_fill_rate_alert_rule(channel: str, *, mcp_endpoint: str) -> str:
    """Create the intentionally coarse, channel-only fill-rate baseline rule."""
    return _ensure_alert_rule(
        _naive_fill_rate_alert_title(channel),
        _alert_rule_data(_naive_fill_rate_expression(channel), "lt", 0.8),
        mcp_endpoint=mcp_endpoint,
    )


def ensure_naive_error_rate_alert_rule(channel: str, *, mcp_endpoint: str) -> str:
    """Create the intentionally coarse, channel-only VAST-error baseline rule."""
    return _ensure_alert_rule(
        _naive_error_rate_alert_title(channel),
        _alert_rule_data(_naive_error_rate_expression(channel), "gt", 0.05),
        mcp_endpoint=mcp_endpoint,
    )


def create_incident(incident: Incident, *, mcp_endpoint: str) -> str:
    """Create a Grafana incident for an automatically remediated loss."""
    if incident.revenue_at_risk_per_min <= _AUTO_REMEDIATION_FLOOR_PER_MINUTE:
        raise ValueError("Incident risk must exceed the auto-remediation floor")
    result = call_tool(
        mcp_endpoint,
        get_secret(_TOKEN_SECRET),
        CREATE_INCIDENT,
        {
            "title": f"BreakEven: {incident.channel} ad delivery incident",
            "severity": (
                "critical"
                if incident.revenue_at_risk_per_min
                > _CRITICAL_REVENUE_AT_RISK_PER_MINUTE
                else "major"
            ),
            "roomPrefix": "breakeven",
        },
    )
    incident_id = _tool_content(result, CREATE_INCIDENT).get("incidentID")
    if not isinstance(incident_id, str) or not incident_id:
        raise RuntimeError("Grafana create_incident response missing incidentID")
    return incident_id


def add_incident_activity(
    incident_id: str, body: str, timestamp: datetime, *, mcp_endpoint: str
) -> None:
    """Write one lifecycle event at the instant its stage actually completed."""
    result = call_tool(
        mcp_endpoint,
        get_secret(_TOKEN_SECRET),
        ADD_ACTIVITY_TO_INCIDENT,
        {"incidentId": incident_id, "body": body, "eventTime": timestamp.isoformat()},
    )
    _tool_content(result, ADD_ACTIVITY_TO_INCIDENT)


def close_incident(incident_id: str, *, mcp_endpoint: str) -> None:
    """Resolve and read back a Grafana incident using its documented HTTP API."""
    result = call_tool(
        mcp_endpoint,
        get_secret(_TOKEN_SECRET),
        GRAFANA_API_REQUEST,
        {
            "endpoint": _UPDATE_STATUS_ENDPOINT,
            "method": "POST",
            "body": json.dumps(
                {"incidentID": incident_id, "status": "resolved"}, separators=(",", ":")
            ),
        },
    )
    response = _tool_content(result, GRAFANA_API_REQUEST)
    if response.get("status") != 200:
        raise RuntimeError(
            f"Grafana incident close returned {response.get('status')!r}"
        )
    confirmed = _tool_content(
        call_tool(
            mcp_endpoint,
            get_secret(_TOKEN_SECRET),
            GET_INCIDENT,
            {"id": incident_id},
        ),
        GET_INCIDENT,
    )
    if confirmed.get("status") != "resolved":
        raise RuntimeError("Grafana incident close was not confirmed as resolved")


def annotate_incident_detected(incident: Incident, *, mcp_endpoint: str) -> None:
    """Record the detected incident at its evidence timestamp.

    ``mcp_endpoint`` is the Grafana MCP server's own URL (`http://host:8000/mcp` by the
    established convention `watchtower.agent._query` already uses) — **not** the
    simulator's `base_url`, a genuinely different server `orchestrator.py` also threads
    around under that name. Conflating the two here previously sent every annotation
    write to the simulator's HTTP server instead of Grafana's MCP endpoint, which 404'd
    silently until a live run surfaced it — the distinct parameter name is deliberate,
    to make that mistake harder to reintroduce by accident.
    """
    channel = _CHANNEL_NAMES.get(incident.channel, incident.channel)
    region = _display_region(incident.region)
    _create_annotation(
        (
            f"Found a problem on {channel} ({region}) — ads are failing to load for "
            f"viewers. This is costing ${incident.revenue_at_risk_per_min:,.2f} per minute, "
            f"and would reach ${incident.projected_loss_if_unaddressed:,.2f} if left alone."
        ),
        incident.detected_at,
        ["breakeven", "incident-detected"],
        mcp_endpoint=mcp_endpoint,
    )


def annotate_remediation_settled(entry: AuditEntry, *, mcp_endpoint: str) -> None:
    """Record the settled audit outcome at the audit entry's timestamp. See
    :func:`annotate_incident_detected`'s docstring for why ``mcp_endpoint`` is not
    called ``base_url``."""
    _create_annotation(
        _OUTCOME_TEXT[entry.result],
        datetime.fromisoformat(entry.timestamp),
        ["breakeven", "remediation-settled"],
        mcp_endpoint=mcp_endpoint,
    )
