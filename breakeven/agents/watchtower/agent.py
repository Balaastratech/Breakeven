"""Watchtower computes evidenced revenue-at-risk from Grafana MCP metrics."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai.types import Content, Part

from breakeven.agents.incident import Evidence, HealthCheck, SystemHealthAssertion
from breakeven.mcp.client import call_tool
from breakeven.mcp.tools import QUERY_PROMETHEUS
from breakeven.secrets import get_secret
from breakeven.sim.metrics import CONFIRM_FAILED_BREAKS
from breakeven.sim.world import CHANNELS, concurrency_at, emit_labels

MODEL = "gemini-2.5-flash"
WINDOW_SECONDS = 600
_LOGGER = logging.getLogger(__name__)
# `D-S95`: the corrected `F-AGT-03` outcome — an absolute per-cycle ceiling on
# Watchtower's own token cost, not a ratio against Forensics. 1,500 is four independent
# live measurements (954-1,035) plus ~45% headroom, per `D-S95`'s own reasoning. `INV-S03`
# names this as an absolute-cost concern precisely because Watchtower runs constantly, on
# a ~30s loop — nothing else in this repo would catch a future model swap silently
# blowing this budget.
WATCHTOWER_TOKEN_CEILING = 1500
CONSERVATION_TOLERANCE = 0.05
# ponytail: calibration knob; tune only against observed Grafana daypart variance.
DAYPART_TOLERANCE = 0.25
_DATASOURCE_UID = "grafanacloud-prom"
_NUMERIC_VALUE_KEYS = {
    "viewers",
    "breaks_per_hour",
    "ads_per_break",
    "cpm_usd",
    "requests",
    "fills",
    "errors",
    "billable_impressions",
    "beacon_failures",
    "slot_failure_ratio",
    "failed_breaks_streak",
}
# `D-S110`: read from the simulator's own per-break gauges rather than defaulted to 0.0
# when absent. `-1.0` means "this deployment does not emit them", which is a different
# thing from "it emits them and they are zero" — the first falls back to the legacy
# counter ratio, the second is a healthy channel. Defaulting both to 0.0 would silently
# report every channel healthy against a simulator too old to emit these.
_OPTIONAL_METRIC_NAMES = frozenset({"slot_failure_ratio", "failed_breaks_streak"})
_METRIC_ABSENT = -1.0
# Gauges (`_world_gauges`, sim/metrics.py) are emitted for every channel on every tick,
# so a missing one is a real fault. Counters only increment for a channel once it
# actually breaks, so a niche/cold channel can legitimately lag on these alone.
_GAUGE_METRIC_NAMES = frozenset(
    {"viewers", "breaks_per_hour", "ads_per_break", "cpm_usd"}
)
_CHANNELS_BY_ID = {channel.channel_id: channel for channel in CHANNELS}
_REGIONS_BY_CHANNEL = {
    channel.channel_id: emit_labels(index)[0] for index, channel in enumerate(CHANNELS)
}

root_agent = LlmAgent(
    name="watchtower_judge",
    model=MODEL,
    instruction=(
        "Rank the supplied channel revenue-at-risk figures and give one concise judgment. "
        "Do not calculate figures, open incidents, or request more data."
    ),
)


def revenue_at_risk(
    viewers: float,
    breaks_per_hour: float,
    ads_per_break: float,
    cpm_usd: float,
    slot_failure: float,
) -> float:
    """Return one channel's dollar risk per minute without performing I/O."""
    return (
        viewers
        * (breaks_per_hour / 60)
        * ads_per_break
        * (cpm_usd / 1000)
        * slot_failure
    )


def _slot_failure(
    ratio: float, failed_breaks_streak: float, *, legacy_ratio: float
) -> float:
    """Return the channel's current slot-failure rate under `D-S110`'s two-part rule.

    The old single expression — cumulative errors over cumulative requests across a
    600s window — answered "how bad has it been on average for ten minutes", and was
    read as if it answered "how bad is it now". A fault one minute old therefore
    reported at roughly a tenth of its true size, and climbed for the full window
    before it read true; on a small channel it could sit under the incident floor for
    minutes while genuinely costing money the whole time.

    Split into the two questions that were being conflated:

    * `ratio` — the most recent break's own failure rate. Current by construction, so
      it needs no window and cannot be diluted by healthy history.
    * `failed_breaks_streak` — how many consecutive breaks have failed. This, not a
      wide averaging window, is what makes a single bad break unable to trigger a
      remedy.

    Below the streak threshold the channel reads as healthy: one failed break is the
    transient this guard exists to absorb. A simulator too old to emit either gauge
    reports `_METRIC_ABSENT`, and falls back to the legacy ratio rather than silently
    reporting every channel healthy.
    """
    if ratio == _METRIC_ABSENT or failed_breaks_streak == _METRIC_ABSENT:
        return legacy_ratio
    if failed_breaks_streak < CONFIRM_FAILED_BREAKS:
        return 0.0
    return ratio


def aggregate_error_rate(channels: Mapping[str, Mapping[str, float]]) -> float | None:
    """Return the D-S29 viewer-weighted rate, excluding unevaluable channels."""
    impressions = sum(channel["impressions"] for channel in channels.values())
    if not impressions:
        return None
    return (
        sum(
            channel["impressions"] * channel["slot_failure"]
            for channel in channels.values()
        )
        / impressions
    )


def _query(query: str) -> tuple[dict[str, object], Evidence]:
    """Issue one literal PromQL query through the pinned Grafana MCP tool."""
    result = call_tool(
        os.environ.get("BREAKEVEN_MCP_ENDPOINT", "http://localhost:8000/mcp"),
        get_secret("grafana-sa-token"),
        QUERY_PROMETHEUS,
        {
            "expr": query,
            "datasourceUid": _DATASOURCE_UID,
            "endTime": "now",
            "queryType": "instant",
        },
    )
    is_error = result.get("isError")
    if "isError" in result and not isinstance(is_error, bool):
        raise RuntimeError("Grafana MCP response has a non-boolean isError flag")
    if is_error is True:
        raise RuntimeError("Grafana MCP rejected the Watchtower PromQL query")
    content = result.get("content")
    if not isinstance(content, list) or not content:
        raise RuntimeError("Grafana MCP response has no content")
    first = content[0]
    if not isinstance(first, dict) or not isinstance(first.get("text"), str):
        raise RuntimeError("Grafana MCP response has no text payload")
    text = first["text"]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        raise RuntimeError("Grafana MCP returned non-JSON Prometheus text") from error
    if not isinstance(parsed, dict):
        raise RuntimeError("Grafana MCP returned a non-object Prometheus payload")
    return parsed, Evidence(
        query=query, result=text, taken_at=datetime.now(timezone.utc)
    )


def query_scalar(query: str) -> float:
    """Return the sole finite value from an unlabelled Prometheus aggregation."""
    payload, _ = _query(query)
    data = payload.get("data")
    if not isinstance(data, list):
        raise RuntimeError(f"Prometheus payload for {query!r} has no vector result")
    if not data:
        return 0.0
    if len(data) != 1:
        raise RuntimeError(
            f"Prometheus payload for {query!r} has multiple scalar series"
        )
    series = data[0]
    if not isinstance(series, dict):
        raise RuntimeError(f"Prometheus payload for {query!r} has a non-object series")
    value = series.get("value")
    if not isinstance(value, list) or len(value) != 2:
        raise RuntimeError(
            f"Prometheus payload for {query!r} has no instant scalar value"
        )
    try:
        scalar = float(value[1])
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            f"Prometheus payload for {query!r} has a non-numeric scalar"
        ) from error
    if not math.isfinite(scalar):
        raise RuntimeError(
            f"Prometheus payload for {query!r} has non-finite scalar {value[1]!r}"
        )
    return scalar


def _channel_values(payload: Mapping[str, object]) -> dict[str, float]:
    """Extract channel-labelled instant-vector values from a Prometheus response."""
    data = payload.get("data")
    if not isinstance(data, list):
        raise RuntimeError("Prometheus payload has no vector result")
    values: dict[str, float] = {}
    for series in data:
        if not isinstance(series, dict):
            raise RuntimeError("Prometheus vector contains a non-object series")
        metric = series.get("metric")
        value = series.get("value")
        if not isinstance(metric, dict) or not isinstance(metric.get("channel"), str):
            raise RuntimeError("Prometheus vector series has no channel label")
        if not isinstance(value, list) or len(value) != 2:
            raise RuntimeError("Prometheus vector series has no instant value")
        parsed_value = float(value[1])
        if not math.isfinite(parsed_value):
            raise RuntimeError(
                "Prometheus vector series for channel "
                f"{metric['channel']} has non-finite value {value[1]!r}"
            )
        channel = metric["channel"]
        if channel in values:
            raise RuntimeError(
                f"Prometheus vector channel {channel} appeared twice in one result"
            )
        values[channel] = parsed_value
    return values


def _fetch_live() -> dict[str, dict[str, object]]:
    """Fetch all Watchtower inputs solely through Grafana MCP."""
    viewer_selectors = " or ".join(
        "stream_concurrent_viewers" f'{{channel="{channel}",region="{region}"}}'
        for channel, region in sorted(_REGIONS_BY_CHANNEL.items())
    )
    queries = {
        "viewers": f"max by (channel) ({viewer_selectors})",
        "breaks_per_hour": "max by (channel) (channel_breaks_per_hour)",
        "ads_per_break": "max by (channel) (channel_ads_per_break)",
        "cpm_usd": "max by (channel) (channel_cpm_usd)",
        "requests": f"sum by (channel) (increase(ad_break_requests_total[{WINDOW_SECONDS}s]))",
        "fills": f"sum by (channel) (increase(ad_break_fills_total[{WINDOW_SECONDS}s]))",
        "errors": f"sum by (channel) (increase(ad_break_errors_total[{WINDOW_SECONDS}s]))",
        "billable_impressions": f"sum by (channel) (increase(ad_impressions_billable_total[{WINDOW_SECONDS}s]))",
        "beacon_failures": f"sum by (channel) (increase(ad_beacon_failures_total[{WINDOW_SECONDS}s]))",
        # `D-S110`: instant reads, deliberately *not* wrapped in a range window. These
        # answer "how bad is this channel right now" and "has it been bad for more than
        # one break" as two separate questions, which is what lets detection be both
        # immediate and blip-resistant. Deriving the same answer from the counters above
        # cannot be: any window wide enough to hold two samples also averages a
        # just-started fault down by the fraction of the window it has existed for.
        "slot_failure_ratio": "max by (channel) (ad_slot_failure_ratio)",
        "failed_breaks_streak": "max by (channel) (ad_slot_failed_breaks_streak)",
    }
    # `GAPS.md` #12: each `_query` is a blocking network round-trip (real Grafana MCP
    # queries measured ~34s each, `D-S116`) — run concurrently, not one after another, so
    # the real cost of detection is the slowest single query, not their sum. Threads, not
    # `asyncio`, because `_query`/`call_tool` are synchronous I/O; a thread per query is
    # released back to the OS the moment the network response lands.
    with ThreadPoolExecutor(max_workers=len(queries)) as executor:
        fetched = dict(zip(queries.keys(), executor.map(_query, queries.values())))
    values = {name: _channel_values(payload) for name, (payload, _) in fetched.items()}
    channels = set().union(*(metric_values.keys() for metric_values in values.values()))
    # A counter with zero channels while other metrics have channels is a pipeline
    # outage (a scrape/recording-rule break), not a cold channel — a cold channel is
    # merely absent from *this one* counter while present in others, which the
    # per-channel default below already covers. Defaulting an entirely-empty counter
    # to 0.0 per channel would silently read every channel as healthy on exactly the
    # invariants this counter feeds (`slot_conservation`, `beacon_delivery`).
    for name, metric_values in values.items():
        if (
            name not in _GAUGE_METRIC_NAMES
            and name not in _OPTIONAL_METRIC_NAMES
            and not metric_values
            and channels
        ):
            raise RuntimeError(f"Prometheus metric {name} returned no channels at all")
    channel_records: dict[str, dict[str, object]] = {}
    for channel in channels:
        channel_values: dict[str, object] = {}
        for name, metric_values in values.items():
            if channel not in metric_values:
                if name in _GAUGE_METRIC_NAMES:
                    raise RuntimeError(
                        f"Prometheus metric {name} has no value for channel {channel}"
                    )
                channel_values[name] = (
                    _METRIC_ABSENT if name in _OPTIONAL_METRIC_NAMES else 0.0
                )
                continue
            channel_values[name] = metric_values[channel]
        channel_records[channel] = {
            **channel_values,
            "evidence": {name: evidence for name, (_, evidence) in fetched.items()},
        }
    return channel_records


# `RESOURCE_EXHAUSTED` (Vertex AI's 429) is a real per-minute rate limit, not a spend
# cap — retrying after a short wait is the correct response, the same way any client
# of a rate-limited API should behave. Every other model failure (bad auth, no model
# access, malformed request) is permanent and must keep failing immediately; retrying
# those would just burn the same three attempts on a call that can never succeed.
_RATE_LIMIT_RETRIES = 3
_RATE_LIMIT_BACKOFF_SECONDS = 2.0


def _judge_once(table: str) -> tuple[int, int, int]:
    """One real ADK judgment call — no retry here, `_judge` owns that policy."""
    sessions = InMemorySessionService()
    session = asyncio.run(
        sessions.create_session(app_name="watchtower", user_id="watchtower")
    )
    runner = Runner(app_name="watchtower", agent=root_agent, session_service=sessions)
    events = runner.run(
        user_id="watchtower",
        session_id=session.id,
        new_message=Content(role="user", parts=[Part(text=table)]),
    )
    usage = None
    failures: list[str] = []
    for event in events:
        if event.usage_metadata is not None:
            usage = event.usage_metadata
        # W1: ADK reports a failed model call on the event itself, not by raising.
        # Reading only `usage_metadata` turns any model-side failure into "no token
        # counts" and discards the cause — a missing API key cost two sessions of
        # diagnosis exactly this way. Collect the real reason so it reaches the caller.
        if event.error_code is not None or event.error_message is not None:
            failures.append(f"{event.error_code}: {event.error_message}")
    if failures:
        raise RuntimeError(
            "The Watchtower judgment model call failed: " + "; ".join(failures)
        )
    if usage is None:
        raise RuntimeError("ADK emitted no usage_metadata for the Watchtower judgment")
    counts = (
        usage.prompt_token_count,
        usage.candidates_token_count,
        usage.total_token_count,
    )
    if any(count is None for count in counts):
        raise RuntimeError(
            "ADK usage_metadata omitted a required Watchtower token count"
        )
    return tuple(int(count) for count in counts)


def _judge(table: str) -> tuple[int, int, int]:
    """Run the bounded judgment prompt, retrying only a real rate limit."""
    for attempt in range(1, _RATE_LIMIT_RETRIES + 1):
        try:
            return _judge_once(table)
        except RuntimeError as error:
            is_rate_limited = "RESOURCE_EXHAUSTED" in str(error) or "429" in str(error)
            if not is_rate_limited or attempt == _RATE_LIMIT_RETRIES:
                raise
            wait_seconds = _RATE_LIMIT_BACKOFF_SECONDS * (2 ** (attempt - 1))
            _LOGGER.warning(
                "Watchtower judgment hit a rate limit (attempt %d/%d) — retrying in "
                "%.0fs: %s",
                attempt,
                _RATE_LIMIT_RETRIES,
                wait_seconds,
                error,
            )
            time.sleep(wait_seconds)
    raise AssertionError("unreachable — loop always returns or raises")


def _validated_numeric_value(channel: str, key: str, raw_value: object) -> float:
    """Return one finite injected channel value or name its contract violation."""
    try:
        value = float(raw_value)
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            f"Watchtower channel {channel} has non-numeric value for key {key}"
        ) from error
    if not math.isfinite(value):
        raise RuntimeError(
            f"Watchtower channel {channel} has non-finite value {value!r} for key {key}"
        )
    return value


def _evaluate_channel(
    channel: str, values: Mapping[str, object]
) -> tuple[list[HealthCheck], dict[str, float] | None, float | None]:
    """Evaluate one channel's conservation result and Python-owned risk."""
    numeric_values: dict[str, float] = {}
    for key in (
        "viewers",
        "breaks_per_hour",
        "ads_per_break",
        "cpm_usd",
        "requests",
        "fills",
        "errors",
        "evidence",
    ):
        if key not in values:
            raise RuntimeError(
                f"Watchtower channel {channel} has no value for required key {key}"
            )
        if key in _NUMERIC_VALUE_KEYS:
            numeric_values[key] = _validated_numeric_value(channel, key, values[key])
    requests = numeric_values["requests"]
    fills = numeric_values["fills"]
    errors = numeric_values["errors"]
    evidence = values["evidence"]
    if not isinstance(evidence, dict) or not isinstance(
        evidence.get("requests"), Evidence
    ):
        raise RuntimeError("Watchtower fetcher returned no request evidence")
    if requests == 0:
        return (
            [
                HealthCheck(
                    invariant="slot_conservation",
                    channel=channel,
                    held=None,
                    detail="requests=0.0; slot conservation not evaluable",
                    evidence=evidence["requests"],
                    region=_REGIONS_BY_CHANNEL.get(channel),
                )
            ],
            None,
            None,
        )
    held = abs(requests - fills - errors) <= requests * CONSERVATION_TOLERANCE
    conservation_check = HealthCheck(
        invariant="slot_conservation",
        channel=channel,
        held=held,
        detail=f"requests={requests}, fills={fills}, errors={errors}, held={held}",
        evidence=evidence["requests"],
        region=_REGIONS_BY_CHANNEL.get(channel),
    )
    billable_impressions = _validated_numeric_value(
        channel, "billable_impressions", values.get("billable_impressions", fills)
    )
    beacon_failures = _validated_numeric_value(
        channel, "beacon_failures", values.get("beacon_failures", 0.0)
    )
    beacon_held = billable_impressions >= fills and beacon_failures == 0
    beacon_check = HealthCheck(
        invariant="beacon_delivery",
        channel=channel,
        held=beacon_held,
        detail=(
            f"fills={fills}, billable_impressions={billable_impressions}, "
            f"beacon_failures={beacon_failures}, held={beacon_held}"
        ),
        evidence=evidence.get("billable_impressions", evidence["requests"]),
        region=_REGIONS_BY_CHANNEL.get(channel),
    )
    impressions = (
        numeric_values["viewers"]
        * (numeric_values["breaks_per_hour"] / 60)
        * numeric_values["ads_per_break"]
    )
    slot_failure = _slot_failure(
        numeric_values.get("slot_failure_ratio", _METRIC_ABSENT),
        numeric_values.get("failed_breaks_streak", _METRIC_ABSENT),
        legacy_ratio=errors / requests,
    )
    beacon_loss = max(0.0, fills - billable_impressions) / fills if fills else 0.0
    risk = revenue_at_risk(
        numeric_values["viewers"],
        numeric_values["breaks_per_hour"],
        numeric_values["ads_per_break"],
        numeric_values["cpm_usd"],
        max(slot_failure, beacon_loss),
    )
    if not math.isfinite(slot_failure) or not math.isfinite(risk):
        raise RuntimeError(
            f"Watchtower channel {channel} computed a non-finite slot failure or risk"
        )
    return (
        [conservation_check, beacon_check],
        {"impressions": impressions, "slot_failure": slot_failure},
        risk,
    )


def _daypart_check(
    channel: str, viewers: object, hour: int, evidence: Evidence
) -> HealthCheck | None:
    """Compare one channel's region-matched viewers with its Python daypart curve."""
    channel_obj = _CHANNELS_BY_ID.get(channel)
    region = _REGIONS_BY_CHANNEL.get(channel)
    if channel_obj is None or region is None:
        return None
    observed = _validated_numeric_value(channel, "viewers", viewers)
    expected = concurrency_at(channel_obj, region, hour)
    held = abs(observed - expected) <= expected * DAYPART_TOLERANCE
    return HealthCheck(
        invariant="daypart_concurrency",
        channel=channel,
        held=held,
        detail=(
            f"observed_viewers={observed}, expected_daypart_viewers={expected}, "
            f"tolerance={DAYPART_TOLERANCE}, held={held}"
        ),
        evidence=evidence,
        region=region,
    )


def run_cycle(
    *,
    fetch: Callable[[], dict[str, dict[str, object]]] = _fetch_live,
    judge: Callable[[str], tuple[int, int, int]] = _judge,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> SystemHealthAssertion:
    """Compute and explicitly emit one evidenced health assertion."""
    emitted_at = now()
    evaluable: dict[str, dict[str, float]] = {}
    checks: list[HealthCheck] = []
    risk: dict[str, float] = {}
    fetched = dict(fetch())
    if not fetched:
        raise RuntimeError("No channel data was observed for this Watchtower cycle")
    for channel, values in fetched.items():
        channel_checks, contribution, channel_risk = _evaluate_channel(channel, values)
        checks.extend(channel_checks)
        daypart_check = _daypart_check(
            channel, values["viewers"], emitted_at.hour, channel_checks[0].evidence
        )
        if daypart_check is not None:
            checks.append(daypart_check)
        if contribution is not None and channel_risk is not None:
            evaluable[channel] = contribution
            risk[channel] = channel_risk
    tokens = judge(
        "\n".join(
            (
                f"{channel}: observed_viewers={int(fetched[channel]['viewers'])}, "
                "expected_daypart_viewers="
                f"{concurrency_at(
                    _CHANNELS_BY_ID[channel],
                    _REGIONS_BY_CHANNEL[channel],
                    emitted_at.hour,
                )}, "
                f"revenue_at_risk_per_min=${amount:.2f}"
                if channel in _CHANNELS_BY_ID
                else f"{channel}: revenue_at_risk_per_min=${amount:.2f}"
            )
            for channel, amount in sorted(risk.items())
        )
    )
    # `K-R06`: this used to `raise`, discarding every channel check, the revenue-at-risk
    # arithmetic, and the daypart judgement this cycle just computed — none of which cost
    # anything to keep, all of which are Watchtower's actual job. The tokens are already
    # spent by this point, so raising saved nothing and instead turned a cost regression
    # into a detection outage on every subsequent ~30s cycle for as long as the regression
    # persists — the exact trade `D-S95`'s own closing bullet declines to make for the
    # thinking budget, for the same reason. Logged loudly instead; `total_tokens` on the
    # returned assertion already carries the number for anyone consuming the assertion to
    # check it themselves.
    if tokens[2] > WATCHTOWER_TOKEN_CEILING:
        _LOGGER.critical(
            "Watchtower's judgment cost %d tokens this cycle, over the `D-S95` ceiling "
            "of %d — `INV-S03` requires this stay cheap; a model swap or prompt bloat "
            "needs investigating, but detection for this cycle is not discarded over it",
            tokens[2],
            WATCHTOWER_TOKEN_CEILING,
        )
    return SystemHealthAssertion(
        emitted_at=emitted_at,
        window_seconds=WINDOW_SECONDS,
        checks=checks,
        aggregate_error_rate=aggregate_error_rate(evaluable),
        revenue_at_risk_per_min=risk,
        prompt_tokens=tokens[0],
        output_tokens=tokens[1],
        total_tokens=tokens[2],
    )
