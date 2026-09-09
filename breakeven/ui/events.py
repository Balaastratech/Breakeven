"""The agent-event bus and Grafana MCP call instrumentation — F-UI-01, F-UI-04, F-UI-05.

Push, never poll: an agent thread calls :meth:`EventBus.publish`, every connected
WebSocket handler is holding a blocking `Queue.get` on its own subscription, and the
`put` wakes it immediately. Nothing anywhere asks "is there anything new yet?".

**Coverage boundary, stated because `F-UI-04` says "every".** :class:`McpCallRecorder`
observes `breakeven.mcp.client.call_tool`, which is the funnel Watchtower's `_query` and
therefore Forensics' `_fetch` both route through — every Grafana MCP call this slice's
agents make. It does **not** see ADK-native tool calls made inside an `LlmAgent` loop by
an `MCPToolset` (the shape `agents/probe/agent.py` uses); those happen inside ADK and are
only reachable through ADK's own callback surface. No agent on the Slice 1 path uses that
shape, so the count matches today — but a future agent built the probe's way would need
its own observer, and this recorder would not silently cover it.
"""

from __future__ import annotations

import json
import logging
import queue
import re
import threading
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from itertools import count

from breakeven.actions.audit import AuditEntry, now_stamp
from breakeven.agents.brief import operator_brief

# Forensics issues a fixed, ordered tuple of queries per incident and labels the evidence
# it hands the model `e0`…`e3` by that position. Reading the tuple back is what turns a
# claim's `evidence_id` into the literal query that supports it (`INV-S04`). Importing the
# private name mirrors what `forensics` itself does with `watchtower._query`, and is
# strictly better than re-deriving the position from `Incident.evidence`'s order, which
# only coincidentally matches when nothing else has appended evidence to the incident.
from breakeven.agents.forensics import _queries as _forensics_queries

# `e4`'s Loki query is deterministic in `incident.channel` alone, so it can be
# reconstructed exactly like `e0`-`e3` — mirrors `forensics.py`'s own `loki_query`
# literal, which is not itself importable (assembled inline in `diagnose()`).
_LOKI_QUERY_TEMPLATE = '{{service="transcoder", channel="{channel}"}} | json'
from breakeven.agents.incident import Incident
from breakeven.mcp import client as mcp_client
from breakeven.sim.world import CHANNELS

_LOGGER = logging.getLogger(__name__)

# Every kind the transport accepts. Publishing anything else raises rather than streaming
# a message the client cannot identify; task 18b will add the `stage` display surface.
EVENT_KINDS = frozenset(
    {
        "mcp_call",
        "evidence",
        "brief",
        "stage",
        "narration",
        "approval",
        "control",
        "revenue",
        "player",
        "risk",
    }
)

MAX_QUEUED_EVENTS = 500
MAX_HISTORY_EVENTS = 500
RESULT_SUMMARY_LIMIT = 400

_EVIDENCE_ID = re.compile(r"^e(\d+)$")
_CHANNEL_NAMES = {channel.channel_id: channel.name for channel in CHANNELS}


@dataclass(frozen=True)
class AgentEvent:
    """One thing an agent did, as the browser will see it.

    Frozen and pre-serialised: `at` is already an ISO-8601 string with its offset, so a
    replayed event carries the time it actually happened rather than the time it was
    re-sent. That is what stops a reconnecting page from presenting history as live.
    """

    seq: int
    kind: str
    at: str
    payload: Mapping[str, object]

    def as_message(self, *, replay: bool) -> dict[str, object]:
        """The wire form. `replay` is the caller's statement about how it is being sent."""
        return {
            "seq": self.seq,
            "kind": self.kind,
            "at": self.at,
            "replay": replay,
            "payload": dict(self.payload),
        }


class Subscription:
    """One connected client's bounded backlog.

    Bounded and non-blocking on purpose: a browser tab that stops reading must not be
    able to stall the agent thread that publishes. When the backlog is full the new event
    is dropped and counted, and the count is sent to the client as its own message — so a
    slow client sees a stated gap rather than a stream that quietly skipped ahead.
    """

    def __init__(self, max_queued: int) -> None:
        self._queue: queue.Queue[AgentEvent] = queue.Queue(maxsize=max_queued)
        self._lock = threading.Lock()
        self._dropped = 0

    @property
    def dropped(self) -> int:
        """How many events have been dropped since the last :meth:`take_dropped`."""
        with self._lock:
            return self._dropped

    def offer(self, event: AgentEvent) -> None:
        """Enqueue ``event`` if there is room, else count it as dropped. Never blocks."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            with self._lock:
                self._dropped += 1

    def take_dropped(self) -> int:
        """Return the drop count and reset it, so each gap is reported exactly once."""
        with self._lock:
            dropped, self._dropped = self._dropped, 0
        return dropped

    def next_event(self, timeout: float) -> AgentEvent | None:
        """Wait up to ``timeout`` seconds for the next event, or return `None`.

        `None` means "nothing arrived in that window", which the handler needs to tell
        apart from an event without catching an exception on its hot path.
        """
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def pending(self) -> int:
        """How many events are waiting to be sent to this client."""
        return self._queue.qsize()


class EventBus:
    """In-process fan-out from the agent threads to every connected WebSocket."""

    def __init__(
        self,
        *,
        max_queued: int = MAX_QUEUED_EVENTS,
        max_history: int = MAX_HISTORY_EVENTS,
    ) -> None:
        self._max_queued = max_queued
        self._history: deque[AgentEvent] = deque(maxlen=max_history)
        self._subscriptions: list[Subscription] = []
        self._sequence = count(1)
        self._published = 0
        self._lock = threading.Lock()

    def publish(self, kind: str, payload: Mapping[str, object]) -> AgentEvent:
        """Record one event and hand it to every current subscriber, in order.

        The fan-out happens under the same lock that assigns the sequence number, so two
        publishing threads can never deliver their events to a client in the opposite
        order to the one the history records. That is affordable because
        :meth:`Subscription.offer` never blocks.
        """
        if kind not in EVENT_KINDS:
            raise ValueError(
                f"unknown event kind {kind!r}; expected one of {sorted(EVENT_KINDS)}"
            )
        with self._lock:
            event = AgentEvent(
                seq=next(self._sequence),
                kind=kind,
                at=now_stamp(),
                payload=dict(payload),
            )
            self._history.append(event)
            self._published += 1
            for subscription in self._subscriptions:
                subscription.offer(event)
        return event

    def subscribe(self) -> Subscription:
        """Register a new client backlog. Call before reading :meth:`history`, so no
        event published in between is lost."""
        subscription = Subscription(self._max_queued)
        with self._lock:
            self._subscriptions.append(subscription)
        return subscription

    def unsubscribe(self, subscription: Subscription) -> None:
        """Drop ``subscription``. Silent if already dropped, so a handler can call this in
        a ``finally`` without tracking whether it got that far."""
        with self._lock:
            while subscription in self._subscriptions:
                self._subscriptions.remove(subscription)

    def history(self) -> tuple[AgentEvent, ...]:
        """The replay buffer — the most recent `max_history` events, oldest first."""
        with self._lock:
            return tuple(self._history)

    def subscriber_count(self) -> int:
        """How many clients are currently attached."""
        with self._lock:
            return len(self._subscriptions)

    @property
    def published_count(self) -> int:
        """Every event ever published, including those aged out of the replay buffer."""
        with self._lock:
            return self._published


class McpCallRecorder:
    """Publishes one `mcp_call` event per `mcp.client.call_tool` call — `F-UI-04`.

    Register it with :meth:`start` (or use it as a context manager) and the tool name,
    arguments and a bounded result summary reach the browser as each call completes.

    The instrumented count is incremented *before* the event is published, deliberately:
    if publishing ever failed, `instrumented_count` would exceed the number of rendered
    events and the count-equality test would go red. Incrementing afterwards would make
    that test true by construction and prove nothing.
    """

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._lock = threading.Lock()
        self._count = 0

    @property
    def instrumented_count(self) -> int:
        """How many `call_tool` calls this recorder has been told about."""
        with self._lock:
            return self._count

    def __call__(
        self,
        tool_name: str,
        arguments: Mapping[str, object],
        result: dict[str, object] | None,
        error: str | None,
    ) -> None:
        """The `mcp_client.CallObserver` contract."""
        with self._lock:
            self._count += 1
        self._bus.publish(
            "mcp_call",
            {
                "tool": tool_name,
                # The Grafana service-account token is a parameter of `call_tool`, never
                # of the tool being called, so it is not in `arguments` and cannot be
                # rendered. `tests/test_ui.py` asserts that rather than filtering here.
                "arguments": _renderable(arguments),
                "result_summary": _summarise(result) if error is None else error,
                "ok": error is None,
            },
        )

    def start(self) -> McpCallRecorder:
        """Begin observing every `call_tool` call in this process."""
        mcp_client.add_call_observer(self)
        return self

    def stop(self) -> None:
        """Stop observing. Safe to call twice."""
        mcp_client.remove_call_observer(self)

    def __enter__(self) -> McpCallRecorder:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()


def evidence_rows(incident: Incident) -> list[dict[str, object]]:
    """Pair each root-cause claim with the literal query that supports it — `INV-S04`.

    A claim whose cited evidence is not present on the incident is returned with
    ``grounded`` false and no query, and logged at error level. It is never dropped (that
    would hide an ungrounded claim) and never rendered as though it were supported (that
    would be the confabulation the evidence panel exists to make impossible).
    """
    by_query = {evidence.query: evidence for evidence in incident.evidence}
    rows: list[dict[str, object]] = []
    for claim, evidence_id in incident.root_cause_claims:
        query = _cited_query(incident, evidence_id)
        evidence = by_query.get(query) if query is not None else None
        if evidence is None:
            _LOGGER.error(
                "incident %s cites evidence %r that the incident does not carry; "
                "rendering the claim as ungrounded",
                incident.id,
                evidence_id,
            )
            rows.append(
                {
                    "claim": claim,
                    "query": None,
                    "result": None,
                    "taken_at": None,
                    "grounded": False,
                }
            )
            continue
        rows.append(
            {
                "claim": claim,
                "query": evidence.query,
                # Verbatim, not summarised: this is the grounding proof a judge reads.
                "result": evidence.result,
                "taken_at": evidence.taken_at.isoformat(),
                "grounded": True,
            }
        )
    return rows


def publish_evidence(bus: EventBus, incident: Incident) -> AgentEvent:
    """Stream the incident's grounding chain to the evidence panel — `F-UI-05`."""
    return bus.publish(
        "evidence",
        {
            "incident_id": incident.id,
            "channel": _CHANNEL_NAMES.get(incident.channel, incident.channel),
            "region": incident.region,
            "rows": evidence_rows(incident),
        },
    )


def publish_brief(
    bus: EventBus,
    incident: Incident,
    entry: AuditEntry,
    links: Mapping[str, str | None] | None = None,
) -> AgentEvent:
    """Stream task 17's plain-language brief. Rendered, never re-derived here."""
    # A module-level import would create a cycle: orchestrator imports this function.
    from breakeven.agents.orchestrator import PROJECTED_LOSS_HORIZON_MINUTES

    settled_at = datetime.fromisoformat(entry.timestamp)
    elapsed_minutes = (settled_at - incident.detected_at).total_seconds() / 60
    elapsed_minutes = max(0.0, min(elapsed_minutes, PROJECTED_LOSS_HORIZON_MINUTES))
    actual_loss_usd = incident.revenue_at_risk_per_min * elapsed_minutes
    loss_averted_usd = max(
        0.0, incident.projected_loss_if_unaddressed - actual_loss_usd
    )
    return bus.publish(
        "brief",
        {
            "incident_id": incident.id,
            "text": operator_brief(incident, entry),
            "revenue_at_risk_per_min": incident.revenue_at_risk_per_min,
            "actual_loss_usd": actual_loss_usd,
            "loss_averted_usd": loss_averted_usd,
            "channel": _CHANNEL_NAMES.get(incident.channel, incident.channel),
            "region": incident.region,
            "outcome": entry.result.value,
            "dashboard_url": links.get("dashboard_url") if links else None,
            "incident_url": links.get("incident_url") if links else None,
            "alert_rule_url": links.get("alert_rule_url") if links else None,
        },
    )


_TEMPO_QUERY_PREFIX = "get-trace "


def _cited_query(incident: Incident, evidence_id: str) -> str | None:
    """The literal query behind one `eN` citation, or `None` if there is no such query.

    `e4` (Loki) is deterministic in `incident.channel` alone, same as `e0`-`e3`, so it is
    reconstructed here too. `e5` (Tempo, `get-trace {trace_id}`) is **not** reconstructable
    this way — its `trace_id` is extracted live from the dominant Loki record and carried
    nowhere else on `Incident`. Rather than re-deriving it, this looks up the one attached
    evidence entry whose own query starts with `get-trace ` — safe, not the "coincidental
    order" fragility the module comment above warns about, because `forensics.diagnose()`
    attaches at most one Tempo evidence entry per incident, ever, so the prefix is
    unambiguous regardless of position.
    """
    match = _EVIDENCE_ID.match(evidence_id)
    if match is None:
        return None
    index = int(match.group(1))
    queries = _forensics_queries(incident.channel)
    if index < len(queries):
        return queries[index]
    if index == len(queries):
        return _LOKI_QUERY_TEMPLATE.format(channel=incident.channel)
    if index == len(queries) + 1:
        for evidence in incident.evidence:
            if evidence.query.startswith(_TEMPO_QUERY_PREFIX):
                return evidence.query
        return None
    return None


def _renderable(value: Mapping[str, object]) -> dict[str, object]:
    """A JSON-round-tripped copy of ``value``.

    Every event crosses a WebSocket, and `send_json` has no `default=` hook — one
    unserialisable argument value would close the socket and take the whole panel down
    mid-demo. MCP arguments are JSON by construction, so this normally copies; it exists
    for the failure path, where `call_tool` may have raised precisely because they were not.
    """
    return json.loads(json.dumps(dict(value), default=repr))


def _summarise(result: object, *, limit: int = RESULT_SUMMARY_LIMIT) -> str:
    """A bounded, deterministic rendering of one tool result.

    Bounded because a single Prometheus response can be megabytes, and a panel that
    streams all of it stops being readable — which is the one thing `F-UI-04` cannot
    afford. The full evidence is still recorded verbatim on the incident itself.
    """
    text = json.dumps(result, sort_keys=True, default=repr)
    if len(text) <= limit:
        return text
    return f"{text[:limit]} … (truncated from {len(text)} characters)"
