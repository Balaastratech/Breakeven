"""FastAPI + WebSocket backend for the operator UI — F-UI-01, F-UI-04, F-UI-05.

The page and WebSocket remain push-driven. Explicit operator button clicks use POST routes;
nothing polls for agent state, and the UI process alone reads the simulator's live revenue
endpoint before pushing each changed value to connected browsers.

**No authentication.** This serves agent telemetry — incident detail, PromQL, evidence —
to anyone who can reach the port, so :func:`serve` binds loopback by default. Exposing it
publicly needs an explicit authentication decision; this module intentionally does not
make that deployment-policy choice.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from html import escape as html_escape
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, RedirectResponse, Response
from pydantic import BaseModel
from starlette.websockets import WebSocketState

from breakeven.secrets import get_secret
from breakeven.ui.events import AgentEvent, EventBus, Subscription

if TYPE_CHECKING:
    from breakeven.ui.controls import ControlPlane

_LOGGER = logging.getLogger(__name__)

UI_ROOT = Path(__file__).resolve().parent
AGENT_HTML = UI_ROOT / "static" / "agent.html"
SIMULATOR_HTML = UI_ROOT / "static" / "simulator.html"

# `D-S76`: Grafana Cloud sends `frame-ancestors 'none'` on every dashboard URL, including
# public-dashboard shares — an iframe embed is not possible there, full stop, regardless
# of any account permission. A rendered PNG has no such restriction, but the render API
# needs the real service-account bearer token, which must never reach the browser — so
# this process fetches the image itself and streams the bytes back, same-origin. Cached
# briefly so the console's periodic client-side refresh doesn't hammer Grafana's render
# API on every tick.
_GRAFANA_RENDER_URL = (
    "https://glowingwasp1671.grafana.net/render/d-solo/breakeven-revenue-watch"
    "?panelId=1&width=900&height=420&tz=UTC"
)
_PANEL_CACHE_SECONDS = 30.0

# How long one drain step waits on the subscriber queue before looping. This is not a data
# poll — `Queue.get` returns the instant an event is published, so it never delays an
# event. It only bounds how quickly the handler notices its client has gone away.
_WAKEUP_SECONDS = 0.25
_REVENUE_POLL_SECONDS = 1.0
_PLAYER_SESSION_TIMEOUT_SECONDS = 5.0
# `player` used to be published once at startup and never again. The replay buffer only
# keeps the most recent `MAX_QUEUED_EVENTS` (500) events, so any client that reloaded or
# reconnected after ~500 other events had gone by (narration, mcp_call, revenue, ...) got a
# snapshot with no `player` event in it at all — the live-player panel stuck on "Waiting for
# the simulator's live player session" forever, even though the real session was fine.
# Republishing on this interval keeps a `player` event inside the replay window at all times.
_PLAYER_SESSION_REPUBLISH_SECONDS = 30.0


class ActionRequest(BaseModel):
    """The action selected by an operator control."""

    action_id: str


class FaultRequest(BaseModel):
    """`GAPS.md` #8: the fault shape an operator picked, or none for the original default."""

    fault_type: str | None = None


def messages_for(
    subscription: Subscription, event: AgentEvent | None
) -> list[dict[str, object]]:
    """The messages to send for one drain step, in order.

    A drop notice comes first and always, even when there is no event to send with it: a
    client that fell behind learns about the gap at the earliest moment, rather than when
    the next event happens to arrive.
    """
    messages: list[dict[str, object]] = []
    dropped = subscription.take_dropped()
    if dropped:
        messages.append({"type": "dropped", "count": dropped})
    if event is not None:
        messages.append({"type": "event", **event.as_message(replay=False)})
    return messages


def create_app(bus: EventBus, controls: ControlPlane | None = None) -> FastAPI:
    """Build the operator-UI app over ``bus``."""
    stop_revenue_stream = threading.Event()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        """Publish simulator-backed revenue without a browser-side ticker."""
        if controls is not None:
            threading.Thread(
                target=_stream_revenue,
                args=(bus, controls.simulator_url, stop_revenue_stream),
                daemon=True,
                name="breakeven-revenue-stream",
            ).start()
            # Repeating, not one-shot (`_PLAYER_SESSION_REPUBLISH_SECONDS`): a single publish
            # at startup ages out of the replay buffer once ~500 other events have fired,
            # permanently blanking the live-player panel for anyone who reloads after that.
            # This also self-heals the original one-shot concern — a first attempt before the
            # simulator is reachable just succeeds on a later tick instead of being a hole.
            threading.Thread(
                target=_stream_player_session,
                args=(bus, controls.simulator_url, stop_revenue_stream),
                daemon=True,
                name="breakeven-player-session",
            ).start()
        try:
            yield
        finally:
            stop_revenue_stream.set()

    app = FastAPI(title="BreakEven operator UI", lifespan=lifespan)

    def require_controls() -> ControlPlane:
        if controls is None:
            raise HTTPException(
                status_code=503, detail="operator controls are not configured"
            )
        return controls

    def run_control(operation):
        try:
            return operation()
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        except RuntimeError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error

    @app.get("/", response_class=RedirectResponse)
    async def page() -> RedirectResponse:
        """Keep the former console URL pointed at the real agent page."""
        return RedirectResponse(url="/agent")

    @app.get("/agent", response_class=FileResponse)
    async def agent_page() -> FileResponse:
        """Serve the autonomous-agent view.

        Yuvraj, 2026-09-09: used to start the continuous polling loop the moment this page
        loaded — meaning every reload, every judge who opened the tab, started real Grafana
        calls that then ran forever. `inject_fault()` (`ui/controls.py`) is the real trigger
        now; simply viewing the console starts nothing.
        """
        return FileResponse(AGENT_HTML, media_type="text/html")

    @app.get("/simulator", response_class=FileResponse)
    async def simulator_page() -> FileResponse:
        """Serve the isolated real-fault lab."""
        return FileResponse(SIMULATOR_HTML, media_type="text/html")

    panel_cache: dict[str, object] = {"bytes": None, "at": 0.0}

    @app.get("/grafana/panel.png")
    def grafana_panel() -> Response:
        """Proxy the live revenue-watch panel as an image (`D-S76`) — the Grafana
        service-account token is fetched and used here, server-side, and never reaches
        the browser. Closure-scoped cache, not module-level, so each `create_app` call
        (the test suite makes several) gets its own, never bleeding state across tests.
        """
        now = time.monotonic()
        if (
            panel_cache["bytes"] is None
            or now - panel_cache["at"] > _PANEL_CACHE_SECONDS
        ):
            token = get_secret("grafana-sa-token")
            request = urllib.request.Request(
                _GRAFANA_RENDER_URL, headers={"Authorization": f"Bearer {token}"}
            )
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    panel_cache["bytes"] = response.read()
                    panel_cache["at"] = now
            except urllib.error.URLError as error:
                raise HTTPException(
                    status_code=502, detail=f"Grafana render failed: {error}"
                ) from error
            finally:
                del token
        return Response(content=panel_cache["bytes"], media_type="image/png")

    @app.get("/health")
    async def health() -> dict[str, object]:
        """Report liveness and how much has been streamed, for the soak run."""
        return {
            "status": "ok",
            "published": bus.published_count,
            "subscribers": bus.subscriber_count(),
        }

    @app.get("/investigate/{channel}")
    def investigate_channel(channel: str) -> dict[str, object]:
        """Run the tool-choosing Investigator live against `channel` and return its
        verdict plus real tool-call trace.

        Read-only and fully isolated from `ControlPlane`/the orchestrator's
        multiprocess cycle: this route never mutates fault or incident state, only
        queries real Grafana MCP through a fresh, throwaway `Incident`.
        """
        # pylint: disable=import-outside-toplevel
        from datetime import datetime, timezone

        from breakeven.agents.incident import Incident
        from breakeven.agents.investigator import investigate

        incident = Incident(
            id=f"console-investigate-{channel}",
            detected_at=datetime.now(timezone.utc),
            channel=channel,
            region="us-east",
            revenue_at_risk_per_min=0.0,
            projected_loss_if_unaddressed=0.0,
            failure_signature="operator-requested investigation",
        )
        try:
            result = investigate(incident)
        except RuntimeError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error
        return {
            "incident_id": result.incident_id,
            "root_cause": result.root_cause,
            "confidence": result.confidence,
            "recommended_action": result.recommended_action,
            "gate_action": result.gate_action,
            "accepted": result.accepted,
            "tool_calls": [
                {
                    "tool": call.tool,
                    "args": call.args,
                    "query": call.query,
                    "result": call.result_summary,
                }
                for call in result.tool_calls
            ],
        }

    @app.post("/controls/inject")
    def inject_fault(request: FaultRequest | None = None) -> dict[str, object]:
        """Inject the real demo fault only — `D-S106` Part A, no cycle spawned here.

        `GAPS.md` #8: an absent body (or an absent/`null` `fault_type`) keeps the original
        default fault, so every existing caller that never sent a body is unaffected.
        """
        fault_type = request.fault_type if request is not None else None
        return run_control(lambda: require_controls().inject_fault(fault_type))

    @app.post("/controls/check")
    def check_now() -> dict[str, object]:
        """Run one isolated agent cycle against the already-injected fault."""
        return run_control(require_controls().check_now)

    @app.post("/controls/clear-fault")
    def clear_fault() -> dict[str, object]:
        """Explicitly remove the active fault."""
        return run_control(require_controls().clear_fault)

    @app.post("/controls/revert")
    def revert_now(request: ActionRequest) -> dict[str, object]:
        """Revert one executed action through the reviewed executor API."""
        return run_control(lambda: require_controls().revert_now(request.action_id))

    @app.post("/controls/approve")
    def approve(request: ActionRequest) -> dict[str, object]:
        """Approve the currently pending, policy-gated action."""
        return run_control(lambda: require_controls().approve(request.action_id))

    @app.post("/controls/reject")
    def reject(request: ActionRequest) -> dict[str, object]:
        """Reject the currently pending action without touching the platform."""
        return run_control(lambda: require_controls().reject(request.action_id))

    @app.get("/controls/decide", response_class=Response)
    def decide_page(
        action_id: str,
        proposed_action: str = "",
        projected_saving: str = "",
        blast_radius: str = "",
    ) -> Response:
        """The page a human lands on from the approval email's link.

        Deliberately a `GET` that only *renders* — never one that acts. Email clients and
        corporate link-scanners (Gmail, Outlook Safe Links) fetch every link in an email
        automatically to prescan it; a `GET` that approved or rejected on load would fire
        for real before any human read a word of it. The actual decision still requires a
        genuine click on one of this page's two buttons, each a real `POST` to the same
        routes the console's own Approve/Reject buttons use.
        """
        escaped = {
            "action_id": html_escape(action_id),
            "proposed_action": html_escape(proposed_action),
            "projected_saving": html_escape(projected_saving),
            "blast_radius": html_escape(blast_radius),
        }
        body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>BreakEven — decision needed</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background: #0a0f16; color: #e8eef5;
         max-width: 560px; margin: 60px auto; padding: 0 20px; }}
  h1 {{ font-size: 20px; }}
  dl {{ background: #141c27; border: 1px solid #2a3644; border-radius: 8px; padding: 16px 20px; }}
  dt {{ color: #90a8c2; font-size: 12px; text-transform: uppercase; margin-top: 12px; }}
  dt:first-child {{ margin-top: 0; }}
  dd {{ margin: 4px 0 0; font-size: 15px; }}
  button {{ font-size: 15px; padding: 12px 22px; border-radius: 6px; border: 0; cursor: pointer; margin-top: 20px; margin-right: 10px; }}
  #approve {{ background: #35e0c8; color: #06251f; }}
  #reject {{ background: #3a2430; color: #f3c9d6; }}
  #result {{ margin-top: 18px; font-size: 14px; }}
</style></head>
<body>
  <h1>BreakEven — a fix is waiting for your decision</h1>
  <dl>
    <dt>Proposed action</dt><dd>{escaped["proposed_action"]}</dd>
    <dt>Projected saving</dt><dd>{escaped["projected_saving"]}</dd>
    <dt>Blast radius</dt><dd>{escaped["blast_radius"]}</dd>
  </dl>
  <button id="approve">Approve</button>
  <button id="reject">Reject</button>
  <div id="result"></div>
  <script>
    var actionId = {json.dumps(action_id)};
    function decide(path, label) {{
      document.getElementById("approve").disabled = true;
      document.getElementById("reject").disabled = true;
      fetch(path, {{
        method: "POST",
        headers: {{"Content-Type": "application/json"}},
        body: JSON.stringify({{action_id: actionId}})
      }}).then(function (response) {{
        return response.json().then(function (data) {{
          document.getElementById("result").textContent = response.ok
            ? label + " sent. You can close this tab."
            : "Could not " + label.toLowerCase() + ": " + (data.detail || response.status);
        }});
      }}).catch(function (error) {{
        document.getElementById("result").textContent = "Could not reach the console: " + error;
      }});
    }}
    document.getElementById("approve").onclick = function () {{ decide("/controls/approve", "Approval"); }};
    document.getElementById("reject").onclick = function () {{ decide("/controls/reject", "Rejection"); }};
  </script>
</body></html>"""
        return Response(content=body, media_type="text/html")

    @app.post("/controls/kill")
    def kill_agent() -> dict[str, object]:
        """Kill only the child agent process; the web server remains alive."""
        return run_control(require_controls().kill_agent)

    @app.websocket("/ws/events")
    async def events(socket: WebSocket) -> None:
        """Replay the backlog, then push every new agent event as it happens."""
        await socket.accept()
        subscription = bus.subscribe()
        try:
            replayed_through = await _send_snapshot(socket, bus)
            await _stream(socket, subscription, replayed_through)
        except WebSocketDisconnect as closed:
            _LOGGER.debug("operator UI websocket disconnected: %r", closed)
        except RuntimeError as error:
            # A client can vanish between the liveness check and the send, and Starlette
            # reports that as a plain RuntimeError. Only that case is tolerated — a
            # RuntimeError on a still-connected socket is a real bug and is re-raised.
            if socket.client_state is WebSocketState.CONNECTED:
                raise
            _LOGGER.debug("operator UI websocket closed mid-send: %r", error)
        finally:
            bus.unsubscribe(subscription)

    return app


def publish_player_session(bus: EventBus, simulator_url: str) -> bool:
    """Push the simulator's hero player session to the console — `F-RPL-02` via `F-UI-01`.

    The URL is assembled here because this process is the only one that knows the
    browser-reachable simulator base; the simulator supplies the session id and its own
    origin's playlist URL, which it alone knows. Returns whether the event was published,
    so a caller that needs the panel present can tell rather than assume.
    """
    try:
        with urllib.request.urlopen(
            f"{simulator_url}/player-session", timeout=_PLAYER_SESSION_TIMEOUT_SECONDS
        ) as response:
            payload = json.loads(response.read())
        bus.publish(
            "player",
            {
                "player_url": (
                    f"{simulator_url}/player_harness.html"
                    f"?session={quote(payload['session'], safe='')}"
                    f"&origin={quote(payload['origin_playlist_url'], safe='')}"
                ),
                "channel_id": payload["channel_id"],
            },
        )
        return True
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, TypeError) as error:
        _LOGGER.warning("could not read the simulator's live player session: %s", error)
        return False


def _stream_player_session(
    bus: EventBus, simulator_url: str, stopped: threading.Event
) -> None:
    """Keep a `player` event inside the replay window for the whole life of the server —
    see `_PLAYER_SESSION_REPUBLISH_SECONDS`'s docstring for why a one-shot publish was a
    real, live bug, not just theoretical."""
    while not stopped.is_set():
        publish_player_session(bus, simulator_url)
        stopped.wait(_PLAYER_SESSION_REPUBLISH_SECONDS)


def _stream_revenue(
    bus: EventBus, simulator_url: str, stopped: threading.Event
) -> None:
    """Read the simulator's cumulative revenue and push each live value to the UI."""
    last_revenue: float | None = None
    while not stopped.is_set():
        try:
            with urllib.request.urlopen(
                f"{simulator_url}/revenue", timeout=5
            ) as response:
                payload = json.loads(response.read())
            revenue = float(payload["tonight_revenue_usd"])
            if revenue != last_revenue:
                bus.publish("revenue", {"tonight_revenue_usd": revenue})
                last_revenue = revenue
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as error:
            _LOGGER.warning("could not read live simulator revenue: %s", error)
        stopped.wait(_REVENUE_POLL_SECONDS)


def serve(
    bus: EventBus,
    controls: ControlPlane | None = None,
    *,
    host: str = "127.0.0.1",
    port: int = 8081,
) -> None:
    """Run the operator UI over ``bus``, on loopback unless told otherwise.

    ``bus`` is required rather than defaulted: the page is only worth serving over the
    same bus the agent process publishes to, and a convenience default would quietly
    serve an empty stream that looks like a working UI with nothing happening.

    `D-S121`: any real cycle spawned from ``controls`` ends up calling Watchtower's
    Gemini judge, which resolves its backend from the environment, not from code
    (`orchestrator.py`'s own `require_vertex_environment` docstring). `orchestrator.main()`
    already checks this before calling `serve()`, but nothing enforced it for a caller that
    imports and calls `serve()` directly — exactly what this session's own live-verification
    scripts did, and exactly how "ADK emitted no usage_metadata" turned out to reproduce:
    not a code bug, but this check simply never running for that launch path. Checking here
    means every real launch path gets it, not just the one CLI entrypoint.
    """
    if controls is not None:
        # Deferred import: `orchestrator.py` imports `serve` from this module, so importing
        # `orchestrator` back at module scope here would be circular.
        from breakeven.agents.orchestrator import (  # pylint: disable=import-outside-toplevel
            require_vertex_environment,
        )

        require_vertex_environment()
    # Imported here so that importing this module — which the test suite does — does not
    # pull in an ASGI server it never runs.
    import uvicorn  # pylint: disable=import-outside-toplevel

    uvicorn.run(create_app(bus, controls), host=host, port=port)


async def _send_snapshot(socket: WebSocket, bus: EventBus) -> int:
    """Send the replay buffer as one snapshot; return the highest sequence number in it.

    Every event in it is flagged `replay` and keeps the timestamp it was published with,
    so a reconnecting page cannot present the backlog as live.
    """
    history = bus.history()
    await socket.send_json(
        {
            "type": "snapshot",
            "events": [event.as_message(replay=True) for event in history],
        }
    )
    return history[-1].seq if history else 0


async def _stream(
    socket: WebSocket, subscription: Subscription, replayed_through: int
) -> None:
    """Push events until the client goes away.

    Anything at or below ``replayed_through`` was already sent in the snapshot — it can be
    queued too, because the subscription is registered before the snapshot is read, which
    is what guarantees no event falls between the two.
    """
    disconnected = asyncio.create_task(_await_disconnect(socket))
    try:
        while not disconnected.done():
            event = await asyncio.to_thread(subscription.next_event, _WAKEUP_SECONDS)
            if disconnected.done():
                break
            if event is not None and event.seq <= replayed_through:
                event = None
            for message in messages_for(subscription, event):
                await socket.send_json(message)
    finally:
        # A receiver that ended by raising something `_await_disconnect` does not handle
        # would otherwise have its exception discarded unread — asyncio reports that only
        # as a stray "Task exception was never retrieved" with no context about this
        # socket. Retrieving and logging it keeps the cause attached to the handler.
        if disconnected.done():
            failure = disconnected.exception()
            if failure is not None:
                _LOGGER.warning("operator UI websocket receiver failed: %r", failure)
        else:
            disconnected.cancel()


async def _await_disconnect(socket: WebSocket) -> None:
    """Return once the client has gone.

    The protocol is server-to-client only, so anything the client sends is ignored.
    Awaiting `receive` is the only way a handler that otherwise only sends ever learns the
    socket closed — without it, a closed tab would leave a subscription on the bus for the
    life of the process.
    """
    try:
        while True:
            message = await socket.receive()
            if message["type"] == "websocket.disconnect":
                return
    except (WebSocketDisconnect, RuntimeError) as closed:
        # Returning rather than propagating: this task's whole purpose is to complete when
        # the socket ends, and every way it can end arrives here. Logged, not swallowed.
        _LOGGER.debug("operator UI websocket receive ended: %r", closed)
