"""Standard-library HTTP endpoint for the simulator world."""

from __future__ import annotations

import http.client
import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from breakeven.sim.control import ControlRegistry
from breakeven.sim.faults import CDN_PATHWAYS, FaultRegistry
from breakeven.sim.logs import LogEntry, LokiWriter
from breakeven.sim.origins import make_origin_pair
from breakeven.sim.metrics import (
    BASELINE_DECISION_LATENCY_SECONDS,
    CONFIRM_FAILED_BREAKS,
    FAULT_DECISION_LATENCY_SECONDS,
    MetricState,
    RemoteWriter,
)
from breakeven.sim.traces import TraceWriter
from breakeven.sim.schedule import generate_break_schedule, run_schedule_live
from breakeven.sim.steering import SteeringRegistry, SteeringSessionError
from breakeven.sim.world import (
    CHANNELS,
    CREATIVE_IDS,
    DEFAULT_SEED,
    concurrency_at,
    emit_labels,
    world_payload,
)

_LOGGER = logging.getLogger(__name__)
_STATIC_DIR = Path(__file__).with_name("static")
_STATIC_TYPES = {
    "/player_harness.html": "text/html; charset=utf-8",
    "/hls.min.js": "text/javascript; charset=utf-8",
    "/dash.all.min.js": "text/javascript; charset=utf-8",
}
# ponytail: shorten only the /tick retry pause; raise it if Mimir recovery needs patience.
TICK_RETRY_SECONDS = 2

# The one session the operator console renders as real video (`F-RPL-02` via `F-UI-01`,
# `docs/DECISIONS.md` `D-S105` Part B). `CHANNELS[0]` is not an arbitrary pick: it is the
# exact channel `ui/controls.py`'s Inject-fault control faults, so the panel a judge is
# watching is the panel the button they press actually affects. `cdn-a` is the hero origin
# because it is the head of the default pathway priority the steering registry hands out.
PLAYER_HERO_CHANNEL = CHANNELS[0].channel_id
PLAYER_HERO_SESSION = f"{PLAYER_HERO_CHANNEL}:console-hero"
# `D-S107`: the exact creative `ui/controls.py`'s Inject-fault control targets — matching
# `PLAYER_HERO_CHANNEL`'s own reasoning above, this is the creative the visible panel's
# swap predicate watches for, not an arbitrary pick.
PLAYER_HERO_FAULT_CREATIVE = CREATIVE_IDS[1]


class _WorldHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        """Serve the world payload and reject every other route."""
        path = urlparse(self.path).path
        if path in _STATIC_TYPES:
            self._static_response(path)
            return
        if path == "/v1/steer":
            try:
                session = self._session_query()
                host, port = self.server.server_address[:2]
                manifest = self.server.steering.manifest_for(session, host, port)
            except SteeringSessionError as error:
                self._json_response(400, {"error": str(error)})
                return
            self._json_response(200, manifest.to_json())
            return
        if self.path == "/control/blocklist":
            self._json_response(
                200,
                [
                    {"channel_id": channel_id, "creative_id": creative_id}
                    for channel_id, creative_id in self.server.control.active_pairs()
                ],
            )
            return
        if self.path == "/control/pathway":
            # `D-S115`: every channel's real current pathway, in stable order — the read
            # side of the state `set_active_pathway` mutates, mirroring `/control/blocklist`.
            self._json_response(
                200,
                [
                    {
                        "channel_id": channel.channel_id,
                        "active_pathway": self.server.control.active_pathway(
                            channel.channel_id
                        ),
                    }
                    for channel in CHANNELS
                ],
            )
            return
        if path == "/revenue":
            self._json_response(
                200,
                {"tonight_revenue_usd": self.server.metric_state.revenue_usd},
            )
            return
        if path == "/player-session":
            # Its own route rather than a field on `/world`: `tests/test_sim_world.py`
            # asserts the `/world` response equals `world_payload()` exactly, and that
            # payload is process-independent by design while these ports are not.
            session = getattr(self.server, "player_session", None)
            if session is None:
                self._json_response(
                    503, {"error": "no media origins are attached to this server"}
                )
                return
            public_scheme = self.headers.get("X-Forwarded-Proto", "http").split(",", 1)[0]
            public_host = self.headers.get(
                "Host", f"{self.server.server_address[0]}:{self.server.server_address[1]}"
            )
            session = dict(session)
            session["origin_playlist_url"] = (
                f"{public_scheme}://{public_host}/player/playlist.m3u8?live=1"
            )
            self._json_response(200, session)
            return
        if path.startswith("/player/"):
            self._player_proxy(path, urlparse(self.path).query)
            return
        if self.path != "/world":
            self.send_error(404)
            return

        body = json.dumps(world_payload()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        """Create a simulator fault, or run one tick of live emission."""
        path = urlparse(self.path).path
        if path == "/v1/player-qoe":
            try:
                payload = self._json_body()
                session = payload["session"]
                if not isinstance(session, str):
                    raise ValueError("session must be a string")
                channel_id, separator, player_session_id = session.partition(":")
                if (
                    not separator
                    or not player_session_id
                    or channel_id not in {channel.channel_id for channel in CHANNELS}
                ):
                    raise ValueError("session must identify a configured channel cohort")
                samples = self.server.metric_state.record_player_qoe(
                    channel_id=channel_id,
                    cdn_pathway=self.server.control.active_pathway(channel_id),
                    player=payload["player"],
                    startup_time_seconds=payload["startup_time_seconds"],
                    rebuffer_ratio=payload["rebuffer_ratio"],
                    bitrate_switches=payload["bitrate_switches"],
                )
                with self.server.tick_lock:
                    self.server.writer.write(samples)
            except (
                KeyError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ) as error:
                self._json_response(400, {"error": str(error) or "invalid QoE observation"})
                return
            except (OSError, RuntimeError) as error:
                _LOGGER.exception("player QoE metric write failed")
                self._json_response(502, {"error": f"metric write failed: {error}"})
                return
            self._json_response(201, {"emitted": True})
            return
        if path == "/v1/segment-ack":
            try:
                self.server.steering.record_segment_ack(self._session_query())
            except SteeringSessionError as error:
                self._json_response(400, {"error": str(error)})
                return
            self._json_response(201, {})
            return
        if self.path == "/tick":
            cycle = _emit_current_state(self.server)
            self._json_response(200, {"cycle": cycle})
            return
        if self.path == "/control/blocklist":
            try:
                payload = self._json_body()
                self.server.control.block(
                    channel_id=payload["channel_id"], creative_id=payload["creative_id"]
                )
                _schedule_state_emission(self.server)
            except (
                KeyError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ) as error:
                self._json_response(
                    400, {"error": str(error) or "invalid control request"}
                )
                return
            self._json_response(201, {})
            return
        if self.path == "/control/pathway":
            # `D-S115`: the one real mutation `steer_pathway`'s remedy makes once a
            # migration completes — before this route existed, that remedy's only
            # effect was a local file on the orchestrator's own machine, invisible to
            # this simulator (a separate deployment) and causally connected to nothing.
            try:
                payload = self._json_body()
                self.server.control.set_active_pathway(
                    channel_id=payload["channel_id"],
                    cdn_pathway=payload["active_pathway"],
                )
                _schedule_state_emission(self.server)
            except (
                KeyError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ) as error:
                self._json_response(
                    400, {"error": str(error) or "invalid control request"}
                )
                return
            self._json_response(201, {})
            return
        if self.path != "/faults":
            self.send_error(404)
            return
        try:
            payload = self._json_body()
            if payload.get("fault_type") == "beacon_blackhole":
                fault_id = self.server.faults.create_delivery_loss(
                    channel_id=payload["channel_id"],
                    failure_rate=payload["failure_rate"],
                )
            elif payload.get("fault_type") == "origin_degradation":
                fault_id = self.server.faults.create_origin_degradation(
                    channel_id=payload["channel_id"],
                    cdn_pathway=payload["cdn_pathway"],
                    failure_rate=payload["failure_rate"],
                )
            elif payload.get("fault_type") == "stitch_corruption":
                # `GAPS.md` #8: `create_stitch_corruption` was real fault-registry code
                # with no route to it at all — added the same way the other two named
                # shapes already are, not guessed at.
                fault_id = self.server.faults.create_stitch_corruption(
                    channel_id=payload["channel_id"],
                    failure_rate=payload["failure_rate"],
                )
            else:
                fault_id = self.server.faults.create(
                    creative_id=payload["creative_id"],
                    channel_id=payload["channel_id"],
                    failure_rate=payload["failure_rate"],
                )
        except (
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as error:
            self._json_response(400, {"error": str(error) or "invalid fault request"})
            return
        # A judge's Inject click is itself a state transition. Emit it immediately so
        # the live dashboard and player see the fault on this request, not on the next
        # Cloud Scheduler tick.
        #
        # `D-S110`: play out `CONFIRM_FAILED_BREAKS` breaks, not one. A detector that
        # refuses to act on a single failed break (so a lone blip can never trigger a
        # remedy) otherwise cannot confirm this fault until Cloud Scheduler's *next*
        # tick, up to 60s later. These are real breaks against the real fault producing
        # real errors — the simulated world is advanced promptly, the signal is not
        # fabricated.
        _schedule_state_emission(self.server, cycles=CONFIRM_FAILED_BREAKS)
        self._json_response(201, {"fault_id": fault_id})

    def do_DELETE(self) -> None:
        """Delete an active fault by ID."""
        control_prefix = "/control/blocklist/"
        if self.path.startswith(control_prefix):
            parts = self.path.removeprefix(control_prefix).split("/")
            if len(parts) != 2 or not all(parts):
                self.send_error(404)
                return
            try:
                removed = self.server.control.unblock(parts[0], parts[1])
            except ValueError as error:
                self._json_response(400, {"error": str(error)})
                return
            if not removed:
                self._json_response(404, {"error": "creative is not blocked"})
                return
            _schedule_state_emission(self.server)
            self.send_response(204)
            self.end_headers()
            return
        prefix = "/faults/"
        if not self.path.startswith(prefix) or len(self.path) == len(prefix):
            self.send_error(404)
            return
        if not self.server.faults.delete(self.path.removeprefix(prefix)):
            self._json_response(404, {"error": "unknown fault_id"})
            return
        _schedule_state_emission(self.server)
        self.send_response(204)
        self.end_headers()

    def _json_body(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            raise ValueError("request body is required")
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("request body must be an object")
        return payload

    def _session_query(self) -> str:
        sessions = parse_qs(urlparse(self.path).query).get("session", [])
        if len(sessions) != 1:
            raise SteeringSessionError("session query parameter is required")
        return sessions[0]

    def _json_response(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static_response(self, path: str) -> None:
        try:
            body = _STATIC_DIR.joinpath(path.lstrip("/")).read_bytes()
        except FileNotFoundError:
            self._json_response(404, {"error": "static asset not found"})
            return
        except OSError:
            self._json_response(500, {"error": "static asset unavailable"})
            return
        self.send_response(200)
        self.send_header("Content-Type", _STATIC_TYPES[path])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _player_proxy(self, path: str, query: str) -> None:
        """Expose the attached real origin through the browser-reachable API host."""
        origin = getattr(self.server, "player_origin", None)
        if origin is None:
            self._json_response(503, {"error": "no media origins are attached to this server"})
            return
        origin_path = path.removeprefix("/player") or "/"
        if query:
            origin_path += "?" + query
        connection = http.client.HTTPConnection("127.0.0.1", origin.server_port, timeout=5)
        try:
            connection.request("GET", origin_path)
            response = connection.getresponse()
            body = response.read()
            if urlparse(origin_path).path == "/playlist.m3u8":
                body = body.replace(b"\n/seg-", b"\n/player/seg-")
            self.send_response(response.status)
            content_type = response.getheader("Content-Type")
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except (OSError, http.client.HTTPException) as error:
            self._json_response(502, {"error": f"player origin unavailable: {error}"})
        finally:
            connection.close()


def _emit_current_state(server: ThreadingHTTPServer) -> int:
    """Write one real metric sample immediately after a live state transition.

    Cloud Scheduler continues to provide the idle cadence. Controls cannot wait for its
    next minute, though: a blocklist, unblock, or fault removal changes delivery now, so
    Grafana must receive the matching counter/gauge sample in that same request.
    """
    with server.tick_lock:
        cycle = server.tick_cycle
        server.tick_cycle += len(CHANNELS)
        try:
            run_emit_cycle(
                server.metric_state,
                server.writer,
                server.faults,
                server.control,
                cycle,
                server.log_writer,
            )
        except RuntimeError as error:
            # Local browser/player proofs deliberately use the production RemoteWriter
            # without K_SERVICE. Preserve the state transition and make the limitation
            # explicit; deployed Cloud Run requests never enter this branch.
            if (
                "refusing to write live metrics to the shared production Grafana project"
                not in str(error)
            ):
                raise
            _LOGGER.warning("state changed, but local live-metric emission is disabled: %s", error)
    return cycle


def _schedule_state_emission(server: ThreadingHTTPServer, *, cycles: int = 1) -> None:
    """Start transition telemetry without making the operator wait on remote writers."""
    threading.Thread(
        target=_emit_state_in_background,
        args=(server, cycles),
        daemon=True,
        name="breakeven-transition-emission",
    ).start()


def _emit_state_in_background(server: ThreadingHTTPServer, cycles: int = 1) -> None:
    for _ in range(cycles):
        try:
            _emit_current_state(server)
        except Exception:  # pragma: no cover - the concrete writer logs its own details
            _LOGGER.exception("transition metric emission failed")
            return

def make_server(
    host: str,
    port: int,
    *,
    faults: FaultRegistry | None = None,
    control: ControlRegistry | None = None,
    metric_state: MetricState | None = None,
    writer: RemoteWriter | None = None,
    log_writer: LokiWriter | None = None,
    steering: SteeringRegistry | None = None,
) -> ThreadingHTTPServer:
    """Create the live simulator HTTP server without starting its loop."""
    server = ThreadingHTTPServer((host, port), _WorldHandler)
    server.faults = faults or FaultRegistry(seed=DEFAULT_SEED)
    server.control = control or ControlRegistry()
    server.metric_state = metric_state or MetricState()
    server.writer = writer or RemoteWriter(retry_seconds=TICK_RETRY_SECONDS)
    server.log_writer = log_writer or LokiWriter()
    server.steering = steering or SteeringRegistry()
    server.tick_lock = threading.Lock()
    server.tick_cycle = 0
    return server


def attach_player_origins(
    server: ThreadingHTTPServer,
) -> tuple[ThreadingHTTPServer, ThreadingHTTPServer]:
    """Start ``server``'s media origin pair and publish its hero player session.

    Until this ran, `make_origin_pair` was only ever called from a test process, so there
    was no browser-reachable playlist outside pytest and nothing in the running console
    could render a real player. The origins run as daemon threads for the lifetime of the
    calling process — the same lifecycle the existing headless proofs give them — and the
    pair is returned so a caller that outlives its own server can shut them down.

    Segment delivery on both origins is gated on the *same* real state the metrics path
    reads: a fault on the hero channel whose creative is still in rotation. So the stall a
    viewer sees and the errors Grafana sees have one cause, and blocklisting the creative —
    the agent's actual remedy — is what ends both.

    Which of the two real fixture clips plays is gated on that same real blocklist read too
    (`D-S107`): once the fault creative is no longer eligible, the panel doesn't just resume
    — it visibly switches clips, because the real remedy really did swap what's serving.

    `D-S115`: content-phase segments are gated the same way, but on the channel's real
    *active pathway* rather than a creative — an origin-degradation fault on the pathway
    the channel is actually being served from stalls the program itself, and the stall
    genuinely stops the instant `POST /control/pathway` really migrates the channel onto
    the healthy one, because that call is what `content_degraded()` reads.
    """
    origin_a, origin_b = make_origin_pair()

    def degraded() -> bool:
        return bool(
            server.faults.errors_for(
                PLAYER_HERO_CHANNEL,
                1,
                server.control.eligible_creatives(PLAYER_HERO_CHANNEL),
            )
        )

    def showing_safe() -> bool:
        return PLAYER_HERO_FAULT_CREATIVE not in server.control.eligible_creatives(
            PLAYER_HERO_CHANNEL
        )

    def content_degraded() -> bool:
        active_pathway = server.control.active_pathway(PLAYER_HERO_CHANNEL)
        return server.faults.origin_errors_for(PLAYER_HERO_CHANNEL, active_pathway, 1) > 0

    for origin in (origin_a, origin_b):
        origin.degraded = degraded
        origin.showing_safe = showing_safe
        origin.content_degraded = content_degraded
        threading.Thread(
            target=origin.serve_forever,
            daemon=True,
            name=f"breakeven-origin-{origin.origin_name}",
        ).start()
    server.player_origin = origin_a
    server.player_session = {
        "session": PLAYER_HERO_SESSION,
        "channel_id": PLAYER_HERO_CHANNEL,
        "origin_playlist_url": "/player/playlist.m3u8?live=1",
    }
    return origin_a, origin_b


def run_emit_cycle(
    state: MetricState,
    writer: RemoteWriter,
    faults: FaultRegistry,
    control: ControlRegistry,
    cycle: int,
    log_writer: LokiWriter | None = None,
    trace_writer: TraceWriter | None = None,
) -> None:
    """Emit one live break per channel for the given cycle offset."""
    active_log_writer = log_writer or LokiWriter()
    active_trace_writer = trace_writer or TraceWriter()
    for index, channel in enumerate(CHANNELS):
        scheduled = generate_break_schedule(
            channel,
            seed=DEFAULT_SEED + cycle + index,
            window_seconds=601,
        )[0]
        channel_region, channel_device = emit_labels(index)

        def emit(
            event: tuple[float, int],
            *,
            selected_channel=channel,
            region=channel_region,
            device=channel_device,
        ) -> None:
            eligible_creatives = control.eligible_creatives(selected_channel.channel_id)
            utc_hour = time.gmtime().tm_hour
            errors = faults.errors_for(
                selected_channel.channel_id,
                event[1],
                eligible_creatives,
                region=region,
                hour=utc_hour,
            )
            delivery_losses_for = getattr(faults, "delivery_losses_for", None)
            beacon_failures = (
                0
                if delivery_losses_for is None
                else delivery_losses_for(
                    selected_channel.channel_id,
                    event[1],
                    region=region,
                    hour=utc_hour,
                )
            )
            stitch_failures_for = getattr(faults, "stitch_failures_for", None)
            manifest_errors, viewers_exited = (
                (0, 0)
                if stitch_failures_for is None
                else stitch_failures_for(
                    selected_channel.channel_id, event[1], region=region, hour=utc_hour
                )
            )
            decision_latency_seconds = (
                FAULT_DECISION_LATENCY_SECONDS
                if errors
                else BASELINE_DECISION_LATENCY_SECONDS
            )
            samples = state.record_break(
                selected_channel,
                event,
                region=region,
                device=device,
                errors=errors,
                beacon_failures=beacon_failures,
                manifest_errors=manifest_errors,
                viewers_exited=viewers_exited,
                decision_latency_seconds=decision_latency_seconds,
                hour=utc_hour,
            )
            # `D-S111`: origin health is per (channel, cdn_pathway), not per ad break —
            # folded into this same write rather than a separate one, so every existing
            # caller's "one `writer.write()` per channel per cycle" assumption
            # (e.g. `test_decision_latency_agrees_between_the_metric_and_the_trace_span`,
            # which zips metric batches 1:1 against per-channel trace calls) stays true.
            # `origin_errors_for` degrades to `getattr`'s `None` default the same way the
            # beacon/stitch faults above do, so a `FaultRegistry` built before this fault
            # type existed still emits (a healthy 0.0 rate), never raises.
            origin_errors_for = getattr(faults, "origin_errors_for", None)
            if origin_errors_for is not None:
                viewer_count = concurrency_at(selected_channel, region, utc_hour)
                for cdn_pathway in CDN_PATHWAYS:
                    failed_fetches = origin_errors_for(
                        selected_channel.channel_id, cdn_pathway, viewer_count
                    )
                    samples += state.record_origin_health(
                        selected_channel,
                        cdn_pathway,
                        region=region,
                        device=device,
                        failed_fetches=failed_fetches,
                        requested_fetches=viewer_count,
                    )
            try:
                writer.write(samples)
            except OSError:
                _LOGGER.exception(
                    "metrics write failed for %s; continuing",
                    selected_channel.channel_id,
                )
            trace_id = (uuid4().hex + uuid4().hex[:16])[:32]
            if errors:
                timestamp_ns = time.time_ns()
                try:
                    active_log_writer.write(
                        LogEntry(
                            timestamp_ns=timestamp_ns,
                            level="error",
                            service="transcoder",
                            channel_id=selected_channel.channel_id,
                            region=region,
                            vast_error_code=vast_error_code,
                            creative_id=creative_id,
                            advertiser_id="",
                            ladder_rung="",
                            message="creative conditioning failed for ladder rung",
                            trace_id=trace_id,
                        )
                        for vast_error_code, creative_id, _impression_count in errors
                    )
                except OSError:
                    _LOGGER.exception(
                        "logs write failed for %s; continuing",
                        selected_channel.channel_id,
                    )
            try:
                active_trace_writer.write(
                    trace_id=trace_id,
                    channel_id=selected_channel.channel_id,
                    region=region,
                    slot_count=event[1],
                    errors=errors,
                    decision_latency_seconds=decision_latency_seconds,
                )
            except OSError:
                _LOGGER.exception(
                    "traces write failed for %s; continuing",
                    selected_channel.channel_id,
                )

        try:
            run_schedule_live(((0.0, scheduled[1]),), emit)
        # ponytail: catch-and-continue, not crash-to-restart — restarting the
        # container would wipe the in-memory FaultRegistry/ControlRegistry that
        # tasks 12 and 16 act on. A Mimir outage must cost one cycle, not
        # all emission (INV-S05). Detecting "healthy but silent" is the
        # dashboard's no-data alert, not this loop's job.
        except OSError:
            _LOGGER.exception(
                "live emission failed for %s; continuing", channel.channel_id
            )


def run_live_emitter(
    state: MetricState,
    writer: RemoteWriter,
    faults: FaultRegistry,
    control: ControlRegistry,
    log_writer: LokiWriter | None = None,
    trace_writer: TraceWriter | None = None,
    *,
    interval_seconds: float = 30.0,
    stop: threading.Event | None = None,
) -> None:
    """Emit an immediate live break per channel, then repeat every interval.

    Used by local/dev runs and by the test suite's own threads. The deployed
    container no longer calls this — see `serve_live`'s docstring.
    """
    stopped = stop or threading.Event()
    active_log_writer = log_writer or LokiWriter()
    cycle = 0
    while not stopped.is_set():
        run_emit_cycle(
            state,
            writer,
            faults,
            control,
            cycle,
            active_log_writer,
            trace_writer,
        )
        cycle += len(CHANNELS)
        stopped.wait(interval_seconds)


def serve_live(host: str = "0.0.0.0", port: int = 8080) -> None:
    """Serve the fault API; live metrics are emitted per external POST /tick.

    # ponytail: request-driven, not a background thread — a Cloud Scheduler
    # job hits /tick on a cadence instead of this process looping forever, so
    # Cloud Run bills request-based (CPU only during the tick) instead of
    # instance-based (CPU allocated the whole time). Local/dev use and the
    # test suite still drive `run_live_emitter` directly on a real timer.
    """
    server = make_server(host, port)
    # Attached here rather than in `make_server`: every test that builds a server would
    # otherwise bind two extra sockets it never closes, and the two existing headless
    # proofs already start their own pair.
    attach_player_origins(server)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    serve_live(port=int(os.environ.get("PORT", "8080")))
