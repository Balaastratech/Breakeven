"""Operator controls over the existing simulator, agent, and action backends."""

from __future__ import annotations

import json
import logging
import multiprocessing
import re
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from breakeven.actions.executor import revert_action
from breakeven.agents.escalation_email import console_url, send_best_effort
from breakeven.sim.world import CHANNELS, CREATIVE_IDS
from breakeven.ui.events import EventBus

_SAFE_ACTION_ID = re.compile(r"[A-Za-z0-9_-]+")
_FAULT_CHANNEL = CHANNELS[0]
_FAULT_CREATIVE = CREATIVE_IDS[1]
_FAULT_RATE = 0.95
# `GAPS.md` #8: `cdn-a` is the world's own default active pathway (`sim/control.py`), the
# same one `D-S111`/`D-S115`'s live-verified A1 demo degrades and migrates away from.
_FAULT_PATHWAY = "cdn-a"
# The three named shapes `sim/api.py`'s `/faults` route actually dispatches on, beyond its
# own default (`fault_type` absent or unrecognised → `create()`, the original creative
# fault this console has always injected).
_NAMED_FAULT_TYPES = frozenset(
    {"beacon_blackhole", "origin_degradation", "stitch_corruption"}
)
_APPROVAL_TIMEOUT_SECONDS = 2.0
_LOGGER = logging.getLogger(__name__)


# At the 5s poll interval (`start_agent_loop`), 60 idle cycles is 5 minutes — generous
# headroom over real Grafana Cloud propagation latency (`D-S99`/`D-S110`; observed this
# session taking anywhere from under a minute to several minutes) without polling forever.
_DEFAULT_MAX_IDLE_CYCLES = 60


@dataclass(frozen=True)
class _AgentLoopProcess:
    """Pickleable configuration for the spawned continuous-cycle process.

    Yuvraj, 2026-09-09: this used to poll Grafana forever, `while True`, from the moment
    `/agent` was first loaded until someone explicitly killed it — real API calls, running
    24/7 on a `min-instances=1` deploy, whether or not anything was actually wrong. The real
    trigger should be an injected fault, not a page load, and the loop should stop calling
    Grafana once there is nothing left to find it. `cycle_target` now reports whether it
    found and fully finished a real incident (`orchestrator.cycle_process_main`'s return);
    the loop exits the instant that happens, and also exits after `max_idle_cycles`
    consecutive empty checks — generous enough to ride out real Grafana Cloud propagation
    latency (`D-S99`), not an excuse to poll forever.
    """

    cycle_target: Callable[..., object]
    interval_seconds: int
    max_idle_cycles: int = _DEFAULT_MAX_IDLE_CYCLES

    def __call__(
        self, event_queue, decision_queue, base_url: str, state_dir: Path, log_path: Path
    ) -> None:
        """Run killable agent cycles until something is found and finished, or nothing
        shows up for `max_idle_cycles` checks in a row — never forever."""
        interval_elapsed = threading.Event()
        idle_streak = 0
        while True:
            finished_real_incident = self.cycle_target(
                event_queue, decision_queue, base_url, state_dir, log_path
            )
            if finished_real_incident:
                event_queue.put(("loop_stopped", "resolved"))
                return
            idle_streak += 1
            if idle_streak >= self.max_idle_cycles:
                event_queue.put(("loop_stopped", "idle"))
                return
            interval_elapsed.wait(self.interval_seconds)


class ControlPlane:  # pylint: disable=too-many-instance-attributes
    """State-changing controls for one operator-console process."""

    def __init__(
        self,
        bus: EventBus,
        *,
        simulator_url: str,
        state_dir: Path,
        log_path: Path,
        process_target: Callable[..., None] | None = None,
    ) -> None:
        self.bus = bus
        self.simulator_url = simulator_url.rstrip("/")
        self.state_dir = state_dir
        self.log_path = log_path
        self._process_target = process_target
        self._context = multiprocessing.get_context("spawn")
        self._process: multiprocessing.Process | None = None
        self._is_loop = False
        self._event_queue = None
        self._decision_queue = None
        self._fault_id: str | None = None
        self._pending_approval: dict[str, object] | None = None
        self._current_action_id: str | None = None
        self._operator_killed = False
        self._operator_rejected = False
        self._generation: int = 0
        self._approval_action_id: str | None = None
        self._approval_event: threading.Event | None = None
        self._approval_result: tuple[str, str] | None = None
        self._lock = threading.Lock()

    @property
    def agent_alive(self) -> bool:
        """Whether the isolated cycle process is still running."""
        with self._lock:
            return self._process is not None and self._process.is_alive()

    @property
    def pending_approval(self) -> dict[str, object] | None:
        """A copy of the proposal currently waiting for one operator decision."""
        with self._lock:
            return (
                dict(self._pending_approval)
                if self._pending_approval is not None
                else None
            )

    @property
    def current_action_id(self) -> str | None:
        """The action whose executor has confirmed its watchdog is armed."""
        with self._lock:
            return self._current_action_id

    def inject_fault(self, fault_type: str | None = None) -> dict[str, object]:
        """Create the real simulator fault, and start the agent looking for it.

        `D-S106` Part A's original concern — an early cycle finding nothing auto-deleting
        the fault before real Grafana propagation caught up — was fixed by making
        `clear_fault()` the only deletion path, not by keeping injection and detection two
        separate manual clicks forever. Yuvraj, 2026-09-09: that manual second click (and
        the `while True` loop it used to start, which then polled Grafana forever whether
        or not anything was ever found — real API calls running 24/7 on a `min-instances=1`
        deploy) is gone. Injecting a fault is now the one real trigger; `_AgentLoopProcess`
        stops itself once it finds and finishes a real incident, or after a few empty
        checks in a row.

        `GAPS.md` #8: ``fault_type`` lets an operator pick which of the simulator's real
        fault shapes to inject (`None` keeps the original creative-error default) instead
        of the console always sending the one hardcoded shape regardless of what a judge
        selected.
        """
        if fault_type is not None and fault_type not in _NAMED_FAULT_TYPES:
            raise ValueError(f"unknown fault_type {fault_type!r}")
        with self._lock:
            process_alive = self._process is not None and self._process.is_alive()
            if self._fault_id is not None and process_alive:
                raise ValueError(f"fault {self._fault_id!r} is already active")
            fault_id = self._create_fault(fault_type)
            self._fault_id = fault_id
            self._operator_killed = False
            self._operator_rejected = False
            self._current_action_id = None

        self.bus.publish(
            "control",
            {
                "control": "inject",
                "status": "created",
                "fault_id": fault_id,
                "message": "Fault injected. Watching for it now.",
            },
        )
        if not process_alive:
            try:
                self.start_agent_loop()
            except ValueError:
                # A cycle is already alive by the time we got the lock back (a
                # `check_now` raced this call) — its own next poll will see the new
                # fault; nothing here needs to start a second one.
                pass
        return {
            "status": "created",
            "fault_id": fault_id,
            "message": "Fault injected. Watching for it now.",
        }

    def check_now(self) -> dict[str, object]:
        """Run one isolated agent cycle against the already-injected fault.

        `D-S106` Part A: split out of the old `inject_fault()` so a fault can accumulate
        real signal across as many `check_now` calls as it takes, instead of being deleted
        after the first cycle finds nothing.
        """
        with self._lock:
            process_alive = self._process is not None and self._process.is_alive()
            if process_alive:
                raise ValueError("an agent cycle is already running")
            if self._fault_id is None:
                raise ValueError("no fault is active; press Inject first")

            fault_id = self._fault_id
            event_queue = self._context.Queue()
            decision_queue = self._context.Queue()
            target = self._process_target
            if target is None:
                from breakeven.agents.orchestrator import (  # pylint: disable=import-outside-toplevel
                    cycle_process_main,
                )

                target = cycle_process_main
            process = self._context.Process(
                target=target,
                args=(
                    event_queue,
                    decision_queue,
                    self.simulator_url,
                    self.state_dir,
                    self.log_path,
                ),
            )
            try:
                process.start()
            except BaseException as start_error:
                # No fault rollback here (`D-S106` Part A): the fault's lifecycle is now
                # independent of any one cycle's — a failed start just means try `check_now`
                # again, the same way a `SKIPPED` result does.
                raise RuntimeError(
                    f"agent process failed to start: {start_error}"
                ) from start_error
            self._event_queue = event_queue
            self._decision_queue = decision_queue
            self._process = process
            self._generation += 1
            generation = self._generation

        threading.Thread(
            target=self._relay_events,
            args=(event_queue, generation),
            daemon=True,
            name=f"breakeven-cycle-events-{process.pid}",
        ).start()
        threading.Thread(
            target=self._watch_process,
            args=(process, event_queue, generation),
            daemon=True,
            name=f"breakeven-cycle-watch-{process.pid}",
        ).start()
        self.bus.publish(
            "control",
            {
                "control": "check",
                "status": "started",
                "fault_id": fault_id,
                "pid": process.pid,
                "message": "Checking whether the injected fault has affected anything yet.",
            },
        )
        return {
            "status": "started",
            "fault_id": fault_id,
            "pid": process.pid,
            "message": "Checking whether the injected fault has affected anything yet.",
        }

    def start_agent_loop(self) -> dict[str, object]:
        """Start continuous detection in the same killable process model as one check."""
        with self._lock:
            process_alive = self._process is not None and self._process.is_alive()
            if process_alive:
                raise ValueError("an agent cycle is already running")

            event_queue = self._context.Queue()
            decision_queue = self._context.Queue()
            cycle_target = self._process_target
            # Yuvraj, 2026-09-09: was `WINDOW_SECONDS // 20` (30s) — with `CONFIRM_FAILED_BREAKS`
            # now 1 (`sim/metrics.py`), a real fault confirms on its very first break, so the
            # only thing standing between "inject" and "detected" is how long the idle loop
            # waits before its next cycle. 5s keeps that gap small without spamming Grafana
            # faster than a real cycle (~30-40s of MCP round trips) can even return.
            _AGENT_LOOP_INTERVAL_SECONDS = 5.0
            if cycle_target is None:
                from breakeven.agents.orchestrator import (  # pylint: disable=import-outside-toplevel
                    cycle_process_main,
                )

                cycle_target = cycle_process_main
            process = self._context.Process(
                target=_AgentLoopProcess(
                    cycle_target=cycle_target,
                    interval_seconds=_AGENT_LOOP_INTERVAL_SECONDS,
                ),
                args=(
                    event_queue,
                    decision_queue,
                    self.simulator_url,
                    self.state_dir,
                    self.log_path,
                ),
            )
            try:
                process.start()
            except BaseException as start_error:
                raise RuntimeError(
                    f"agent loop process failed to start: {start_error}"
                ) from start_error
            self._event_queue = event_queue
            self._decision_queue = decision_queue
            self._process = process
            self._is_loop = True
            self._generation += 1
            generation = self._generation

        threading.Thread(
            target=self._relay_events,
            args=(event_queue, generation),
            daemon=True,
            name=f"breakeven-loop-events-{process.pid}",
        ).start()
        threading.Thread(
            target=self._watch_process,
            args=(process, event_queue, generation),
            daemon=True,
            name=f"breakeven-loop-watch-{process.pid}",
        ).start()
        self.bus.publish(
            "control",
            {
                "control": "loop",
                "status": "started",
                "pid": process.pid,
                "message": "The agent is checking for faults continuously.",
            },
        )
        return {
            "status": "started",
            "pid": process.pid,
            "message": "The agent is checking for faults continuously.",
        }

    def clear_fault(self) -> dict[str, object]:
        """Explicitly remove the active fault. The only cleanup path now that a `check_now`
        finding nothing no longer auto-deletes it (`D-S106` Part A)."""
        with self._lock:
            process_alive = self._process is not None and self._process.is_alive()
            if process_alive:
                raise ValueError("an agent cycle is running; wait for it to finish first")
            fault_id = self._fault_id
            if fault_id is None:
                raise ValueError("no fault is active to clear")
        self._delete_fault(fault_id)
        with self._lock:
            self._fault_id = None
        self.bus.publish(
            "control",
            {
                "control": "clear",
                "status": "cleared",
                "fault_id": fault_id,
                "message": "The injected fault was removed.",
            },
        )
        return {
            "status": "cleared",
            "fault_id": fault_id,
            "message": "The injected fault was removed.",
        }

    def kill_agent(self) -> dict[str, object]:
        """Kill only the cycle process, leaving the UI and watchdog untouched."""
        with self._lock:
            process = self._process
            if process is None or not process.is_alive():
                raise ValueError("no live agent cycle exists to kill")
            if self._current_action_id is None and not self._is_loop:
                raise ValueError(
                    "the agent has no watchdog-armed action yet; kill is not safe now"
                )
            self._operator_killed = True
            process.kill()
        process.join(timeout=5.0)
        if process.is_alive():
            raise RuntimeError(f"agent process {process.pid} did not stop after kill")
        self.bus.publish(
            "control",
            {
                "control": "kill",
                "status": "killed",
                "pid": process.pid,
                "message": "The agent is dead; the safety watchdog is still armed.",
            },
        )
        self.bus.publish(
            "narration",
            {"text": "The agent is dead; the safety watchdog is still armed."},
        )
        send_best_effort(
            "BreakEven: agent killed by operator",
            "An operator killed the running agent cycle from the console.\n\n"
            f"Process: pid {process.pid}\n"
            "Watchdog: still armed — any action already in flight will be reverted "
            "automatically on its own TTL, with no agent running to do it.\n\n"
            f"Operator console: {console_url()}",
        )
        return {
            "status": "killed",
            "pid": process.pid,
            "dead": True,
            "message": "The agent is dead; the safety watchdog is still armed.",
        }

    def approve(self, action_id: str) -> dict[str, object]:
        """Release the exact pending proposal back to the child for policy execution."""
        return self._decide(action_id, decision="approve")

    def reject(self, action_id: str) -> dict[str, object]:
        """Reject the exact pending proposal without executing it."""
        return self._decide(action_id, decision="reject")

    def revert_now(self, action_id: str) -> dict[str, object]:
        """Revert a real action and prove its durable state reached ``reverted``."""
        state_path = self._state_path(action_id)
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("status") == "reverted":
            raise ValueError(f"action {action_id!r} is already reverted")

        revert_action(action_id, state_dir=self.state_dir)

        restored = json.loads(state_path.read_text(encoding="utf-8"))
        if restored.get("status") != "reverted":
            raise RuntimeError(
                f"action {action_id!r} did not record a completed revert"
            )
        # What it was actually restored *to* — read straight from the same audit record
        # `revert_action` just wrote, not re-derived or guessed, so the email can never
        # claim a value this action didn't really have.
        target_path = restored.get("target_path")
        previous_value = restored.get("previous_value")
        target_name = Path(target_path).name if target_path else "the affected file"
        if previous_value is None or previous_value == "":
            restored_to = f"{target_name} is empty again (nothing was blocked before this action)"
        else:
            restored_to = f"{target_name} was restored to its exact prior content: {previous_value}"
        self.bus.publish(
            "control",
            {
                "control": "revert",
                "status": "reverted",
                "action_id": action_id,
                "message": "The selected fix was reverted and the prior state restored.",
            },
        )
        self.bus.publish(
            "narration",
            {
                "text": (
                    "The operator reverted the fix. The prior state is restored — "
                    f"{restored_to}."
                )
            },
        )
        send_best_effort(
            "BreakEven: fix reverted by operator",
            "An operator reverted a fix from the console.\n\n"
            f"Action: {action_id}\n"
            f"Restored to: {restored_to}\n\n"
            f"Operator console: {console_url()}",
        )
        return {
            "status": "reverted",
            "action_id": action_id,
            "message": "The selected fix was reverted and the prior state restored.",
        }

    def _state_path(self, action_id: str) -> Path:
        if not _SAFE_ACTION_ID.fullmatch(action_id):
            raise ValueError(
                "action_id must contain only letters, numbers, hyphens or underscores"
            )
        path = self.state_dir / f"{action_id}.json"
        if not path.exists():
            raise ValueError(
                f"action {action_id!r} was never executed; nothing to revert"
            )
        return path

    def _decide(self, action_id: str, *, decision: str) -> dict[str, object]:
        with self._lock:
            proposal = self._pending_approval
            decision_queue = self._decision_queue
            if proposal is None or decision_queue is None:
                raise ValueError("that approval is stale; no action is waiting")
            pending_action_id = proposal.get("action_id")
            if action_id != pending_action_id:
                raise ValueError(
                    f"that approval is stale; action {pending_action_id!r} is waiting instead"
                )
            if self._process is None or not self._process.is_alive():
                raise ValueError(
                    "that approval is stale; its agent cycle is no longer running"
                )
            approval_event = None
            if decision == "approve":
                approval_event = threading.Event()
                self._approval_action_id = action_id
                self._approval_event = approval_event
                self._approval_result = None
            else:
                self._operator_rejected = True
            decision_queue.put({"decision": decision, "action_id": action_id})
            self._pending_approval = None

        if approval_event is not None:
            # K1: this wait is a *confirmation* budget, never an execution deadline. The
            # child has already been told to proceed, and the window it must beat spans
            # select_remedy → engine.execute → execute_action (atomic write plus detached
            # watchdog spawn) → a POST to deployed Cloud Run. Overrunning it means the
            # answer is not back yet, NOT that nothing happened — reporting "was not
            # executed" there tells the operator the opposite of the truth about a live
            # control-plane change, and the page then contradicts itself seconds later
            # when the real confirmation arrives. So a timeout reports honest uncertainty
            # and defers to the event stream; only a reported failure is a failure.
            confirmed = approval_event.wait(_APPROVAL_TIMEOUT_SECONDS)
            with self._lock:
                result = self._approval_result
            if not confirmed and result is None:
                status = "executing"
                message = (
                    "The approved fix was sent to the agent and is being applied. "
                    "Watch the live feed for confirmation."
                )
            elif result is None or result[0] != "executed":
                detail = (
                    result[1] if result is not None else "execution was not confirmed"
                )
                raise RuntimeError(f"the approved action was not executed: {detail}")
            else:
                status = "executed"
                message = "The approved fix passed policy and is now active."
        else:
            status = "rejected"
            message = "The operator rejected this fix. The platform was left unchanged."
        self.bus.publish(
            "control",
            {
                "control": decision,
                "status": status,
                "action_id": action_id,
                "message": message,
            },
        )
        self.bus.publish("narration", {"text": message})
        return {"status": status, "action_id": action_id, "message": message}

    def _create_fault(self, fault_type: str | None = None) -> str:
        body: dict[str, object] = {
            "channel_id": _FAULT_CHANNEL.channel_id,
            "failure_rate": _FAULT_RATE,
        }
        if fault_type is None:
            body["creative_id"] = _FAULT_CREATIVE
        else:
            body["fault_type"] = fault_type
            if fault_type == "origin_degradation":
                body["cdn_pathway"] = _FAULT_PATHWAY
        payload = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            f"{self.simulator_url}/faults",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10.0) as response:
                if response.status != 201:
                    raise RuntimeError(
                        f"simulator fault request returned HTTP {response.status}"
                    )
                try:
                    body = json.loads(response.read().decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as error:
                    raise RuntimeError(
                        f"simulator fault response was not valid JSON: {error}"
                    ) from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise RuntimeError(f"simulator fault request failed: {error}") from error
        fault_id = body.get("fault_id") if isinstance(body, dict) else None
        if not isinstance(fault_id, str) or not fault_id:
            raise RuntimeError("simulator fault response did not contain a fault_id")
        return fault_id

    def _delete_fault(self, fault_id: str) -> None:
        request = urllib.request.Request(
            f"{self.simulator_url}/faults/{fault_id}", method="DELETE"
        )
        try:
            with urllib.request.urlopen(request, timeout=10.0) as response:
                if response.status not in {200, 204}:
                    raise RuntimeError(
                        f"simulator fault rollback returned HTTP {response.status}"
                    )
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise RuntimeError(
                    f"simulator fault rollback failed: HTTP {error.code}"
                ) from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise RuntimeError(f"simulator fault rollback failed: {error}") from error

    def _relay_events(self, event_queue, generation: int) -> None:
        while True:
            try:
                message = event_queue.get()
                if message[0] != "process_exit":
                    with self._lock:
                        stale = generation != self._generation
                    if stale:
                        _LOGGER.debug(
                            "ignoring stale %s event for cycle generation %s",
                            message[0],
                            generation,
                        )
                        continue
                if self._relay_message(message):
                    return
            except Exception as error:  # pylint: disable=broad-exception-caught
                _LOGGER.exception("operator control event relay failed")
                try:
                    self.bus.publish(
                        "control",
                        {
                            "control": "cycle",
                            "status": "failed",
                            "message": f"The agent event relay failed: {error}",
                        },
                    )
                except Exception:  # pylint: disable=broad-exception-caught
                    _LOGGER.exception("failed to publish the event-relay failure")
                return

    def _relay_message(self, message) -> bool:  # pylint: disable=too-many-branches
        kind = message[0]
        if kind == "event":
            self.bus.publish(message[1], message[2])
        elif kind == "approval":
            proposal = dict(message[1])
            with self._lock:
                self._pending_approval = proposal
            self.bus.publish("approval", proposal)
        elif kind == "result":
            record = message[1]
            arguments = record.get("arguments", {})
            action_id = arguments.get("action_id")
            self.bus.publish(
                "control",
                {
                    "control": "cycle",
                    "status": "completed",
                    "action_id": action_id,
                    "message": "The agent cycle completed.",
                },
            )
        elif kind == "action_started":
            action_id = message[1]
            with self._lock:
                self._current_action_id = action_id
                if self._approval_action_id == action_id:
                    self._approval_result = ("executed", "")
                    if self._approval_event is not None:
                        self._approval_event.set()
            self.bus.publish(
                "control",
                {
                    "control": "action",
                    "status": "watchdog_armed",
                    "action_id": action_id,
                    "message": "The fix is active and its safety watchdog is armed.",
                },
            )
        elif kind == "approval_failed":
            action_id, detail = message[1], message[2]
            with self._lock:
                if self._approval_action_id == action_id:
                    self._approval_result = ("failed", detail)
                    if self._approval_event is not None:
                        self._approval_event.set()
        elif kind == "loop_stopped":
            reason = message[1]
            text = (
                "The agent finished handling the incident and is no longer polling "
                "Grafana. Inject a new fault to start it again."
                if reason == "resolved"
                else "Nothing has been wrong for a while, so the agent stopped polling "
                "Grafana. Inject a new fault to start it again."
            )
            self.bus.publish(
                "control",
                {"control": "loop", "status": "stopped", "message": text},
            )
            self.bus.publish("narration", {"text": text})
        elif kind == "process_exit":
            self._handle_process_exit(message[1], message[2])
            return True
        else:
            self.bus.publish(
                "control",
                {
                    "control": "cycle",
                    "status": "failed",
                    "message": f"Unknown child-process message {kind!r}.",
                },
            )
        return False

    def _handle_process_exit(self, generation: int, exit_code: int | None) -> None:
        """Note the cycle stopped. `D-S106` Part A: this no longer auto-deletes the fault
        when the cycle exits with no action taken (e.g. `open_incident` was `SKIPPED`) —
        `check_now` can be pressed again against the same fault until it accumulates enough
        real signal, and `clear_fault` is now the only way it gets removed."""
        with self._lock:
            if generation != self._generation:
                _LOGGER.debug(
                    "ignoring stale exit event for cycle generation %s", generation
                )
                return
            self._is_loop = False
            approval_event = self._approval_event
            if approval_event is not None and not approval_event.is_set():
                self._approval_result = ("failed", "the agent cycle exited")
                approval_event.set()
        if exit_code and not self._operator_killed:
            self.bus.publish(
                "narration",
                {
                    "text": "The agent cycle stopped unexpectedly. The page is still "
                    "running and any safety watchdog remains armed."
                },
            )

    @staticmethod
    def _watch_process(process: multiprocessing.Process, event_queue, generation: int) -> None:
        process.join()
        try:
            event_queue.put(("process_exit", generation, process.exitcode))
        except Exception:  # pylint: disable=broad-exception-caught
            _LOGGER.exception("could not report exit of agent process %s", process.pid)
