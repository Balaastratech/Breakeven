"""Minimal streamable-HTTP client for the Grafana MCP server."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping
from urllib.request import Request, urlopen

_LOGGER = logging.getLogger(__name__)

# Gap #2 (`GAPS.md`): with no timeout, a genuinely hung MCP server (not just a slow one)
# blocks the entire detect/diagnose path forever. 90s leaves comfortable margin over the
# ~34s per-query round-trip to real Grafana Cloud measured in `D-S116` — long enough to
# never falsely time out a real, merely-slow query, short enough to still bound a hang.
_HTTP_TIMEOUT_SECONDS = 90

# `(tool_name, arguments, result, error)` — `result` is set on success and `error` is a
# short description of the failure otherwise. Exactly one of the two is ever populated.
CallObserver = Callable[
    [str, Mapping[str, object], dict[str, object] | None, str | None], None
]

# Task 18 (`F-UI-04`) needs every Grafana MCP call rendered in the operator UI, and this
# function is the one funnel Watchtower and Forensics route through. An observer list is
# the smallest addition that achieves it: with none registered — which is every existing
# caller — `_notify` is a no-op loop and nothing about this module's HTTP behaviour
# changes. The alternative, threading a callback parameter down through `watchtower._query`
# and `forensics._fetch`, would have edited two modules this task is only meant to observe.
_observers: list[CallObserver] = []


def open_session(endpoint: str, token: str, auth_header: str | None = None) -> str:
    """Initialize an MCP session and return its required session identifier."""
    request = Request(
        endpoint,
        data=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "breakeven", "version": "0.1.0"},
                },
            },
            separators=(",", ":"),
        ).encode("utf-8"),
        headers={
            "Authorization": auth_header or f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        method="POST",
    )
    with urlopen(
        request, timeout=_HTTP_TIMEOUT_SECONDS
    ) as response:  # noqa: S310 - endpoint is caller-supplied MCP URL.
        session_id = response.headers.get("Mcp-Session-Id")
    if not session_id:
        raise RuntimeError("MCP initialize response missing Mcp-Session-Id")
    return session_id


def add_call_observer(observer: CallObserver) -> None:
    """Register ``observer`` to be told about every subsequent :func:`call_tool` call."""
    _observers.append(observer)


def remove_call_observer(observer: CallObserver) -> None:
    """Unregister ``observer``. Silent if it was never registered, so a caller can
    unregister in a ``finally`` without first checking."""
    while observer in _observers:
        _observers.remove(observer)


def _notify(
    tool_name: str,
    arguments: Mapping[str, object],
    result: dict[str, object] | None,
    error: str | None,
) -> None:
    """Tell every observer about one call, on both the success and the failure path.

    An observer that raises is logged with its traceback and the next observer still
    runs. Telemetry must never be able to break a real remediation — but the failure is
    never silent either, because a rendered-call count that no longer matches the
    instrumented count is exactly the thing `F-UI-04` claims cannot happen.
    """
    for observer in tuple(_observers):
        try:
            observer(tool_name, arguments, result, error)
        # pylint: disable=broad-except
        except Exception:
            _LOGGER.exception(
                "MCP call observer %r failed for tool %s", observer, tool_name
            )


def call_tool(
    endpoint: str,
    token: str,
    tool_name: str,
    arguments: dict[str, object],
    auth_header: str | None = None,
) -> dict[str, object]:
    """Call one MCP tool, tell every registered observer, and return its result.

    The call itself is :func:`_post_tool_call`; this wrapper adds only the observer
    notification. `BaseException` rather than `Exception`, so a `KeyboardInterrupt`
    landing mid-call still records that the call was made — the same reasoning as
    `remediator.remediate`'s wait handling.
    """
    try:
        result = _post_tool_call(endpoint, token, tool_name, arguments, auth_header)
    except BaseException as error:
        _notify(tool_name, arguments, None, repr(error))
        raise
    _notify(tool_name, arguments, result, None)
    return result


def _post_tool_call(
    endpoint: str,
    token: str,
    tool_name: str,
    arguments: dict[str, object],
    auth_header: str | None = None,
) -> dict[str, object]:
    """Call one MCP tool and fail loudly when its JSON-RPC response is an error."""
    session_id = open_session(endpoint, token, auth_header)
    request = Request(
        endpoint,
        data=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            },
            separators=(",", ":"),
        ).encode("utf-8"),
        headers={
            "Authorization": auth_header or f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Mcp-Session-Id": session_id,
            "MCP-Protocol-Version": "2025-03-26",
        },
        method="POST",
    )
    with urlopen(
        request, timeout=_HTTP_TIMEOUT_SECONDS
    ) as response:  # noqa: S310 - endpoint is caller-supplied MCP URL.
        payload = response.read().decode("utf-8")
    frames = [
        json.loads(line.removeprefix("data: "))
        for line in payload.splitlines()
        if line.startswith("data: ")
    ]
    response_payload = frames[-1] if frames else json.loads(payload)
    if "error" in response_payload:
        error = response_payload["error"]
        message = error.get("message", error) if isinstance(error, dict) else error
        raise RuntimeError(f"MCP tool {tool_name} failed: {message}")
    result = response_payload.get("result")
    if not isinstance(result, dict):
        raise RuntimeError(f"MCP tool {tool_name} returned no result")
    return result
