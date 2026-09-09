"""Narrow runtime checks for the healthy-system verification features."""

from __future__ import annotations

import os
from datetime import datetime, timedelta

from breakeven.agents.scribe.agent import _milliseconds, _tool_value
from breakeven.mcp.client import call_tool
from breakeven.mcp.tools import GET_ANNOTATIONS
from breakeven.secrets import get_secret

_TOKEN_SECRET = "grafana-sa-token"
_FUTURE_WINDOW = timedelta(days=1)


def future_incident_annotations(future_start: datetime) -> list[object]:
    """Return incident-detection annotations recorded in one future-day window."""
    result = call_tool(
        os.environ.get("BREAKEVEN_MCP_ENDPOINT", "http://localhost:8000/mcp"),
        get_secret(_TOKEN_SECRET),
        GET_ANNOTATIONS,
        {
            "tags": ["breakeven", "incident-detected"],
            "from": _milliseconds(future_start),
            "to": _milliseconds(future_start + _FUTURE_WINDOW),
        },
    )
    annotations = _tool_value(result, GET_ANNOTATIONS)
    if isinstance(annotations, dict):
        annotations = annotations.get("Payload")
    if not isinstance(annotations, list):
        raise RuntimeError("Grafana MCP get_annotations returned non-list content")
    return annotations
