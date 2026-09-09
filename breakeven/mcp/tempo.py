"""Trace retrieval through Grafana Cloud's Tempo MCP server."""

from __future__ import annotations

import base64
import os

from breakeven.mcp.client import call_tool
from breakeven.secrets import get_secret

TEMPO_MCP_ENDPOINT = "https://tempo-prod-19-prod-ap-south-1.grafana.net/tempo/api/mcp"
TEMPO_BASIC_USERNAME = "1699604"

DOCS_CONFIG = "docs-config"
DOCS_TRACEQL = "docs-traceql"
GET_ATTRIBUTE_NAMES = "get-attribute-names"
GET_ATTRIBUTE_VALUES = "get-attribute-values"
GET_TRACE = "get-trace"
TRACEQL_METRICS_INSTANT = "traceql-metrics-instant"
TRACEQL_METRICS_RANGE = "traceql-metrics-range"
TRACEQL_SEARCH = "traceql-search"


def fetch_trace(trace_id: str) -> str:
    """Return one Tempo trace payload by its 32-hex trace identifier."""
    token = get_secret("grafana-traces-read-token")
    basic_auth = base64.b64encode(
        f"{TEMPO_BASIC_USERNAME}:{token}".encode("utf-8")
    ).decode("ascii")
    result = call_tool(
        os.environ.get("BREAKEVEN_TEMPO_MCP_ENDPOINT", TEMPO_MCP_ENDPOINT),
        token,
        GET_TRACE,
        {"trace_id": trace_id},
        auth_header=f"Basic {basic_auth}",
    )
    is_error = result.get("isError")
    if "isError" in result and not isinstance(is_error, bool):
        raise RuntimeError("Tempo MCP response has a non-boolean isError flag")
    if is_error is True:
        raise RuntimeError("Tempo MCP rejected the trace query")
    content = result.get("content")
    if not isinstance(content, list) or not content:
        raise RuntimeError("Tempo MCP response has no content")
    first = content[0]
    if not isinstance(first, dict) or not isinstance(first.get("text"), str):
        raise RuntimeError("Tempo MCP response has no text payload")
    return first["text"]
