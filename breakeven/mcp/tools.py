"""Pinned Grafana MCP tool names validated from the captured live response."""

from __future__ import annotations

import json
from pathlib import Path

TOOLS_DUMP_PATH = Path(__file__).with_name("tools_dump.json")

QUERY_PROMETHEUS = "query_prometheus"
QUERY_LOKI_LOGS = "query_loki_logs"
CREATE_ANNOTATION = "create_annotation"
GET_ANNOTATIONS = "get_annotations"
ALERTING_MANAGE_RULES = "alerting_manage_rules"
LIST_DATASOURCES = "list_datasources"
CREATE_INCIDENT = "create_incident"
ADD_ACTIVITY_TO_INCIDENT = "add_activity_to_incident"
GET_INCIDENT = "get_incident"
LIST_INCIDENTS = "list_incidents"
GRAFANA_API_REQUEST = "grafana_api_request"
GENERATE_DEEPLINK = "generate_deeplink"

REFERENCED_TOOL_NAMES = frozenset(
    {
        QUERY_PROMETHEUS,
        QUERY_LOKI_LOGS,
        CREATE_ANNOTATION,
        GET_ANNOTATIONS,
        ALERTING_MANAGE_RULES,
        LIST_DATASOURCES,
        CREATE_INCIDENT,
        ADD_ACTIVITY_TO_INCIDENT,
        GET_INCIDENT,
        LIST_INCIDENTS,
        GRAFANA_API_REQUEST,
        GENERATE_DEEPLINK,
    }
)


def _tool_names_from_dump(path: Path = TOOLS_DUMP_PATH) -> frozenset[str]:
    """Return tool names from the unedited streamable-HTTP tools/list response."""
    messages = [
        json.loads(line.removeprefix("data: "))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("data: ")
    ]
    response = next((message for message in messages if message.get("id") == 2), None)
    if response is None:
        raise RuntimeError(f"MCP tools/list response missing from {path}")
    return frozenset(tool["name"] for tool in response["result"]["tools"])


def _validate_referenced_tool_names(available_tool_names: frozenset[str]) -> None:
    missing = sorted(REFERENCED_TOOL_NAMES - available_tool_names)
    if missing:
        raise RuntimeError(
            f"Referenced MCP tools absent from dump: {', '.join(missing)}"
        )


TOOL_NAMES = _tool_names_from_dump()
_validate_referenced_tool_names(TOOL_NAMES)
