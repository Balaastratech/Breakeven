"""A minimal ADK agent proving Grafana MCP connectivity."""

from __future__ import annotations

from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool.mcp_toolset import (
    MCPToolset,
    StreamableHTTPConnectionParams,
)

from breakeven.mcp.tools import LIST_DATASOURCES
from breakeven.secrets import get_secret

# INV-S03: later detection agents inherit this fast model to keep their loop cheap.
MODEL = "gemini-2.5-flash"


def _authorization_header(_: object) -> dict[str, str]:
    """Fetch the Grafana token only when ADK opens the MCP connection."""
    return {"Authorization": f"Bearer {get_secret('grafana-sa-token')}"}


root_agent = LlmAgent(
    name="grafana_datasource_probe",
    model=MODEL,
    instruction="List the available Grafana datasources and return their names.",
    tools=[
        MCPToolset(
            connection_params=StreamableHTTPConnectionParams(
                url="http://localhost:8000/mcp"
            ),
            tool_filter=[LIST_DATASOURCES],
            header_provider=_authorization_header,
        )
    ],
)
