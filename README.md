# BreakEven

BreakEven is an autonomous P&L operations agent for FAST/AVOD streaming. It uses
Google ADK and Gemini to detect revenue-impacting delivery faults, investigate them
through Grafana Cloud MCP, apply bounded remedies, verify recovery, and automatically
revert actions that cannot be proven safe.

## Requirements

- Python 3.11 or newer
- Google Cloud Application Default Credentials with access to project
  `breakeven-pnl-agent`
- Vertex AI enabled in `us-central1`
- A Grafana Cloud MCP endpoint and the required Grafana credentials in Google Secret
  Manager

The runtime reads these Secret Manager entries:

- `grafana-sa-token`
- `grafana-metrics-write-token`
- `grafana-logs-write-token`
- `grafana-traces-write-token`
- `grafana-traces-read-token`

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env`, then export its values into the shell that will run BreakEven. The
application intentionally does not load `.env` automatically.

Authenticate locally:

```powershell
gcloud auth application-default login
gcloud config set project breakeven-pnl-agent
```

## Run the simulator

In the first terminal, load the environment values and run:

```powershell
python -m breakeven.sim.api
```

The simulator listens on `http://127.0.0.1:8080` by default.

## Run the agent

Start or configure the Grafana Cloud MCP endpoint named by
`BREAKEVEN_MCP_ENDPOINT`. In a second terminal, load the same environment values and
run:

```powershell
python -m breakeven.agents.orchestrator
```

The operator console listens on `http://127.0.0.1:8081` by default. Use the simulator
view to inject a fault and the agent view to observe detection, diagnosis, remediation,
verification, and watchdog-backed rollback.

## License

MIT. See [LICENSE](LICENSE).
