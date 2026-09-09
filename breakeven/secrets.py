"""Runtime access to BreakEven secrets in Google Secret Manager."""

from __future__ import annotations

_PROJECT_ID = "breakeven-pnl-agent"


def get_secret(secret_name: str) -> str:
    """Return the latest value of ``secret_name`` from Secret Manager.

    The SDK is imported here, not at module scope: on this project's dev
    machine, importing ``google.cloud.secretmanager`` alone costs 30-46s
    (``google.api_core``'s own transitive import graph), which every module
    that does ``from breakeven.secrets import get_secret`` at its own module
    scope was paying merely to be imported — including `breakeven.sim.api`
    and, through it, every real subprocess `test_entrypoint.py`/`test_ui.py`
    start and wait on with a 30s deadline. None of those call sites ever
    reach a real ``get_secret()`` call in these tests; every one either
    never executes that branch or has ``get_secret`` monkeypatched first.
    Deferring the import to call time means importing this module — and
    everything that merely imports it — is cheap again, and the cost is
    paid only by the caller that actually needs a live secret.
    """
    import google.cloud.secretmanager as _secretmanager  # pylint: disable=import-outside-toplevel

    client = _secretmanager.SecretManagerServiceClient()
    version = client.secret_version_path(_PROJECT_ID, secret_name, "latest")
    response = client.access_secret_version(request={"name": version})
    return response.payload.data.decode("utf-8")
