"""Email escalation — `GAPS.md` #11.

The console's own text already claims a human is alerted on several outcomes
(`orchestrator._narrate_outcome`'s `UNVERIFIED_REVERTED_AND_ESCALATED` message); until this
module existed that claim was false — the only wiring was `escalate=print` into a spawned
child process's discarded stdout. This is the real out-of-band channel: plain SMTP, one
function, no new dependency (`smtplib`/`email.message` are stdlib — ponytail rung 3).

Credentials and addresses are read from environment variables at send time, never
hardcoded and never logged — set them in the shell that runs the demo, not in this repo.
"""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage

_LOGGER = logging.getLogger(__name__)

# Well under `remediator.SETTLE_MARGIN_SECONDS` (60s): `escalate()` runs inside that
# window, and a slow SMTP round trip there must not itself push a real verdict onto the
# `UNVERIFIED_REVERTED_BY_TTL` edge (`GAPS.md` #11's own note; `GAPS.md` #2 already flags
# two other un-timed network calls in this repo — this must not become a third).
_SMTP_TIMEOUT_SECONDS = 5.0

DEFAULT_CONSOLE_URL = "http://127.0.0.1:8081"


def console_url() -> str:
    """The operator console's own URL, for every email's "go look" link."""
    return os.environ.get("BREAKEVEN_CONSOLE_URL", DEFAULT_CONSOLE_URL)


def send_alert(subject: str, body: str) -> None:
    """Send one plain-text alert email over Gmail SMTP + an app password.

    Raises on any failure (missing configuration, auth failure, connection failure) —
    never swallowed here. Whether a failure here may safely be swallowed depends on where
    the caller sits relative to the safety path (`escalate()` calls inside `settle()` must
    let this propagate so the honest `UNVERIFIED_SETTLEMENT_FAILED` distinction still
    applies; every other, purely informational caller in `orchestrator.py` catches and logs
    instead, so a notification hiccup can never break detection or diagnosis).
    """
    host = os.environ.get("BREAKEVEN_SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("BREAKEVEN_SMTP_PORT", "587"))
    sender = os.environ["BREAKEVEN_SMTP_FROM"]
    recipient = os.environ["BREAKEVEN_SMTP_TO"]
    password = os.environ["BREAKEVEN_SMTP_PASSWORD"]

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    message.set_content(body)

    with smtplib.SMTP(host, port, timeout=_SMTP_TIMEOUT_SECONDS) as server:
        server.starttls(context=ssl.create_default_context())
        server.login(sender, password)
        server.send_message(message)


def send_best_effort(subject: str, body: str) -> None:
    """Send one alert, logging rather than raising on failure.

    For the informational checkpoints this session added (fault detected, cause found,
    approval needed, and the post-settlement outcome mail) — none of these sit on the
    safety path `settle()` already owns, so a bad SMTP config must cost a missed email,
    never a broken detection/diagnosis/remediation cycle.
    """
    try:
        send_alert(subject, body)
    # pylint: disable=broad-exception-caught
    except Exception:
        _LOGGER.exception("best-effort alert email failed to send: %r", subject)
