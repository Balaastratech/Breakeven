"""The walking skeleton's reversible creative blocklist action."""

from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

from breakeven.actions import executor
from breakeven.actions.executor import _state_path, execute_action
from breakeven.policy.engine import ActionResult, Cohort

_LOGGER = logging.getLogger(__name__)

# Gap #2 (`GAPS.md`): with no timeout, a hung target blocks this call forever, the TTL
# watchdog that everything else depends on never spawns, and no audit entry is written —
# a silent failure in the one path the whole safety story rests on. 60s comfortably
# exceeds this simulator's real observed latency (control-plane POSTs, not the ~34s
# Grafana MCP queries measured in `D-S116`) while still bounding the hang.
_HTTP_TIMEOUT_SECONDS = 60


class DuplicateBlocklistCallError(ValueError):
    """Raised by `blocklist_creative`'s own upfront duplicate-call guard (`K-S01`) —
    never by `execute_action`'s own, later, unrelated "already executed" guard
    (`executor.py:580-581`), which stays a bare :class:`ValueError` for its own scenario
    (the narrow concurrent-call race this function's own docstring already names as out
    of scope).

    A :class:`ValueError` subclass for the same reason `executor.DuplicateActionError`
    is one: every existing caller that already matches on :class:`ValueError` (this
    module's own rollback `except Exception` blocks, `tests/test_blocklist.py`'s own
    ``pytest.raises(ValueError, ...)``) keeps handling this the same way, unchanged.
    What is new is that a caller can now `isinstance`-check for this specific type to
    recognise "this was a harmless collision with a still-live action, not a genuine
    execution failure" — see `remediator.remediate`'s `except BaseException` handler,
    which does exactly that to avoid forcing a compensating revert on the wrong action
    (`NEW-1`, the S6 Tier-A review of `09765c2`).
    """


def _post_blocklist(base_url: str, channel_id: str, creative_id: str) -> None:
    payload = json.dumps({"channel_id": channel_id, "creative_id": creative_id}).encode(
        "utf-8"
    )
    request = urllib.request.Request(
        f"{base_url}/control/blocklist",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT_SECONDS) as response:
        if not 200 <= response.status < 300:
            raise ValueError(f"blocklist POST returned {response.status}")


def _rollback_and_raise(
    action_id: str,
    undo_urls: list[str],
    failure: Exception,
    *,
    escalate: Callable[[str], None] | None = None,
) -> None:
    """Best-effort DELETE every URL already applied, then re-raise ``failure`` —
    never abandons the rest of the rollback after one `_http_delete` fails, and never
    lets a rollback failure replace or mask the real one that triggered it (any
    rollback failures are chained onto ``failure`` as the cause via an
    `ExceptionGroup`).

    Shared by both callers in :func:`blocklist_creative`: a mid-loop `_post_blocklist`
    failure, and `K-R01` — `execute_action` itself failing *after* every POST already
    landed, which otherwise leaves creatives blocked in production with no durable
    record and nothing left to ever revert them (`_force_compensating_revert_after_
    execution_failure` reads "no record" as "never executed" and correctly does
    nothing, because for every *other* action type that is true).

    `K-S02`: a rollback DELETE failing here is the double-fault limit this module's own
    docstring already names — nothing left in this process has another mechanism to
    undo that channel, and until this fix nothing told anyone either. Logged at
    CRITICAL and escalated directly (if a channel is available) rather than relying on
    a caller several layers up to notice a discarded ``__cause__``.
    """
    rollback_errors: list[Exception] = []
    for undo_url in undo_urls:
        try:
            executor._http_delete(
                undo_url
            )  # noqa: SLF001 - rollback reuses the idempotent undo primitive
        except (
            Exception
        ) as rollback_error:  # noqa: BLE001 - must not abort the remaining rollback attempts
            rollback_errors.append(rollback_error)
    if rollback_errors:
        _LOGGER.critical(
            "action %s: rollback DELETE failed for %d already-blocked channel(s) "
            "(%r) while handling %r; those creatives may remain blocked in production "
            "with no revert path left: %r",
            action_id,
            len(rollback_errors),
            undo_urls,
            failure,
            rollback_errors,
        )
        if escalate is not None:
            try:
                escalate(
                    f"action {action_id}: blocklist rollback failed for "
                    f"{len(rollback_errors)} channel(s) while handling {failure!r} — "
                    "creatives may remain blocked in production with no revert path "
                    "left"
                )
            # An unavailable escalation channel must be visible in logs, never replace
            # the double-fault this is escalating in the first place.
            except Exception:  # noqa: BLE001
                _LOGGER.exception(
                    "failed to escalate the blocklist rollback double-fault"
                )
        raise failure from ExceptionGroup(
            "rollback DELETE failed for one or more already-blocked channels",
            rollback_errors,
        )
    raise failure


def blocklist_creative(
    action: ActionResult,
    *,
    creative_id: str,
    cohort: Cohort,
    base_url: str,
    state_dir: Path,
    escalate: Callable[[str], None] | None = None,
) -> None:
    """Block a creative in the approved cohort and schedule its HTTP undo.

    Atomic across the cohort: either every channel ends up blocked and recorded, or the
    call raises with zero state artifacts written for this ``action_id`` and zero
    channels left blocked. A mid-loop `_post_blocklist` failure, and a failure in the
    ``execute_action`` call itself (`K-R01` — the durable record can fail to write
    *after* every POST already succeeded, since `execute_action`'s own record-before-
    mutate ordering has no mutation left to precede here), both trigger the same
    best-effort rollback via :func:`_rollback_and_raise` before re-raising. This never
    leaves a channel blocked with no `execute_action` record to revert it *unless the
    rollback DELETE for that specific channel itself also fails* — a real, named
    double-fault limit, not a bug: nothing left in this call has another mechanism to
    undo a channel whose own undo request failed. That double fault is surfaced to the
    caller instead of being silently reported as recovered.

    `K-S01`: a duplicate call for an ``action_id`` that already has a durable record is
    refused *before* any POST — never reaching the `execute_action`/rollback path below
    at all. Without this, `execute_action`'s own "already executed" guard fires *after*
    every channel above has already been (redundantly) re-blocked, and the `except`
    around `execute_action` could not tell that legitimate collision apart from a
    genuine record-write failure — rolling back would have DELETEd the blocks a live,
    still-TTL-armed *earlier* action still holds, corrupting a state that was never
    actually broken. `execute_action`'s own guard remains as defence in depth against
    the narrow window between this check and the state write it cannot see (two
    concurrent calls for the same ``action_id``) — that residual race is unchanged from
    before this fix and is not this function's concurrency model to solve.
    """
    if _state_path(state_dir, action.action_id).exists():
        raise DuplicateBlocklistCallError(
            f"action {action.action_id!r} was already executed"
        )
    undo_urls: list[str] = []
    for channel_id in cohort.channels:
        try:
            _post_blocklist(base_url, channel_id, creative_id)
        except Exception as post_error:
            _rollback_and_raise(
                action.action_id, undo_urls, post_error, escalate=escalate
            )
        undo_urls.append(
            f"{base_url}/control/blocklist/{urllib.parse.quote(channel_id, safe='')}/"
            f"{urllib.parse.quote(creative_id, safe='')}"
        )
    try:
        execute_action(action, state_dir=state_dir, undo_urls=undo_urls)
    except (
        Exception
    ) as record_error:  # noqa: BLE001 - see _rollback_and_raise's docstring
        _rollback_and_raise(
            action.action_id, undo_urls, record_error, escalate=escalate
        )
