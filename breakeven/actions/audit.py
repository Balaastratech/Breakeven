"""The append-only action audit log — F-ACT-29.

One JSON line per audit entry, written with the file opened in append mode and nothing
else. That is the whole mechanism, and it is deliberate: a database would be a new
dependency (LAW 4) for a guarantee the operating system already gives, and any writer that
can seek is a writer that can rewrite history. `export` re-reads the file every time, so
what a caller gets back is a copy — there is no live handle on the log to edit through.

Append-only is asserted three ways in `tests/test_actions_audit.py`: an exported entry
cannot be mutated or deleted, an append never rewrites the bytes an earlier entry wrote,
and an AST scan of this module proves it contains no file-open mode that could.

Plain typed Python, no model anywhere (`INV-S02`, same contract as the rest of
`breakeven.actions`).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path


class RevertStatus(Enum):
    """Where an action stands with respect to its revert.

    Three states, not a boolean — `D-S36`: the executor's record moves ``"executed"`` →
    ``"reverting"`` → ``"reverted"``, and ``"reverting"`` is a real, reachable, retryable
    state. A boolean would record an action interrupted mid-revert as either fully
    reverted or never touched, and both are false.
    """

    NOT_REVERTED = "not_reverted"
    REVERTING = "reverting"
    REVERTED = "reverted"


class ActionOutcome(Enum):
    """What the verification window decided. A typed value, never a free-form string —
    the same reasoning as `engine.RejectionReason`: an audit trail whose outcome column is
    prose cannot be counted, filtered, or trusted to mean the same thing twice.
    """

    VERIFIED = "verified"
    UNVERIFIED_REVERTED_AND_ESCALATED = "unverified_reverted_and_escalated"
    # The predicted effect did not hold *and* the settlement itself failed — the revert
    # raised, or the escalation did. Never rounded up to the row above: that row is a
    # claim that a human was told, and this one is the honest statement that they may not
    # have been. `revert_status` says separately how far the revert actually got.
    UNVERIFIED_SETTLEMENT_FAILED = "unverified_settlement_failed"
    # The verification window was ended by the TTL watchdog *during* measurement, so no
    # verdict on the predicted effect is available — the measurement describes a world
    # that no longer exists by the time it returns. Distinct from the row above: that row
    # is a verdict that the effect did *not* hold; this one is the honest absence of any
    # verdict at all, because the thing being measured was put back mid-measurement.
    UNVERIFIED_REVERTED_BY_TTL = "unverified_reverted_by_ttl"
    # `measure` itself raised, so no verdict on the predicted effect was ever reached —
    # distinct from `UNVERIFIED_SETTLEMENT_FAILED` above, whose own docstring presupposes a
    # verdict ("did not hold") was already computed before revert/escalate failed. Naming
    # a measurement failure "settlement failed" would claim a verdict that never existed.
    UNVERIFIED_MEASUREMENT_FAILED = "unverified_measurement_failed"
    # Written once, at execution time, before `settle()` has run — not a verdict, a
    # receipt. `F-ACT-29`'s "every action logged" cannot hold for an action that is
    # executed and then never settled (a crash, a process killed before `settle()` is
    # reached); this is the entry that still exists when that happens. `settle()` always
    # writes its own, final entry afterwards on every path it can reach at all — this one
    # is never updated in place (the log is append-only, `audit.py`'s own docstring), so a
    # settled action legitimately carries two entries: this receipt, then the verdict.
    EXECUTED_AWAITING_SETTLEMENT = "executed_awaiting_settlement"


_TEXT_FIELDS = ("agent_identity", "timestamp")


def now_stamp() -> str:
    """An ISO-8601 timestamp in UTC, with the offset present."""
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class AuditEntry:
    """One action's audit record. Exactly the six fields `F-ACT-29` names, in its order.

    Frozen, so an entry handed to a caller cannot be edited into a different history.
    """

    agent_identity: str
    timestamp: str
    arguments: Mapping[str, object]
    evidence_chain: tuple[Mapping[str, object], ...]
    result: ActionOutcome
    revert_status: RevertStatus

    def __post_init__(self) -> None:
        for field in fields(self):
            if getattr(self, field.name) is None:
                raise ValueError(
                    f"AuditEntry.{field.name} is required; None is not a default"
                )
        for name in _TEXT_FIELDS:
            if not str(getattr(self, name)).strip():
                raise ValueError(f"AuditEntry.{name} is required; blank is not a value")
        if not isinstance(self.result, ActionOutcome):
            raise ValueError(
                f"AuditEntry.result must be an ActionOutcome, got {self.result!r}"
            )
        if not isinstance(self.revert_status, RevertStatus):
            raise ValueError(
                "AuditEntry.revert_status must be a RevertStatus, got "
                f"{self.revert_status!r}"
            )
        if not self.evidence_chain:
            raise ValueError(
                "AuditEntry.evidence_chain is required; an entry with no evidence "
                "records a claim with nothing behind it"
            )
        self._require_unambiguous_timestamp()

    def _require_unambiguous_timestamp(self) -> None:
        """A timestamp with no offset cannot be ordered against one from another host,
        and ordering is most of what an audit log is for."""
        try:
            parsed = datetime.fromisoformat(self.timestamp)
        except ValueError as malformed:
            raise ValueError(
                f"AuditEntry.timestamp {self.timestamp!r} is not an ISO-8601 timestamp"
            ) from malformed
        if parsed.tzinfo is None:
            raise ValueError(
                f"AuditEntry.timestamp {self.timestamp!r} has no UTC offset; an audit "
                "timestamp must be unambiguous"
            )

    def as_record(self) -> dict[str, object]:
        """The JSON-ready shape written to the log — enums flattened to their values."""
        return {
            "agent_identity": self.agent_identity,
            "timestamp": self.timestamp,
            "arguments": dict(self.arguments),
            "evidence_chain": [dict(evidence) for evidence in self.evidence_chain],
            "result": self.result.value,
            "revert_status": self.revert_status.value,
        }


def append_entry(entry: AuditEntry, *, log_path: Path) -> None:
    """Append ``entry`` to ``log_path`` as one JSON line, creating the log if needed.

    The only write path in this module, and it opens the file in append mode. A caller
    cannot reach an earlier line through it, because the operating system will not seek an
    append-mode handle backwards.

    The payload is serialised *before* the handle is opened, so a value that cannot be
    JSON-encoded raises without leaving a truncated line behind.

    Ceiling, stated rather than implied: a write that fails part-way through — a full disk
    — can still leave an incomplete final line. That is loud rather than lost, because
    :func:`export` refuses to parse it and names the line number.
    """
    line = json.dumps(entry.as_record(), allow_nan=False)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def export(log_path: Path) -> tuple[AuditEntry, ...]:
    """Read the whole log back as typed entries, in the order they were written.

    Raises :class:`FileNotFoundError` if the log does not exist — an empty export and a
    mistyped path must not look alike, or a missing audit trail reads as "nothing
    happened". Raises :class:`ValueError` naming the offending ``path:line`` if any line
    is not a complete entry; a line that cannot be parsed is never skipped, because a
    silently skipped line is a deleted one.
    """
    exported: list[AuditEntry] = []
    with log_path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            # A blank line carries no entry, so skipping one loses nothing — this is not
            # the same as skipping a line that failed to parse, which below refuses to do.
            # `append_entry` never writes one; a hand-edited log might.
            if not line.strip():
                continue
            exported.append(_parse_line(line, log_path=log_path, number=number))
    return tuple(exported)


def _parse_line(line: str, *, log_path: Path, number: int) -> AuditEntry:
    try:
        record = json.loads(line)
        arguments = record["arguments"]
        if not isinstance(arguments, Mapping):
            raise TypeError(
                f"arguments must be a mapping, got {type(arguments).__name__}"
            )
        evidence_chain = record["evidence_chain"]
        if not isinstance(evidence_chain, list):
            raise TypeError(
                f"evidence_chain must be a list, got {type(evidence_chain).__name__}"
            )
        for item in evidence_chain:
            if not isinstance(item, Mapping):
                raise TypeError(
                    "evidence_chain items must be mappings, got "
                    f"{type(item).__name__}"
                )
        return AuditEntry(
            agent_identity=record["agent_identity"],
            timestamp=record["timestamp"],
            arguments=arguments,
            evidence_chain=tuple(evidence_chain),
            result=ActionOutcome(record["result"]),
            revert_status=RevertStatus(record["revert_status"]),
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as malformed:
        raise ValueError(
            f"{log_path.name}:{number} is not a valid audit entry: {malformed!r}"
        ) from malformed
