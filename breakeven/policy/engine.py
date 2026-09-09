"""The safety kernel's blast-radius gate — F-ACT-20, F-ACT-24, F-ACT-25.

The crew *proposes*; this module *disposes*. Plain typed Python, no model anywhere in the
decision path (`INV-S02`) — an over-scoped action cannot reach the executor, because the
executor is only ever called by :func:`execute`, after every check has passed.

Blast radius is counted in live viewers, and only the ``channels`` dimension narrows the
count: the simulated world exposes one region (``us-east``) and one device class (``ctv``)
and emits no per-pathway concurrency, so ``regions``, ``devices`` and ``cdn_pathways``
cannot reduce a viewer total yet. Treating them as non-narrowing **over**-estimates blast
radius, which is the conservative direction for a gate — it rejects more, never less.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from datetime import timedelta
from enum import Enum, auto
from typing import Literal, TypeVar

WILDCARD: Literal["*"] = "*"

_T = TypeVar("_T")


class Plane(Enum):
    """The three — and only three — writable control planes.

    `PRODUCTION_ACTION_LAYER.md` §2. Plane C has zero viewer blast radius, which is why
    the wildcard rule does not apply to it.
    """

    A = "content-steering"
    B = "ad-decisioning"
    C = "grafana"


class ActionType(Enum):
    """The frozen action catalog, `PRODUCTION_ACTION_LAYER.md` §3."""

    A1 = "A1"  # reprioritise pathway for one cohort
    A2 = "A2"  # disable top ladder rung + clone pathway onto shield tier
    A3 = "A3"  # blocklist creative for a rendition
    A4 = "A4"  # halt creative on an impression-conservation violation
    A5 = "A5"  # fail over to backup ad-decision server
    A6 = "A6"  # lower floor price for one channel x daypart
    A7 = "A7"  # set pod policy to house_content
    A8 = "A8"  # enable origin shield + retune TTL
    A9 = "A9"  # unpublish a broken rendition
    A10 = "A10"  # author a replacement alert rule, silence the old one
    A11 = "A11"  # annotate, file/close incident, post timeline
    A12 = "A12"  # block a non-compliant publish


class RejectionReason(Enum):
    """Why the gate refused. Typed values — never a free-form string."""

    WILDCARD_IN_TWO_DIMENSIONS = auto()
    OVER_BLAST_RADIUS_CEILING = auto()
    BLAST_RADIUS_UNMEASURABLE = auto()


PLANES_BY_ACTION_TYPE: Mapping[ActionType, frozenset[Plane]] = {
    ActionType.A1: frozenset({Plane.A}),
    ActionType.A2: frozenset({Plane.A}),
    ActionType.A3: frozenset({Plane.B}),
    ActionType.A4: frozenset({Plane.B, Plane.C}),
    ActionType.A5: frozenset({Plane.B}),
    ActionType.A6: frozenset({Plane.B}),
    ActionType.A7: frozenset({Plane.B}),
    ActionType.A8: frozenset({Plane.A}),
    ActionType.A9: frozenset({Plane.B}),
    ActionType.A10: frozenset({Plane.C}),
    ActionType.A11: frozenset({Plane.C}),
    ActionType.A12: frozenset({Plane.B, Plane.C}),
}

# PROVISIONAL. `PRODUCTION_ACTION_LAYER.md` §4.2 says "the configured ceiling for its
# type" and names no values, so these are chosen here and owed upward for ratification.
# Sized in live viewers against the simulator world (`src/breakeven/sim/world.py`):
# flagship `ch_flagship_01` baseline 850,000 · niche `ch_niche_07` 1,800 · world 1,738,000
# (8 channels, since Slice 5 widened it from the original 2-channel/851,800 world —
# `GAPS.md` #3, corrected 2026-09-07: a legitimate whole-world Plane-C wildcard action was
# being rejected as `OVER_BLAST_RADIUS_CEILING` against the stale, pre-widening number).
# Deliberately literal integers, not an import — the gate must not depend on the
# simulator it polices, and these are production ceilings that outlive the simulator.
#
# The three bands, and what separates them:
#   playback-degrading   — the viewer sees it. Capped well below the flagship channel, so
#                          one wrong call cannot reach the whole paying audience.
#   ad-path only         — no playback impact, TTL-reversible. Flagship-wide permitted.
#   zero viewer radius   — Plane C. Detection and memory only; nothing here degrades a
#                          stream, so the ceiling is the world (§2.3, "widest autonomy").
MAX_VIEWERS_BY_ACTION_TYPE: Mapping[ActionType, int] = {
    ActionType.A1: 250_000,  # steering: quality-neutral intent, but a bad pathway
    #                          choice degrades everyone routed onto it
    ActionType.A2: 100_000,  # drops a ladder rung — §3 marks it "blast-radius capped"
    ActionType.A3: 850_000,  # ad-path only, one creative, trivially reversible
    ActionType.A4: 850_000,  # conservation violation: containment must not be
    #                          scope-blocked, and the violation is itself the proof
    ActionType.A5: 850_000,  # ad-path only, decision-server failover
    ActionType.A6: 1_800,  # money and contracts, human-gated: niche-only autonomously
    ActionType.A7: 50_000,  # house content is viewer-visible and books a revenue loss
    ActionType.A8: 250_000,  # delivery-path change, human-first
    ActionType.A9: 100_000,  # removes a playable rendition from a device class
    ActionType.A10: 1_738_000,  # Plane C only — zero viewer blast radius
    ActionType.A11: 1_738_000,  # Plane C only — zero viewer blast radius
    ActionType.A12: 1_738_000,  # compliance block: never scope-blocked
}

_WILDCARD_RULE_PLANES = frozenset({Plane.A, Plane.B})
_TEXT_FIELDS = ("action_id", "predicted_effect", "verification_query")


class PolicyRejection(Exception):
    """Raised instead of returning a verdict, so a rejection can never be advisory."""

    def __init__(self, reason: RejectionReason, detail: str) -> None:
        super().__init__(f"{reason.name}: {detail}")
        self.reason = reason


@dataclass(frozen=True)
class Cohort:
    """A declared blast radius. Never a string, never "global".

    Shape is `PRODUCTION_ACTION_LAYER.md` §4.2, field for field.
    """

    channels: frozenset[str] | Literal["*"]
    regions: frozenset[str] | Literal["*"]
    devices: frozenset[str] | Literal["*"]
    cdn_pathways: frozenset[str] | Literal["*"]

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if value == WILDCARD:
                continue
            if not isinstance(value, frozenset) or not value:
                raise ValueError(
                    f"Cohort.{field.name} must be a non-empty frozenset[str] or "
                    f'"*", got {value!r}'
                )

    def viewer_count(self, telemetry: Mapping[str, int]) -> int:
        """Return the live viewers inside this cohort.

        ``telemetry`` maps ``channel_id`` to that channel's current concurrent viewers.
        A named channel absent from ``telemetry`` raises :class:`KeyError` rather than
        contributing zero — an uncountable cohort must not read as a small one.
        """
        if self.channels == WILDCARD:
            return sum(telemetry.values())
        return sum(telemetry[channel] for channel in sorted(self.channels))

    def wildcard_dimensions(self) -> tuple[str, ...]:
        """Return the names of the dimensions set to ``"*"``."""
        return tuple(
            field.name
            for field in fields(self)
            if getattr(self, field.name) == WILDCARD
        )


@dataclass(frozen=True)
class ActionResult:
    """The six-field action contract the policy engine reads. None of it is decorative.

    Every field is required and validated here. ``ttl`` is a value on this record and
    nothing more — scheduling the revert belongs to the action executor (`INV-S01`).
    """

    action_id: str
    reversible: bool
    blast_radius: Cohort
    predicted_effect: str
    verification_query: str
    ttl: timedelta

    def __post_init__(self) -> None:
        for field in fields(self):
            if getattr(self, field.name) is None:
                raise ValueError(
                    f"ActionResult.{field.name} is required; None is not a default"
                )
        for name in _TEXT_FIELDS:
            if not getattr(self, name).strip():
                raise ValueError(
                    f"ActionResult.{name} is required; blank is not a value"
                )
        if self.ttl <= timedelta(0):
            raise ValueError(
                f"ActionResult.ttl must be a positive duration, got {self.ttl!r}"
            )


def idempotency_key(
    action_type: ActionType, cohort: Cohort, failure_signature: str
) -> str:
    """Return the idempotency key for acting on ``failure_signature`` in ``cohort`` with
    ``action_type`` — F-ACT-25.

    `docs/FEATURES.md:229`: *"Key derived from `(type, cohort, failure_signature)`. A
    retry can never double-apply."* The executor's own guard is per ``action_id``, which
    is assigned per *proposal*; this key identifies the real-world *situation*, so two
    separately-proposed actions against the same one collide even though their
    ``action_id``s differ.

    Computed, never judged (`INV-S02`) — a pure function of its three arguments with no
    I/O and no model anywhere near it.

    Derived from the cohort's **content**, never from ``id()`` or a default ``repr()``:
    each dimension's members are sorted, so two structurally-equal cohorts built in
    different orders give the same key. The wildcard is encoded as a JSON string and a
    member set as a JSON array, so ``channels="*"`` (every channel) and
    ``channels=frozenset({"*"})`` (one channel literally named ``"*"``, which
    :meth:`Cohort.__post_init__` permits) are different blast radii and get different
    keys.

    SHA-256 rather than :func:`hash`: the key is written to disk and compared across
    processes, and ``hash()`` on a ``str`` is randomised per interpreter by ``PYTHONHASHSEED``,
    so it would not survive the executor's own watchdog subprocess boundary. The digest
    is also safe as a filename component, which is how the executor stores it.
    """
    payload = json.dumps(
        {
            "type": action_type.value,
            "cohort": {
                field.name: (
                    WILDCARD
                    if getattr(cohort, field.name) == WILDCARD
                    else sorted(getattr(cohort, field.name))
                )
                for field in fields(cohort)
            },
            "failure_signature": failure_signature,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def execute(
    action_type: ActionType,
    action: ActionResult,
    telemetry: Mapping[str, int],
    executor: Callable[[ActionResult], _T],
) -> _T:
    """Run ``executor`` on ``action`` if and only if the action is within policy.

    Raises :class:`PolicyRejection` — with a typed
    :class:`RejectionReason` — before ``executor`` is touched. There is no code path on
    which a rejected action reaches the executor, and no verdict a caller can ignore.
    """
    planes = PLANES_BY_ACTION_TYPE[action_type]
    ceiling = MAX_VIEWERS_BY_ACTION_TYPE[action_type]

    wildcards = action.blast_radius.wildcard_dimensions()
    if len(wildcards) > 1 and planes & _WILDCARD_RULE_PLANES:
        raise PolicyRejection(
            RejectionReason.WILDCARD_IN_TWO_DIMENSIONS,
            f"{action.action_id} ({action_type.value}) wildcards "
            f"{', '.join(wildcards)}; at most one is allowed on planes "
            f"{sorted(plane.name for plane in planes & _WILDCARD_RULE_PLANES)}",
        )

    try:
        viewers = action.blast_radius.viewer_count(telemetry)
    except KeyError as unknown_channel:
        raise PolicyRejection(
            RejectionReason.BLAST_RADIUS_UNMEASURABLE,
            f"{action.action_id} ({action_type.value}) names channel "
            f"{unknown_channel.args[0]!r}, which has no telemetry; blast radius cannot "
            f"be counted, so the action cannot be authorised",
        ) from unknown_channel

    if viewers > ceiling:
        raise PolicyRejection(
            RejectionReason.OVER_BLAST_RADIUS_CEILING,
            f"{action.action_id} ({action_type.value}) covers {viewers} viewers, "
            f"ceiling is {ceiling}",
        )

    return executor(action)
