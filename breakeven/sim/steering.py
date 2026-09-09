"""In-memory session acknowledgements and executor-backed steering manifests.

Acknowledgements and last-known-good manifests are keyed by the complete session
string so similarly named sessions in different channel cohorts cannot collide.
"""

from __future__ import annotations

import json
import logging
import random
import threading
from pathlib import Path

from breakeven.actions.steering import in_ramp
from breakeven.sim.steering_manifest import SteeringManifest, validate_pathway_existence
from breakeven.sim.world import CHANNELS

_DEFAULT_PRIORITY = ("cdn-a", "cdn-b")
_LIVE_PATHWAY_IDS = frozenset(_DEFAULT_PRIORITY)
_CONFIGURED_TTL = 300
_KNOWN_CHANNEL_IDS = frozenset(channel.channel_id for channel in CHANNELS)
_LOGGER = logging.getLogger(__name__)


class SteeringSessionError(ValueError):
    """Raised when a request does not contain a supported encoded session."""


class SteeringRegistry:
    """Build manifests from acknowledged sessions and executor-owned priority files."""

    def __init__(self, state_dir: Path = Path(".breakeven-state")) -> None:
        self.state_dir = state_dir
        self._acknowledged_sessions: set[str] = set()
        self._last_good: dict[str, SteeringManifest] = {}
        self._lock = threading.Lock()

    def record_segment_ack(self, session: str) -> None:
        """Record a first successful segment fetch for a valid full session string."""
        self._parse_session(session)
        with self._lock:
            self._acknowledged_sessions.add(session)

    def manifest_for(self, session: str, host: str, port: int) -> SteeringManifest:
        """Build a validated manifest, falling back to a per-session last good value."""
        channel_id = self._parse_session(session)
        with self._lock:
            try:
                priority = (
                    self._priority_for(channel_id, session)
                    if session in self._acknowledged_sessions
                    else _DEFAULT_PRIORITY
                )
                manifest = self._manifest(session, host, port, priority)
                self._last_good[session] = manifest
                return manifest
            except Exception:  # pylint: disable=broad-except
                if session in self._last_good:
                    _LOGGER.warning(
                        "steering manifest fallback for session %s", session, exc_info=True
                    )
                    return self._last_good[session]
                # No prior value exists only before the first successful build; default is safe.
                _LOGGER.warning(
                    "steering manifest default fallback for session %s", session, exc_info=True
                )
                return self._manifest(session, host, port, _DEFAULT_PRIORITY)

    @staticmethod
    def _parse_session(session: str) -> str:
        channel_id, separator, session_id = session.partition(":")
        if not separator or not session_id or channel_id not in _KNOWN_CHANNEL_IDS:
            raise SteeringSessionError(
                "session must be '{channel_id}:{session_id}' for a known channel"
            )
        return channel_id

    def _priority_for(self, channel_id: str, session: str) -> tuple[str, ...]:
        try:
            value = json.loads(
                self.state_dir.joinpath(f"steer_{channel_id}.json").read_text(encoding="utf-8")
            )
        except FileNotFoundError:
            return _DEFAULT_PRIORITY
        except UnicodeDecodeError:
            _LOGGER.warning("malformed priority file for channel %s: invalid encoding", channel_id)
            return _DEFAULT_PRIORITY
        except json.JSONDecodeError:
            _LOGGER.warning("malformed priority file for channel %s: invalid JSON", channel_id)
            return _DEFAULT_PRIORITY
        except OSError as error:
            _LOGGER.warning("unreadable priority file for channel %s: %s", channel_id, error)
            return _DEFAULT_PRIORITY
        if isinstance(value, list):
            priority = tuple(value)
        elif isinstance(value, dict):
            last_good = value.get("last_good_priority")
            target = value.get("target_priority")
            fraction = value.get("ramp_percent")
            if (
                not isinstance(last_good, list)
                or not isinstance(target, list)
                or not isinstance(fraction, (int, float))
                or not 0 <= fraction <= 1
                or not all(isinstance(pathway, str) for pathway in last_good + target)
            ):
                _LOGGER.warning(
                    "malformed priority file for channel %s: invalid ramp shape", channel_id
                )
                return _DEFAULT_PRIORITY
            _, _, session_id = session.partition(":")
            priority = tuple(target if in_ramp(channel_id, session_id, fraction) else last_good)
        else:
            _LOGGER.warning("malformed priority file for channel %s: unsupported shape", channel_id)
            return _DEFAULT_PRIORITY
        if not priority:
            _LOGGER.warning("malformed priority file for channel %s: empty priority", channel_id)
            return _DEFAULT_PRIORITY
        if any(pathway not in _LIVE_PATHWAY_IDS for pathway in priority):
            _LOGGER.warning(
                "unknown pathway in priority file for channel %s", channel_id
            )
            return _DEFAULT_PRIORITY
        return priority

    @staticmethod
    def _manifest(
        session: str, host: str, port: int, priority: tuple[str, ...]
    ) -> SteeringManifest:
        manifest = SteeringManifest(
            version=1,
            ttl=int(round(_CONFIGURED_TTL * random.uniform(0.8, 1.2))),
            reload_uri=f"http://{host}:{port}/v1/steer?session={session}",
            pathway_priority=priority,
            pathway_clones=(),
        )
        validate_pathway_existence(manifest, _LIVE_PATHWAY_IDS)
        return manifest
