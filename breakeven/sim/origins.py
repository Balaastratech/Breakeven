"""Independent live HTTP origins for the streaming simulator."""

from __future__ import annotations

import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from xml.sax.saxutils import quoteattr

# `docs/DECISIONS.md` `D-S105` Part C: a real, checked-in, decodable clip rather than
# placeholder bytes, so a real `<video>` element genuinely decodes real frames and a real
# delivery failure produces a real, visible stall. Read once at import — the assets are
# immutable and every origin instance serves the same bytes.
_FIXTURE = Path(__file__).with_name("static") / "fixture-segment.ts"
_SEGMENT = _FIXTURE.read_bytes()
# `D-S107`/`D-S122`: a second, visually distinct real clip. Both ad fixtures are now real
# stock footage with a burned-in "AD" badge (a different colour/creative id per fixture),
# so the ad break reads as an ad on sight — the swap between them (this remedy's real
# effect) no longer relies on a viewer already knowing "gradient" from "bars".
_SEGMENT_SAFE = (Path(__file__).with_name("static") / "fixture-segment-safe.ts").read_bytes()
# `D-S108`/`D-S122`: the actual program, no ad badge — visually unmistakable from either ad
# fixture on sight alone. Ten real 2-second clips, not one repeating loop, so a viewer
# watching more than one cycle sees the program genuinely continue rather than the same two
# seconds looping — `_segment_bytes` below picks one deterministically by sequence. Named
# `_CONTENT_CLIPS`, not `_CONTENT_SEGMENTS`, to stay distinct from `_CONTENT_SEGMENTS` below
# (`D-S108`'s existing per-cycle *count*, an unrelated `int`).
_CONTENT_CLIPS = tuple(
    (Path(__file__).with_name("static") / f"fixture-content-{index}.ts").read_bytes()
    for index in range(10)
)
# The fixture's true duration, measured at generation time
# (`ffprobe … -show_entries format=duration` → `2.000000`). The manifests below declare
# this rather than a rounded guess: a playlist that misstates segment duration makes a
# player's own buffer arithmetic wrong, which is indistinguishable from the delivery stall
# this origin exists to demonstrate.
SEGMENT_SECONDS = 2.0
_SEGMENT_M4S = b"\x00\x00\x00\x18ftypiso6BREAKEVEN-FRAGMENTED-MP4-SEGMENT"

# Live mode names each segment by its media sequence number, so every refresh fetches a
# genuinely new URL and a delivery failure is observed within one segment duration. VOD
# mode keeps the single fixed `/seg-0001.ts` name the existing proofs assert on.
_SEGMENT_PATH = re.compile(r"^/seg-(\d+)\.ts$")
_LIVE_WINDOW_SEGMENTS = 3

# `D-S108`: the program/ad-break cycle. Sequence 0 and 1 are the ad break (so the existing
# `/seg-0001.ts` proofs, which assert the fault/safe fixture directly, keep passing
# unchanged); sequences 2-6 are the program. A real channel's `breaks_per_hour` cadence
# (minutes between breaks) is unwatchable in a live demo, so this is a deliberately
# accelerated, fixed cycle rather than a derivation from that config — ponytail: demo pacing
# only, not a claim about real ad-break frequency.
_AD_BREAK_SEGMENTS = 2
_CONTENT_SEGMENTS = 5
_CYCLE_SEGMENTS = _AD_BREAK_SEGMENTS + _CONTENT_SEGMENTS


def _phase_for(sequence: int) -> str:
    """Return "ad" or "content" for a segment's position in the repeating cycle."""
    return "ad" if sequence % _CYCLE_SEGMENTS < _AD_BREAK_SEGMENTS else "content"


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        """Serve HLS or DASH manifests and their media segments."""
        parsed = urlparse(self.path)
        if parsed.path == "/playlist.m3u8":
            live = parse_qs(parsed.query).get("live", [""])[0] == "1"
            self._response(
                "application/vnd.apple.mpegurl",
                self._playlist(live=live).encode("utf-8"),
                no_store=live,
            )
            return
        segment_match = _SEGMENT_PATH.match(parsed.path)
        if segment_match:
            phase = _phase_for(int(segment_match.group(1)))
            # `D-S108` scoped the ad break as the only phase that could fail this way.
            # `D-S115` revises that: origin/CDN pathway degradation is a *content*-delivery
            # concept in the real world (Plane A), distinct from the ad-decisioning faults
            # `D-S108` modeled (Plane B) — so content now has its own, separately-supplied
            # degradation predicate, checked only for its own phase, the same shape
            # `_delivery_degraded` already uses.
            if phase == "ad" and self._delivery_degraded():
                # A real HTTP delivery failure, not a rendering flag: the player's own
                # error and buffer-stall handling is what the console panel then shows.
                self.send_error(503, "segment delivery is degraded")
                return
            if phase == "content" and self._content_degraded():
                self.send_error(503, "origin pathway is degraded")
                return
            self._response(
                "video/mp2t", self._segment_bytes(phase, int(segment_match.group(1)))
            )
            return
        if parsed.path == "/manifest.mpd":
            self._response("application/dash+xml", self._manifest().encode("utf-8"))
            return
        if parsed.path == "/seg-0001.m4s":
            self._response("video/iso.segment", _SEGMENT_M4S)
            return
        self.send_error(404)

    def _delivery_degraded(self) -> bool:
        """Whether this origin is currently failing segment delivery.

        The predicate is supplied by whoever started the origin, so this module keeps
        knowing nothing about faults, channels, or remedies — it only asks.
        """
        degraded = self.server.degraded
        return degraded is not None and degraded()

    def _content_degraded(self) -> bool:
        """Whether the program content is currently failing to deliver.

        `D-S115`: same optional-predicate shape as `_delivery_degraded`, `None` unless a
        caller attaches one — a pair started on its own never fails content delivery,
        matching every other predicate's own default-off contract in this module.
        """
        content_degraded = self.server.content_degraded
        return content_degraded is not None and content_degraded()

    def _segment_bytes(self, phase: str, sequence: int) -> bytes:
        """Which real clip to serve for this segment's phase.

        `D-S108`: the program (`"content"`) never depends on any fault/remedy state — only
        an `"ad"` phase segment picks between the original and safe fixture, same shape as
        `_delivery_degraded`. `showing_safe` is supplied the same optional way `degraded`
        is: `None` unless a caller attaches one, so an origin pair started on its own always
        serves the original ad fixture, exactly as before this predicate existed.

        `D-S122`: content picks one of `_CONTENT_CLIPS` by `sequence`, the same modulo
        shape `_phase_for` already uses to place the ad break within the cycle — so content
        genuinely advances through real footage across the program's five segments per
        cycle, rather than repeating the same two seconds five times over.
        """
        if phase == "content":
            return _CONTENT_CLIPS[sequence % len(_CONTENT_CLIPS)]
        showing_safe = self.server.showing_safe
        if showing_safe is not None and showing_safe():
            return _SEGMENT_SAFE
        return _SEGMENT

    def _clone_data(self) -> str:
        return json.dumps(
            {
                "PATHWAY-CLONES": [
                    {
                        "BASE-ID": self.server.origin_name,
                        "ID": f"{self.server.origin_name}-clone",
                        "URI-REPLACEMENT": {
                            "HOST": (
                                f"{self.server.partner_name}.localhost:"
                                f"{self.server.partner_port}"
                            )
                        },
                    }
                ]
            },
            separators=(",", ":"),
        )

    def _playlist(self, *, live: bool) -> str:
        header = (
            "#EXTM3U",
            "#EXT-X-VERSION:10",
            '#EXT-X-SESSION-DATA:DATA-ID="com.breakeven.pathway-clones",VALUE="'
            + self._clone_data().replace('"', '\\"')
            + '"',
            f"#EXT-X-TARGETDURATION:{round(SEGMENT_SECONDS)}",
        )
        if not live:
            return "\n".join(
                header
                + (
                    "#EXT-X-MEDIA-SEQUENCE:0",
                    f"#EXTINF:{SEGMENT_SECONDS:.3f},",
                    "/seg-0001.ts",
                    "#EXT-X-ENDLIST",
                    "",
                )
            )
        return "\n".join(header + self._live_window() + ("",))

    def _live_window(self) -> tuple[str, ...]:
        """A sliding window over the looping fixture, positioned by wall clock.

        The same clip repeats, so each entry restarts the media timeline and must carry
        `EXT-X-DISCONTINUITY` — without it a player maps every repeat onto the same
        presentation timestamps and stalls at the loop point, which would look exactly
        like the delivery fault this origin is built to demonstrate.
        """
        elapsed = max(0.0, time.time() - self.server.started_at)
        first = max(0, int(elapsed / SEGMENT_SECONDS) - (_LIVE_WINDOW_SEGMENTS - 1))
        lines = [
            f"#EXT-X-MEDIA-SEQUENCE:{first}",
            f"#EXT-X-DISCONTINUITY-SEQUENCE:{first}",
        ]
        for sequence in range(first, first + _LIVE_WINDOW_SEGMENTS):
            lines.append("#EXT-X-DISCONTINUITY")
            lines.append(f"#EXTINF:{SEGMENT_SECONDS:.3f},")
            lines.append(f"/seg-{sequence:04d}.ts")
        return tuple(lines)

    def _manifest(self) -> str:
        clone_data = quoteattr(self._clone_data())
        return "\n".join(
            (
                '<?xml version="1.0" encoding="UTF-8"?>',
                '<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static"',
                '     mediaPresentationDuration="PT1S" minBufferTime="PT1S"',
                '     profiles="urn:mpeg:dash:profile:isoff-on-demand:2011">',
                "  <Period>",
                '    <AdaptationSet mimeType="video/mp4" segmentAlignment="true">',
                '      <SupplementalProperty schemeIdUri="com.breakeven.pathway-clones"',
                f"                            value={clone_data}/>",
                f'      <Representation id="{self.server.origin_name}" bandwidth="500000"',
                '                      codecs="avc1.64001f" width="640" height="360">',
                "        <BaseURL>/seg-0001.m4s</BaseURL>",
                '        <SegmentBase indexRange="0-0"/>',
                "      </Representation>",
                "    </AdaptationSet>",
                "  </Period>",
                "</MPD>",
                "",
            )
        )

    def end_headers(self) -> None:
        """Allow cross-origin reads on *every* response, errors included.

        On the degraded path this is what makes the difference between a player seeing the
        503 this origin actually sent and a browser refusing to show it the response at
        all: measured this session, without the header Chrome reports a CORS violation and
        `hls.js` gets a failure with no status behind it.
        """
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def _response(self, content_type: str, body: bytes, *, no_store: bool = False) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if no_store:
            # A cached live playlist would freeze the window and stop the player asking
            # for new segments, which would hide both the stall and the recovery.
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def make_origin_pair(
    host: str = "127.0.0.1",
) -> tuple[ThreadingHTTPServer, ThreadingHTTPServer]:
    """Construct two independent origins on OS-assigned ports without starting them."""
    origin_a = ThreadingHTTPServer((host, 0), _OriginHandler)
    origin_b = ThreadingHTTPServer((host, 0), _OriginHandler)
    origin_a.origin_name = "cdn-a"
    origin_a.partner_name = "cdn-b"
    origin_a.partner_port = origin_b.server_address[1]
    origin_b.origin_name = "cdn-b"
    origin_b.partner_name = "cdn-a"
    origin_b.partner_port = origin_a.server_address[1]
    for origin in (origin_a, origin_b):
        origin.started_at = time.time()
        # No degradation predicate unless a caller attaches one, so an origin pair started
        # on its own serves every segment exactly as it did before.
        origin.degraded = None
        # `D-S107`: same reasoning — no swap predicate unless a caller attaches one, so an
        # origin pair started on its own always serves the original fixture only.
        origin.showing_safe = None
        # `D-S115`: same reasoning again — no content-degradation predicate unless a
        # caller attaches one, so an origin pair started on its own never fails content.
        origin.content_degraded = None
    return origin_a, origin_b
