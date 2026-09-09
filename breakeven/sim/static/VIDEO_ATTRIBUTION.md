# Player fixture attribution

**`D-S122` (2026-09-08): replaced with user-supplied stock footage.** Yuvraj provided four
source clips directly (not sourced or selected by an agent) to make the demo player look
like real television rather than an abstract test pattern. Each fixture below is a
re-encoded excerpt of one of those four source files — H.264, video-only MPEG-TS, 640×360,
25fps, exact 2.000-second duration (`breakeven.sim.origins.SEGMENT_SECONDS`), matching the
prior fixtures' own spec exactly.

**Licensing is not verified here and is Yuvraj's responsibility, not an agent's to assert.**
These clips were supplied as local files with no accompanying licence information. If any
of the source footage is stock content requiring an attribution or a paid licence for its
intended use (a hackathon demo, a recorded video, a public repository), that must be
confirmed and satisfied separately before wide distribution.

## Ad fixtures (`D-S122`)

- **`fixture-segment.ts`** (the default/"broken" creative) — a car commercial-style clip,
  with a burned-in red "AD" badge and a `cr:summer_sale` creative-id label, so the ad break
  reads as an ad on sight, not just by position in the cycle.
- **`fixture-segment-safe.ts`** (the "safe"/replacement creative, served once the real
  remedy blocklists the default one) — a watch commercial-style clip, with a burned-in
  green "AD" badge and a `cr:new_series` label — a different colour and a different real
  clip, so the swap this remedy actually performs is visually obvious, not merely
  inferred from the on-screen label changing.

## Content fixtures (`D-S122`)

- **`fixture-content-0.ts` through `fixture-content-9.ts`** — ten distinct 2-second
  excerpts from two scenic/documentary-style source clips, no ad badge. `origins.py`'s
  `_segment_bytes` selects one by `sequence % 10`, so the five content segments in each
  program/ad-break cycle show real, continuing footage rather than one 2-second clip
  looping identically five times a cycle.

## Prior fixtures (superseded, kept only as history)

`fixture-segment.ts` and `fixture-segment-safe.ts` were originally two distinct two-second
excerpts from **Big Buck Bunny** by the Blender Foundation
(https://commons.wikimedia.org/wiki/File:Big_buck_bunny_mcu.ogv, CC BY 3.0,
© Blender Foundation | www.blender.org) — a moving gradient vs. a colour-bar pattern,
chosen for being unmistakable apart without a text overlay. `fixture-content.ts` (removed,
replaced by the ten `fixture-content-N.ts` files above) was a third excerpt from the same
source, a moving cellular-automaton pattern standing in for "the program."
