# 3. One aho-corasick detection pass; detection is separate from materialization

Date: 2026-07-24
Status: Accepted

## Context

Whole-medium carving is O(image/dump), so it must be paid once per source no
matter how many formats are hunted — not N times, once per format. And a naive
"scan a chunk, carve the chunk" design has a correctness bug: an artifact larger
than the scan chunk is truncated to the chunk. Fleet ADR 0001 §4 makes
*detection ≠ materialization* the correctness crux and rejects both per-parser
whole-medium scans and signature-overlap-alone.

The engine implements this (`src/engine.rs`):

- **One detection pass over all formats.** Every carver's signatures are compiled
  into a single `AhoCorasick` automaton (`src/engine.rs:92`–`105`); one
  `find_overlapping_iter` pass finds every format's magic at once.
- **Chunk-boundary overlap.** The scan buffer is a carried overlap tail
  (`longest_magic − 1`) prepended to each fresh chunk, so a magic straddling a
  chunk boundary is found in exactly one chunk, with a dedup guard that skips a
  match lying wholly in the carry (`src/engine.rs:107`–`150`). A pathologically
  small configured `chunk_size` is clamped up to the longest magic so a magic can
  always fit the scan buffer (`src/engine.rs:114`; the RED/GREEN pair
  `6c00c9c`/`b0f5873`).
- **Materialize only the carver-declared window, around the hit.** After a magic
  hit, the artifact start is anchored (the magic may sit mid-artifact, so
  `abs_start − sig.offset`, `src/engine.rs:153`), then a separate positioned read
  materializes only `carver.max_window().min(opts.max_window)` bytes
  (`src/engine.rs:160`–`167`) — never the whole scanned chunk, and capped by both
  the carver and a global alloc-bomb backstop.

## Decision

The `sweep` engine runs exactly one aho-corasick multi-pattern detection pass
over the supplied regions, with `longest_magic − 1` overlap carried across chunk
boundaries and a straddle-dedup guard. Detection is decoupled from
materialization: a magic hit is converted to an absolute offset, then only the
carver-declared bounded window is materialized around that offset (capped by
`carver.max_window()` and `CarveOptions::max_window`) and handed to the carver. A
short read from `RegionSource` marks the window truncated; bytes are never
fabricated.

## Consequences

- The O(image) cost is paid once per source for all formats together.
- A large artifact receives its trailing bytes (up to the cap) instead of being
  truncated to a scan chunk.
- The engine owns both the detection overlap and the window materialization, so a
  driver author cannot get the boundary/window logic wrong per medium.
- Two defensive guards on the chunk loop are provably unreachable under the loop
  invariants and are annotated `// cov:unreachable` rather than deleted
  (`src/engine.rs:104`,`126`), preserving degradation if a future change breaks
  the invariant (see ADR 0008).
