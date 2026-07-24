# 4. `RecoveryMethod` is the fleet provenance vocabulary and owns the plain name

Date: 2026-07-24
Status: Accepted

## Context

Every carved item must record *how* it was recovered so machine output
round-trips it and an analyst can filter carved from live evidence — a carved
record indistinguishable from a live one is a fabrication hazard (fleet ADR 0001
§9). A `RecoveryMethod` enum already existed, but in the wrong place and at the
wrong scope: `browser-forensic-carve::RecoveryMethod` (`FreePage`,
`WalUncommitted`, `JournalRollback`, `DirectScan`) was a SQLite-record substrate
detail, not a fleet-level vocabulary.

Fleet ADR 0001 §3 resolves this: carving *is* a recovery method, so the general
concept owns the plain name, and the SQLite enum is a substrate detail *under*
one variant (renamed `SqliteRecoveryMethod`). Alternatives `RecoveryOrigin` and
`AcquisitionMethod` were rejected — "acquisition" means evidence imaging.

This repo carries the fleet vocabulary: `RecoveryMethod { Tombstone,
FileInternalCarve, UnallocatedCarve, MemoryCarve }` with per-variant docstrings
mapping each to its CLI flag/tier (`src/lib.rs:24`–`56`). It is `#[non_exhaustive]`
(`src/lib.rs:29`) so a future variant is additive, and exposes a stable
serialization token via `as_str()` — `"tombstone"`, `"file-internal-carve"`,
`"unallocated-carve"`, `"memory-carve"` — for translation onto the report model's
`Evidence`/tags at orchestration (`src/lib.rs:43`–`55`).

## Decision

Own the fleet-level recovery provenance vocabulary here as
`RecoveryMethod { Tombstone, FileInternalCarve, UnallocatedCarve, MemoryCarve }`,
mapping 1:1 to the fleet flag taxonomy (`--deleted`, default Tier-1, `--unallocated`,
memory leg). Make it `#[non_exhaustive]` and give it stable `as_str()` tokens that
must never change once shipped. The narrower `browser-forensic-carve` enum is
demoted to `SqliteRecoveryMethod` (a substrate detail under `FileInternalCarve`),
per fleet ADR 0001 §3.

## Consequences

- Every carved item across the fleet is provenance-tagged from one vocabulary,
  and the tokens round-trip through machine output.
- The same enum absorbs the non-carving tombstone case, which an
  "origin"-flavoured name could not have.
- `browser-forensic-carve` takes a non-breaking rename with a deprecated alias.
- Structural recovery-method fields on `forensicnomicon::report` stay deferred
  until ≥2 consumers query recovery method structurally (fleet ADR 0001 §2); the
  typed envelope lives here meanwhile.
