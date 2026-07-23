# Validation

forensic-carve is a medium-agnostic sweep engine plus a carving contract. It is
**not** a value-producing decoder: it routes bytes to per-format carvers and
never itself claims to have reconstructed an artifact's meaning. That distinction
governs how its correctness is established and, just as importantly, what it does
**not** claim.

The engine has no independent third-party oracle of its own, because there is no
external tool that "sweeps a region and dispatches to a carver" to differential
against. Its correctness rests on three internal checks, each labelled by the
trustworthiness of what confirms it.

## Tier-2 — disk↔memory conformance (derivable ground truth)

The engine's central promise is that a carver produces the *same* `CarvedItem`
regardless of medium. This is proven by a conformance test, not asserted.

`tests/conformance.rs` — `same_carver_conforms_across_disk_and_memory_adapters`
runs one unchanged carver over two `RegionSource` adapters that differ **only** in
storage layout:

- a `DiskLikeSource` — a flat, contiguous byte span (an unallocated run);
- a `MemoryLikeSource` — the *same* bytes split across non-contiguous 4 KiB pages
  and stitched back together on read, mimicking a VA space whose pages are
  scattered across physical frames.

The test asserts the two adapters return byte-identical data at the artifact
offset, then that the carver yields items with identical offset, format,
confidence, and payload across both. The **only** permitted difference is the
driver-set `RecoveryMethod` (`UnallocatedCarve` on disk, `MemoryCarve` in memory).

This is Tier-2: the scenario is constructed here, but the expected answer is
derivable from the construction (the two adapters are defined to carry the same
bytes), so the equality is a genuine check, not a fixture written to match a bug.

## Tier-2 — fuzzing (robustness against arbitrary input)

`fuzz/fuzz_targets/fuzz_sweep.rs` drives the engine's entire attacker-controllable
surface: arbitrary source bytes, arbitrary regions (including out-of-range,
overlapping-past-end, and zero-length), and an arbitrary chunk size, dispatched to
a carver with realistic multi-length magics. The invariant is that `sweep` never
panics — no out-of-bounds slice, no arithmetic overflow, no unbounded allocation —
and returns no items on malformed input rather than crashing. The README records
138k+ executions with zero crashes; the fuzz job re-runs the target in CI.

"Never panics on arbitrary input" is a property, and the fuzz target is its
backstop rather than a value to oracle-check.

## Tier-3 — line coverage (regression backstop)

The crate holds 100% line coverage (`cargo llvm-cov --lib`, failing on any
uncovered line without a `// cov:unreachable` marker). The behavioural tests
(`tests/conformance.rs`, `tests/sweep.rs`, `tests/chunking.rs`,
`tests/contract.rs`, `tests/edges.rs`, `tests/provenance.rs`,
`tests/registry.rs`) exercise the detection, materialization, dedup, clamping, and
attribution paths end to end. Coverage here is a regression backstop that proves
those paths are exercised, not a correctness oracle.

## Where real-artifact Tier-1 validation lives

The engine only moves bytes that its consumers validate. Real-artifact,
independent-oracle validation therefore lives in the **consumer carver repos**,
not here:

- **sqlite-forensic** validates deleted-row / freelist carving against the
  independent `fqlite` oracle on real SQLite databases.
- **winevt-carver** validates `ElfChnk` record recovery against real EVTX corpora.

Those repos reconcile carved counts and contents against their reference tools on
genuine artifacts. forensic-carve deliberately makes **no** Tier-1 oracle claim
for itself: it has none, and claiming one would overstate what a byte-routing
engine can prove in isolation.
