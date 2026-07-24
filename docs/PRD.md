# forensic-carve — Purpose & Scope

*A library-tier intent doc (fleet ADR-0003: `docs/PRD.md` for every tier; content
depth varies by tier). `forensic-carve` is **linked**, not run — it ships no
binary an examiner invokes — so this is a concise Purpose & Scope, not a product
PRD. Every claim below is grounded in a same-session read of `src/` and
`Cargo.toml` (2026-07-24); the load-bearing decisions live as ADRs
[0001](decisions/0001-carving-contract-and-engine-live-here.md)–[0008](decisions/0008-panic-free-fuzzed-conformance-gate.md).
The governing fleet design is `ronin-issen/docs/decisions/0001-fleet-carving-flags-sweep-engine-contract.md`.*

## What it is

`forensic-carve` is the SecurityRonin fleet's carving foundation: one carving
*contract* and one single-pass *sweep engine*, so the same per-format carver
recovers a deleted artifact from unallocated disk space *and* from a memory
image, unchanged.

- **The contract** (`src/lib.rs`): the `Carver` trait plus its value types —
  `Signature`, `CarveContext`, `CarvedItem`/`CarvedPayload`, `ConfidencePolicy`,
  and the fleet-wide `RecoveryMethod` provenance vocabulary. A carver sees only
  `&[u8]` windows and plain values, so it is medium-agnostic by construction
  (ADR 0002).
- **The sweep engine** (`src/engine.rs`): `sweep(source, regions, carvers, opts)`
  runs one aho-corasick multi-pattern detection pass over the supplied regions,
  materializes only the carver-declared window each hit needs (detection ≠
  materialization — a large artifact is never truncated to a scan chunk), runs the
  matching carver, and returns each medium-neutral `CarvedItem` wrapped in a
  `SweptItem<R>` carrying the region's attribution tag (ADR 0003).
- **The registry** (`src/registry.rs`): carvers self-register via `inventory`, so
  a consumer collects the whole set through `registered_carvers()` without
  depending on the parser crates directly (ADR 0005).

## Who links it

- **Parser / PARSER-layer crates** (`sqlite-forensic`, `winevt-carver`,
  `winreg-forensic`, `browser-forensic-carve`, …) implement `Carver` for their
  format and submit a `CarverRegistration`.
- **`memf-carve`** (memory-forensic member) drives the engine over VAD regions,
  implementing `RegionSource` on `read_virt`.
- **Disk drivers** drive the engine over `forensic-vfs` unallocated extents,
  implementing `RegionSource` on positioned reads.
- **`issen`** force-links the producer crates, collects the carver set, wires the
  `--deleted`/`--unallocated`/`--residual` flags to one `sweep` per source, and
  stamps `RecoveryMethod` provenance into the timeline.

## Scope

- The medium-agnostic carving contract types and provenance vocabulary.
- The single-pass detection engine: multi-pattern scan, chunk-boundary overlap,
  around-hit window materialization capped by carver and global limits, and a
  confidence policy applied at the edge.
- The link-time carver registry.
- The positioned-read `RegionSource` edge that both disk and memory drivers
  implement (ADR 0001).

## Non-goals

- **No format knowledge.** Every `Carver` impl (magic bytes, structural
  validation, confidence grading) lives in that format's own PARSER crate, never
  here.
- **No medium stacks.** The crate depends on neither `forensic-vfs` nor a memory
  provider; drivers supply bytes through `RegionSource` (ADR 0001). Region
  enumeration (disk unallocated extents, memory VAD regions) belongs to the
  drivers.
- **No I/O in the contract.** `CarveContext` carries plain values only — never a
  `Read`/`Seek`, VFS handle, or memory provider; a carver that must chase virtual
  pointers is a memory *walker* and belongs in `memf-windows` (ADR 0002).
- **No binary / CLI / GUI.** The carving flags and their help text are wired by
  the consuming CLIs (`issen`, the `*4n6` tools), per fleet ADR 0001 §1.
- **No report-model change.** Recovery provenance rides existing
  `forensicnomicon::report` types via translation at orchestration; a typed report
  field is deferred (ADR 0004; fleet ADR 0001 §2).
- **Memory Plane P, pagefile gap-fill, and content-reassembly** are deferred to a
  later phase (fleet ADR 0001 §6) and are out of this crate's v1 scope.

## Correctness & robustness posture

- **Input-fuzzed.** `fuzz_sweep` drives arbitrary source bytes, out-of-range and
  zero-length regions, and arbitrary chunk sizes through the engine (README:
  138k+ execs, 0 crashes) (ADR 0008).
- **Panic-free by lint.** `unwrap_used`/`expect_used` denied in production; the
  engine returns *no items* on malformed input rather than panicking.
- **`#![forbid(unsafe_code)]`** — a pure computation engine with no `unsafe` site
  (ADR 0006).
- **Disk↔memory conformance gate.** `tests/conformance.rs` proves the same carver
  produces the same `CarvedItem` over a contiguous disk source and a
  page-scattered memory source — the publish precondition of fleet ADR 0001 §8/C2
  (ADR 0008).
- **100% line coverage** with documented `// cov:unreachable` exemptions on
  provably-dead defensive guards (ADR 0008).
