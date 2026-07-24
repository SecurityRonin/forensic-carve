# 2. A carver sees only `&[u8]`; medium attribution is wrapped by the driver

Date: 2026-07-24
Status: Accepted

## Context

The crate's central thesis is that the *same* per-format carver recovers a
deleted artifact from unallocated disk and from a memory image, unchanged. That
only holds if a carver cannot observe its medium. The failure mode to prevent is
a carver reaching for a disk `Read`/`Seek`, a VFS handle, or a memory provider —
which would make it disk-only or memory-only and fork the fleet's carvers by
medium (the divergence fleet ADR 0001 exists to stop: three incompatible carve
surfaces had already appeared).

The evidence: `Carver::carve(&self, window: &[u8], ctx: &CarveContext) ->
Vec<CarvedItem>` takes only a byte window and a value context
(`src/lib.rs:267`). `CarveContext` carries plain values only — base offset,
confidence policy, and recovery method — with a docstring stating it "never
carries a `Read`/`Seek`, a VFS handle, or a memory provider: a carver that must
chase virtual pointers is a memory *walker*, not a medium-agnostic carver"
(`src/lib.rs:98`). `CarvedItem` is medium-neutral: it holds format, offset,
confidence, method, and payload, and carries no PID/VA/PFN or volume/run id
(`src/lib.rs:169`). Medium-specific attribution rides outside the item: the
engine wraps each `CarvedItem` in a `SweptItem<R> { region: R, offset, item }`
where `R` is the opaque driver tag (`src/engine.rs:41`), and the driver un-scatters
physically-discontiguous memory pages behind `RegionSource` *before* the carver
ever sees the window.

## Decision

Make the carver contract medium-blind by construction:

- `Carver::carve` accepts only `&[u8]` plus a values-only `CarveContext`.
- `CarveContext` never carries an I/O handle or memory provider.
- `CarvedItem` stays medium-neutral; all medium attribution (disk volume/run id,
  memory PID/VA/PFN) is attached by the driver *after* the carve, via
  `SweptItem<R>`'s region tag.

A carver echoes `ctx.recovery_method()`, so one carver stamps `UnallocatedCarve`
on a disk sweep and `MemoryCarve` on a memory sweep with no code change.

## Consequences

- A format carver is authored once and validated once, then runs on every
  medium; the disk↔memory conformance test (ADR 0008) exists to prove this.
- A carver that genuinely needs to follow virtual pointers is out of scope here —
  it belongs in `memf-windows` as a walker, not as a `Carver`.
- Consumers that want medium attribution read it off `SweptItem`, not off
  `CarvedItem`; the two-type split is a deliberate cost to keep the item neutral.
