# forensic-carve

One carving contract, one single-pass sweep engine. The same carver recovers a
deleted artifact from unallocated disk *and* from a memory image.

`forensic-carve` is the SecurityRonin fleet's carving foundation. It owns the
medium-agnostic carving contract and the sweep engine that drives it; per-format
recovery logic lives in the consumer carver crates (sqlite-forensic,
winevt-carver, and the rest).

## The `Carver` trait

A carver is small and medium-agnostic. It sees only `&[u8]` windows and plain
values, never learning whether it is sweeping disk or memory:

- `format() -> &'static str` — the artifact family it recovers (e.g. `"sqlite"`).
- `signatures() -> &[Signature]` — the magic byte patterns the engine scans for.
- `max_window() -> u64` — the largest window the carver wants materialized for a
  hit, so a large artifact is bounded rather than truncated to a scan chunk.
- `carve(window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem>` — validate the
  window and emit recovered items, echoing `ctx.recovery_method()`.

Because a carver never touches medium-specific state, the same implementation
serves both disk and memory sweeps.

## The `sweep` engine

`sweep(source, regions, carvers, opts)` runs in two phases:

1. **Detection.** A single aho-corasick pass over the supplied regions matches
   every carver's signatures at once. One pass, all patterns, whatever the region
   count.
2. **Materialization.** For each hit, the engine reads a capped window (bounded by
   the carver's `max_window` and the option's `max_window`) from the source and
   hands it to the matching carver. Detection is separate from materialization, so
   a signature found near the end of a scan chunk still yields the carver its full
   window.

`source` is any `RegionSource` — a positioned `read_at`. A disk `ImageSource`
exposes unallocated extents; a memory virtual-address space un-scatters
physically-discontiguous pages behind the same `read_at`. Regions carry a caller
tag for attribution (volume/run id on disk, PID/VA on memory).

Carvers register themselves with `inventory::submit!`, so a binary that
force-links a set of carver crates collects them all via `registered_carvers()`.
The consumer never depends on the parser crates directly.

## The recovery vocabulary

Every carved item carries a `RecoveryMethod` describing *how* it was recovered.
The driver sets it once per sweep; the carver echoes it. Carving is itself a
recovery method:

| Variant | Source |
|---|---|
| `Tombstone` | a deletion the filesystem recorded |
| `FileInternalCarve` | a located artifact's own slack (freelist / WAL / `ElfChnk`) |
| `UnallocatedCarve` | whole-image unallocated carving |
| `MemoryCarve` | a memory image (process VA region or physical frame) |

The same carver stamps `UnallocatedCarve` on a disk sweep and `MemoryCarve` on a
memory sweep. The method flows from the driver through the engine; the carver
stays agnostic.

## Where to go next

- [Validation](validation.md) — how the engine's correctness is established, and
  where the real-artifact Tier-1 oracles live.
- The consumer carver crates carry their own artifact-specific validation.
