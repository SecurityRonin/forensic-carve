# 1. The carving contract and sweep engine live in a standalone crate, not in forensicnomicon

Date: 2026-07-24
Status: Accepted

## Context

The fleet needed one home for the medium-agnostic carving *execution* model —
the `Carver` trait, the signature/context/item value types, and the single-pass
sweep engine — shared by disk-unallocated and memory carving. Two homes were
plausible: fold it into `forensicnomicon` (the zero-dependency KNOWLEDGE leaf
that already owns magic-byte constants), or publish a new crate.

Fleet ADR 0001 §2 settled this fleet-wide: `forensicnomicon`'s charter is
"schemas and invariants, NO parsing algorithms," and a carving *execution*
abstraction is an algorithm, so it may not live in the leaf — the leaf
contributes only the magic-byte constants a carver anchors on. The decision is
visible in this repo: the crate is `forensic-carve` with `[lib] name =
"forensic_carve"` (`Cargo.toml`), the contract and engine are its whole public
surface (`src/lib.rs`, `src/engine.rs`), and the module docstring names fleet
ADR 0001 as the governing design (`src/lib.rs:10`).

The dependency graph is deliberately minimal. The crate depends only on
`aho-corasick` (multi-pattern detection) and `inventory` (the carver registry) —
`Cargo.toml` `[dependencies]`. It does **not** depend on `forensic-vfs` or a
memory provider; instead the engine defines its own positioned-read edge,
`RegionSource::read_at(offset, buf) -> usize` (`src/engine.rs:19`), which a disk
driver implements over `forensic-vfs` reads and a memory driver over `read_virt`.
The self-defined edge keeps `forensic-carve` free of both the disk and the memory
stacks, so it can be linked by either without dragging the other in.

## Decision

Publish `forensic-carve` as a standalone crate owning the entire carving
execution model: the contract types (`Carver`, `Signature`, `CarveContext`,
`CarvedItem`, `CarvedPayload`, `RecoveryMethod`, `ConfidencePolicy`) and the
`sweep` engine plus its `RegionSource`/`Region`/`SweptItem`/`CarveOptions`
support types. Depend only downward on `aho-corasick` and `inventory`; define the
source edge (`RegionSource`) locally rather than depending on `forensic-vfs`, so
neither the disk nor the memory stack is a build dependency of the carving
foundation.

## Consequences

- A parser crate, `issen`, and `memf-carve` can all link the carving contract
  without inheriting each other's medium stacks.
- `forensicnomicon` stays a pure zero-I/O leaf; a report-model change for
  recovery provenance is explicitly deferred (fleet ADR 0001 §2), so this crate
  carries the provenance vocabulary itself (see ADR 0004).
- The locally-defined `RegionSource` is one more small trait each driver must
  implement, accepted in exchange for the dependency isolation.
