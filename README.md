# forensic-carve

[![Crates.io](https://img.shields.io/crates/v/forensic-carve.svg)](https://crates.io/crates/forensic-carve)
[![Docs.rs](https://docs.rs/forensic-carve/badge.svg)](https://docs.rs/forensic-carve)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/forensic-carve/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/forensic-carve/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![fuzzed](https://img.shields.io/badge/fuzzed-libFuzzer-orange.svg)](fuzz/)

**One carving contract, one single-pass sweep engine — the same carver recovers a
deleted artifact from unallocated disk *and* from a memory image.**

`forensic-carve` is the SecurityRonin fleet's carving foundation. A per-format
**carver** sees only `&[u8]` windows, so it is medium-agnostic by construction; the
**sweep engine** runs one aho-corasick detection pass over supplied regions (disk
unallocated extents or memory VAD regions), materializes only the window each hit
needs (detection ≠ materialization — a large artifact is never truncated to a scan
chunk), and hands it to the matching carver.

## A carver is tiny

```rust
use forensic_carve::{Carver, Signature, CarveContext, CarvedItem, RecoveryMethod};

struct SqliteCarver;

impl Carver for SqliteCarver {
    fn format(&self) -> &'static str { "sqlite" }
    fn signatures(&self) -> &[Signature] {
        const S: &[Signature] = &[Signature::new(b"SQLite format 3\0", 0)];
        S
    }
    fn max_window(&self) -> u64 { 1 << 30 }
    fn carve(&self, window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
        // validate the header, bound the DB, then:
        vec![CarvedItem::artifact_bytes(
            "sqlite", ctx.base_offset(), 0.9,
            ctx.recovery_method(),          // echoed — UnallocatedCarve on disk, MemoryCarve in RAM
            window.to_vec(),
        )]
    }
}
```

## One sweep, any medium

```rust
use forensic_carve::{sweep, Region, CarveOptions, RecoveryMethod, registered_carvers};

let opts = CarveOptions { recovery_method: RecoveryMethod::UnallocatedCarve, ..Default::default() };
let items = sweep(&source, unallocated_regions, &registered_carvers(), &opts);
// each item: the medium-neutral CarvedItem + its source offset + the region's attribution tag
```

`source` is any `RegionSource` (a positioned `read_at`): a disk `ImageSource`, or a
memory `VirtualAddressSpace` whose `read_virt` un-scatters physically-discontiguous
pages. Carvers register themselves with `inventory::submit!`, so a binary that
force-links them collects the whole set via `registered_carvers()` — the consumer
never depends on the parser crates.

## The recovery vocabulary

Every carved item carries a `RecoveryMethod` — *how* it was recovered, set by which
sweep ran (carving **is** a recovery method):

| Variant | Source |
|---|---|
| `Tombstone` | a deletion the filesystem recorded (`--deleted`) |
| `FileInternalCarve` | a located artifact's own slack (freelist/WAL/`ElfChnk`) |
| `UnallocatedCarve` | whole-image unallocated carving (`--unallocated`) |
| `MemoryCarve` | a memory image (process VA region or physical frame) |

## Trust, but verify

- **Input-fuzzed.** `fuzz_sweep` drives arbitrary bytes, out-of-range/zero-length
  regions, and arbitrary chunk sizes through the engine (138k+ execs, 0 crashes).
- **Panic-free by lint.** `unwrap_used`/`expect_used` are denied in production; the
  engine returns *no items* on any malformed input rather than panicking.
- **`#![forbid(unsafe_code)]`** — no `unsafe`, anywhere.

Governing design: SecurityRonin fleet ADR 0001 (*carving — one flag taxonomy, one
sweep engine, one contract*).
