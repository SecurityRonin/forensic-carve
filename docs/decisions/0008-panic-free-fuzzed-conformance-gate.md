# 8. Panic-free by lint, input-fuzzed, and a disk↔memory conformance gate before publish

Date: 2026-07-24
Status: Accepted

## Context

The sweep engine is the crate's attacker-controllable parse surface: arbitrary
image/memory bytes as the source, arbitrary regions (including out-of-range and
zero-length), and an arbitrary chunk size (`fuzz/fuzz_targets/fuzz_sweep.rs:1`).
For an untrusted-input parser the fleet requires the static panic-free posture
*and* an empirical fuzz test — the lints make panics unreachable by construction;
the fuzzer tests that claim over N executions. It also required, uniquely for
this crate, a proof that the cross-medium thesis actually holds before publish.

The evidence:

- **Panic-free by lint.** `Cargo.toml` denies `unwrap_used` and `expect_used` in
  production (`#![cfg_attr(test, allow(...))]` re-permits them only in tests,
  `src/lib.rs:17`). The engine returns *no items* on any malformed input rather
  than panicking, using saturating/`checked` arithmetic and `let … else`
  fallbacks throughout (`src/engine.rs`), so bad regions or a truncated source
  yield an empty result, never a crash.
- **Input-fuzzed.** `fuzz_sweep` drives arbitrary bytes, regions, and chunk sizes
  through `sweep` (target `47805c5`); the README records 138k+ execs with 0
  crashes.
- **Defense-in-depth over coverage purism.** Provably-unreachable defensive
  guards are annotated `// cov:unreachable: <invariant>` and kept, not deleted to
  turn a line green (`src/engine.rs:104`,`126`,`157`); commit `f2b56d0` enables
  the 100% line-coverage gate with those exemptions.
- **Disk↔memory conformance gate.** Fleet ADR 0001 §8/C2 forbids publishing until
  the *same* registered carver produces the *same* `CarvedItem` over a disk
  (unallocated) adapter and a memory (VAD) adapter, differing only in the
  driver-set `RecoveryMethod`. `tests/conformance.rs` is that gate; its RED/GREEN
  pair (`7cd67d0`/`1c1c9be`) shows the memory adapter had to stitch
  non-contiguous 4 KiB pages before the two mediums agreed.

## Decision

Gate the crate's quality on three complementary controls:

1. **Static:** `unwrap_used`/`expect_used = deny` in production; `sweep` returns
   an empty result on any malformed input instead of panicking.
2. **Empirical:** a `fuzz_sweep` libFuzzer target over arbitrary source bytes,
   regions, and chunk sizes; robustness is reported as measured exec counts, not
   a bare "panic-free" absolute.
3. **Cross-medium correctness:** a disk↔memory conformance test proving one
   carver runs unchanged over both a contiguous disk source and a page-scattered
   memory source — the publish precondition of fleet ADR 0001 §8/C2.

Keep provably-unreachable defensive guards, annotated `// cov:unreachable`,
rather than deleting them to satisfy the coverage gate.

## Consequences

- The engine degrades to "no items" on hostile input rather than crashing a
  carving run; fuzzing backs the claim with evidence, and the README leads with
  the measured "input-fuzzed" evidence beside the qualified "panic-free by lint"
  posture (never a bare panic-free absolute).
- Publishing is blocked until the cross-medium thesis is demonstrated, so the
  "one carver, both media" promise is proven, not asserted.
- 100% line coverage holds with documented, intentionally-unreachable exemptions,
  preserving the defensive guards.
