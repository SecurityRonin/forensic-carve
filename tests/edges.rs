//! Sweep-engine edge behaviours — the defensive/boundary branches the happy-path
//! tests don't reach (empty pattern set, source shorter than the region, short-magic
//! carry dedup, negative artifact anchor, zero-length window). These are real,
//! reachable branches of the contract, exercised end-to-end.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_carve::{
    sweep, CarveContext, CarveOptions, CarvedItem, Carver, Region, RegionSource, Signature,
};

/// An in-memory positioned-read source for tests.
struct MemSource(Vec<u8>);

impl RegionSource for MemSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        let off = offset as usize;
        if off >= self.0.len() {
            return 0;
        }
        let n = buf.len().min(self.0.len() - off);
        buf[..n].copy_from_slice(&self.0[off..off + n]);
        n
    }
}

/// A `ZZ`-header carver (2-byte magic).
struct ZzCarver;
impl Carver for ZzCarver {
    fn format(&self) -> &'static str {
        "zz"
    }
    fn signatures(&self) -> &[Signature] {
        const SIGS: &[Signature] = &[Signature::new(b"ZZ", 0)];
        SIGS
    }
    fn max_window(&self) -> u64 {
        8
    }
    fn carve(&self, window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
        if window.starts_with(b"ZZ") {
            vec![CarvedItem::records(
                "zz",
                ctx.base_offset(),
                0.9,
                ctx.recovery_method(),
            )]
        } else {
            Vec::new()
        }
    }
}

#[test]
fn sweep_with_no_carvers_yields_nothing() {
    // Empty pattern set: the engine returns early (engine.rs `patterns.is_empty()`).
    let src = MemSource(b"ZZxx".to_vec());
    let carvers: Vec<&dyn Carver> = Vec::new();
    let items = sweep(
        &src,
        vec![Region {
            start: 0,
            len: 4,
            tag: (),
        }],
        &carvers,
        &CarveOptions::default(),
    );
    assert!(items.is_empty());
}

#[test]
fn sweep_stops_when_source_ends_before_the_region() {
    // Region claims 100 bytes but the source has 4; the second read returns 0 and
    // the loop breaks (engine.rs `if n == 0 { break }`). The single magic is found.
    let src = MemSource(b"ZZ..".to_vec());
    let carvers: Vec<&dyn Carver> = vec![&ZzCarver];
    let items = sweep(
        &src,
        vec![Region {
            start: 0,
            len: 100,
            tag: (),
        }],
        &carvers,
        &CarveOptions::default(),
    );
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].offset, 0);
}

#[test]
fn sweep_dedups_a_short_magic_fully_inside_the_carry() {
    // Two carvers of different magic lengths: the 8-byte magic forces overlap = 7,
    // so a 2-byte "AB" found in one chunk's fresh tail lands *fully inside* the next
    // chunk's carry — the dedup branch `abs_end <= chunk_new_start` (engine.rs).
    struct AbCarver;
    impl Carver for AbCarver {
        fn format(&self) -> &'static str {
            "ab"
        }
        fn signatures(&self) -> &[Signature] {
            const SIGS: &[Signature] = &[Signature::new(b"AB", 0)];
            SIGS
        }
        fn max_window(&self) -> u64 {
            4
        }
        fn carve(&self, window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
            if window.starts_with(b"AB") {
                vec![CarvedItem::records(
                    "ab",
                    ctx.base_offset(),
                    0.9,
                    ctx.recovery_method(),
                )]
            } else {
                Vec::new()
            }
        }
    }
    /// Never appears in the data — present only to make the longest magic 8 bytes.
    struct LongCarver;
    impl Carver for LongCarver {
        fn format(&self) -> &'static str {
            "long"
        }
        fn signatures(&self) -> &[Signature] {
            const SIGS: &[Signature] = &[Signature::new(b"LONGMGIC", 0)];
            SIGS
        }
        fn max_window(&self) -> u64 {
            8
        }
        fn carve(&self, _window: &[u8], _ctx: &CarveContext) -> Vec<CarvedItem> {
            Vec::new()
        }
    }

    // "AB" at offset 5 sits in chunk 0's fresh bytes [0,8) and then, with overlap 7,
    // wholly within chunk 1's carry (bytes [1,8)). It must be reported exactly once.
    let src = MemSource(b".....AB.........".to_vec()); // 16 bytes, "AB" at offset 5
    let carvers: Vec<&dyn Carver> = vec![&AbCarver, &LongCarver];
    let opts = CarveOptions {
        chunk_size: 8,
        ..CarveOptions::default()
    };
    let items = sweep(
        &src,
        vec![Region {
            start: 0,
            len: 16,
            tag: (),
        }],
        &carvers,
        &opts,
    );
    assert_eq!(
        items.len(),
        1,
        "the short magic must be reported once, not per-chunk"
    );
    assert_eq!(items[0].offset, 5);
}

#[test]
fn sweep_skips_a_hit_whose_anchor_would_underflow() {
    // A mid-artifact magic (offset 100) matched near the source start would put the
    // artifact start before 0; `checked_sub` yields None and the hit is skipped
    // (engine.rs `let Some(artifact_start) = abs_start.checked_sub(..) else`).
    struct DeepMagicCarver;
    impl Carver for DeepMagicCarver {
        fn format(&self) -> &'static str {
            "deep"
        }
        fn signatures(&self) -> &[Signature] {
            const SIGS: &[Signature] = &[Signature::new(b"MG", 100)];
            SIGS
        }
        fn max_window(&self) -> u64 {
            8
        }
        fn carve(&self, _window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
            vec![CarvedItem::records(
                "deep",
                ctx.base_offset(),
                0.9,
                ctx.recovery_method(),
            )]
        }
    }
    let src = MemSource(b"MG......".to_vec()); // "MG" at offset 0, anchor would be -100
    let carvers: Vec<&dyn Carver> = vec![&DeepMagicCarver];
    let items = sweep(
        &src,
        vec![Region {
            start: 0,
            len: 8,
            tag: (),
        }],
        &carvers,
        &CarveOptions::default(),
    );
    assert!(items.is_empty());
}

#[test]
fn sweep_skips_a_zero_length_window() {
    // A carver declaring `max_window == 0` yields a zero-length materialization
    // window, which the engine skips (engine.rs `if window_len == 0 { continue }`).
    struct ZeroWindowCarver;
    impl Carver for ZeroWindowCarver {
        fn format(&self) -> &'static str {
            "zw"
        }
        fn signatures(&self) -> &[Signature] {
            const SIGS: &[Signature] = &[Signature::new(b"ZW", 0)];
            SIGS
        }
        fn max_window(&self) -> u64 {
            0
        }
        fn carve(&self, _window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
            vec![CarvedItem::records(
                "zw",
                ctx.base_offset(),
                0.9,
                ctx.recovery_method(),
            )]
        }
    }
    let src = MemSource(b"ZWxxxx".to_vec());
    let carvers: Vec<&dyn Carver> = vec![&ZeroWindowCarver];
    let items = sweep(
        &src,
        vec![Region {
            start: 0,
            len: 6,
            tag: (),
        }],
        &carvers,
        &CarveOptions::default(),
    );
    assert!(items.is_empty());
}
