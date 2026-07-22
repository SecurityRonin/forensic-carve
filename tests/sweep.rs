//! Sweep-engine behaviour (fleet ADR 0001 §2/§4/§8/C1).
//!
//! RED first: the engine runs ONE detection pass over supplied regions, converts a
//! magic hit to an absolute offset, materializes only the carver-declared window
//! (detection ≠ materialization), dispatches to the owning carver, wraps the
//! medium-neutral `CarvedItem` in a `SweptItem<R>` carrying the region tag, and
//! applies the confidence policy. Cross-chunk straddling magics are found (overlap)
//! and not double-reported (dedup).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_carve::{
    sweep, CarveContext, CarveOptions, CarvedItem, Carver, ConfidencePolicy, RecoveryMethod,
    Region, RegionSource, Signature,
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

/// A carver for a fake `ZZ` header format.
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
                RecoveryMethod::UnallocatedCarve,
            )]
        } else {
            Vec::new()
        }
    }
}

#[test]
fn sweep_finds_a_magic_and_dispatches_with_region_tag() {
    let src = MemSource(b"....ZZxx....".to_vec()); // ZZ at offset 4
    let regions = vec![Region {
        start: 0,
        len: 12,
        tag: "region-A",
    }];
    let carvers: Vec<&dyn Carver> = vec![&ZzCarver];
    let items = sweep(&src, regions, &carvers, &CarveOptions::default());
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].region, "region-A");
    assert_eq!(items[0].offset, 4);
    assert_eq!(items[0].item.image_offset(), 4);
    assert_eq!(items[0].item.format(), "zz");
}

#[test]
fn sweep_finds_magic_straddling_a_chunk_boundary() {
    // ZZ at offset 3-4 with chunk_size 4 crosses the boundary at 4.
    let src = MemSource(b"xxxZZyyy".to_vec());
    let regions = vec![Region {
        start: 0,
        len: 8,
        tag: 0u32,
    }];
    let carvers: Vec<&dyn Carver> = vec![&ZzCarver];
    let opts = CarveOptions {
        chunk_size: 4,
        ..CarveOptions::default()
    };
    let items = sweep(&src, regions, &carvers, &opts);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].offset, 3);
}

#[test]
fn sweep_dedups_overlap_no_double_report() {
    // A single ZZ must not be reported twice even with a tiny chunk + overlap.
    let src = MemSource(b"ZZ".to_vec());
    let regions = vec![Region {
        start: 0,
        len: 2,
        tag: (),
    }];
    let carvers: Vec<&dyn Carver> = vec![&ZzCarver];
    let opts = CarveOptions {
        chunk_size: 1,
        ..CarveOptions::default()
    };
    assert_eq!(sweep(&src, regions, &carvers, &opts).len(), 1);
}

#[test]
fn sweep_reports_absolute_offset_from_region_start() {
    let mut data = vec![b'.'; 100];
    data.extend_from_slice(b"..ZZ.."); // ZZ at source offset 102
    let src = MemSource(data);
    let regions = vec![Region {
        start: 100,
        len: 6,
        tag: "r",
    }];
    let carvers: Vec<&dyn Carver> = vec![&ZzCarver];
    let items = sweep(&src, regions, &carvers, &CarveOptions::default());
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].offset, 102);
    assert_eq!(items[0].item.image_offset(), 102);
}

#[test]
fn sweep_confidence_floor_drops_low_items_but_keepall_keeps_them() {
    struct LowCarver;
    impl Carver for LowCarver {
        fn format(&self) -> &'static str {
            "low"
        }
        fn signatures(&self) -> &[Signature] {
            const SIGS: &[Signature] = &[Signature::new(b"LO", 0)];
            SIGS
        }
        fn max_window(&self) -> u64 {
            4
        }
        fn carve(&self, _window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
            vec![CarvedItem::records(
                "low",
                ctx.base_offset(),
                0.5,
                RecoveryMethod::UnallocatedCarve,
            )]
        }
    }
    let carvers: Vec<&dyn Carver> = vec![&LowCarver];

    let floored = CarveOptions {
        confidence_policy: ConfidencePolicy::Minimum(0.7),
        ..CarveOptions::default()
    };
    assert!(sweep(
        &MemSource(b"LOxx".to_vec()),
        vec![Region {
            start: 0,
            len: 4,
            tag: ()
        }],
        &carvers,
        &floored
    )
    .is_empty());

    assert_eq!(
        sweep(
            &MemSource(b"LOxx".to_vec()),
            vec![Region {
                start: 0,
                len: 4,
                tag: ()
            }],
            &carvers,
            &CarveOptions::default() // KeepAll
        )
        .len(),
        1
    );
}
