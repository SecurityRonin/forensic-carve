#![no_main]
//! The sweep engine is the crate's attacker-controllable parse surface: arbitrary
//! image/memory bytes as the source, arbitrary regions (including out-of-range and
//! zero-length), an arbitrary chunk size, dispatched to carvers. It must NEVER panic
//! — no OOB slice, no arithmetic overflow, no unbounded allocation.

use forensic_carve::{
    sweep, CarveContext, CarveOptions, CarvedItem, Carver, Region, RegionSource, Signature,
};
use libfuzzer_sys::fuzz_target;

struct FuzzSource<'a>(&'a [u8]);

impl RegionSource for FuzzSource<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        let off = usize::try_from(offset).unwrap_or(usize::MAX);
        if off >= self.0.len() {
            return 0;
        }
        let n = buf.len().min(self.0.len() - off);
        buf[..n].copy_from_slice(&self.0[off..off + n]);
        n
    }
}

/// A carver with realistic multi-length magics that returns artifact bytes, so the
/// engine's materialization + confidence paths are exercised on every hit.
struct FuzzCarver;

impl Carver for FuzzCarver {
    fn format(&self) -> &'static str {
        "fuzz"
    }
    fn signatures(&self) -> &[Signature] {
        const SIGS: &[Signature] = &[
            Signature::new(b"MZ", 0),
            Signature::new(b"regf", 0),
            Signature::new(b"ElfChnk\x00", 0),
            Signature::new(b"SQLite format 3\x00", 0),
        ];
        SIGS
    }
    fn max_window(&self) -> u64 {
        65536
    }
    fn carve(&self, window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
        if window.len() >= 4 {
            let take = window.len().min(64);
            vec![CarvedItem::artifact_bytes(
                "fuzz",
                ctx.base_offset(),
                0.5,
                ctx.recovery_method(),
                window[..take].to_vec(),
            )]
        } else {
            Vec::new()
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let src = FuzzSource(data);
    let carvers: Vec<&dyn Carver> = vec![&FuzzCarver];
    let len = data.len() as u64;
    let regions = vec![
        Region {
            start: 0,
            len,
            tag: 0u32,
        },
        Region {
            start: len / 2,
            len,
            tag: 1u32,
        }, // overlaps past end
        Region {
            start: len.saturating_add(1000),
            len: 50,
            tag: 2u32,
        }, // fully past end
        Region {
            start: 0,
            len: 0,
            tag: 3u32,
        }, // zero-length
    ];
    // First byte drives a small chunk_size (stresses overlap/dedup/clamp);
    // small max_window caps materialization.
    let opts = CarveOptions {
        chunk_size: usize::from(data.first().copied().unwrap_or(1)).max(1),
        max_window: 128,
        ..CarveOptions::default()
    };
    let _ = sweep(&src, regions, &carvers, &opts);
});
