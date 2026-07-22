//! Chunking robustness (fuzz-surfaced): the sweep must find a magic regardless of
//! `chunk_size` — a small chunk must not defeat detection of a longer magic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_carve::{
    sweep, CarveContext, CarveOptions, CarvedItem, Carver, Region, RegionSource, Signature,
};

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

struct LongCarver;

impl Carver for LongCarver {
    fn format(&self) -> &'static str {
        "long"
    }
    fn signatures(&self) -> &[Signature] {
        const SIGS: &[Signature] = &[Signature::new(b"LONGMAGX", 0)];
        SIGS
    }
    fn max_window(&self) -> u64 {
        16
    }
    fn carve(&self, window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
        if window.starts_with(b"LONGMAGX") {
            vec![CarvedItem::records(
                "long",
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
fn sweep_finds_magic_longer_than_chunk_size() {
    // 8-byte magic "LONGMAGX" at offset 3, with chunk_size 3 (< magic len).
    let src = MemSource(b"...LONGMAGX...".to_vec());
    let carvers: Vec<&dyn Carver> = vec![&LongCarver];
    let opts = CarveOptions {
        chunk_size: 3,
        ..CarveOptions::default()
    };
    let items = sweep(
        &src,
        vec![Region {
            start: 0,
            len: 14,
            tag: (),
        }],
        &carvers,
        &opts,
    );
    assert_eq!(
        items.len(),
        1,
        "an 8-byte magic must be found even when chunk_size (3) is smaller than it"
    );
    assert_eq!(items[0].offset, 3);
}
