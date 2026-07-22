//! Disk↔memory conformance — the publish gate of fleet ADR 0001 §8/C2.
//!
//! The gate: **the SAME registered carver, run unchanged, must produce the SAME
//! `CarvedItem` over a disk (unallocated) adapter and a memory (VAD) adapter** —
//! the ONLY difference being the driver-set `RecoveryMethod`. A second consumer
//! that merely calls the same parser does not count; the proof is that one carver
//! sweeps two `RegionSource` adapters that differ only in medium.
//!
//! RED first: `MemoryLikeSource` reassembles the artifact bytes from
//! non-contiguous 4 KiB "pages" (mimicking a VA space). Until `read_at` stitches
//! across page boundaries it serves only the first page, so a magic living in a
//! later page is invisible to the memory sweep and the cross-medium equality
//! assertions fail. GREEN implements the reassembly; both mediums then agree.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_carve::{
    sweep, CarveContext, CarveOptions, CarvedItem, Carver, RecoveryMethod, Region, RegionSource,
    Signature,
};

const PAGE_SIZE: usize = 4096;
/// An 8-byte magic (ADR: real carvers anchor on a substantive signature, not a
/// two-byte accident). Placed in a *later* page so a naive single-page adapter misses it.
const MAGIC: &[u8] = b"CONFORM8";
const MAGIC_OFFSET: u64 = 5000;

/// A "disk-like" source: a single flat, contiguous byte span (an unallocated run).
struct DiskLikeSource(Vec<u8>);

impl RegionSource for DiskLikeSource {
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

/// A "memory-like" source: the *same* bytes split across non-contiguous 4 KiB
/// pages and reassembled on read, mimicking a VA space whose pages are scattered
/// across physical frames. It must return identical bytes to `DiskLikeSource` for
/// any given offset — only the storage layout differs.
struct MemoryLikeSource {
    pages: Vec<Vec<u8>>,
}

impl RegionSource for MemoryLikeSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        // RED: not yet reassembling across non-contiguous pages — serves only the
        // first page, so any offset beyond page 0 reads as end-of-source.
        let Some(page) = self.pages.first() else {
            return 0;
        };
        let off = offset as usize;
        if off >= page.len() {
            return 0;
        }
        let n = buf.len().min(page.len() - off);
        buf[..n].copy_from_slice(&page[off..off + n]);
        n
    }
}

/// The one carver used across both mediums. It anchors on an 8-byte magic, echoes
/// the driver-set recovery method, and is otherwise medium-agnostic — it never
/// learns whether it is sweeping disk or memory.
struct ConformCarver;

impl Carver for ConformCarver {
    fn format(&self) -> &'static str {
        "conform"
    }
    fn signatures(&self) -> &[Signature] {
        const SIGS: &[Signature] = &[Signature::new(MAGIC, 0)];
        SIGS
    }
    fn max_window(&self) -> u64 {
        16
    }
    fn carve(&self, window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
        if window.starts_with(MAGIC) {
            vec![CarvedItem::records(
                "conform",
                ctx.base_offset(),
                0.95,
                ctx.recovery_method(),
            )]
        } else {
            Vec::new()
        }
    }
}

/// Build the shared artifact bytes: 3 uniform 4 KiB pages with the magic in page 1.
fn artifact_bytes() -> Vec<u8> {
    let mut data = vec![b'.'; PAGE_SIZE * 3];
    let start = MAGIC_OFFSET as usize;
    data[start..start + MAGIC.len()].copy_from_slice(MAGIC);
    data
}

fn split_pages(data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(PAGE_SIZE).map(<[u8]>::to_vec).collect()
}

#[test]
fn same_carver_conforms_across_disk_and_memory_adapters() {
    let data = artifact_bytes();
    let disk = DiskLikeSource(data.clone());
    let memory = MemoryLikeSource {
        pages: split_pages(&data),
    };

    // Both adapters must be byte-identical at the artifact offset — differing only
    // in storage layout (flat span vs. scattered pages), not in content.
    let mut d = [0u8; 8];
    let mut m = [0u8; 8];
    assert_eq!(disk.read_at(MAGIC_OFFSET, &mut d), 8);
    assert_eq!(memory.read_at(MAGIC_OFFSET, &mut m), 8);
    assert_eq!(
        d, m,
        "adapters must return identical bytes for the same offset"
    );

    let carvers: Vec<&dyn Carver> = vec![&ConformCarver];
    let region = |tag: &'static str| {
        vec![Region {
            start: 0,
            len: data.len() as u64,
            tag,
        }]
    };

    // The SAME carver over the disk (unallocated) adapter…
    let disk_opts = CarveOptions {
        recovery_method: RecoveryMethod::UnallocatedCarve,
        ..CarveOptions::default()
    };
    let disk_items = sweep(&disk, region("disk"), &carvers, &disk_opts);

    // …and over the memory (VAD) adapter — same carver, same magic, same offset.
    let mem_opts = CarveOptions {
        recovery_method: RecoveryMethod::MemoryCarve,
        ..CarveOptions::default()
    };
    let mem_items = sweep(&memory, region("memory"), &carvers, &mem_opts);

    // Each medium finds exactly the one artifact.
    assert_eq!(disk_items.len(), 1, "disk sweep must find the artifact");
    assert_eq!(mem_items.len(), 1, "memory sweep must find the artifact");
    let disk_item = &disk_items[0].item;
    let mem_item = &mem_items[0].item;

    // Medium-agnostic identity: same offset, same format, same confidence, same payload.
    assert_eq!(disk_items[0].offset, MAGIC_OFFSET);
    assert_eq!(mem_items[0].offset, MAGIC_OFFSET);
    assert_eq!(disk_item.image_offset(), mem_item.image_offset());
    assert_eq!(disk_item.format(), mem_item.format());
    assert_eq!(disk_item.format(), "conform");
    assert_eq!(
        disk_item.confidence().to_bits(),
        mem_item.confidence().to_bits()
    );
    assert_eq!(disk_item.payload(), mem_item.payload());

    // The ONLY difference is the driver-set recovery method — proving the method
    // flows from the driver through the engine while the carver stays agnostic.
    assert_eq!(
        disk_item.recovery_method(),
        RecoveryMethod::UnallocatedCarve
    );
    assert_eq!(mem_item.recovery_method(), RecoveryMethod::MemoryCarve);
    assert_ne!(disk_item.recovery_method(), mem_item.recovery_method());
}
