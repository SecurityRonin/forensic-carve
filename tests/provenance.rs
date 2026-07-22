//! Recovery-method provenance flows driver → context → item (fleet ADR 0001 §3/§9).
//!
//! RED first: the fleet `RecoveryMethod` (unallocated vs memory vs file-internal) is
//! set by *which sweep ran*, not by the format, so a medium-agnostic carver can't
//! hard-code it. The driver puts it in `CarveOptions`; the engine threads it through
//! `CarveContext`; the carver echoes `ctx.recovery_method()`. So the *same* carver
//! stamps `UnallocatedCarve` on a disk sweep and `MemoryCarve` on a memory sweep.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_carve::{
    sweep, CarveContext, CarveOptions, CarvedItem, Carver, RecoveryMethod, Region, RegionSource,
    Signature,
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

/// A carver that echoes the context's recovery method — proving the carver stays
/// medium-agnostic and the method is the driver's to decide.
struct EchoCarver;

impl Carver for EchoCarver {
    fn format(&self) -> &'static str {
        "echo"
    }
    fn signatures(&self) -> &[Signature] {
        const SIGS: &[Signature] = &[Signature::new(b"EC", 0)];
        SIGS
    }
    fn max_window(&self) -> u64 {
        4
    }
    fn carve(&self, _window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
        vec![CarvedItem::records(
            "echo",
            ctx.base_offset(),
            0.9,
            ctx.recovery_method(),
        )]
    }
}

#[test]
fn carve_context_carries_the_recovery_method() {
    let ctx = CarveContext::at(0).with_method(RecoveryMethod::MemoryCarve);
    assert_eq!(ctx.recovery_method(), RecoveryMethod::MemoryCarve);
    // Default is the disk Tier-2 (`--unallocated`) case.
    assert_eq!(
        CarveContext::at(0).recovery_method(),
        RecoveryMethod::UnallocatedCarve
    );
}

#[test]
fn sweep_stamps_the_recovery_method_from_options() {
    let carvers: Vec<&dyn Carver> = vec![&EchoCarver];

    let memory = CarveOptions {
        recovery_method: RecoveryMethod::MemoryCarve,
        ..CarveOptions::default()
    };
    let items = sweep(
        &MemSource(b"ECxx".to_vec()),
        vec![Region {
            start: 0,
            len: 4,
            tag: (),
        }],
        &carvers,
        &memory,
    );
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].item.recovery_method(), RecoveryMethod::MemoryCarve);

    // Default options carve unallocated disk.
    let disk = sweep(
        &MemSource(b"ECxx".to_vec()),
        vec![Region {
            start: 0,
            len: 4,
            tag: (),
        }],
        &carvers,
        &CarveOptions::default(),
    );
    assert_eq!(
        disk[0].item.recovery_method(),
        RecoveryMethod::UnallocatedCarve
    );
}
