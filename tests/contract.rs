//! Contract behaviour for `forensic-carve` (fleet ADR 0001 §2/§3/§8).
//!
//! RED first: these exercise the carving contract the crate must expose — the
//! medium-agnostic `Carver` trait over `&[u8]` windows, the `RecoveryMethod`
//! provenance vocabulary, plain-values `CarveContext`, and the medium-neutral
//! `CarvedItem` with its `Records` / `ArtifactBytes` payload split.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_carve::{
    CarveContext, CarvedItem, CarvedPayload, Carver, ConfidencePolicy, RecoveryMethod, Signature,
};

/// A minimal carver for a fake `ZZ` format, used to exercise the contract shape
/// without pulling in a real parser.
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
        64
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
fn recovery_method_has_the_four_fleet_variants() {
    // ADR 0001 §3 — carving IS a recovery method; the fleet vocabulary.
    let all = [
        RecoveryMethod::Tombstone,
        RecoveryMethod::FileInternalCarve,
        RecoveryMethod::UnallocatedCarve,
        RecoveryMethod::MemoryCarve,
    ];
    assert_eq!(all.len(), 4);
    // Stable serialization tokens (for the report-Evidence translation, ADR §2).
    assert_eq!(RecoveryMethod::Tombstone.as_str(), "tombstone");
    assert_eq!(
        RecoveryMethod::FileInternalCarve.as_str(),
        "file-internal-carve"
    );
    assert_eq!(
        RecoveryMethod::UnallocatedCarve.as_str(),
        "unallocated-carve"
    );
    assert_eq!(RecoveryMethod::MemoryCarve.as_str(), "memory-carve");
}

#[test]
fn signature_reports_magic_and_offset() {
    let s = Signature::new(b"SQLite format 3\0", 0);
    assert_eq!(s.magic(), b"SQLite format 3\0");
    assert_eq!(s.offset(), 0);
    // A mid-artifact magic anchors the window start correctly.
    let mid = Signature::new(b"ElfChnk", 512);
    assert_eq!(mid.offset(), 512);
}

#[test]
fn carver_is_object_safe_and_dispatches() {
    let carvers: Vec<&dyn Carver> = vec![&ZzCarver];
    assert_eq!(carvers[0].format(), "zz");
    assert_eq!(carvers[0].max_window(), 64);
    assert_eq!(carvers[0].signatures().len(), 1);

    let ctx = CarveContext::at(0x1000);
    let items = carvers[0].carve(b"ZZhello", &ctx);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].format(), "zz");
    assert_eq!(items[0].image_offset(), 0x1000);
    assert!((items[0].confidence() - 0.9).abs() < f32::EPSILON);
    assert_eq!(items[0].recovery_method(), RecoveryMethod::UnallocatedCarve);

    // A non-matching window yields nothing.
    assert!(carvers[0].carve(b"nope", &ctx).is_empty());
}

#[test]
fn carve_context_carries_plain_values_only() {
    // Base offset + confidence policy — no I/O handles, no VA translation.
    let ctx = CarveContext::at(42).with_policy(ConfidencePolicy::Minimum(0.7));
    assert_eq!(ctx.base_offset(), 42);
    assert!(matches!(ctx.policy(), ConfidencePolicy::Minimum(_)));
    // Default policy keeps everything (defaults live in the driver, ADR §8).
    assert!(matches!(
        CarveContext::at(0).policy(),
        ConfidencePolicy::KeepAll
    ));
}

#[test]
fn carved_item_payload_is_records_or_artifact_bytes() {
    let recs = CarvedItem::records("zz", 0, 0.5, RecoveryMethod::MemoryCarve);
    assert!(matches!(recs.payload(), CarvedPayload::Records));

    let art = CarvedItem::artifact_bytes(
        "sqlite",
        0x2000,
        0.8,
        RecoveryMethod::UnallocatedCarve,
        vec![1, 2, 3],
    );
    match art.payload() {
        CarvedPayload::ArtifactBytes(b) => assert_eq!(b, &[1, 2, 3][..]),
        CarvedPayload::Records => panic!("expected artifact bytes"),
    }
    assert_eq!(art.image_offset(), 0x2000);
}
