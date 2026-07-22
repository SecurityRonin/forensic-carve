//! Carver inventory registration (fleet ADR 0001 §2/§8, M2).
//!
//! RED first: a binary that force-links a parser crate gets its `Carver`
//! auto-registered via `inventory::submit!`, and a consumer reads the whole set
//! through `registered_carvers()` WITHOUT depending on the parser crates directly.
//! This is the seam issen's `CarverSelector` and `mem4n6` use.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_carve::{
    registered_carvers, CarveContext, CarvedItem, Carver, CarverRegistration, Signature,
};

struct RegCarver;

impl Carver for RegCarver {
    fn format(&self) -> &'static str {
        "reg-test"
    }
    fn signatures(&self) -> &[Signature] {
        const SIGS: &[Signature] = &[Signature::new(b"RG", 0)];
        SIGS
    }
    fn max_window(&self) -> u64 {
        4
    }
    fn carve(&self, _window: &[u8], _ctx: &CarveContext) -> Vec<CarvedItem> {
        Vec::new()
    }
}

static REG_CARVER: RegCarver = RegCarver;
inventory::submit! { CarverRegistration::new(&REG_CARVER) }

#[test]
fn registered_carvers_collects_submitted() {
    let all = registered_carvers();
    assert!(
        all.iter().any(|c| c.format() == "reg-test"),
        "a submitted carver must appear in the inventory registry"
    );
}

#[test]
fn carver_registration_exposes_its_carver() {
    let reg = CarverRegistration::new(&REG_CARVER);
    assert_eq!(reg.carver().format(), "reg-test");
}
