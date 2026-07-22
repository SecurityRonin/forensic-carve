//! Carver inventory registration (fleet ADR 0001 §2/§8, M2).
//!
//! A parser crate registers its carver with
//! `inventory::submit! { CarverRegistration::new(&MY_CARVER) }`. Any binary that
//! force-links that crate then auto-collects the carver, and a consumer
//! (`issen`'s `CarverSelector`, `memf-carve`, `mem4n6`) reads the whole set via
//! [`registered_carvers`] **without depending on the parser crates directly** — the
//! decoupling keeps `memf-carve` free of the parser fleet.

use crate::Carver;

/// A carver registration submitted by a parser crate. Holds a `'static` reference to
/// the carver so it can live in the inventory's link-time set.
pub struct CarverRegistration {
    carver: &'static dyn Carver,
}

impl CarverRegistration {
    /// Register `carver` (a `'static` carver, typically a zero-field unit struct).
    #[must_use]
    pub const fn new(carver: &'static dyn Carver) -> Self {
        Self { carver }
    }

    /// The registered carver.
    #[must_use]
    pub fn carver(&self) -> &'static dyn Carver {
        self.carver
    }
}

inventory::collect!(CarverRegistration);

/// Every carver registered (via `inventory::submit!`) into the final binary.
///
/// Empty unless the binary force-links the producer crates — the same anchoring
/// discipline `issen-parsers` uses so dead-code elimination does not drop the
/// registrations.
#[must_use]
pub fn registered_carvers() -> Vec<&'static dyn Carver> {
    inventory::iter::<CarverRegistration>
        .into_iter()
        .map(CarverRegistration::carver)
        .collect()
}
