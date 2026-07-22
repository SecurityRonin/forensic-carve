//! `forensic-carve` — the SecurityRonin fleet carving contract and single-pass
//! sweep engine.
//!
//! This crate owns the medium-agnostic carving *contract* — the [`Carver`] trait,
//! [`Signature`], [`CarveContext`], [`CarvedItem`], and the [`RecoveryMethod`]
//! provenance vocabulary — plus (in later increments) the aho-corasick sweep engine
//! that runs one detection pass over disk-unallocated or memory regions and
//! dispatches capped windows to the matching carver.
//!
//! Fleet ADR 0001 (`ronin-issen/docs/decisions/`) is the governing design.
//!
//! Increment 1: the contract types only. The sweep engine lands in a later cycle.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
