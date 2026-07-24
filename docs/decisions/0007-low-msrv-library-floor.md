# 7. Declared MSRV is a low library floor (1.75), not the dev toolchain pin

Date: 2026-07-24
Status: Accepted

## Context

The fleet separates the *dev toolchain* (what everyone builds/lints with) from
the *declared MSRV* (a downstream-facing promise). `rust-toolchain.toml` pins the
current stable — `channel = "1.96.0"` here — for consistent dev/CI builds. But
the declared MSRV is set by repo *role*: apps declare MSRV = the pin, while
published libraries keep a low, CI-verified MSRV as a deliberate compatibility
feature and README trust signal.

`forensic-carve` is a library — a contract + engine that other fleet crates
*link*, not a binary an examiner runs. It was initially set at MSRV 1.80, then
lowered to 1.75 in commit `39bd365` ("chore: lower MSRV 1.80 -> 1.75 (fleet
low-MSRV floor; matches winevt-carver)") — the low floor was widened to match a
peer carver crate so consumers on older toolchains can link it. The current state
is `Cargo.toml` `rust-version = "1.75"` with the README `Rust 1.75+` badge, while
`rust-toolchain.toml` pins 1.96.0.

## Decision

Declare `rust-version = "1.75"` (a low, CI-verified library floor), independent
of the `rust-toolchain.toml` dev pin (`1.96.0`). Raise the declared MSRV only if
the crate genuinely needs a newer-Rust feature — never merely to match the
toolchain — because raising a published library's MSRV narrows its crates.io
audience.

## Consequences

- Consumers on toolchains back to 1.75 can link the carving foundation.
- The crate builds and lints on the pinned 1.96.0 in dev/CI while promising only
  1.75 downstream; a low-MSRV CI job must hold the floor honest.
- New engine code must avoid post-1.75 language/stdlib features unless a
  deliberate MSRV bump is agreed.
