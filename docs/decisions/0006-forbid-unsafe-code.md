# 6. `#![forbid(unsafe_code)]` — no bounded-unsafe exception is needed

Date: 2026-07-24
Status: Accepted

## Context

The fleet's default and goal is `unsafe_code = "forbid"` — a provable,
badge-able "zero places a crafted input can corrupt memory" — downgraded to
`"deny"` plus a bounded per-site `#[allow]` only where a real benefit justifies
it. The container readers that memory-map their evidence (`ewf`,
`memory-forensic`) take that downgrade for their `mmap` sites. `forensic-carve`
has no such need: it is a pure computation engine over caller-supplied `&[u8]`
windows and positioned reads through the `RegionSource` trait — it maps no files
and holds no raw pointers. Detection is `aho-corasick`; materialization is a
`Vec<u8>` plus a `read_at`.

The evidence: `Cargo.toml` sets `[lints.rust] unsafe_code = "forbid"`, and the
README carries the `unsafe forbidden` badge (which the fleet standard permits
only for genuinely `forbid` crates, not the `deny`+allow mmap crates).

## Decision

Set `#![forbid(unsafe_code)]` crate-wide. Do not take the `deny`+bounded-allow
downgrade, because the engine has no `unsafe` site to justify — no `mmap`, no raw
pointer, no FFI. Carry the `unsafe forbidden` README badge honestly.

## Consequences

- The crate wears the strongest, un-overridable memory-safety guarantee; the
  badge is earned, not over-claimed.
- Any future feature that would need `unsafe` (e.g. a zero-copy mmap source)
  cannot be added silently — `forbid` cannot be locally overridden, so it forces
  a deliberate ADR to downgrade to `deny` with a justified per-site allow.
- Combined with the panic-free lints and fuzzing (ADR 0008), the attacker-
  controllable parse surface has no memory-corruption class by construction.
