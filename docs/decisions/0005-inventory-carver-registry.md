# 5. Carvers self-register via `inventory`, decoupling consumers from producers

Date: 2026-07-24
Status: Accepted

## Context

A carving consumer — `issen`'s carver selector, `memf-carve`, `mem4n6` — needs
the whole set of registered carvers, but each carver lives in its own PARSER
crate (`sqlite-forensic`, `winevt-carver`, hive `regf`/`hbin`, …). If the
consumer had to name every producer crate, `memf-carve` would depend on the
entire parser fleet, inverting the layer dependency rules (a memory-navigation
crate must not import PARSER crates) and coupling consumers to producers.

The repo uses `inventory` for link-time collection (`src/registry.rs`): a parser
crate submits `inventory::submit! { CarverRegistration::new(&MY_CARVER) }`;
`inventory::collect!(CarverRegistration)` (`src/registry.rs:32`) is the
collection point; and `registered_carvers()` returns every carver linked into the
final binary (`src/registry.rs:40`). The docstring records the intent: the
consumer "reads the whole set … *without depending on the parser crates
directly* — the decoupling keeps `memf-carve` free of the parser fleet"
(`src/registry.rs:1`–`8`). `Carver: Send + Sync` (`src/lib.rs:253`) so the set is
shareable across worker threads (the RED/GREEN pair `857b3e0`/`8d458ce`).

## Decision

Provide an `inventory`-based carver registry: `CarverRegistration::new(&carver)`
submitted by each producer crate, collected at `inventory::collect!`, and read by
consumers through `registered_carvers() -> Vec<&'static dyn Carver>`. Consumers
force-link the producer crates (the same anchoring discipline `issen-parsers`
uses so dead-code elimination does not drop registrations) and never name them as
direct dependencies.

## Consequences

- `memf-carve` and `issen` collect the full carver set without importing any
  parser crate, honoring the layer dependency direction.
- A new format carver becomes available to every consumer just by force-linking
  its crate — no consumer edit.
- The registry is empty unless the binary force-links the producers; the
  anchoring requirement is documented on `registered_carvers()`
  (`src/registry.rs:34`–`38`) so a missing carver is diagnosed as a link issue,
  not silently absent.
