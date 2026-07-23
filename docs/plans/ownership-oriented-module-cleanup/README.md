# Ownership-Oriented Module Cleanup

Status: Phase 8 complete. Phases 0 through 8 have implementation results and
verification evidence recorded.

Parent plan: repo-wide code health and maintainability cleanup.

Planning baseline date: 2026-07-05.

## Goal

Make the owned runtime crates easier to follow by moving large files,
repeated-context helper clusters, and readability-harming loose functions into
responsibility-owned modules. The final shape should make ownership obvious:
concrete structs own lifecycle state, configuration, sinks, runtime handles,
and protocol context; traits exist only at real seams; pure helpers remain
private, stateless, and local.

This is an organization and ownership refactor. It must not change runtime
behavior unless an approved phase explicitly says so.

## Non-Negotiables

- Do not implement this plan until the user approves a phase.
- Implement one approved phase at a time, then stop for approval.
- Preserve behavior. If behavior must change to make ownership correct, stop
  and get approval before changing it.
- Use the 300-line guideline as a readability smell detector, not an absolute
  law. Prefer smaller owner-focused files when that makes ownership easier to
  follow, but keep cohesive owners, command families, or scenario tests together
  when splitting would make the code harder to read. Document any larger touched
  file and the readability reason for keeping it together.
- Do not create placeholder modules, unused public APIs, or dead traits.
- Do not add traits only to make a split look cleaner. Traits belong at
  platform, runtime, protocol, policy, sink, and test-double seams.
- Loose production free functions are prohibited by default. They are allowed
  only when private, stateless, local to an owner, and clearly easier to read
  than an owner method.
- Do not use line count as the only cleanup trigger. A short file with
  orphaned behavior can still be harder to read than a larger cohesive owner.
  Each implementation phase should audit loose functions in touched modules,
  Phase 7 performs the repo-wide verification/instruction lock, and Phase 8
  owns the filesystem-specific loose-function cleanup discovered by that
  inventory.
- Validation belongs to the validated type or to a named validator owner.
  Avoid orphan `validate_*` functions.
- Defaults belong in `Default` impls or derives. Avoid `default_*` helper
  functions unless a serde or protocol hook requires that exact spelling, and
  keep such hooks private.
- Avoid decorative `with_*` APIs. Prefer complete constructors, or explicit
  mutating owner methods such as `add_*` and `set_*` for accumulated state.
- Do not introduce unnecessary copies. Borrow read-only data, move values at
  natural ownership boundaries, and clone only when sharing across async tasks
  or long-lived owners requires it.
- Keep module roots thin. `foo.rs` may own the public surface and re-exports;
  behavior-heavy submodules live under `foo/`.
- Keep sibling concepts in the same family directory. Surfaces belong under a
  surface root, runners under a runner root, and owner tests beside the owner
  module where practical.
- Keep CLI code as wiring. Rendering, artifact lookup, policy/session logic,
  and runtime orchestration must stay in the owning domain crates.
- Every implementation phase must include real code-backed tests. Put tests
  beside the crate owner when behavior is crate-local; put fixture owners and
  integration tests in `erebor-runtime-e2e` when the behavior crosses crates,
  process boundaries, the CLI binary, browser/CDP, session mediation, or other
  lifecycle boundaries. Manual probes and shell scripts are evidence, not
  substitutes for committed Rust tests.
- Every implementation phase must include focused tests plus the live lifecycle
  probe in `lifecycle-probe.md` when it touches runtime/session behavior.
- Do not touch external source trees or unrelated dirty files.

## Ownership Style Contract

Use these rules while implementing every phase:

- If operations repeatedly pass the same state bundle, or if a loose function
  coordinates behavior that naturally belongs to a nearby type, make that
  bundle or type an owner with methods.
- If an operation validates, normalizes, resolves paths, reads/writes files,
  copies artifacts, renders output, hashes evidence, redacts content, manages a
  clock, or coordinates lifecycle state, it belongs to the type or owner that
  holds that context.
- If a transformation is pure and stateless, keep it private and close to the
  owner. Do not turn tiny pure transformations into unnecessary objects, but do
  not export them as loose utilities either.
- If a module coordinates IO or lifecycle, give it one named owner for that
  lifecycle. The caller should not juggle its internal handles.
- If a module parses or renders a contract, name the decoder/renderer and keep
  wire compatibility tests next to that owner.
- If a type has a real default, implement `Default`. `default_*` functions are
  only acceptable as private serde/protocol hooks that delegate to `Default`.
- Use `with_*` only when the API intentionally returns a new immutable value
  and the caller benefits from that shape. Accumulators should expose
  constructors plus `add_*` or `set_*` methods.
- If tests need many helper functions, create fixture owners or support modules
  instead of growing a single test file.
- If tests exercise a clear owner module, colocate them with that owner. Use a
  shared test prelude only for imports or tiny shared fixtures.
- Prefer module-local visibility. Use `pub(crate)` or `pub(super)` only where a
  sibling module genuinely needs the item.
- Keep all phase instructions grounded in current paths after each phase. If a
  concept moves into a family directory, future phases must name the family
  path and remove the stale one-off path.

## Baseline Summary

Commands run for this planning baseline and re-run during Phase 0:

```sh
cargo metadata --no-deps --format-version 1
rg --files crates -g '*.rs' | sort | xargs wc -l | sort -nr
find crates -maxdepth 2 -name Cargo.toml -print | sort
```

Observed baseline:

- Cargo metadata sees 13 owned packages under `crates/`.
- `crates/erebor-runtime-approvals`,
  `crates/erebor-runtime-linux-process-guard`, and
  `crates/erebor-runtime-server` currently contain no Rust source files and no
  package manifest.
- Owned Rust source and test files total 47,213 lines.
- 26 Rust files are over the 300-line readability guideline.
- 26 additional Rust files are between 251 and 296 lines and are tracked as the
  near-threshold watch list in
  `phase-0-baseline-inventory-and-ownership-contract.md`.
- The largest production files are:
  - `crates/erebor-runtime-core/src/config.rs` - 4,600 lines.
  - `crates/erebor-runtime-cdp/src/server.rs` - 2,106 lines.
  - `crates/erebor-runtime-cli/src/cli.rs` - 1,802 lines.
  - `crates/erebor-runtime-session/src/os/linux/process_guard.rs` - 1,522
    lines.
  - `crates/erebor-runtime-audit/src/session_review.rs` - 1,366 lines.
  - `crates/erebor-runtime-audit/src/evidence_trace.rs` - 1,227 lines.
  - `crates/erebor-runtime-cdp/src/browser.rs` - 1,099 lines.

## Crate Inventory

| Crate | Rust files | Files over 300 | Plan treatment |
| --- | ---: | ---: | --- |
| `erebor-runtime-approvals` | 0 | 0 | No implementation work unless it becomes a package. |
| `erebor-runtime-audit` | 10 | 3 | Phase 2. Split review, evidence, and filter owners. |
| `erebor-runtime-cdp` | 15 | 9 | Phase 3 complete. Server, browser, protocol, message, state, and tests are split into owner modules. |
| `erebor-runtime-cli` | 7 | 1 | Phase 4. Keep parsing/wiring in CLI; move command owners into modules. |
| `erebor-runtime-core` | 18 | 3 | Phase 1. Split config and session ownership first. |
| `erebor-runtime-e2e` | 7 | 0 | Guard only after Phase 3 lifecycle follow-up split e2e fixtures. |
| `erebor-runtime-error` | 3 | 0 | Guard only; no split needed. |
| `erebor-runtime-events` | 3 | 0 | Guard only; no split needed. |
| `erebor-runtime-filesystem` | 53 | 0 | Phase 8 complete. Production module-level functions are eliminated; remaining module-level functions 