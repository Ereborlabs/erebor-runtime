# Phase 0: Baseline Inventory And Ownership Contract

Status: Done.

## Purpose

Lock the current source-tree baseline before any code movement. This phase
prevents a cosmetic split by forcing an owner map, loose-function inventory,
line-count map, and test contract for every crate.

## Scope

- Regenerate the all-file Rust inventory from the current tree.
- Confirm Cargo's package view and whether every package under `crates/` is
  covered by workspace checks.
- Record every file over 300 lines and every file between 250 and 300 lines.
- Record production free-function clusters that may need owners even when the
  file is not large.
- For each oversized production file, write the intended owner modules before
  moving code.
- For each readability-harming free-function cluster, write the intended owner,
  validator, renderer, resolver, or lifecycle collaborator before moving code.
- For each oversized test file, write the fixture or scenario split before
  moving tests.
- For each later implementation phase, name the expected code-backed test or
  fixture location. Use crate-local owner tests for crate-local behavior and
  `erebor-runtime-e2e` fixture owners when behavior crosses crates, the CLI
  binary, sessions, browsers, process mediation, or lifecycle boundaries.
- Confirm no external source tree is part of this plan.

## Required Commands

```sh
cargo metadata --no-deps --format-version 1
find crates -maxdepth 2 -name Cargo.toml -print | sort
rg --files crates -g '*.rs' | sort | xargs wc -l | sort -nr
for f in $(rg --files crates -g '*.rs' | sort); do n=$(wc -l < "$f"); if [ "$n" -gt 250 ]; then printf '%s %s\n' "$n" "$f"; fi; done
rg -n "^(pub(\([^)]*\))? )?(struct|enum|trait|fn|async fn|const|static) |^impl( |<)" crates -g '*.rs'
cargo test --workspace --all-targets --all-features --no-run
git diff --check
```

## Deliverables

- Updated baseline section in `README.md` if the inventory has drifted.
- Phase-by-phase owner map for every oversized file.
- Phase-by-phase owner map for loose-function clusters that reduce readability.
- Near-threshold watch list for files between 250 and 300 lines.
- Verification note for `cargo metadata`, `cargo test --no-run`, and
  `git diff --check`.
- Test-location contract for later phases, including whether proof belongs
  beside crate owners or under `erebor-runtime-e2e`.

## Acceptance

- No production behavior changes.
- No code movement.
- Every crate, every Rust file, and every material loose-function cluster is
  accounted for by either an implementation phase, a test/fixture phase, a
  Phase 7 ownership sweep item, or a guard-only note.
- The user can approve Phase 1 with a concrete owner map.

## Locked Ownership Contract

Every later phase must apply this contract before it is marked done:

- Production free functions are exceptions, not the default shape. Keep them
  private, stateless, local to an owner, and document why a method would make
  the code harder to follow.
- Functions that validate, normalize, resolve paths, copy artifacts, render,
  hash, redact, manage clocks, or coordinate IO/lifecycle belong to the owning
  type or to a named owner/validator/collaborator.
- Real defaults use `Default` impls or derives. `default_*` helpers are allowed
  only as private serde/protocol hooks that delegate to `Default`.
- Avoid decorative `with_*` methods. Use constructors for complete values and
  explicit `add_*`/`set_*` methods for accumulated owners.
- Keep sibling concepts under the same family root and owner tests beside the
  owner module. Shared test prelude files may centralize imports only.
- Every implementation phase must add or update committed Rust tests. Use
  crate-local owner tests for crate-local behavior and e2e fixture owners for
  cross-crate, CLI, session, browser/CDP, process-mediation, or lifecycle
  behavior. Manual probes are evidence, not replacements.
- Do not introduce extra clones, copies, or moves while reorganizing ownership.

## Stop Point

Stop after the inventory and ownership contract are updated. Wait for user
approval before Phase 1.

## Phase Result

State: Done.

Completed on 2026-07-05.

No Rust code moved in this phase. No production behavior changed.

Plan hygiene update on 2026-07-05 tightened the ownership contract for future
phases without changing the Phase 0 inventory result.

## Inventory Result

Cargo package and workspace view:

- `cargo metadata --no-deps --format-version 1` passed.
- Cargo metadata reports 13 packages and 13 workspace members.
- `find crates -maxdepth 2 -name Cargo.toml -print | sort` found these 13
  package manifests:

```text
crates/erebor-runtime-audit/Cargo.toml
crates/erebor-runtime-cdp/Cargo.toml
crates/erebor-runtime-cli/Cargo.toml
crates/erebor-runtime-core/Cargo.toml
crates/erebor-runtime-e2e/Cargo.toml
crates/erebor-runtime-error/Cargo.toml
crates/erebor-runtime-events/Cargo.toml
crates/erebor-runtime-filesystem/Cargo.toml
crates/erebor-runtime-ipc/Cargo.toml
crates/erebor-runtime-policy/Cargo.toml
crates/erebor-runtime-session/Cargo.toml
crates/erebor-runtime-telemetry/Cargo.toml
crates/erebor-runtime-terminal/Cargo.toml
```

Rust line-count result:

- Owned Rust source and test files total 47,213 lines.
- 26 Rust files are over the 300-line readability guideline.
- The oversized-file table in `README.md` matches the current source tree.
- The crate treatment table in `README.md` accounts for every crate as an
  implementation phase, a test/fixture phase, or guard-only/no-package note.

Near-threshold watch list, generated with the Phase 0 command for files over
250 lines and filtered to files that are still under or equal to 300 lines:

| File | Lines | Phase treatment |
| --- | ---: | --- |
| `crates/erebor-runtime-filesystem/src/checkpoint/tests.rs` | 296 | Guard-only watch list; filesystem crate has no over-300 files. |
| `crates/erebor-runtime-session/src/session_side_resources.rs` | 295 | Phase 5 watch list; avoid growing session lifecycle helpers. |
| `crates/erebor-runtime-ipc/src/v1.rs` | 294 | Guard-only watch list unless Phase 5 explicitly approves IPC codec reuse. |
| `crates/erebor-runtime-session/tests/filesystem_surface_lifecycle/linux_host/support.rs` | 291 | Phase 6 watch list; split support if lifecycle tests add setup. |
| `crates/erebor-runtime-core/src/runtime.rs` | 285 | Phase 1 watch list; keep runtime orchestration stable. |
| `crates/erebor-runtime-session/src/os/linux/process_guard/file_interception.rs` | 284 | Phase 5 watch list; split only if guard ownership changes require it. |
| `crates/erebor-runtime-filesystem/src/error.rs` | 284 | Guard-only watch list; split before adding error variants. |
| `crates/erebor-runtime-filesystem/src/promotion/preimage.rs` | 281 | Guard-only watch list. |
| `crates/erebor-runtime-filesystem/src/promotion.rs` | 281 | Guard-only watch list. |
| `crates/erebor-runtime-audit/src/tests.rs` | 279 | Phase 2 watch list; move tests with audit owner splits if needed. |
| `crates/erebor-runtime-core/src/config/filesystem_surface.rs` | 278 | Phase 1 watch list; moved to `config/surfaces/filesystem.rs` during Phase 1. |
| `crates/erebor-runtime-filesystem/src/normalizer/tests.rs` | 275 | Guard-only watch list. |
| `crates/erebor-runtime-error/src/ext.rs` | 275 | Guard-only watch list; split before adding error extension behavior. |
| `crates/erebor-runtime-cli/src/error.rs` | 270 | Phase 4 watch list; split only if CLI error surface grows. |
| `crates/erebor-runtime-session/src/runtime_interception_broker/platform.rs` | 266 | Phase 5 watch list; avoid platform growth while process owners move. |
| `crates/erebor-runtime-filesystem/src/promotion/tests/multivolume.rs` | 265 | Guard-only watch list. |
| `crates/erebor-runtime-filesystem/src/storage.rs` | 264 | Guard-only watch list. |
| `crates/erebor-runtime-core/src/engine.rs` | 263 | Phase 1 watch list; keep engine owner small. |
| `crates/erebor-runtime-session/tests/filesystem_surface_lifecycle.rs` | 261 | Phase 6 watch list; split if lifecycle test root grows. |
| `crates/erebor-runtime-core/src/tests.rs` | 261 | Phase 1 watch list; move tests with core owner splits if needed. |
| `crates/erebor-runtime-session/tests/filesystem_surface_lifecycle/linux_host/overlay_multivolume_support.rs` | 258 | Phase 6 watch list. |
| `crates/erebor-runtime-filesystem/src/promotion/tests/transaction_catalog.rs` | 255 | Guard-only watch list. |
| `crates/erebor-runtime-filesystem/src/checkpoint/stage.rs` | 255 | Guard-only watch list. |
| `crates/erebor-runtime-session/src/surfaces/filesystem.rs` | 253 | Phase 5 watch list only if session surface ownership changes touch it. |
| `crates/erebor-runtime-session/src/adoption.rs` | 252 | Phase 5 watch list. |
| `crates/erebor-runtime-filesystem/src/metadata.rs` | 251 | Guard-only watch list. |

Item inventory:

- The required item inventory command completed successfully:

```sh
rg -n "^(pub(\([^)]*\))? )?(struct|enum|trait|fn|async fn|const|static) |^impl( |<)" crates -g '*.rs'
```

- The output confirms the owner clusters captured in the README phase map:
  core config and session planning, audit review/evidence pipelines, CDP proxy
  and browser ownership, CLI command wiring, session interception/process guard
  lifecycle, terminal mediation, and test fixture clusters.
- The full command output is intentionally not embedded because it is thousands
  of lines; future implementation phases must re-run focused item inventories
  for the files they move and include before/after item lists in that phase
  result.

External source trees:

- No external source tree is part of this plan.
- The external source trees named by the root agent instructions and local
  reference trees remain out of scope for implementation.

## Verification Result

```text
cargo metadata --no-deps --format-version 1
passed

find crates -maxdepth 2 -name Cargo.toml -print | sort
passed

rg --files crates -g '*.rs' | sort | xargs wc -l | sort -nr
passed

for f in $(rg --files crates -g '*.rs' | sort); do n=$(wc -l < "$f"); if [ "$n" -gt 250 ]; then printf '%s %s\n' "$n" "$f"; fi; done
passed

rg -n "^(pub(\([^)]*\))? )?(struct|enum|trait|fn|async fn|const|static) |^impl( |<)" crates -g '*.rs'
passed

cargo test --workspace --all-targets --all-features --no-run
passed

git diff --check
passed
```

`cargo test --workspace --all-targets --all-features --no-run` built all
workspace test targets without executing them, including:

- `erebor-runtime-audit`
- `erebor-runtime-cdp` unit tests, `proxy_e2e`, and `runtime_e2e`
- `erebor-runtime-cli`
- `erebor-runtime-core`
- `erebor-runtime-e2e` and `session_review`
- `erebor-runtime-error`
- `erebor-runtime-events`
- `erebor-runtime-filesystem`
- `erebor-runtime-ipc` and `contract`
- `erebor-runtime-policy`
- `erebor-runtime-session` unit tests, process guard test target, and session
  integration test targets
- `erebor-runtime-telemetry`
- `erebor-runtime-terminal`

The live lifecycle probe was not required for Phase 0 because this phase made
no runtime/session code changes.

## Next Approval Point

Phase 1, `Core Config And Session Owners`, is ready for user approval. Do not
start Phase 1 without explicit approval.
