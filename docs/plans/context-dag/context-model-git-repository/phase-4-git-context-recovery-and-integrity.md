# Phase 4: Recovery, Integrity, And Operational Boundaries

Status: Done.

## Purpose

Make the Git context repository safe to reopen after normal shutdown or an
abrupt process exit, expose explicit full-graph verification, and document the
performance and durability boundaries actually proved.

## Current Baseline

Phase 3 will provide direct scope refs, checked multi-ref transactions, and
ordered two-parent commits. It will prove normal returned success and rejected
preparation, but not killed-process behavior, stale-lock handling, full-graph
integrity, or startup cost.

## Ownership And Files

- Extend `crates/erebor-runtime-context/src/repository.rs` with bounded open and
  recovery behavior.
- Add `src/repository/inspect.rs` for read-only commit, parent, tree, object,
  ancestry, and full-verification methods owned by `ContextRepository`.
- Extend crate-owned errors in `src/error.rs`; do not return raw Gitoxide or IO
  errors from the public boundary.
- Add cross-process fixtures under
  `crates/erebor-runtime-e2e/tests/context_repository_recovery.rs` because
  process termination and shared-repository access cross the crate boundary.

## Open Versus Full Verification

`ContextRepository::open(...)` is deliberately bounded:

1. open exactly the requested bare repository;
2. validate SHA-256 format and supported repository configuration;
3. enumerate the repository-owned scope namespace;
4. reject symbolic or malformed scope refs;
5. resolve every scope head to an existing commit and its root tree;
6. expose the repository.

Open does not walk every ancestor, subtree, and blob. Reads validate every
object and object kind they touch. `ContextRepository::verify_full()` is the
explicit operation that walks every retained scope history and every object
required by its commits.

```text
open
  format -> direct refs -> head commits -> head root trees
                                          bounded by current ref count

read/inspect
  requested commit/path -> validate each touched object lazily

verify_full
  all retained refs -> all ancestors -> all trees -> all referenced blobs
                                                proportional to retained graph
```

This split avoids making every session restart proportional to its full history
while preserving an explicit integrity operation.

## Scope

- Provide read-only graph access for direct ref heads, commits, ordered parents,
  tree entries, exact object lookup, and ancestry checks. It returns Git facts
  only; it does not reconstruct actions, deliveries, runtime status, or a total
  cross-scope timeline.
- Enforce V2 write order in the repository owner: blobs, changed subtrees, root
  tree, commit, then compare-and-swap ref update.
- Treat objects left unreachable by an interrupted or rejected ref update as
  valid, harmless Git objects. No automatic cleanup runs.
- Reject any scope head that resolves to a missing object, non-commit target,
  missing root tree, malformed direct ref, or unsupported repository format.
- Make deeper missing/corrupt objects fail the exact read that touches them and
  fail `verify_full()` with typed object and path context.
- Exercise loose and packed direct refs and stale `.lock` files without reading
  reflogs as context state.
- Use Git's `fsck --full` only as an independent test oracle. Never invoke the
  Git executable as the production read or write path.

## Process-Crash Contract

- Subprocess fixtures terminate a writer after blob, subtree, root-tree, and
  commit writes, as well as immediately before and immediately after the
  repository owner calls Gitoxide to edit one or multiple refs. The latter are
  repository-owner boundaries, not a claim to interrupt Gitoxide between its
  internal preparation and physical commit steps.
- A stale ref lock is never silently deleted merely because it exists. Recovery
  follows the selected Gitoxide lock policy and returns a typed conflict when
  ownership or safety cannot be established.
- Subprocess fixtures also terminate before and after the multi-ref edit call.
  The phase records the exact durable ref set observed after reopen; it does
  not claim a probe inside Gitoxide's multi-ref physical commit.
- Erebor does not infer missing transaction intent from commit messages,
  timestamps, reflogs, or object reachability. If a killed multi-ref commit
  leaves individually valid refs at different old/new targets, inspection
  reports those facts and the caller must retry or reconcile at its own
  adapter boundary.
- Phase 3's normal-operation contract remains: stale preparation changes no
  checked ref; returned success reaches every requested target. Phase 4 does
  not turn that into an unproved crash-atomicity promise.
- The phase result distinguishes process-crash recovery from machine or power
  loss. It may claim power-loss durability only if object and ref fsync behavior
  is explicitly configured in the selected binding and independently tested.

## Checkpoint

- Restart tests cover every completed V2 operation from Phases 1–3 with loose
  and packed direct refs.
- Crate-local tests cover lazy and full integrity failures, packed refs, and a
  stale lock. Test-only failure injection supplies object write boundaries and
  the boundaries immediately before and after a Gitoxide ref-edit call.
- `erebor-runtime-e2e` subprocess fixtures cover abruptly exited writers,
  same-ref and distinct-ref writers in separate processes, stale locks, and
  before/after multi-ref edit observations. They do not claim a kill inside
  Gitoxide's physical multi-ref commit.
- Tests prove a later unrelated commit is not reported as available at an
  earlier pinned commit.
- A fixture with a valid head but corrupt deep ancestor proves bounded open does
  not scan history, the exact deep read fails, and `verify_full()` fails.
- Valid fixtures pass both repository inspection and `git fsck --full`; corrupt
  fixtures fail with the expected typed error.
- A scale fixture records wall time, object count, and repository size for:
  - 10,000 direct scope refs sharing existing commits;
  - a 100,000-commit retained graph with shared trees;
  - bounded open, ref enumeration, one append, and `verify_full()`.
- The phase defines no hard production SLA from one development machine. It
  does verify that ordinary open does not traverse the full 100,000-commit
  history and records a baseline for later regression comparison.
- Workspace formatting, tests, and Clippy pass with warnings denied.

## Acceptance

- Bounded open preserves exact object ids, parent order, tree entries, and
  scope heads from completed operations.
- Every exposed scope ref is direct and points to an existing commit with an
  existing root tree.
- Deeper corruption is never hidden: it fails lazy inspection and full
  verification with typed context.
- Process-crash behavior is backed by subprocess evidence and stated without a
  stronger cross-ref or power-loss claim.
- Recovery exposes only durable Git facts. It never guesses a replacement head,
  synthesizes rollback, or adds a transaction journal.
- Startup cost is bounded by repository open and current ref heads rather than
  all retained commits and blobs.
- The repository never turns unrelated commits into a total order or makes
  later content available at an earlier commit.

## Not In Scope

- automatic repair of corrupt objects or guessed ref heads;
- cross-ref reader snapshots or crash rollback for multi-ref commits;
- an unproved power-loss guarantee;
- ref deletion, archival refs, `git gc`, repacking policy, or object pruning;
- session-directory creation, policy input, audit fields, or adapter capture.

## Stop Point

Stop after repository recovery, explicit verification, subprocess behavior, and
scale boundaries are documented with evidence. Wait for Phase 5 approval before
wiring the repository into live session ownership.

## Phase Result

State: Done.

Completed on 2026-07-14.

### Implementation Summary

- Added `repository/inspect.rs`, owned by `ContextRepository`. It exposes only
  Git facts: validated direct scope refs, commits with ordered parents, trees
  with exact name bytes and modes, object lookup, ancestry, and explicit
  `verify_full()` reachability verification. It does not introduce an action,
  delivery, event, actor, or evidence layer.
- `ContextRepository::open` now validates the requested bare SHA-256
  repository's owned refs, every direct scope head, and each head's root tree.
  It intentionally does not walk ancestors, subtrees, or blobs. Reads validate
  only the objects they touch; `verify_full()` performs the iterative retained
  graph walk without recursive call-stack depth.
- Owned-ref enumeration and descendant conflict checks use Gitoxide's prefix
  iterator. This preserves the direct-ref namespace while avoiding a scan of
  every Git ref for each new scope.
- Full verification reports the exact tree/path/object when a referenced tree
  entry is missing or has the wrong kind. Its typed status preserves a nested
  context-object failure such as `NotFound` rather than flattening it into an
  unstructured Git error.
- Test-only termination configuration is feature-gated; production boundary
  calls are no-ops. Production behavior remains Git objects followed by
  Gitoxide ref edits; no test journal, recovery record, ref cleanup, reflog
  interpretation, or guessed rollback exists.

### Code Shape

- `repository/inspect.rs` is 315 lines because the immutable read surface and
  iterative full-graph traversal are both behavior owned by
  `ContextRepository`; splitting them would separate Git facts from the object
  validation that makes those facts safe to expose.
- The 304-line crate-local inspection scenario and the 407-line e2e fixture
  keep related graph/recovery assertions and the child-process dispatch in one
  readable flow. The e2e fixture does not share its process environment,
  metadata source, or scale setup with another runtime surface, so a generic
  test utility would obscure rather than improve ownership.

### Code-Backed Evidence

- Crate-local inspection tests cover completed root/fork/merge graphs, ordered
  parents, packed direct refs and objects, exact earlier-tree visibility, lazy
  deep-blob failure, malformed and symbolic refs, missing/non-commit heads,
  missing head trees, stale `.lock` files, and `git fsck --full` as an
  independent oracle.
- `erebor-runtime-e2e/tests/context_repository_recovery.rs` runs real child
  processes. It observes `process::exit` after object writes and immediately
  before/after Gitoxide single- and multi-ref edit calls; verifies same-ref CAS
  yields one winner; verifies independent scopes both advance; and proves a
  stale lock remains present after a restarted writer fails.
- The subprocess hooks can establish the durable state on either side of the
  Gitoxide call. They do not establish a kill point inside Gitoxide's opaque
  multi-ref transaction and therefore do not turn normal returned-success
  semantics into a crash-atomicity or power-loss guarantee.

### Development-Machine Scale Baseline

The explicitly ignored `context_repository_scale_baseline` fixture was run on
2026-07-14. It created 10,000 direct refs sharing the root commit and a
100,000-commit retained chain with shared trees, then reopened and verified the
repository:

```text
direct-ref fixture construction  350.621244 ms
100,000 one-parent appends       142.756919368 s
bounded open                     3.705653561 s
scope-ref enumeration            198.909146 ms
one append after reopen          1.821007 ms
verify_full                      20.716930526 s

reachable scope refs             10,002
reachable commits                100,002
reachable trees                  3
reachable blobs                  2
repository size                  24,350,272 bytes
```

The 10,000 direct refs are a test fixture written directly as valid Git ref
files so the measurement targets bounded open, enumeration, append, and full
verification rather than 10,000 serial test setup transactions. The fixture
defines no production SLA. The retained-chain time includes 100,000 ordinary
object writes and checked direct-ref updates on this development machine.

### Verification

```text
cargo fmt --all
  passed

cargo test -p erebor-runtime-context --all-targets --all-features
  passed: 29 tests

cargo test -p erebor-runtime-e2e --test context_repository_recovery
  passed: 5 tests, 1 ignored

cargo test -p erebor-runtime-e2e --test context_repository_recovery \
  context_repository_scale_baseline -- --exact --ignored --nocapture
  passed: 1 test in 170.71 s

cargo clippy --workspace --all-targets --all-features -- -D warnings
  passed

cargo test --workspace --all-targets --all-features
  blocked by host filesystem-test failures outside this phase:
  `erebor-runtime-filesystem` promotion tests could not create or copy their
  required test artifacts (`Operation not permitted` / missing manifest path).
  The focused rerun, `cargo test -p erebor-runtime-filesystem --all-targets
  --all-features`, reproduced four host `Operation not permitted` failures;
  every Phase 4 context and recovery test passed.
```

### Operational Boundary

- Reopen is bounded by current owned scope refs and their head/root-tree
  objects. It is not proportional to retained commit history or blob count.
- `verify_full()` is intentionally proportional to the retained graph and is
  the operation that discovers a missing deep blob or ancestor.
- A process exit after an object write can leave an unreachable object. It is a
  valid Git object and is neither treated as context state nor cleaned up.
- Returned success and stale preparation retain Phase 3's normal-operation
  contract. This phase adds no cross-ref reader snapshot, recovery journal,
  guessed replacement ref, inner Gitoxide crash-atomicity proof, or power-loss
  durability claim.

### Not Done In This Phase

- No ref deletion, archival ref, garbage collection, object pruning, repair,
  or retention policy was added.
- No session ownership, live adapter capture, context pin, policy input,
  audit projection, database, or universal tree/blob schema was added.
- A process kill inside Gitoxide's physical multi-ref commit and machine or
  power-loss durability remain unproved and explicitly outside this phase.
