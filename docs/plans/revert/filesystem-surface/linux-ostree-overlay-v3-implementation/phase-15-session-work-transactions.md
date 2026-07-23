# Phase 15: Session Work Transactions And Autocommit

Status: Implemented.

## Purpose

Move beyond session-end promotion/rollback toward reversible units of session
work.

The user goal for revert includes being able to recover from specific agent
actions. Phase 9 supports session-end promotion/rollback. This phase plans a
session-work transaction model: a bounded unit of filesystem work is committed
only when the user issues a commit or when a configured autocommit rule fires.

The user-facing concept is a transaction or session-work commit, not a
checkpoint. Existing `erebor/checkpoints/...` refs may remain an internal
storage artifact, but Phase 15 should not expose "checkpoint" as the product or
policy model.

## Recorded Decision

Autocommit is configured in runtime config. Explicit transaction commit,
rollback, list, show, and rename operations should follow the Phase 10 CLI/API
style.

## Scope

- Define session-work transaction semantics:
  - explicit user/runtime commit request through CLI/API;
  - explicit transaction list/show/rename/rollback through CLI/API;
  - autocommit at semantic boundaries selected in runtime config, such as
    action boundary, pre-approval, pre-mediation, or session finish.
- Define autocommit configuration fields and defaults in runtime config.
- Explicitly exclude timer-based or periodic background commits.
- Define quiescence requirements before a transaction commit:
  - process tree pause or cooperative barrier;
  - active writer fd detection;
  - timeout and fail-closed behavior.
- Commit session-work transaction layers without promoting to host.
- Maintain transaction lineage metadata:
  - transaction id;
  - commit source: user or autocommit;
  - autocommit rule id when applicable;
  - action/request id when available;
  - parent transaction id;
  - volume refs.
- Add revert-to-transaction semantics for:
  - session overlay state before promotion;
  - promoted host state only if matching preimages exist.
- Add CLI and crate API tests for list/show/rename/commit/rollback.
- Add tests for user-issued commit, autocommit at a configured boundary,
  active-writer refusal, and revert-to-transaction behavior.

## Non-Goals

- Do not add timer-based or periodic transaction commits.
- Do not introduce background promotion without explicit user approval.
- Do not make autocommit an operator command; it is config-driven.
- Do not claim exact action-level revert unless preimages exist for any host
  mutation involved.
- Do not skip the quiescence contract.

## Lifecycle Probe Growth

Extend the live probe with a governed Linux-host session:

- perform one governed action that replaces and creates files;
- enable a config-defined `session_finish` autocommit rule and prove it creates
  transaction A at session finish;
- issue an explicit CLI/API session-work commit for transaction B against the
  session storage;
- verify both transaction manifests and layer refs exist with lineage metadata
  that records user commit vs autocommit;
- verify active writer fd blocks a transaction commit with a clear reason;
- revert overlay state to transaction A;
- verify the filesystem state matches the selected transaction.

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-filesystem --all-targets --all-features
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-filesystem --lib session_work -- --nocapture
cargo test -p erebor-runtime-core --lib filesystem -- --nocapture
cargo test -p erebor-runtime-cli --all-targets --all-features filesystem -- --nocapture
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle session_work_transaction -- --test-threads=1 --nocapture
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle session_work_transaction -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

## Required Evidence

- Approved transaction list/show/rename/commit/rollback command/API shape.
- Approved autocommit runtime config and semantic trigger list.
- Quiescence contract.
- Transaction lineage manifest examples.
- Active-writer failure output.
- Lifecycle revert-to-transaction output.

## Acceptance

- Session-work transactions can be committed before session finish by explicit
  user commit.
- Configured autocommit can commit transactions only at approved semantic
  boundaries.
- No timer-based or periodic transaction commits exist.
- Transaction commits refuse to claim exactness while writers are active.
- Revert-to-transaction behavior is explicit about whether it affects overlay
  state, host state, or both.

## Stop Point

Stop after Phase 15 verification. Backend expansion is separate.

## Phase 15 Result

State: Done for the implemented Phase 15 boundary.

Implemented:

- Added `erebor-runtime-filesystem::session_work` owners for checkpoint-backed
  session-work commits, catalogs, rename, and overlay-state rollback.
- Session-work commits store committed manifests under
  `erebor/session-work/<session-id>/<transaction-id>/manifest`, with volume
  layer refs pointing at internal checkpoint refs.
- Transaction ids are sequential and human-auditable:
  `<session-id>.work-000001`, `<session-id>.work-000002`, and so on. No hash is
  used for the operator-visible transaction id.
- Lineage metadata records source (`user` or `autocommit`), autocommit rule id,
  optional action request id, parent transaction id, checkpoint ref, and volume
  layer refs.
- Added `surfaces.filesystem.revert.autocommit` runtime config. The first
  implemented boundary is `session_finish`; unsupported boundaries fail config
  validation instead of being accepted silently.
- Session finish now does:
  - promotion when `promote_on_session_finish = true`;
  - session-work autocommit when promotion is disabled and a `session_finish`
    autocommit rule is enabled;
  - legacy checkpoint-only commit when promotion is disabled and no autocommit
    rule is configured.
- Added `filesystem transactions commit --registry ... --session ... [--name]`
  for explicit user commits.
- Existing `filesystem transactions list/show/rename/rollback` can also operate
  on `work@{n}` session-work handles. Promoted host rollback remains `tx@{n}`;
  unpromoted session-work rollback restores overlay upperdir state and does not
  mutate the host.
- Session-work commit and rollback both go through quiescence checks. Active
  writer fds under the session/merged/upper paths fail closed before claiming an
  exact transaction.

Not done:

- `action_boundary`, `pre_approval`, and `pre_mediation` autocommit triggers
  are not accepted yet because the runtime has no implemented quiescent action
  barrier for those boundaries.
- There is no timer or periodic commit mechanism.
- Exact host rollback for session-work commits still requires promoted
  preimages; unpromoted `work@{n}` rollback is explicitly overlay-state only.
- Some cohesive owner files are over the 300-line readability target after this
  phase (`session_work/catalog.rs`, `commit.rs`, `rollback.rs`, and
  `state.rs`, plus the existing filesystem config/CLI command files). They are
  clippy-clean and ownership-local, but a follow-up organization pass should
  split loaders, models, renderers, and rollback materialization helpers before
  adding more behavior to them.

Verification:

- `cargo fmt`
- `cargo check -p erebor-runtime-filesystem --all-targets --all-features`
- `cargo check -p erebor-runtime-core --all-targets --all-features`
- `cargo check -p erebor-runtime-cli --all-targets --all-features`
- `cargo check -p erebor-runtime-session --all-targets --all-features`
- `cargo test -p erebor-runtime-filesystem --lib session_work -- --nocapture`
- `cargo test -p erebor-runtime-core --lib filesystem -- --nocapture`
- `cargo test -p erebor-runtime-cli --all-targets --all-features filesystem -- --nocapture`
- `cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle session_work_transaction -- --test-threads=1 --nocapture`
- `PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle session_work_transaction -- --test-threads=1 --nocapture`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-targets --all-features`

Lifecycle result:

- The sandboxed opt-in lifecycle run failed with runtime broker
  `Operation not permitted`, as expected for ptrace/socket/mount operations
  under the sandbox.
- The same opt-in lifecycle probe passed outside the sandbox with the required
  environment. It verified config-driven `session_finish` autocommit, explicit
  CLI user commit, session-work list/show by handle/name, active-writer
  refusal, and overlay-state rollback to the autocommitted transaction.
