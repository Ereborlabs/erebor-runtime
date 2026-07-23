# Phase 10: Transaction Catalog And Rollback Operator Workflow

Status: Done.

## Purpose

Expose committed revert artifacts as an operator-usable transaction catalog
instead of only a crate API.

Phase 9 proves rollback through Rust lifecycle tests, but the V3 manual probe
still cannot inspect or roll back through the CLI. This phase closes that
product/API gap and creates the same structured API shape a future GUI should
use.

## Scope

- Add a filesystem transaction catalog API in the owning runtime/filesystem
  crate. The CLI must be a thin frontend over this API; future GUI work should
  use the same API instead of parsing CLI output.
- Represent committed revert units as:
  - transaction: a session-work/promotion rollback unit;
  - subtransaction: a rollbackable child unit inside a transaction, initially
    one configured filesystem volume from the promotion manifest.
- Keep immutable ids separate from operator names:
  - immutable ids come from committed artifacts, such as session id,
    promotion/transaction id, and volume id;
  - default display handles are generated in a `git stash list`-style format;
  - custom names can be assigned and updated without rewriting committed
    rollback refs.
- Store mutable catalog metadata, such as custom names and per-subtransaction
  rollback state, in an auditable session-side catalog/journal. Do not mutate
  committed layer/preimage refs to rename entries.
- Add transaction catalog commands. Candidate shape for implementation:

```sh
erebor filesystem transactions list \
  --registry <workspace>/.erebor/sessions \
  --session <session-id>

erebor filesystem transactions show \
  --registry <workspace>/.erebor/sessions \
  --session <session-id> \
  tx@{0}

erebor filesystem transactions rename \
  --registry <workspace>/.erebor/sessions \
  --session <session-id> \
  tx@{0} "before dependency update"

erebor filesystem transactions rollback \
  --registry <workspace>/.erebor/sessions \
  --session <session-id> \
  tx@{0}

erebor filesystem transactions rollback \
  --registry <workspace>/.erebor/sessions \
  --session <session-id> \
  tx@{0}.sub@{1}
```

- `list` must show transactions and subtransactions for a session in a compact
  operator table with git-stash-like handles, for example:

```text
╭────────────────┬────────────────┬─────────┬──────┬────────────────────────────────────────┬─────────┬───────┬─────────╮
│ HANDLE         ┆ TYPE           ┆ STATE   ┆ NAME ┆ SESSION                                ┆ VOLUME  ┆ SUBTX ┆ CHANGES │
╞════════════════╪════════════════╪═════════╪══════╪════════════════════════════════════════╪═════════╪═══════╪═════════╡
│ tx@{0}         ┆ transaction    ┆ applied ┆ -    ┆ session-filesystem-transaction-catalog ┆ -       ┆ 2     ┆ 8       │
│ tx@{0}.sub@{0} ┆ subtransaction ┆ applied ┆ -    ┆ session-filesystem-transaction-catalog ┆ project ┆ -     ┆ 4       │
│ tx@{0}.sub@{1} ┆ subtransaction ┆ applied ┆ -    ┆ session-filesystem-transaction-catalog ┆ cache   ┆ -     ┆ 4       │
╰────────────────┴────────────────┴─────────┴──────┴────────────────────────────────────────┴─────────┴───────┴─────────╯
```

- `show` must display the changed paths and operations for a transaction or
  subtransaction. It should support machine-readable output, for example
  `--json`, so the same domain model can feed a future GUI.
- `rename` must assign or update an operator-visible name for a transaction or
  subtransaction while preserving immutable ids and audit history.
- `rollback` must accept either a transaction handle or a subtransaction
  handle:
  - rolling back a transaction restores all rollbackable subtransactions;
  - rolling back a subtransaction restores only that child unit, initially one
    filesystem volume;
  - state tracking must record partial rollback without pretending the whole
    transaction is restored.
- Resolve session filesystem storage from the session registry artifact instead
  of requiring callers to rebuild volume requests manually.
- Load the original filesystem volume config from the copied session
  `config.json`.
- Validate that the session has committed transaction/promotion artifacts.
- Add rollback APIs that can restore either:
  - the whole transaction/promotion;
  - one selected subtransaction/volume.
- Write auditable rollback records with:
  - session id
  - transaction/promotion id
  - selected transaction or subtransaction handle
  - restored subtransactions/volumes
  - refs used
  - success/failure state
- Make repeat rollback idempotent or fail closed with a clear already-restored,
  partially-restored, or not-applied reason.
- Add CLI tests for argument validation and artifact resolution.
- Add filesystem/session integration tests for successful rollback, missing
  session, missing transaction/promotion manifest, incomplete promotion
  journal, transaction list/show/rename, and subtransaction rollback.

## Non-Goals

- Do not change promotion semantics.
- Do not implement the GUI in this phase.
- Do not parse CLI output from future GUI code. The shared catalog API is the
  contract.
- Do not add session-work transactions or autocommit.
- Do not solve metadata exactness beyond the current Phase 9 guarantees.
- Do not add path-level subtransactions in this phase. The first
  subtransaction boundary is the configured filesystem volume.

## Lifecycle Probe Growth

Extend `lifecycle-probe.md` so the Phase 9 manual CLI success path performs
real transaction catalog inspection and CLI rollback instead of stopping at
promoted host state.

The live probe must:

- run a two-volume promoted session;
- delete mutable `work/promotions/<session-id>` before rollback;
- invoke `transactions list` and verify it shows one transaction with two
  subtransactions;
- invoke `transactions show` for the parent transaction and each
  subtransaction and verify changed paths are visible;
- rename one subtransaction and verify the list/show output carries the new
  name while immutable ids remain stable;
- roll back one subtransaction by handle and verify only that volume is
  restored while the other remains promoted;
- roll back the remaining transaction/subtransaction and verify both host
  directories are restored;
- verify rollback used committed promotion/preimage refs, not mutable work
  files;
- verify transaction catalog state and rollback audit records exist;
- rerun rollback for an already-restored subtransaction and prove the outcome
  is idempotent or fail-closed with a precise, documented reason;
- keep the Phase 9 failure probe passing.

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-filesystem --all-targets --all-features
cargo check -p erebor-runtime-cli --all-targets --all-features
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-filesystem --lib transaction_catalog
cargo test -p erebor-runtime-cli --all-targets --all-features
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle transaction_catalog -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

## Required Evidence

- Approved transaction/subtransaction command shape.
- Example `transactions list` output.
- Example `transactions show` output for a parent transaction and a
  subtransaction.
- Example `transactions rename` output or audit record.
- Example successful transaction rollback CLI output.
- Example successful subtransaction rollback CLI output.
- Example rollback audit record.
- Test names for CLI and lifecycle coverage.
- Full lifecycle probe output with transaction catalog CLI, not crate-only
  rollback.

## Acceptance

- A user can list, show, rename, and roll back filesystem transactions for a
  session using only registry/session inputs.
- A user can roll back a selected subtransaction by its generated or renamed
  handle.
- Rollback does not require manually reconstructing volume requests in code.
- Rollback works after mutable local promotion work files are removed.
- Rollback audit evidence identifies refs, selected transaction or
  subtransaction, and restored volumes.
- The transaction catalog API is structured enough for a future GUI to present
  the same list/show/rename/rollback operations.
- Repeated rollback is idempotent or fails closed without corrupting host state.

## Stop Point

Stop after Phase 10 verification. Wait for approval before metadata exactness
or larger backend work.

## Phase 10 Result

State: Done.

Implemented:

- Added filesystem crate transaction catalog APIs:
  `list_transaction_catalog`, `show_transaction_target`,
  `rename_transaction_target`, and `rollback_transaction_target`.
- Added transaction/subtransaction domain models for future GUI use without
  parsing CLI text.
- Added mutable catalog metadata and JSONL journal under
  `<session-dir>/filesystem/transaction-catalog/` for names, rollback state,
  selected handles, restored volumes, outcomes, and committed refs used.
- Catalog discovery uses committed promotion manifest refs, then checks out
  committed layer refs to show changed paths. Rollback works after deleting
  mutable `work/promotions/<session-id>`.
- Added selected-volume rollback so a subtransaction can restore only one
  configured filesystem volume.
- Added CLI commands:
  - `erebor filesystem transactions list`
  - `erebor filesystem transactions show <target>`
  - `erebor filesystem transactions rename <target> <name>`
  - `erebor filesystem transactions rollback <target>`
- Text output is table formatted with `comfy_table`; JSON output preserves the
  structured API model.
- Added lifecycle probe coverage:
  `linux_host_transaction_catalog_cli_rolls_back_subtransactions`.

Example text outputs:

```text
╭────────────────┬────────────────┬─────────┬──────┬────────────────────────────────────────┬─────────┬───────┬─────────╮
│ HANDLE         ┆ TYPE           ┆ STATE   ┆ NAME ┆ SESSION                                ┆ VOLUME  ┆ SUBTX ┆ CHANGES │
╞════════════════╪════════════════╪═════════╪══════╪════════════════════════════════════════╪═════════╪═══════╪═════════╡
│ tx@{0}         ┆ transaction    ┆ applied ┆ -    ┆ session-filesystem-transaction-catalog ┆ -       ┆ 2     ┆ 8       │
│ tx@{0}.sub@{0} ┆ subtransaction ┆ applied ┆ -    ┆ session-filesystem-transaction-catalog ┆ project ┆ -     ┆ 4       │
│ tx@{0}.sub@{1} ┆ subtransaction ┆ applied ┆ -    ┆ session-filesystem-transaction-catalog ┆ cache   ┆ -     ┆ 4       │
╰────────────────┴────────────────┴─────────┴──────┴────────────────────────────────────────┴─────────┴───────┴─────────╯
```

```text
╭────────────────┬─────────┬─────────────────────╮
│ HANDLE         ┆ OP      ┆ PATH                │
╞════════════════╪═════════╪═════════════════════╡
│ tx@{0}.sub@{0} ┆ create  ┆ generated           │
│ tx@{0}.sub@{0} ┆ create  ┆ generated/token.txt │
│ tx@{0}.sub@{0} ┆ delete  ┆ old-cache.txt       │
│ tx@{0}.sub@{0} ┆ replace ┆ settings.txt        │
╰────────────────┴─────────┴─────────────────────╯
```

```text
╭─────────────┬─────────────────┬────────────────────────────────────────┬──────────────────╮
│ STATUS      ┆ HANDLE          ┆ PROMOTION                              ┆ RESTORED_VOLUMES │
╞═════════════╪═════════════════╪════════════════════════════════════════╪══════════════════╡
│ rolled_back ┆ project restore ┆ session-filesystem-transaction-catalog ┆ project          │
╰─────────────┴─────────────────┴────────────────────────────────────────┴──────────────────╯
```

Verification:

```sh
cargo fmt
cargo check -p erebor-runtime-filesystem --all-targets --all-features
cargo check -p erebor-runtime-cli --all-targets --all-features
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-filesystem --lib transaction_catalog
cargo test -p erebor-runtime-cli --all-targets --all-features
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle transaction_catalog -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Results:

- Focused catalog unit test passed:
  `promotion::tests::transaction_catalog::catalog_lists_renames_and_rolls_back_subtransactions`.
- CLI argument coverage passed:
  `accepts_filesystem_transaction_catalog_commands` and
  `rejects_incomplete_filesystem_transaction_command`.
- Lifecycle probe passed outside the sandbox with the staged `ostree` binary:
  `linux_host_transaction_catalog_cli_rolls_back_subtransactions`.
- Rollback journal assertions cover promotion id, selected volume state,
  success/already-restored outcomes, and committed promotion/preimage refs.
- Full workspace tests and clippy passed.

Notes:

- The live lifecycle probe sets `core.min-free-space-percent=0` only on its
  temporary OSTree repo because this host is at 97% filesystem usage and OSTree
  otherwise refuses tiny test commits before Phase 10 behavior is reached.
