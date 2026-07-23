# Phase 4: CLI Command Owners

Status: Done.

## Purpose

Keep CLI code as wiring by splitting Clap definitions and command dispatch into
small command-owner modules without moving domain logic into the CLI crate.

## Scope

Touch only `crates/erebor-runtime-cli`.

Primary file:

- `src/cli.rs` - 1,802 lines.

Target modules:

- `cli.rs` as a thin root with `Cli`, top-level `Command`, and dispatch.
- `cli/start.rs` with start args and launch-plan wiring.
- `cli/session.rs` with session subcommands and session execution wiring.
- `cli/dev.rs` with development command wiring.
- `cli/policy.rs` with policy test wiring.
- `cli/audit.rs` with audit review/evidence command wiring.
- `cli/parsers.rs` for Clap value parsers.
- `cli/config_paths.rs` with config path resolution.
- Existing `cli/filesystem.rs` stays domain-specific CLI wiring and is not
  merged into the root.

## Ownership Rules

- Do not move audit rendering, policy evaluation internals, session execution,
  or runtime orchestration into CLI helpers.
- Command modules own argument structs and a small command owner that
  translates arguments into domain requests.
- CLI-local free functions are exceptions. Keep them private, stateless, local
  to the command owner, and only when they make argument wiring easier to read.
- Shared path resolution should be a named owner if it repeatedly needs the
  config base directory, current directory, environment, or output mode.
- Validation of CLI argument combinations belongs to the argument type or
  command owner. Do not leave stray `validate_*` functions in the root.
- Avoid decorative `with_*` APIs for command options. Use constructors for
  complete request values and explicit setters for accumulated CLI state.
- Defaults for CLI request/config values belong in `Default` impls or derives,
  not in `default_*` helpers.
- Keep command families consistent under `cli/`. Do not add a one-off top-level
  file for a command sibling unless it is the command family root.

## Required Tests

Required code-backed tests live beside CLI command owners for parser/dispatch
behavior. CLI behavior that must prove command owners through the real binary
belongs in `erebor-runtime-e2e` fixture owners.

```sh
cargo test -p erebor-runtime-cli --all-targets --all-features
cargo test -p erebor-runtime-e2e --test cli_command_owners --all-features
cargo test --workspace --all-targets --all-features --no-run
cargo fmt
git diff --check
```

Run the live lifecycle probe because CLI session wiring is touched:

```sh
docs/plans/ownership-oriented-module-cleanup/lifecycle-probe.md
```

## Acceptance

- Touched Rust files are split only where ownership/readability improves. Any
  touched file that remains above the 300-line guideline must have a concrete
  readability reason in the phase result.
- CLI help, parsing, aliases, restrictive Clap behavior, and error mapping are
  unchanged.
- Add tests for any command parsing path that was previously only covered by
  incidental integration tests.
- Add a real CLI e2e fixture for cross-crate command-owner behavior; do not rely
  only on unit tests or manual command probes for policy/audit/session wiring.
- `erebor-runtime-cli` remains wiring only.
- Focused item inventory shows remaining CLI free functions are private,
  stateless, local to command owners, and justified in the phase result.

## Stop Point

Stop after Phase 4 verification. Wait for user approval before Phase 5.

## Phase Result

State: Done.

Completed on 2026-07-06.

### Implementation Summary

- Replaced the 1,805-line `crates/erebor-runtime-cli/src/cli.rs` root with an
  87-line Clap root that owns only `Cli`, top-level `Command`, logging
  initialization, and dispatch.
- Added command-owner modules:
  - `cli/start.rs` owns `start` args, start-plan loading, and launch-plan
    wiring.
  - `cli/session.rs` owns session command dispatch and session execution
    request translation; `cli/session/args.rs` owns the session Clap argument
    family.
  - `cli/dev.rs` owns `dev proxy-cdp` launch-plan wiring.
  - `cli/policy.rs` owns policy-test command input loading and CLI output.
  - `cli/audit.rs` owns audit tail and evidence-trace command wiring.
  - `cli/parsers.rs` owns Clap value parser hooks and shared CLI output format.
  - `cli/config_paths.rs` owns config-relative path resolution through
    `ConfigPathResolver` and config loading through `RuntimeConfigLoader`.
- Kept `cli/filesystem.rs` as the filesystem command family and updated
  `cli/filesystem/storage.rs` to use `ConfigPathResolver` instead of a root
  free function.
- Split the former monolithic CLI test block into root Clap parsing tests plus
  owner-adjacent tests for start, dev, session, and config-path behavior.
- Added a Phase 4 e2e CLI command fixture under `erebor-runtime-e2e` that
  writes a real session registry, policy, event, audit JSONL, config artifact,
  and prompt artifact, then proves `policy test`, `audit tail`, and
  `audit evidence-trace` through the actual CLI binary.
- Updated root and engineering instructions plus ownership-plan wording so the
  300-line guideline is treated as a readability signal, not an absolute law.
- Updated root and engineering instructions plus every phase document so each
  implementation phase requires committed Rust tests in the crate owner or in
  `erebor-runtime-e2e` when the behavior crosses process/runtime boundaries.

### Behavior And API

- Public CLI behavior is intended to be unchanged: command names, aliases,
  restrictive Clap parsing, JSON/text output options, and error mappings are
  preserved.
- No new public crate API was added. The new modules and owners are internal
  CLI wiring.
- `erebor-runtime-cli` remains wiring only: runtime launch, session execution,
  policy evaluation, audit rendering, and filesystem transaction behavior still
  live in their owning crates.
- Code-backed cross-crate proof lives in
  `crates/erebor-runtime-e2e/tests/cli_command_owners.rs` because the test must
  exercise the compiled CLI binary plus policy/audit/session-registry crates.

### Line Counts And Readability

No touched CLI Rust file remains above the 300-line guideline. The root Clap
parsing test file is intentionally kept as one 293-line suite because those
tests assert top-level command-family behavior; splitting them further would
scatter the CLI contract more than it would help.

| File | Lines |
| --- | ---: |
| `crates/erebor-runtime-cli/src/cli.rs` | 87 |
| `crates/erebor-runtime-cli/src/cli/audit.rs` | 155 |
| `crates/erebor-runtime-cli/src/cli/config_paths.rs` | 94 |
| `crates/erebor-runtime-cli/src/cli/config_paths/tests.rs` | 75 |
| `crates/erebor-runtime-cli/src/cli/dev.rs` | 107 |
| `crates/erebor-runtime-cli/src/cli/dev/tests.rs` | 39 |
| `crates/erebor-runtime-cli/src/cli/filesystem.rs` | 170 |
| `crates/erebor-runtime-cli/src/cli/filesystem/render.rs` | 203 |
| `crates/erebor-runtime-cli/src/cli/filesystem/storage.rs` | 58 |
| `crates/erebor-runtime-cli/src/cli/parsers.rs` | 74 |
| `crates/erebor-runtime-cli/src/cli/policy.rs` | 117 |
| `crates/erebor-runtime-cli/src/cli/session.rs` | 172 |
| `crates/erebor-runtime-cli/src/cli/session/args.rs` | 190 |
| `crates/erebor-runtime-cli/src/cli/session/tests.rs` | 159 |
| `crates/erebor-runtime-cli/src/cli/start.rs` | 72 |
| `crates/erebor-runtime-cli/src/cli/start/tests.rs` | 142 |
| `crates/erebor-runtime-cli/src/cli/test_support.rs` | 112 |
| `crates/erebor-runtime-cli/src/cli/tests.rs` | 293 |
| `crates/erebor-runtime-e2e/tests/cli_command_owners.rs` | 95 |
| `crates/erebor-runtime-e2e/tests/support/cli_commands.rs` | 229 |

### Focused Item Inventory

- Remaining CLI free-function exceptions:
  - `cli/parsers.rs` contains Clap value parser hooks
    (`parse_ws_url`, `parse_non_empty_path`, `parse_non_empty_string`,
    `parse_positive_pid`). These are stateless framework hooks and keeping them
    as functions makes the Clap attributes easier to read.
  - `cli/filesystem/render.rs` keeps private, stateless table-formatting
    helpers local to the filesystem render owner.
  - `cli/filesystem.rs::execute` remains the existing filesystem command-family
    entrypoint called by the top-level dispatcher.
- Phase 4 e2e fixture support has no loose helper functions; path serialization
  and artifact writing are methods on `CliCommandFixture`.
- No new `validate_*`, `default_*`, or decorative `with_*` APIs were added.
- Copy/clone audit:
  - command owners borrow parsed args;
  - `ConfigPathResolver` owns only the resolved config base path;
  - `RuntimeConfigLoader` returns an owned `RuntimeConfig`;
  - path clones are limited to natural ownership transfer into existing domain
    request types and SNAFU error context.
  - `CliCommandFixture` owns its temp-workspace paths and serializes path
    strings into JSON fixtures; no runtime behavior or command-owner API needed
    extra copies.

### Verification

- `cargo test -p erebor-runtime-cli --all-targets --all-features` passed: 28
  passed.
- `cargo test -p erebor-runtime-e2e --test cli_command_owners --all-features -- --nocapture`
  passed: 1 passed.
- `cargo test --workspace --all-targets --all-features --no-run` passed.
- `cargo fmt` ran, and `cargo fmt --check` passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  passed.
- `git diff --check` passed.
- Live lifecycle probe:
  - sandboxed run was blocked by host mediation permissions:
    `runtime interception broker I/O failed: Operation not permitted (os error
    1)`.
  - rerun outside the sandbox passed.
  - allowed command printed `erebor-lifecycle-allowed`.
  - denied command failed closed with exit code 126 and
    `raw CDP process launch is denied`.
  - audit evidence contained `"type":"deny"` and `deny-raw-cdp`.
  - probe workspace: `/tmp/erebor-ownership-lifecycle.NMAZPI`.
