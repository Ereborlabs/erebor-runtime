# Phase 1: Core Config And Session Owners

Status: Done.

## Purpose

Split the core configuration and session modules so config parsing, validation,
surface planning, runner command planning, registry artifacts, and runner
execution each have an obvious owner.

## Scope

Touch only `crates/erebor-runtime-core`.

Primary files:

- `src/config.rs` - 4,600 lines.
- `src/session.rs` - 526 lines.
- `src/session_registry.rs` - 469 lines.

Target modules:

- `config.rs` as a thin root with public re-exports.
- `config/audit.rs` for `RuntimeAuditConfig`, surface logging configs, and an
  `AuditLoggingConfigValidator`.
- `config/session.rs` for `SessionLayerConfig`,
  `SessionInterceptionLayerConfig`, actor config, diagnostics, and
  interception capabilities.
- `config/session/plan.rs` for `SessionRunPlan` and `SessionAdoptPlan`.
- `config/runner.rs` as the runner root, with `runner/docker.rs` and
  `runner/linux_host.rs` owning command planners.
- `config/surfaces.rs` as the surface root, with browser, filesystem,
  terminal, terminal process mediation, and surface start-plan owners below it.
- `session.rs` as a thin runner root with `session/docker.rs` and
  `session/linux_host.rs`.
- `session_registry.rs` as a thin registry root with artifact-copy, record-IO,
  path, and clock helpers under `session_registry/`.

## Ownership Rules

- Do not add new clones while moving config. Preserve existing ownership unless
  a clone can be removed without changing API behavior.
- Validation that needs config context lives on the validated type or on a
  small validator owner instead of passing config slices through helper chains.
  Do not leave orphan `validate_*` functions.
- Real config defaults use `Default` impls or derives. Serde default hooks must
  stay private and delegate to `Default`.
- Do not keep builder-style `with_*` methods just to claim configurability. Use
  a constructor for complete config values and mutating `add_*`/`set_*` methods
  for accumulated command options.
- Runner command construction belongs to command planner structs, not to
  unowned helper functions.
- Registry file operations belong to `SessionRegistry` or a private artifact
  copy owner.
- Sibling concepts must stay in the same family: surfaces under
  `config/surfaces/`, runners under `config/runner/`, and owner tests beside
  the owner they exercise.
- Production free helpers must be private, stateless, local to an owner, and
  easier to read than a method. Everything else moves to an owner.

## Required Tests

Required code-backed tests live beside the changed core owners. Add or update
crate-local owner tests for config defaults, validators, runner planners,
surface planning, and registry artifact behavior; use `erebor-runtime-e2e` only
if a follow-up crosses the CLI/session lifecycle boundary.

```sh
cargo test -p erebor-runtime-core --all-targets --all-features
cargo test -p erebor-runtime-cli --all-targets --all-features --no-run
cargo fmt
git diff --check
```

Run the live lifecycle probe because config/session ownership affects runtime
startup:

```sh
docs/plans/ownership-oriented-module-cleanup/lifecycle-probe.md
```

## Acceptance

- Touched Rust files are split only where ownership/readability improves. Any
  touched file that remains above the 300-line guideline must have a concrete
  readability reason in the phase result.
- Public config and session APIs are preserved unless explicitly approved.
- Existing config tests still pass; add focused tests for any new validator or
  planner owner that was not directly covered.
- Phase 1 cannot be marked done without committed Rust tests for every changed
  config/session owner; shell probes only supplement those tests.
- The lifecycle probe passes or is marked `Blocked` with the exact host error.

## Stop Point

Stop after Phase 1 verification. Wait for user approval before Phase 2.

## Phase Result

State: Done.

Completed on 2026-07-05.

Plan hygiene update on 2026-07-05 tightened the phase rules to match the
follow-up implementation: validation/defaults are owner-owned, decorative
`with_*` APIs stay out, production free helpers are exceptions, and sibling
modules stay in family roots.

### Implementation Summary

- Split `erebor-runtime-core` config ownership into thin roots and owned
  modules for runtime parsing, audit logging, session/interception config,
  runner config, Docker/Linux-host command planning, surfaces, terminal process
  mediation, surface start planning, and config tests.
- Added the requested owner structs:
  - `AuditLoggingConfigValidator<'_>` owns audit surface validation.
  - `DockerSessionCommandPlanner` owns Docker command construction.
  - `LinuxHostSessionCommandPlanner` owns Linux-host command construction.
  - `SessionRecordIo<'_>` owns registry record read/write/list operations.
- Split `session.rs` into a thin runner root plus `session/docker.rs` and
  `session/linux_host.rs`.
- Split `session_registry.rs` into a registry root plus artifact-copy, record
  IO, path, clock, and test modules.
- Follow-up consistency pass moved sibling owners into their family roots:
  Docker/Linux-host command planners under `config/runner/`, filesystem and
  terminal process mediation under `config/surfaces/`, session plans under
  `config/session/plan.rs`, and surface start planning under
  `config/surfaces/start_plan.rs`.
- Colocated config tests with their owners and left only a tiny
  `config/test_prelude.rs` for shared test imports.
- Preserved runtime behavior. After follow-up review, intentionally narrowed a
  few public helper/builder-style APIs that had cleaner alternatives:
  `DockerSessionCommandOptions::new`,
  `LinuxHostSessionCommandOptions::new`, `DockerSessionMount::read_only`,
  `BrowserCdpSurfaceConfig::with_listen`,
  `BrowserCdpSurfaceConfig::with_browser_remote_debugging_port`, and
  `BrowserLaunchConfig::with_remote_debugging_port`. The public
  `docker_container_name_for_session` and `validate_policy_path` free
  functions were also removed in favor of owner-owned behavior.
- Replaced no-op option constructors with `Default::default`, made Docker
  mount read-only state explicit in `DockerSessionMount::new`, and replaced the
  lazy-browser two-step setter chain with
  `BrowserCdpSurfaceConfig::from_template_for_runtime_browser`.
- Replaced remaining command-option and plan `with_*` mutation chains with
  mutating owner methods such as `add_environment`, `add_mount`,
  `add_wrapper_program`, and `set_config_path`, avoiding unnecessary value
  moves.
- Folded config `default_*` helper functions into the owning `Default`
  impls/derives and removed the audit/process-mediation defaults modules.
- Moved remaining production free helper behavior into owners, including
  `AuditDebugMatcherValidator`, `SurfacePolicyResolver`,
  `PolicyPathValidator`, `DockerSessionEnvironment`, `DockerContainerName`,
  `LinuxHostSessionEnvironment`, `SessionInterceptionOperations`,
  `SessionArtifactCopier`, `SessionRegistryClock`, `SessionRegistryPath`,
  `SessionRegistryPathResolver`, and `LinuxHostTextBusyRetry`.
- Follow-up call-site edits touched
  `crates/erebor-runtime-cli/src/cli.rs`,
  `crates/erebor-runtime-audit/src/session_review.rs`,
  `crates/erebor-runtime-session/src/interception_backend.rs`,
  `crates/erebor-runtime-session/src/interception_setup.rs`, and
  `crates/erebor-runtime-session/src/surfaces/terminal/browser_cdp_process_mediation.rs`,
  plus selected `erebor-runtime-session` tests, only to consume the narrowed
  core API. The session owner split remains Phase 5.

### Line Counts

Existing files:

| File | Before | After |
| --- | ---: | ---: |
| `src/config.rs` | 4,600 | 50 |
| `src/config/filesystem_surface.rs` | 278 | moved to `src/config/surfaces/filesystem.rs` |
| `src/session.rs` | 526 | 241 |
| `src/session_registry.rs` | 469 | 275 |

New owner/test files:

| File | Lines |
| --- | ---: |
| `src/config/audit.rs` | 14 |
| `src/config/audit/level.rs` | 10 |
| `src/config/audit/runtime.rs` | 116 |
| `src/config/audit/surfaces.rs` | 292 |
| `src/config/audit/tests.rs` | 206 |
| `src/config/runner.rs` | 170 |
| `src/config/runner/docker.rs` | 277 |
| `src/config/runner/docker/tests.rs` | 252 |
| `src/config/runner/linux_host.rs` | 198 |
| `src/config/runner/linux_host/tests.rs` | 211 |
| `src/config/runtime.rs` | 137 |
| `src/config/runtime/tests.rs` | 121 |
| `src/config/session.rs` | 127 |
| `src/config/session/interception.rs` | 242 |
| `src/config/session/interception/tests.rs` | 197 |
| `src/config/session/plan.rs` | 279 |
| `src/config/session/plan/tests.rs` | 192 |
| `src/config/session/tests.rs` | 124 |
| `src/config/surfaces.rs` | 154 |
| `src/config/surfaces/browser.rs` | 156 |
| `src/config/surfaces/browser/tests.rs` | 32 |
| `src/config/surfaces/filesystem.rs` | 268 |
| `src/config/surfaces/filesystem/tests.rs` | 231 |
| `src/config/surfaces/start_plan.rs` | 136 |
| `src/config/surfaces/terminal.rs` | 79 |
| `src/config/surfaces/terminal/process_mediation.rs` | 28 |
| `src/config/surfaces/terminal/process_mediation/kinds.rs` | 74 |
| `src/config/surfaces/terminal/process_mediation/layer.rs` | 154 |
| `src/config/surfaces/terminal/process_mediation/runtime.rs` | 110 |
| `src/config/surfaces/terminal/process_mediation/settings.rs` | 189 |
| `src/config/surfaces/terminal/process_mediation/tests.rs` | 295 |
| `src/config/surfaces/terminal/process_mediation/values.rs` | 198 |
| `src/config/test_prelude.rs` | 17 |
| `src/session/docker.rs` | 127 |
| `src/session/linux_host.rs` | 175 |
| `src/session_registry/artifacts.rs` | 64 |
| `src/session_registry/clock.rs` | 12 |
| `src/session_registry/paths.rs` | 28 |
| `src/session_registry/record_io.rs` | 76 |
| `src/session_registry/tests.rs` | 83 |

All touched Rust files are under 300 lines.
The three follow-up session-crate call-site files were not part of the Phase 1
split target; two are under 300 lines and
`src/interception_backend.rs` remains a pre-existing over-300-line Phase 5
target.

### Owner Inventory

Before this phase, `config.rs` owned runtime parsing, audit config,
session/interception config, runner config, command planning, surfaces,
process mediation, and tests in one 4,600-line module. `session.rs` owned both
runner implementations and launcher coordination. `session_registry.rs` owned
registry lifecycle plus artifact copy, record IO, path sanitization, time, and
tests.

After this phase:

- `config/runtime.rs` owns `RuntimeConfig` parsing and validation routing.
- `config/audit/*` owns audit levels, surface configs, type-owned defaults, and
  `AuditLoggingConfigValidator`.
- `config/session.rs`, `config/session/interception.rs`, and
  `config/session/plan.rs` own session layer, actor/diagnostic config,
  interception config, capability reports, and session/adoption run plans.
- `config/runner.rs`, `config/runner/docker.rs`, and
  `config/runner/linux_host.rs` own runner config and command planning.
- `config/surfaces/*` owns surface layer/config conversion, policy resolution,
  filesystem config, and `SessionSurfaceStartPlan` construction.
- `config/surfaces/terminal/process_mediation/*` owns mediation layer
  validation, serde settings, runtime values, type-owned defaults, and
  compatibility aliases.
- Owner tests now sit beside the owner modules; `config/test_prelude.rs`
  centralizes only shared test imports.
- `session/*` owns runner execution by backend while `session.rs` stays the
  launcher/root.
- `session_registry/*` owns artifact copy, record IO, paths, clock, and
  registry tests.

### Copy And Clone Audit

No new data clones were introduced for the new owners. `AuditLoggingConfigValidator`
borrows the audit surface config, the command planner structs and validator
owner structs are zero-sized or borrow existing paths/config, and
`SessionRecordIo`/`SessionArtifactCopier` borrow registry/session paths. The
Docker/Linux-host command planners preserve the existing environment/argument
cloning behavior at command-construction boundaries. Command option updates now
mutate their owning option structs in place instead of returning moved builder
values. The Docker bridge listen rewrite uses a config-internal setter, and
lazy browser mediation now clones its template once inside
`BrowserCdpSurfaceConfig::from_template_for_runtime_browser`.

### Verification

- `cargo test -p erebor-runtime-core --all-targets --all-features`: passed,
  57 tests.
- `cargo test -p erebor-runtime-cli --all-targets --all-features --no-run`:
  passed.
- `cargo test --workspace --all-targets --all-features`: passed.
- `cargo fmt`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  passed.
- Lifecycle probe:
  - Sandboxed attempt was blocked by host permissions:
    `runtime interception broker I/O failed: Operation not permitted (os error 1)`.
  - Escalated host run passed.
  - Allowed command printed `erebor-lifecycle-allowed`.
  - Denied command failed closed with exit code 126.
  - Probe workspace:
    `/tmp/erebor-ownership-lifecycle.j2WLtJ`.
  - Audit evidence contained both `"type":"deny"` and `deny-raw-cdp`.

- `git diff --check`: passed.
