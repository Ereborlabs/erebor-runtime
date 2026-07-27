# Phase 4: Codex Adapter, Final CLI Cutover, And App Server Migration

Status: Done — the daemon/client Codex path, complete nested Context DAG,
adapter-owned hook service, legacy-config removal inventory, same-UID/two-UID
isolation, and privileged live TTY lifecycle evidence are complete. Phase 5
remains separately scoped and unstarted.

## Approved Design Decisions

- A governed session has one daemon-owned I/O boundary. A normal interactive
  `erebor run ... codex` session uses the existing TTY/PTY attachment: the
  daemon owns the PTY and workload process, while the CLI relays terminal bytes
  through its exclusive input lease. Codex's TUI is not an App Server protocol.
- Terminal geometry is part of that governed I/O boundary, not an output-log
  convenience. Session creation records initial rows and columns. Only the
  exclusive controller/input lease may issue a later resize; the daemon applies
  it to its PTY and its foreground process group receives the normal resize
  notification. A read-only observer may neither write bytes nor resize. On
  disconnect the daemon retains the same PTY and workload; a later permitted
  controller attaches to it rather than launching a replacement. This is
  required Linux Phase 4 behavior, not deferred Docker parity.
- A certified `codex-app-server` entrypoint uses a distinct, typed, bounded
  JSON-RPC-over-stdio contract. The daemon owns the child pipes, validates
  frames, correlation, cancellation, EOF, and output before exposing them to
  the CLI. It is not implemented as a generic daemon-control or session-input
  byte passthrough.
- Nested workloads inherit the session's Linux namespace, guard, cgroup,
  filesystem projections, policy, and daemon-loss contract, but cannot gain
  trust. A raw child Codex process cannot reach the daemon socket, install a
  package, mint an alias, register an App Server, or impersonate the admitted
  App Server. The proposed
  [Codex Context DAG and child-agent subplan](phase-4-codex-context-dag/README.md)
  is the only route to a separately trusted child agent: it uses an explicit
  daemon-mediated child admission, not raw nested exec. Until that subplan is
  complete, nested Codex execution is governed only as a descendant effect and
  may be denied by policy.
- Codex hook admission binds the daemon session, guarded peer, ticket, and
  admitted agent-instance lineage. Inherited environment values alone never
  establish trusted hook or App Server identity.
- Hook registration ends with runtime cleanup. The separate App Server output
  ledger remains daemon-owned through terminal output retention so the daemon
  can validate and serve final JSONL safely; it is released only when the
  session is removed or its retained output is pruned.
- The installed daemon still defaults to `/run/erebor/daemon.sock`. The public
  client's absolute `--socket` is only an explicit, process-local foreground
  daemon path for the hands-on host example; it does not create a persisted
  context, remote target, or multi-daemon product model.
- `erebor --socket <absolute-path>` selects that local daemon for every
  daemon-backed command family in the process (`agent`, `run`, `session`,
  `policy`, `runner`, `audit`, `approval`, and `daemon`). Omitting it keeps the
  installed `/run/erebor/daemon.sock` default. The legacy direct `start` and
  `filesystem` commands remain Phase 5 ownership and do not receive a daemon
  selector before they are migrated.
- Linux host containment is root configuration, not a systemd prerequisite.
  `linux_runner.containment` defaults to `direct`, which launches the compiled
  controller directly; `systemd` is an explicit installed-host integration.
  Root configuration may also pin absolute controller, process-guard,
  descriptor-broker, and `systemd-run` helper paths, allowing the foreground
  host lab to stage all trusted helpers outside system directories.

## Purpose

Turn the existing Codex-specific enforcement into the first product-grade
agent adapter and package/install flow, while preserving its current strict
artifact, hook, process, attribution, and App Server guarantees.

The outcome is easy usage through `erebor run ... codex`, not a Codex-specific
daemon architecture. Once the migrated Codex path passes, this phase removes
the last direct foreground implementation. OCI distribution and the formal
installable bundle are later Phase 10 work.

The correct simpler hook shape is one adapter-owned Codex hook service with
authenticated per-session registrations, not one hook server per session. The
daemon owns the service process lifetime and supplies its registrations; the
Codex adapter owns the listener implementation, message family, ticket/peer
authentication, and event dispatch. This does not merge hook traffic into
daemon control or runtime guard: correctness requires a distinct listener,
routing table, queues, deadlines, cancellation, and shutdown contract.

## Scope

### Split Current Codex Configuration By Ownership

- Inventory every field and validation rule in
  `crates/erebor-runtime-core/src/config/agents/codex.rs`, especially
  `CodexProfileLayerConfig`, and map it exactly once:

  | Destination | Current facts that belong there |
  | --- | --- |
  | Codex package | adapter/version, supported platform, entrypoint shapes, executable version/hash requirement, managed hook/startup/requirements/launcher contents and hashes, event-schema hashes, exact hook exec chain, required surfaces, App Server protocol/dispatch compatibility |
  | Installation | verified local executable/artifact paths, observed hashes, owner/mode/trust-root facts, provider, verification time, package digest |
  | Root daemon config | fleet ownership/trust roots, allowed installation providers and roots, host safeguards, storage, runner availability, failure-mode limits |
  | Policy set | effect decisions and organization/user constraints |
  | Run request | local alias, workspace, arguments, TTY/detach, selected policy, constrained runner request |
  | `SessionSpec` | immutable resolved copy of every fact used for this session |

- Remove the target product's `codex.profiles`/`CodexProfileLayerConfig` input
  after the migration. Do not keep a hidden profile adapter, auto-convert old
  runtime JSON, or allow `session_run.rs` to discover Codex by comparing a raw
  argv path.
- Phase 5 owns user agent-state projection. Phase 4 keeps the negative
  boundary: a Codex request cannot inherit caller `HOME`/`CODEX_HOME` or name
  a state path. The later daemon-owned filesystem surface binds any approved
  state source, snapshot, writable upper, retention, refresh, and fixed
  in-namespace target generically for all adapters.

### Completed Legacy Config Inventory

The removed `CodexGovernanceLayerConfig` and
`CodexProfileLayerConfig` are inventoried from their final pre-migration source
revision. This is a removal audit, not a compatibility parser: no current
daemon path accepts `codex.profiles`, selects a profile from raw argv, or
reconstructs the old runtime JSON. Each former field and its validation has one
current owner or an explicit rejection.

| Former field | Former rule | Current owner and proof |
| --- | --- | --- |
| `enabled`, `profiles` | Codex required the legacy session/filesystem layers, at least one profile, and unique profile IDs/executables. | **Removed.** A package/installation selected by typed `CodexRunRequest` is the only admission route. Package, installation, adapter, entrypoint, and policy-set identities are resolved by `DaemonSessionApi`; raw executable/profile selection is impossible. |
| `id` | Safe unique profile identifier. | **Codex package:** `CodexPackageDefinition.release_id`, `AgentPackageManifest`, and canonical package digest; their validators require safe identities. |
| `runner` | Linux-host only. | **Adapter package plus root daemon:** `CodexSupportedPlatform` and `CodexPackageDefinition` certify the supported host; `DaemonConfig.linux_runner` determines the available Linux runner. The public Codex request cannot name a raw runner. |
| `executable`, `executable_sha256` | Normalized path and exact digest; fleet deployments rejected mutable user/temp locations. | **Caller installation:** `InstallationRecord` retains the descriptor-verified local artifact and owner UID after `erebor agent load`; admission revalidates held artifact identity. Root-curated definitions pin the expected executable digest. |
| `deployment`, `trust_root` | Distinguished fleet-managed artifacts and required managed sources below one stable trust root. | **Root daemon configuration:** `RootCuratedCodexPackage.trust_root` validates support-artifact sources and package identity. The ambiguous deployment mode is removed: the daemon never trusts a caller path as fleet-managed, and caller enrollment is always descriptor-brokered. |
| `requirements_source`, `requirements_sha256`, `requirements_path` | Trusted source/digest and fixed managed runtime target. | **Codex package:** `CodexManagedArtifacts.requirements_source` is a `CodexArtifact`; its target is validated under the private `/run/erebor/codex/` projection. |
| `managed_hook_source`, `managed_hook_sha256`, `managed_hook_path` | Trusted source/digest, shared managed directory, fixed hook target. | **Codex package and adapter:** `CodexManagedArtifacts.managed_hook_source` and fixed private target; `CodexHookService` authenticates the projected hook's session, kernel peer, and one-use ticket. |
| `shell_startup_source`, `shell_startup_sha256`, `shell_startup_path` | Trusted source/digest, same managed directory as the hook. | **Codex package:** `CodexManagedArtifacts.shell_startup_source` and target enforce the same package source/digest and private projection constraints. |
| `hook_shell`, `hook_exec_history` | Exact direct/shell interpreter chain, normalized absolute paths, first executable, final managed hook. | **Codex package:** `CodexHookContract.shell` and `exec_history` preserve the exact validated chain using `CodexHookExec`; the adapter compares runtime evidence against that profile. |
| `event_schemas` | Non-empty, unique event kinds with exact schema fingerprints. | **Codex package and adapter:** `CodexHookContract.event_schemas` validates package facts; `CodexHookBrokerProtocol` rejects an event unless parsed and package-pinned fingerprints match. |
| `app_server_transport.enabled` | App Server was an explicit profile capability. | **Certified entrypoint:** `CodexEntrypoint.app_server_stdio` makes only the package-declared `codex-app-server` entrypoint eligible for the typed daemon-owned stdio bridge. |
| `command_dispatch.program`, `command_dispatch.shell` | Safe exact program and normalized shell path. | **Codex package:** `CodexHookContract.command_dispatch` pins the command envelope; the invocation-lease owner admits only that exact dispatch shape. |
| `command_dispatch.sandbox_launcher.path`, `command_dispatch.sandbox_launcher.sha256` | Optional trusted launcher under the trust root with exact digest. | **Codex package:** optional `CodexManagedArtifacts.sandbox_launcher` plus its private target, with package-digest and root-trust validation. |
| caller `HOME`, `CODEX_HOME`, arbitrary state roots | Previously ambient/configurable state could influence the launch. | **Explicitly rejected in Phase 4.** No run request or installation records a caller state path. Phase 5 may add a generic daemon-owned filesystem binding; it must not reintroduce an ambient Codex exception. |

The package validators live in `erebor-runtime-packages/src/codex.rs`; root
trust ownership is in `erebor-runtime-daemon/src/config.rs`; verified local
enrollment is represented by `InstallationRecord`. The deterministic fixture
and installed-product probe exercise successful enrollment plus wrong package,
artifact replacement, raw argv, non-certified entrypoint, hook-schema, ticket,
and App Server failures.

### `codex-v1` Adapter

- Keep Codex-specific owners under
  `crates/erebor-runtime-session/src/agents/codex/` and expose them through the
  generic adapter contract introduced in Phase 3.
- Preserve and local-release-ground the behavior owned by:
  - `artifacts.rs`: exact hashes, ownership/path validation, and read-only
    projections;
  - `managed_hook.rs`, `ticket.rs`, `hook_client.rs`, and `broker.rs`:
    authenticated hook startup, ticket expiry/single use, independent peer
    evidence, and lifecycle;
  - `guard_lifecycle.rs`, `reconciliation.rs`, and `leases.rs`: guard/session
    binding, fact reconciliation, invocation leases, and terminal cleanup;
  - `native_event.rs`, `hook_output.rs`, and `context.rs`: schema-pinned event
    parsing, output, prompt/turn attribution, and Context DAG evidence; and
  - `transport.rs`: the exact supported App Server stdio transport.
- The adapter may prepare declared files, endpoints, environment, and command
  shapes. It cannot evaluate generic policy, write final session state, choose
  another runner, expose the daemon socket, or trust an event merely because
  the agent emitted it.
- Keep the three `erebord` ingress owners distinct during migration:
  `erebor` and attach traffic enter the daemon control service; Linux
  guard/interception traffic enters the runtime guard service; Codex native
  hook traffic enters the distinct Codex hook service. No App Server message
  is a shortcut between these dispatchers.
- Replace the foreground single-session `CodexHookBroker` listener shape in
  `crates/erebor-runtime-session/src/agents/codex/broker.rs` rather than
  migrating one Unix listener, host directory, accept loop, and server
  lifetime per session into `erebord`. Run one adapter-owned Codex hook listener
  inside the daemon process and give it daemon-owned registrations. Starting a
  Codex session registers its exact session id, single-use ticket authority,
  expected peer facts, reconciliation owner, and invocation-lease owner;
  terminal cleanup and recovery remove or replace that registration.
- A managed session continues to see only its fixed private hook path. Its
  hello must bind the exact session and ticket before the service selects a
  registration. Wrong-session, replayed, expired, or wrong-peer tickets fail
  before they reach Codex attribution code. This is a correctness-preserving
  simplification: one listener removes duplicated listener lifetime without
  sharing authentication, routing, or session state between Codex sessions.
- Reuse the existing Codex ticket, peer-inspection, reconciliation, lease, and
  event owners behind the shared service rather than creating a second Codex
  implementation. Its message allowlist, queues, deadlines, cancellation, and
  shutdown remain distinct from daemon control and runtime guard. The Phase 4
  deterministic daemon/client fixture proves this migration. Phase 5 adds the
  authenticated real-vendor fixture only after its generic filesystem state
  projection exists.

### Package And Installation Flows

- Add root-curated `codex-v1` package fixtures for every supported entrypoint:
  interactive/normal Codex when it is actually enforceable, and the exact
  certified `codex app-server --stdio` entrypoint.
- Package manifests distinguish:
  - redistributable support artifacts that may live in package layers; and
  - vendor/user-provided binaries that require an explicit installation
  provider and local verification.
- `erebor agent load CODEX_REF --from PATH` is explicit. The daemon does not
  trust `PATH`, silently download restricted software, or accept a same-named
  executable. `--from` is resolved under the caller UID through the Phase 2
  UID-dropped descriptor broker; installation hashes/copies from its held
  descriptor and `statx` identity, and root never reopens a separately checked
  raw path. Fleet-managed package requirements retain root ownership and
  safe-path checks. A user-facing launcher or installer release layout may
  help select the explicit candidate, but it establishes no trust: enrollment
  records the resolved final regular executable, its resolution provenance,
  version, and digest. The daemon never scans a user state directory or trusts
  a mutable launcher/symlink at run time.
- Create a local `codex` alias only after the installation is complete and
  linked to the exact package digest. Create `codex-app-server` only for a
  package/entrypoint that passed the App Server compatibility fixture.
- Reverify installation identity at admission and before start. A modified,
  replaced, symlinked, wrongly owned, or now-revoked artifact invalidates the
  installation until explicitly re-enrolled.

### Daemon-Owned App Server

- `erebord` owns the App Server parent/child stdio boundary, bounded message
  transport, dispatch correlation, cancellation, child exit, output, and
  finalization for the entire session.
- The CLI only attaches to daemon output/events. App Server protocol messages
  do not become a public daemon-control passthrough and agent stdout cannot be
  confused with daemon telemetry.
- The App Server workload runs as the requesting UID in the Phase 2 private
  filesystem. It cannot see `/run/erebor/daemon.sock`; it sees only its exact
  admitted Codex hook/guard/surface endpoints and read-only package artifacts.
- The effective daemon-failure mode must be one the Codex guard, hook broker,
  Context DAG/evidence owners, and selected runner jointly support. Otherwise
  admission fails.

### Context DAG And Child-Agent Delegation

The deterministic Codex fixture proves the real Git-shaped
ContextRepository topology for nested agent work, not merely correlated JSONL
audit records. The completed
[Codex Context DAG and child-agent subplan](phase-4-codex-context-dag/README.md)
owns the shared context repository, immutable causal fork, same-session
logical child scope, source-pinned collaboration mapping, child-originated
delivery, parent-owned integration decisions, repeatable two-parent pinned
merges, owner-received asynchronous command results through the same merge
contract, recovery, and deterministic Linux evidence.

The local Codex source makes a necessary distinction: native `spawn_agent`
creates an internal Codex thread, while its hooks and App Server collaboration
events are post-creation observation. A stock Codex profile can therefore
contribute a native logical DAG only. No hook, thread ID, App Server
notification, PID, or nested executable can upgrade an observed child into a
separate Erebor session.

### Example And Documentation

- Rewrite `examples/codex-app-server/README.md` and its fixture configuration to
  use the public package/install/policy/run workflow. The acceptance command is
  structurally:

  ```sh
  erebor agent load CODEX_PACKAGE@sha256:... --from /verified/codex
  erebor run --policy engineering codex-app-server
  ```

- Eliminate the old direct acceptance path based on
  `erebor session run --runner linux-host --config runtime.json ...`.
  Do not claim automatic installation if the fixture still requires an
  externally provided Codex binary.
- The deterministic fixture host lab is a developer acceptance harness, not a
  useful substitute for the real Codex TUI. It proves package enrollment,
  daemon-owned PTY routing, private endpoints, hook attribution, and typed App
  Server behavior without a vendor binary or user state. A real-Codex host
  walkthrough is Phase 5 work after generic private state projection exists.

### Codex Clean Cutover

- After all Codex acceptance tests pass, remove the direct Codex runtime JSON
  command syntax, its profile/config fixtures, and any temporary Phase 3
  Codex-only exception. The `erebor-runtime` binary and compatibility alias
  were already removed in Phase 1; do not reintroduce either or leave a
  daemon-unavailable fallback.
- The remaining foreground `SessionExecutionService`, `SessionRunPlan`, old
  `SessionRegistry`, registry lifecycle, and surface/filesystem test helpers
  are explicitly **not** Phase 4 deletion targets. They still own the legacy
  top-level `erebor start` and filesystem paths that Phase 5 replaces with
  daemon-owned ambient surfaces. Phase 5 must remove those owners and preserve
  existing workspace-local `.erebor/sessions` data as read-only legacy data.
- Verify every formerly public CLI capability is either represented by a typed
  `erebor` daemon request or explicitly removed by this architecture
  (`session adopt`). Update help, examples, shell completion, and exit-code
  tests in the same phase.

## Non-Goals

- Do not add registry networking or external/local package import; use only
  the daemon-installed or root-curated package fixtures admitted by Phase 3.
- Do not add formal package/distribution, install/uninstall, or upgrade
packaging; later Phase 10 owns those release artifacts.
- Do not weaken an executable, artifact, schema, hook-chain, ownership, peer,
  lease, or App Server rule merely to simplify the CLI.
- Do not make Codex the generic session model or claim other agents inherit its
  trusted events.
- Do not mark the removed direct Codex implementation as accepted until the
  Phase 4 daemon/client fixture passes. Authenticated real-vendor Codex
  acceptance is intentionally deferred to Phase 5 because it requires the
  generic filesystem state projection.

## Checkpoint

Replace the direct Codex baseline in `examples/codex-app-server` with a
deterministic Codex-compatible daemon/client fixture and its evidence checks.
It must use only the Phase 4 public interface and redact fixture inputs, hook
tickets, and workload data. It proves Erebor's package, installation, hook,
guard, and App Server contracts without needing a caller credential or host
state directory.

Add daemon/client e2e coverage for the deterministic fixture, retain crate-local
Codex tests, and extend the installed-product systemd probe at
`.github/scripts/daemon-systemd-control-plane.sh` to cover:

- complete field-by-field migration from current Codex config;
- package/install success and every artifact/hash/owner/path/schema failure;
- raw argv unable to select `codex-v1`;
- generic package unable to select Codex entrypoints or protocol;
- ticket expiry, replay, wrong peer, wrong executable, and wrong session;
- many concurrent Codex sessions through one hook listener, registration
  removal, daemon restart/recovery, and proof that a valid session A ticket
  cannot route to session B even when both have the same owner UID;
- hook messages rejected by daemon control/runtime guard and daemon-control or
  guard messages rejected by the Codex hook service;
- invocation lease and Context DAG attribution continuity;
- App Server message, cancellation, EOF, malformed output, child failure, and
  daemon/client disconnect;
- terminal initial geometry, controller-authorized resize, observer resize
  rejection, and detach/reattach of the same running PTY/workload;
- daemon-socket absence and exact per-session endpoint presence;
- supported/rejected failure modes with honest evidence;
- continuing absence of `erebor-runtime` plus final absence of direct-launch
  wiring and
  daemon-unavailable failure before launch; and
- rejection of distribution/import commands before they can affect local
  package, installation, or session state.

The deterministic fixture is the Phase 4 completion contract. Its fixed
binary/version/hash and package/install provenance are evidence. Do not treat
the optional `EREBOR_CODEX_LINUX_V1_*` compatibility probe as daemon acceptance:
it exercises a vendor binary outside the daemon-owned state surface. Phase 5
rewrites and runs that probe as authenticated real-vendor evidence through the
same daemon/client path after state projection is implemented.

The fixture's interactive test must use the same terminal contract needed by a
real TUI: it starts at the requested geometry, follows controller resize, and
remains the same live session across a controller disconnect. It need not mimic
Codex's display or login; presentation of a real Codex TUI is deliberately
deferred to Phase 5.

Run package/config migration, parser, and crate-local Codex tests in the normal
workspace lane. Extend the serial Ubuntu 24.04 `privileged-linux`
installed-product target with the deterministic Codex hook broker, Linux guard,
Linux runner controller, App Server, two-UID socket isolation, and daemon-loss
cases. Missing required systemd/cgroup/sudo/fixture conditions fail that lane
rather than silently skipping acceptance evidence.

```sh
rtk cargo fmt --all -- --check
rtk cargo test --workspace --all-targets --all-features
rtk cargo clippy --workspace --all-targets --all-features -- -D warnings
rtk git diff --check
```

## Required Evidence

- A completed field/validation migration table with no unmapped rule.
- Package and installation digests used by the deterministic daemon session.
- Deterministic Codex-compatible binary version/hash and fixture provenance.
- App Server invocation/result plus hook, lease, Context DAG, policy, and final
  session evidence.
- Shared-hook-service listener/registration evidence, including cross-session
  ticket-routing rejection and separate-service dispatch rejection.
- TTY evidence showing requested initial geometry, an accepted controller
  resize, rejected observer resize/input, and detach/reattach without a new
  workload or PTY.
- Proof that daemon telemetry, App Server transport, and workload output are
  separate.
- Old-to-new Codex command mapping and proof that distribution/import commands
remain unavailable until later Phase 10.
- A production-reference inventory proving that no direct Codex profile,
  runtime JSON, per-session hook listener, or foreground Codex launch caller
  remains. Phase 5 owns the separate inventory for the foreground surface and
  filesystem owners.

## Acceptance

- A verified local `codex` package/install alias produces a daemon-owned,
  governed Codex session without hand-written runtime profile JSON.
- Every current Codex security check remains represented and tested.
- The exact App Server example works through `erebor` and the daemon.
- The deterministic interactive fixture proves the Linux controller PTY
  contract; it is not represented as a real Codex TUI demonstration.
- Codex cannot see the daemon control socket or impersonate another session.
- One shared Codex hook listener serves registered sessions without a
  per-session hook server, while preserving exact ticket/peer/session binding
  and remaining distinct from daemon-control and runtime-guard dispatch.
- No raw command path, package, or hook event can opt itself into trusted
  Codex behavior.
- Stopping the daemon makes every new governed run fail before launch; formal
  installation/distribution claims remain unavailable until later Phase 10.
- There is one daemon-owned session engine and one authoritative live/current
  session store. Legacy workspace data remains untouched data, not a fallback
  runtime or a second product session namespace.

## Stop Point

Stop after Phase 4 evidence and the result update. Wait for explicit approval
before Phase 5 (ambient surfaces) or any later phase.

## Phase 4 Result

State: Done — Phase 5 remains separately scoped and unstarted.

The implementation/evidence list below records the completed Phase 4 source.
Recovery restored the missing process-local socket selector, explicit
direct-controller root configuration, and no-cleanup host-lab scripts. The
privileged Docker/systemd fixture now supplies the required automated live TTY
evidence; the interactive `sudo` host lab remains a useful manual example, not
an additional acceptance gate.

Implemented so far:

- Replaced the direct foreground `runtime.json`/profile App Server test path
  with a daemon-only CLI path. `erebor run ... codex` always requests a
  daemon-owned TTY; `erebor run ... codex-app-server` always requests the
  exact certified non-TTY entrypoint and emits no create/start telemetry on
  protocol stdout.
- Added typed App Server attach, bounded JSONL input, and EOF IPC messages;
  the client never uses generic session input for App Server traffic.
- Added daemon-side exact package/entrypoint/TTY/artifact revalidation,
  exclusive structured-input leases, bounded JSON-RPC validation and
  cancellation correlation, synthetic sensitive-method denials, prompt/turn
  Context DAG attribution, and stdout validation both for attached clients and
  when clients disconnect.
- Added Linux runner stdin EOF handling. The non-TTY process guard owns child
  pipes; the daemon writes or closes them through the active runner only after
  the exact App Server admission check.
- Added the governed Linux terminal contract: initial rows/columns are an
  immutable TTY `SessionSpec` fact; only the current input-lease holder can
  issue a typed resize; the Linux controller applies it with `TIOCSWINSZ` and
  records it as terminal evidence. The CLI reads its terminal geometry before
  an attached run, acknowledges every resize, and resizes again when polling
  observes a changed local terminal. The deterministic fixture reports the
  kernel PTY geometry. Focused tests prove observer rejection and controller
  lease handoff without a second workload start.
- Extended the privileged installed-product fixture to prove the live terminal
  contract through the public daemon/client attachment path. It starts the
  deterministic workload in a real 24x80 PTY, changes the controller terminal
  to 40x120, and proves both the workload's new kernel geometry and its real
  `SIGWINCH`. While that controller owns the lease, a test-only client probe
  attaches read-only and proves that daemon rejects both its input and its
  resize RPCs. After detach, a second controller attaches at 50x140; the
  fixture proves the new geometry and `SIGWINCH`, while the test compares the
  immutable workload process identity before and after reattach.
- Removed the stale direct `codex_linux_v1_session_run` test and its foreground
  session-driver binary. The retained lifecycle probe is compatibility-only;
  it is not a product launch route.
- Removed the unused direct Codex runtime-state-root allowlist from the
  invocation-lease owner. Bootstrap no longer claims an ambient state file;
  the future private state projection is exclusively a Phase 5 filesystem
  surface concern.
- Restored the example for package loading and daemon-owned TTY/App Server
  use. `build-host-lab.sh` builds only local debug artifacts;
  `run-host-lab.sh` stages root-owned helper binaries in a fresh `/tmp` lab,
  runs a foreground root `erebord` without systemd or the default
  `/run/erebor` socket, and gives the caller a client wrapper for that exact
  socket. Exiting the shell stops the daemon only: configuration, logs, state,
  and the complete lab directory are deliberately retained. The deterministic
  fixture continues to defer real-vendor Codex to Phase 5. The approved TTY,
  App Server, nested-agent, lineage, and final-output-ledger decisions remain
  recorded above.
- Added the deterministic `codex-v1-fixture` executable/package fixture. It
  produces a pinned root-curated package definition, a caller-owned enrollment
  binary, exact TTY output, a bounded JSONL App Server, and a projected managed
  hook without a vendor binary, login, `HOME`, or `CODEX_HOME` dependency.
- Renamed the public enrollment command to `erebor agent load`. The durable
  verified-installation record remains an internal identity, not a second
  public command vocabulary.
- Extended the installed Ubuntu 24.04 systemd probe with the fixture and its
  two-UID daemon/client matrix: `agent load`, TTY, JSONL input, cancellation,
  EOF, malformed output, client disconnect, artifact replacement, raw-argv and
  entrypoint rejection, managed-hook replay/wrong-peer/wrong-session rejection,
  concurrent sessions, cleanup, daemon recovery, and daemon-socket absence.
- Kept the Codex hook listener adapter-owned: `CodexHookService` and its
  protocol, ticket/peer authentication, and event dispatch live under the
  Codex adapter. `DaemonSessionApi` owns only its in-process lifetime and
  supplies session registrations. The three listeners remain intentionally
  separate: daemon control accepts `DaemonHello` and its control allowlist;
  the runtime guard accepts `GuardHello` followed only by guard messages; the
  adapter hook service accepts `HookHello` followed only by hook events. A
  foreign RPC is rejected before an owner dispatches it.
- Added the completed legacy `CodexGovernanceLayerConfig`/
  `CodexProfileLayerConfig` field-by-field inventory above. Each former field
  now has one package, installation, root-daemon, policy, session, or explicit
  Phase 5 rejection owner; no compatibility parser or raw profile selection
  remains.
- Added same-UID shared-listener isolation to the installed-product fixture.
  It holds Codex session B registered while the real guarded managed hook from
  session A attempts a `HookHello` for B. The hook wire contract deliberately
  carries no ticket string: the adapter derives A's one-use authority from its
  kernel peer. B rejects that peer/session binding, after which A's own hook
  still succeeds, proving a failed cross-session attempt neither routes nor
  consumes A's authority.
- Repaired the repository-wide Rust verification baseline without adding Phase
  5 behavior: formatted the workspace, replaced the staging-path positional
  tuple with its named owner, removed stale test-only configuration code, and
  removed a useless error conversion.

Verification completed on this source state:

- `rtk cargo check --workspace` passed.
- The App Server crate-local tests passed (five tests), including sensitive
  transport denial, chunked output validation, cancellation/failed-forward
  correlation cleanup, and malformed output rejection.
- The structured non-TTY lease/EOF manager test passed.
- The Codex invocation-lease tests passed (17 tests), including the regression
  that bootstrap does not claim an ambient state file; App Server tests passed
  again (five tests).
- `rtk cargo check --workspace` passed again after stale-state removal.
- `rtk cargo test -p erebor-runtime-ipc --test contract` passed (11 tests).
- The Codex CLI parser test and retained Codex lifecycle probe passed.
- `rtk cargo test --workspace --all-targets --all-features` completed
  successfully in this host.
- `rtk git diff --check` passed.
- `rtk cargo test -p erebor-runtime-e2e --test daemon_control_plane
  daemon_control_plane_and_codex_context_dag_run_in_systemd_container -- --ignored
  --nocapture` passed against the disposable privileged Ubuntu 24.04 systemd
  container after building the staged fixture image, including the same-UID
  cross-session hook rejection and the full live TTY resize/observer/
  detach/reattach contract.
- `rtk cargo test -p erebor-runtime-e2e --test codex_v1_fixture` passed (five
  tests), including malformed cross-session request rejection before a hook is
  launched.
- `rtk cargo test -p erebor-runtime-daemon
  control_service_closes_guard_family_connection_before_dispatch -- --ignored
  --nocapture` passed outside the restricted host sandbox. It sends a
  `GuardHello` to the daemon-control listener and observes connection closure
  before dispatch. `rtk cargo test -p erebor-runtime-session
  managed_hook_client_requires_a_guard_issued_kernel_peer_ticket -- --nocapture`
  passed outside the restricted host sandbox.
- `rtk cargo fmt --all -- --check` and `rtk cargo clippy --workspace
  --all-targets --all-features -- -D warnings` passed.
- `bash .github/scripts/verify-rust-ci.sh` passed after the final Rust edit.
- The temporary-host example scripts pass `bash -n`; focused client, CLI,
  daemon, and fixture tests cover explicit socket parsing/selection,
  root-owned helper configuration, and fixture emission. The repository Rust
  CI procedure passed after the final Rust edit. The live foreground-root
  walkthrough remains optional manual developer evidence because the matching
  privileged Docker/systemd acceptance fixture passes automatically.

Deferred scope, not a Phase 4 acceptance blocker:

- Phase 5 owns authenticated agent-state projection and the privileged
  state-backed real-vendor Codex acceptance fixture. It must provide the
  generic filesystem-surface state binding described there; Phase 4
  intentionally rejects ambient caller-selected `HOME`/`CODEX_HOME` rather
  than inventing a Codex-specific credential provider.

Done within Phase 4:

- All four phases of the
  [Codex Context DAG subplan](phase-4-codex-context-dag/README.md) are complete:
  the P/B/C/D/q deterministic fixture, source-surface routing/denial, guarded
  descendants attributed to logical scopes, public Git-backed graph view, and
  privileged Docker evidence are recorded there. A Codex thread remains a
  same-session scope, never another Erebor session.

There are no remaining Phase 4 acceptance gaps. The deterministic fixture is
evidence for the governed TTY and App Server contracts, not a representation
of the real Codex TUI. The authenticated real-vendor state-backed fixture
remains explicitly deferred to Phase 5's generic filesystem binding.
