# Erebor Daemon–Client Architecture

Status: Active recovery master plan. Phases 1 and 2 are finished and are not
to be revisited. Phase 3 is in progress. Phase 4 implementation was recovered,
but its acceptance evidence and host-lab changes were lost; it is therefore
**not accepted**. Phase 5 and later are planned work.

Parent plan: [Erebor Runtime development plan](../../development-plan.md)

## Recovery Authority

This master was reconstructed on 2026-07-23 from the surviving phase plans,
the recovered source tree, and the daemon/client decisions recorded while the
Codex adapter was being developed. It replaces the former recovery index as
the current phase map. It intentionally does not claim to reproduce the lost
original master word-for-word.

When a historical phase file and this recovery status disagree, use the
following status only for deciding what may be claimed today:

| Phase | Current status | Meaning |
| --- | --- | --- |
| 1 | Done — frozen | Do not change or revisit it for this work. |
| 2 | Done — frozen | Do not change or revisit it for this work. |
| 3 | In progress | Complete the local generic daemon/client path only. |
| 4 | Recovery verification | Keep the recovered implementation, restore its missing evidence/example, and do not call it done yet. |
| 5 | Not started | Complete the remaining Linux daemon-client cutover, ambient surfaces, and filesystem ownership. |
| 6–10 | Later phases | No work starts without a separately approved phase scope. |

The recovered [Phase 4](phase-4-codex-adapter-final-cli-cutover-and-app-server-migration.md)
file says `Status: Done`. That is a historical status claim, not current
acceptance: the deterministic fixture and the real temporary host-lab example
must pass again before that result can be restored to `Done`.

## Goal

Make `erebord` the one privileged, local host authority and `erebor` its one
public typed client. A governed action is admitted, launched, supervised,
observed, and retained by the daemon; the client submits typed requests and
relays an explicitly leased interactive stream. It never becomes a second
runtime supervisor, policy engine, package verifier, filesystem owner, or
alternate daemon path.

The Linux core must support both:

- an interactive governed agent, for example `erebor run … codex`, where the
  daemon owns the PTY and workload, the exclusive controller client relays
  terminal I/O and geometry, and observers are read-only; and
- a typed agent protocol, for example `codex-app-server`, where the daemon
  owns the child stdio and validates bounded JSONL/JSON-RPC messages rather
  than proxying arbitrary bytes through daemon control.

Docker-like ergonomics are a product goal, but Docker is not the architecture:
the daemon remains the sole owner of the governed workload and its resources;
the client is comparable to `docker attach` for interactive I/O, not to a
second process launcher.

## Non-Negotiables

- There is one local `erebord` per host, authenticated by observed Unix peer
  credentials. Request bodies, environment variables, and client-provided UID
  fields never establish identity.
- `erebor` is a client only. After a command migrates, there is no direct
  fallback, foreground launcher, alternate daemon target, session adoption,
  raw control protocol, or compatibility path that bypasses the daemon.
- The daemon control service, runtime guard service, and Codex hook service
  have separate listeners, message families, authentication, queues, and
  dispatch. Sharing an `erebord` process or IPC codec must not merge those
  authority boundaries.
- Admission binds immutable identities: requesting UID, package, installation,
  adapter, policy-set revision, runner capability snapshot, workspace and
  executable/image identity, endpoint and filesystem projection, and failure
  mode. Start revalidates facts that can change.
- Every artifact or user input crossing privilege is bounded and read through
  the UID-dropped descriptor broker. Root does not reopen a checked user path
  string, trust caller `PATH`, inherit caller `HOME`/`CODEX_HOME`, or receive
  an unbounded blob through IPC.
- Packages select compiled adapters; they cannot load plugins, scripts,
  libraries, or subprocess extensions into `erebord`.
- The daemon owns process lifetime, namespaces, private endpoints, output,
  audit/evidence, cancellation, recovery, and retention. A client disconnect
  is not authority to lose or recreate those resources.
- The daemon owns interactive terminal state. The controller/input lease is
  the only authority that may send terminal bytes or change terminal geometry;
  a read-only attachment may observe neither input nor resize. Detach and
  reattach preserve the same PTY and workload rather than creating a client
  owned substitute.
- A child agent inherits the enclosing session's governance, but never its
  trust. Nested Codex cannot reach the daemon socket, mint aliases, load an
  agent, register an App Server, or impersonate another session.
- Unsupported capabilities fail closed and are reported as unavailable. They
  are never approximated by a direct CLI path.
- No phase silently expands into OCI distribution, real authenticated Codex
  state, Docker parity, remote daemon contexts, or an arbitrary plugin model.

## Target Ownership

```text
erebor (unprivileged client)
  │ typed local control requests / attach stream / input lease
  ▼
erebord (one root-owned host process)
  ├── daemon-control service ── packages, policies, approvals, sessions,
  │                            surfaces, audit and client streams
  ├── runtime-guard service ── admitted physical effects only
  ├── Codex hook service ──── authenticated per-session registrations only
  └── SessionManager + runner ─ namespace, process/PTY, output and recovery
        │
        ├── generic-process-v1 workload
        └── codex-v1 workload ─ private hook endpoint / typed App Server stdio
```

The one shared Codex hook listener is a daemon-owned service with a
per-session registration table. It replaces per-session listener lifetime; it
does **not** share tickets, peer validation, queues, or attribution between
sessions, and it does not turn hook messages into daemon-control messages.

## Current-Code Baseline

The recovered source tree already contains the main owners this plan builds
upon. This table is grounding, not an acceptance claim.

| Responsibility | Current owner(s) | Required direction |
| --- | --- | --- |
| Framed typed IPC | `erebor-runtime-ipc` | Keep bounded frame and per-service message-family separation. |
| Client/daemon boundary | `erebor-runtime-client`, `erebor-runtime-daemon/src/control.rs` | Keep client wiring thin; daemon owns mutations and streams. |
| Admission and local objects | `erebor-runtime-daemon/src/session_api.rs`, `session_api/admission.rs`, `local_store.rs` | Finish only the Phase 3/4 local identities and revalidation required by their plans. |
| Generic adapter | `erebor-runtime-session/src/agents/generic.rs` | Retain one compiled `generic-process-v1` adapter; no plugin loader. |
| Codex adapter | `erebor-runtime-session/src/agents/codex/` | Retain adapter-specific artifacts, ticket, hook, attribution, and App Server owners behind the generic contract. |
| Shared hook/App Server services | `agents/codex/broker.rs`, `agents/codex/app_server.rs` | Preserve distinct authenticated hook and typed-stdio contracts. |
| Public CLI | `erebor-runtime-cli/src/cli/` | Migrate remaining public commands to typed daemon requests in their owning phase. |
| Legacy direct filesystem/start paths | `cli/filesystem.rs`, `cli/start.rs` | Do not delete blindly; Phase 5 moves their responsibility into daemon-owned surfaces, then removes the direct paths. |

## Product Vocabulary And Public Shape

An **agent package** declares an adapter and immutable entrypoint/support
contract. An **installation** is the root-curated, locally verified binding of
that package to a vendor or fixture executable. An **agent alias** selects an
exact installation after admission. A **policy set** is an immutable policy
composition. A **session** is one durable, admitted workload. A **surface** is
a named daemon-owned ambient resource that may outlive a client and may be
bound to compatible sessions.

`agent` remains a first-class command family because Erebor governs agents;
`package` is the stored artifact model beneath it. The approved local flow is:

```text
erebor agent load PACKAGE_REF --from EXECUTABLE
erebor run --policy POLICY --workspace WORKSPACE AGENT_ALIAS [agent arguments]
```

`agent load` is deliberate: it records a local, daemon-verified installation
from a caller-owned executable through the descriptor broker. It does not
download software, accept a `PATH` name as proof, or imply external package
distribution. `agent install` is not the public command. `agent import` is
reserved for Phase 10 because it requires OCI layout and publisher-trust
verification.

`erebor run` resolves the requested generic command or admitted alias, creates
and starts a daemon-owned session, then either attaches a client to its daemon-
owned stream or returns after a detached request. It is not an ambient-surface
launcher and it does not create a second privileged namespace outside the
admitted runner plan.

## Decisions Already Made

These decisions came from the daemon/client and Codex-adapter work. Later
phases must preserve them unless the user explicitly changes the architecture.

1. **Complete CLI cutover is required.** Every public command ends as a typed
   client operation. Commands are moved to the daemon owner before their old
   foreground implementation is removed.
2. **`erebor start` is not a product surface.** It is an ambiguous ambient
   foreground launcher. Phase 5 replaces it with `erebor surface
   create|start|ls|inspect|logs|events|stop|rm`; it must then be absent from
   parsing, help, examples, protocol, and compatibility paths.
3. **Filesystem belongs to the daemon-owned surface lifecycle.** The current
   filesystem commands work with workspace/session registry and transaction
   data. Phase 5 moves the workspace/overlay/checkpoint/retention ownership
   into the filesystem surface, exposes typed daemon operations, and only then
   removes the direct client storage access.
4. **Phase 4 is fixture-first.** It uses a deterministic `codex-v1`
   executable/package fixture—not the user’s real Codex installation, login,
   or `CODEX_HOME`. The fixture is acceptance evidence, not a stand-in for a
   useful real-Codex demonstration. Real authenticated Codex state and the
   corresponding walkthrough are Phase 5 filesystem-projection work.
5. **Interactive Codex stays interactive.** `erebor run … codex` presents the
   governed Codex TUI over the daemon-owned PTY. Phase 4 owns Linux TTY
   fidelity: initial rows/columns, controller-authorized resize, `SIGWINCH`
   delivery, read-only observers, and session-preserving detach/reattach.
   `codex-app-server` is a different, typed daemon-owned JSONL protocol path.
6. **Nested agent processes do not escape governance.** A raw nested process
   runs only as a descendant under the admitted session's namespace, guard,
   cgroup, endpoint projection, policy, and daemon-loss contract. It receives
   no independent agent trust. The only exception is the explicit,
   daemon-mediated child-agent contract in the proposed Phase 4
   [Codex Context DAG subplan](phase-4-codex-context-dag/README.md). That
   contract creates a separately admitted child session in one shared context
   family; it never promotes a raw `exec codex` descendant.
7. **The host example is deliberately temporary.** It starts a foreground root
   daemon with isolated temporary state/runtime/log roots and a unique absolute
   Unix socket. The explicit client `--socket` points only to that local
   foreground daemon; it is not a remote context, persistent context, or
   multi-daemon feature. The example does not install a system service or use
   the default system socket. Exiting it stops only that daemon; it never
   automatically deletes the retained lab directory.
8. **OCI and Notation are later work.** They are not a prerequisite for the
   local Linux daemon/client core. Phase 10 owns the approved official
   `notation` executable boundary: version and artifact-digest pinning,
   daemon-owned non-shell invocation, and a pinned validated result contract
   before an Erebor verification receipt is issued.
9. **Real agent state is a generic private projection.** A package declares a
   logical state requirement and a fixed in-namespace target; a typed
   filesystem surface selects an eligible source class. The daemon snapshots
   the source through the descriptor broker, applies a private writable upper
   and any managed configuration there, then mounts only that result. It never
   inherits or mutates caller `HOME`/`CODEX_HOME` or other live user state.
10. **Installer layout is a convenience, not trust.** A visible local Codex
    launcher or release layout may help a user choose an explicit `agent load
    --from` candidate. The daemon trusts only the descriptor-broker-held final
    regular executable, its recorded resolution provenance, version, and
    digest; it does not scan a user home or trust a mutable symlink at run
    time.

## Phase Plan

### Phase 1 — Privileged daemon control plane — Done and frozen

[Phase 1](phase-1-privileged-daemon-control-plane.md) established the local
daemon identity, typed control protocol, protected storage, and a single public
client. It is complete. Do not reopen it while recovering later work.

### Phase 2 — SessionSpec, active runners, daemon-failure contract — Done and frozen

[Phase 2](phase-2-session-spec-active-runners-and-daemon-failure-contract.md)
made session admission durable and bound runners, private execution,
idempotency, daemon-loss behavior, output, and recovery to the daemon. It is
complete. Do not revise it as a shortcut around later phase scope.

### Phase 3 — Local stores, generic adapter, and CLI migration — In progress

[Phase 3](phase-3-local-stores-generic-adapter-and-cli-migration.md) completes
the non-OCI, local Linux generic product path:

- daemon-owned immutable local package, installation, alias, policy-set,
  approval, quota, and retention/lease records;
- the built-in `generic-process-v1` adapter and daemon-owned adapter registry;
- caller-UID executable/interpreter resolution with pinned identity rather
  than root `PATH` resolution;
- generic sessions, policy, approval, audit, runner, and daemon CLI commands
  migrated to typed daemon control; and
- root-curated local packages only, with external package import rejected
  before it can alter the daemon store.

Phase 3 deliberately does not own Codex migration, real agent state,
filesystem surface migration, Docker, OCI, Notation, remote registry work, or
an `agent import` command. Direct Codex stays only as the short transition into
Phase 4; direct filesystem/start remains only until its ownership is moved in
Phase 5.

### Phase 4 — Codex adapter, final CLI cutover, App Server — Recovery verification

[Phase 4](phase-4-codex-adapter-final-cli-cutover-and-app-server-migration.md)
moves Codex to the generic adapter/package/install/session path and removes the
last direct Codex launch. Its intended evidence is:

- a deterministic `codex-v1` package and executable fixture loaded with
  `erebor agent load`, then run through the daemon-owned TTY path;
- a Linux TTY contract covering initial geometry, controller-only resize and
  input, read-only observers, and disconnect/reattach of the same session;
- typed App Server JSONL tests covering input, cancellation, EOF, malformed
  output, child failure, and client/daemon disconnect;
- package/artifact/entrypoint failures, raw-argv rejection, generic-package
  rejection, exact endpoint presence, and daemon-socket absence;
- shared hook-service concurrency, ticket expiry/replay/wrong-peer/wrong-
  session rejection, cleanup, and daemon recovery; and
- the same deterministic fixture in the privileged Linux/systemd/two-UID
  matrix, including process-guard and daemon-loss cases.

The proposed [Codex Context DAG and child-agent subplan](phase-4-codex-context-dag/README.md)
extends this evidence with an explicit child-session path. It preserves the
direct-nested-process denial boundary while proving a Git-shaped scope DAG in
the existing context repository: causal forks, child-originated delivery blobs,
parent-owned receives, repeatable pinned merges, owner-received asynchronous
command results through the same parent-owned merge contract, and physical
descendant attribution. It does not require Phase 5 state projection or a real
authenticated vendor binary.
For stock Codex, native child threads remain logical observations inside the
outer governed invocation; a separately governed child requires the subplan's
explicit pre-spawn delegation bridge.

The recovered `examples/codex-app-server` host lab is a small foreground
fixture-acceptance test, not a system-wide installation or a real-Codex TUI
demonstration. It now has two entry commands:

1. `build-host-lab.sh` builds the local debug daemon, client, trusted helpers,
   and deterministic fixture only;
2. `sudo run-host-lab.sh` creates one fresh retained `/tmp` root, starts a root
   `erebord` in the foreground with isolated state/runtime/log roots and a
   unique absolute socket, then gives the lab shell an
   `erebor --socket <temporary-socket>` client wrapper;
3. load the deterministic fixture with `erebor agent load`; then run both the
   interactive `codex` fixture and the typed `codex-app-server` fixture; and
4. prove the fixture TTY contract, the daemon socket is absent in the
   workload, and terminal/session evidence is coherent.

The restored CLI has one process-local absolute `--socket` selector for every
daemon-backed command and defaults to `/run/erebor/daemon.sock` when it is
omitted. The restored root `linux_runner.containment` configuration defaults to
the direct controller; the installed systemd probe now opts into `systemd`
explicitly. The scripts never delete their lab directory. Static script checks
and focused Rust tests are required first; then reproduce the prior hook
hello/peer failure, if any, with an interactive developer `sudo` run and fix
only the Phase 4 owner identified by that evidence before marking this phase
`Done`.

Phase 4 does **not** add filesystem surfaces, state bindings, caller
`HOME`/`CODEX_HOME`, real authenticated Codex, OCI, or Notation. Phase 5
replaces the fixture-facing walkthrough with the real local-Codex path after
it can safely project agent state.

### Phase 5 — Daemon-owned ambient surfaces — Not started

[Phase 5](phase-5-daemon-owned-ambient-surfaces.md) is the final Linux core
cutover. It owns:

- replacement of `erebor start` by the typed durable `erebor surface` lifecycle;
- one daemon-owned supervisor for long-lived ambient resources, beginning with
  Browser CDP;
- migration of the legacy filesystem transaction and retention commands into
  a daemon-owned filesystem surface; and
- generic filesystem state projections, including a daemon-owned lower
  snapshot and per-session writable upper for a fixed private Codex state
  target, never a caller-selected host `HOME` or `CODEX_HOME`; and
- the real-Codex Linux walkthrough: a user explicitly enrolls a resolved,
  pinned local executable and binds approved state through that projection.
  The daemon stages the verified executable and private state; it neither
  scans nor changes the user's live Codex directory.

This is where the public CLI becomes a daemon client for every public command.
It does not add OCI, Notation, Docker parity, remote listeners, plugins, or
session adoption.

### Phase 6 — Docker and runner parity — Later, detailed plan to be restored

The surviving lifecycle material preserves this phase's boundary: extend the
runner capability contract with Docker execution evidence; pin admitted Docker
images and prohibit implicit pulls. Phase 4 already owns the Linux PTY
controller/geometry contract, so this phase must preserve it rather than
deferring basic interactive behavior.
It must not weaken the Linux-host ownership or daemon-loss contract and must
fail closed when its enforcement or recovery guarantees are unavailable. Its
detailed phase file was not recovered, so it must be written and approved
before implementation.

### Phase 7 — Claude Code discovery and security decision — Later

This is a source/discovery phase: establish the exact supported Claude Code
binary/package, entrypoints, settings/state transport, hook/protocol facts,
and the security proof required for attribution. It does not add an adapter.
Its detailed phase file must be written and approved before work starts.

### Phase 8 — Claude Code adapter migration — Later

After Phase 7 approval, implement the corresponding package, installation,
adapter, typed protocol, process/peer binding, fixture, and two-UID evidence.
It follows the Phase 4 shape without treating Codex-specific hook trust as a
generic agent capability. Its detailed phase file must be written and approved
before work starts.

### Phase 9 — Recovery hardening and product certification — Not started

[Phase 9](phase-9-recovery-and-product-certification.md) hardens the completed
Linux daemon/client product against corruption, overload, hostile users,
upgrades, crashes, and operational failure, then certifies supported commands
and installed-system behavior. It depends on Phases 1–6 and does not require
the optional Claude track.

### Phase 10 — OCI registry, trust, Hub, and packaging — Deferred later

[Phase 10](phase-10-oci-registry-trust-hub-and-packaging.md) begins only after
Phase 9 and explicit approval. It owns OCI layout import, registry transport,
publisher trust, Notation verification, expiry/revocation/stale-receipt
rechecks, signed catalog discovery, and formal distribution packaging. It must
not be pulled into local package loading as a partial or unsound verifier.

## Phase Boundaries And Stop Points

- Do not edit Phases 1 or 2 while completing Phases 3–5.
- Complete and verify Phase 4's deterministic fixture and disposable host lab
  before beginning Phase 5. A real vendor Codex test belongs to Phase 5 only
  after filesystem state projection exists; basic Linux PTY geometry and
  controller behavior are Phase 4 evidence, not a later Docker prerequisite.
- Do not treat a successful foreground lab as a substitute for committed
  daemon/client and privileged two-UID tests.
- Stop after every later phase result. Phase 6, 7, 8, 9, and 10 each require
  separate approval; a later phase must not be started merely because its
  dependency has become possible.
- The [Phase 3+ architectural simplification record](phase-3-onward-architectural-simplification.md)
  is a decision record, not blanket implementation authorization. Apply one
  candidate only when its owner, retained invariants, and proof are explicitly
  accepted by the relevant phase.

## Verification Standard

Every implementation phase needs crate-local tests where behavior is local,
daemon/client e2e where the public boundary is crossed, and the relevant
privileged Linux two-UID/systemd lifecycle probe where runtime ownership is a
claim. The normal Rust gate after code changes is:

```sh
rtk cargo fmt --all -- --check
rtk cargo test --workspace --all-targets --all-features
rtk cargo clippy --workspace --all-targets --all-features -- -D warnings
rtk bash .github/scripts/verify-rust-ci.sh
rtk git diff --check
```

The recovery implementation has passed focused client/CLI/config/runner/fixture
tests, script syntax checks, workspace format/check/Clippy, and the local
host-lab build. The full workspace test stage cannot complete in this restricted
host because its Unix hook/WebSocket listener tests receive `EPERM`; the live
foreground lab also requires an interactive developer `sudo` password. Neither
limitation is acceptance evidence. Run the privileged Linux matrix and the host
lab before marking Phase 4 `Done`.
