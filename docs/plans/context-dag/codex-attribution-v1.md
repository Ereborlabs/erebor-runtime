# Codex App Server Attribution And Governance — Linux V1

Status: Phase 0 is done as a conservative feasibility result: no strict Linux
profile is certified. It records partial live AppServer and CLI-exec evidence
and assigns strict-certification blockers to later phases.
Phase 1 is **done**: its managed profile, generic filesystem projection,
versioned hook IPC, one-use ticket registry, peer-authenticated broker,
original-pipe provenance, root-controlled hook startup, and terminal
production-hook completion are live-tested through `session run`. The
standalone Phase 0 probe observes an additional `PostToolUse` event not emitted
by that guarded session-run fixture; neither surface is promoted beyond its
pinned evidence, and Phase 0's wider lifecycle claims remain unproven.
Phase 2 is **done** for an explicitly enabled, directly launched
`session run` App Server stdio profile: the owned broker commits one pending
context node before forwarding a prompt, pairs native responses, records only
exact authenticated thread/turn hook corroboration, fail-closes on child-output
validation failure, and denies sensitive direct client methods. It is prompt
provenance only; it does not certify hook-first or
IDE-inherited transport, auto-adoption, invocation leases, or physical effects.
Phase 3 has its production hook-exit/ptrace barrier and process/mutation
handoff implemented: the generic guard parks a protected physical syscall
until the authenticated hook exits successfully, then the Codex owner arms
only the exact lease and retains it across kernel-observed descendants. The
real generic ptrace ordering fixture passes. Strict certification is still
blocked: the pinned guarded `session run` evidence remains limited to
`SessionStart`, `UserPromptSubmit`, `PreToolUse`, and `Stop`; no root-owned
verified profile artifact is installed; and the live external Codex App Server
run needs explicit data-export approval. Filesystem/network bypass coverage
remains Phase 4.

Plan type: Linux-specific Codex hook, prompt, tool, and physical-action
governance with a final optional `session auto-adopt` extension, plus Scope
Context DAG attribution. This is a nested Context DAG subplan.

Supersedes for future Linux work:

- [Codex App Server Attribution And Governance — Linux V0](./codex-app-server-attribution-linux-v0.md)

Sibling design:

- [Codex App Server Attribution And Governance — macOS V1](./codex-app-server-attribution-macos-v1.md)

Implementation subplan:

- [Linux V1 implementation phases](./codex-attribution-v1/README.md)

## Purpose

Create one cross-platform Codex governance contract while keeping Linux's
native enforcement options and deferring native auto-admission to the final
optional phases.

Linux V0 proved that a held Linux exec can enter an Erebor session namespace
and, for an IDE-owned App Server, have its stdin/stdout replaced before the
Codex image begins. That experiment is feasibility evidence, not an approved
V1 mechanism or architecture selection. V1 first establishes forced managed
hooks, authenticated runtime attestation, context-partitioned invocation
leases, and coverage states as the common semantic/action contract on Linux
and macOS. Its final auto-adopt phases select and certify any required Linux
held-exec or transport mechanism independently.

The result governs unchanged Codex processes launched by an IDE, CLI, TUI,
Desktop app, or the user. It neither patches Codex nor requires an IDE setting,
PATH shim, shell alias, wrapper, special flag, or source change.

## CLI Vocabulary And V1 Command Contract

Linux V1 has three intentionally different session operations. The plan must
not call one operation by another operation's name.

| Command | Status | Meaning | Strict V1 consequence |
| --- | --- | --- | --- |
| `erebor session run --config <path> --runner <runner> -- <command>` | Current | Starts the supplied new child inside a governed session runner. | It governs that caller-supplied launch. It does not create a route for arbitrary later Codex execs. |
| `erebor session adopt --config <path> --runner linux-host --pid <pid>` or `--match <text>` | Current | Manually attaches one already-running, explicitly selected Linux process. | This is manual adoption. It never repairs the missed launch boundary and cannot promote an existing Codex process to V1 strict. |
| `erebor session auto-adopt add --config <path> --runner linux-host --profile <name> --join-session <id>` or `--create-per-exec` | Deferred final Phases 6–7 | Registers an Erebor-owned route for normally launched future Codex execs. It does not launch Codex itself or require the user to label the later process. | `--join-session` captures the command's derived launch context and joins that session later. `--create-per-exec` installs a default profile route that creates a fresh session. Phase 7 fanotify admission holds the exec before either path can resume it. |
| `erebor session auto-adopt list [--format <format>]` | Deferred final Phase 6 | Lists persistent auto-adoption routes visible to the caller. | A non-root caller sees only routes it owns. |
| `erebor session auto-adopt remove --route <id>` | Deferred final Phase 6 | Removes one caller-owned route. | Context routes also expire with their session/context root; default routes otherwise persist until removal or profile/template invalidation. |

`session auto-adopt` is the public name for the OS-mediated path previously
called “automatic adoption.” Its active registration is an **auto-adoption
route**; a process that passes that route is **auto-admitted**. `session adopt`
remains the name for the current manual PID/process-match operation. The
planned auto-adopt `add` command accepts neither a command position nor `--pid`
or `--match`, and it is Linux-host-only. Its mutually exclusive route modes are
`--join-session <id>` and `--create-per-exec`. A persistent privileged Erebor
host service owns the fanotify marks and durable route registry across CLI
invocations. The blocking `session run` process continues to own its live
session resources and registers an authenticated control endpoint with that
service when it is eligible for `--join-session`.

The later user still launches plain `codex`. No route label travels in that
command, its environment, or its arguments. Erebor derives launch context from
kernel-observable process state and stores the resulting opaque context id in
its own registry. Environment values are allowed only as explicitly reported
cooperative hints; they never select a strict route.

`session run` may itself launch a Codex process, and the common admission owner
may observe that launch. That does not change the command's meaning or make it
an auto-adopt registration for independently launched processes. Similarly,
manual `session adopt` must remain a separate non-strict compatibility path;
it must not be extended until it resembles pre-exec routing.

Automatic adoption is deliberately last. The earlier phases deliver and certify
the normal `session run` governance path—managed hooks, prompt ingress,
invocation leases, physical effects, filesystem/network integration, and
recovery—without requiring a plain user launch to be auto-admitted. Phase 6
adds the bounded host-service control plane and route registry; Phase 7 adds
held-exec admission only after that path and control plane are proven.

## Short Answer

Linux V1 has two complementary paths:

```text
Core Codex governance
  `session run` starts a configured Codex child in a governed session
  -> forced read-only session requirements + managed hook binary
  -> authenticated SessionStart attests the runtime
  -> UserPromptSubmit governs prompt ingress when it is the selected source
  -> PreToolUse creates an exact invocation lease
  -> Linux process/file/network enforcement consumes only that lease
  -> PostToolUse and lifecycle events close dispatch state

Final optional Linux `session auto-adopt` extension
  -> persistent privileged host service owns fanotify and durable routes
  -> context route: captures an Erebor-derived context for existing session S
  -> default profile route: declares a fresh-session template for matching execs
  -> a later normal IDE, CLI, TUI, Desktop, or user Codex exec is held
  -> verify exact Codex executable profile and derive opaque launch context
  -> exact healthy context route: join its existing session
  -> otherwise default profile route: create a fresh governed session
  -> no valid route: deny or report unavailable
  -> join the selected session's namespace, cgroup, interception state, and workspace view
  -> verify process/descriptor state at exec stop
  -> resume unchanged Codex
```

For an auto-admitted IDE App Server whose current source profile certifies an
approved pre-work transport interposition mechanism, the full-duplex transport
broker remains the authoritative original-prompt source. Linux V0's FD-splice
experiment is one Phase 7 candidate, not the selected V1 design. The broker
records the complete `turn/start` or `turn/steer` request before forwarding it
to Codex. `UserPromptSubmit` is then an authenticated hook attestation and
cross-check, not a duplicate prompt scope.

For a CLI, TUI, Desktop, or other profile without a pre-work App Server
transport boundary, a pinned and tested `UserPromptSubmit` hook can be the
prompt source. Its coverage claim is limited to the actual hook ordering proven
for that signed Codex profile.

```text
strict auto-admitted IDE profile
  held exec + namespace + verified stdio broker
  + managed hook attestation + invocation leases
  + approved Linux process/file enforcement
  + governed network boundary

strict normal `session run` non-broker profile
  session-run admission + namespace
  + managed SessionStart/UserPromptSubmit/PreToolUse hooks
  + tested prompt ordering + invocation leases
  + ptrace filesystem/process enforcement
  + governed network boundary
```

Linux may certify a stronger transport prompt source where its current profile
proves one. It must not assume the V0 App Server splice or treat any transport
interposition as a replacement for the mandatory hook-to-physical-effect
handoff.

## V1 Delta From Linux V0

| Concern | Linux V0 | Linux V1 |
| --- | --- | --- |
| Hook role | Exact `PreToolUse`/`PostToolUse` handoff for selected tools. | Common mandatory semantic and lifecycle contract: startup, prompt, tool, permission, subagent, stop, and dispatch closure. |
| Requirements delivery | Session-specific requirements and hook directory mounted in the session namespace. | Verified requirements and hook artifacts are projected read-only at their Codex paths inside the dedicated Erebor session filesystem. They do not alter Codex processes outside Erebor sessions. The final auto-adopt phases join that view before Codex reads configuration. |
| Prompt authority | App Server broker for supported stdio profiles. | Broker remains authoritative where present; `UserPromptSubmit` becomes a certified fallback source and cross-check without duplicate scopes. |
| Runtime state | Enrollment and native bindings are described across V0 sections. | One explicit session-run admission and lease state machine; final auto-adopt reuses it only after its own route proof. |
| Effect policy | ptrace handoff/leases, mostly Linux-specific vocabulary. | Platform-neutral, context-partitioned invocation capability contract consumed by the approved Linux enforcement profile and macOS ES/NE separately. fanotify is a final Phase 7 admission source, not an invocation lease consumer. |
| Coverage reporting | Per-profile strict/degraded conditions. | Shared `strict`, `action-governed`, `prompt-governed`, `degraded`, and `unavailable` states with separate semantic and physical dimensions. |
| Deployment root | Namespace is the primary forcing mechanism. | A root-owned verified artifact store supplies the profile, while the dedicated session filesystem is the delivery boundary at `/etc/codex/requirements.toml` and the managed-hook path. No host-global Codex requirements change is required. A local root user remains outside an unmanaged strict threat model. |

Linux V0 remains historical evidence and is not rewritten. Phase 7 may evaluate
its held-exec experiment as one candidate only after rerunning the relevant
fixture against the V1 requirements/profile and current signed Codex binaries.
No V1 architecture, including x86-64, is selected by the V0 result.

## Shared Governance Contract

### Forced Managed Profile

The supported profile supplies a root-owned, non-user-writable source artifact
and managed hook binary. Erebor projects the verified requirements file and
hook directory read-only into the dedicated session filesystem before Codex
starts or, for Phase 7, before a held candidate resumes. The projected
`/etc/codex/requirements.toml` is visible only in that session view; installing
the profile must not change the host-global Codex configuration seen by
processes outside Erebor sessions. Fleet and local deployment differ in who
protects the source artifact, not in this runtime delivery boundary.

The initial profile is intentionally the same event family as macOS V1. Phase
0 verifies schema and ordering for each signed Linux executable profile before
an event is enabled:

```toml
allow_managed_hooks_only = true
allow_remote_control = false

[features]
hooks = true

[hooks]
managed_dir = "/usr/lib/erebor/codex-hooks"

[[hooks.SessionStart]]
[[hooks.SessionStart.hooks]]
type = "command"
command = "/usr/lib/erebor/codex-hooks/erebor-codex-hook"
timeout = 10

[[hooks.UserPromptSubmit]]
[[hooks.UserPromptSubmit.hooks]]
type = "command"
command = "/usr/lib/erebor/codex-hooks/erebor-codex-hook"
timeout = 10

[[hooks.PreToolUse]]
[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/lib/erebor/codex-hooks/erebor-codex-hook"
timeout = 10

[[hooks.PermissionRequest]]
[[hooks.PermissionRequest.hooks]]
type = "command"
command = "/usr/lib/erebor/codex-hooks/erebor-codex-hook"
timeout = 10

[[hooks.PostToolUse]]
[[hooks.PostToolUse.hooks]]
type = "command"
command = "/usr/lib/erebor/codex-hooks/erebor-codex-hook"
timeout = 10

[[hooks.SubagentStart]]
[[hooks.SubagentStart.hooks]]
type = "command"
command = "/usr/lib/erebor/codex-hooks/erebor-codex-hook"
timeout = 10

[[hooks.SubagentStop]]
[[hooks.SubagentStop.hooks]]
type = "command"
command = "/usr/lib/erebor/codex-hooks/erebor-codex-hook"
timeout = 10

[[hooks.Stop]]
[[hooks.Stop.hooks]]
type = "command"
command = "/usr/lib/erebor/codex-hooks/erebor-codex-hook"
timeout = 10
```

The configuration is a proposal, not a claim that every current Linux Codex
binary exposes every event. The effective requirements composition, hook
inventory, hook schema fingerprint, managed directory, and feature values are
attested per supported executable profile. Conflict, unexpected administrator
hook, missing event, changed binary, or untrusted hook path blocks strict
promotion.

### Authenticated Hook Channel

The hook binary has one stable managed path inside the session view; it never
receives a session socket path from Codex configuration or hook JSON.

```text
enrolled Codex creates the hook stdin/stdout pipes and starts the pinned shell
  -> process guard observes the exact shell/interpreter-to-hook exec chain
  -> guard mints one hook ticket bound to runtime/profile epoch, pidfd/start
     identity, executable objects, argv, namespace/cgroup, and pipe identities
  -> root-owned hook connects to the stable Erebor broker endpoint
  -> broker authenticates SO_PEERCRED and consumes that one-use ticket
  -> broker verifies stdin/stdout still use the original Codex-owned pipes
  -> hook reads one bounded event and returns one authenticated result
  -> native ids become routing data only after the entire channel is trusted
```

The existing Unix broker's session token is useful transport defense but is not
enough for V1 hook authentication. Broad ancestry is also insufficient because
Codex invokes command hooks through a shell and a governed descendant could run
the genuine hook binary. The strict profile must prove the exact exec lineage,
root-controlled shell startup view and launch environment, original stdin and
stdout pipe objects, executable identities, namespace/cgroup identity, and
profile epoch. It rejects user-controlled shell startup, descriptor rewriting,
direct invocation, invocation below an effect-bound tool/subagent branch,
duplicate use, replay, and PID reuse. If a source profile cannot authenticate
both event input and policy result end to end, it cannot be strict.

### Runtime Admission State

Every runtime has one durable state machine:

```text
exec-selected
  -> process-admitted
  -> session-start-attested
  -> prompt-ready
  -> active
  -> draining
  -> closed

any state -> coverage-failed
```

`process-admitted` means that the owning admission path verified the exact
image, session selection, namespace, descriptor policy, and action guard. The
normal `session run` path establishes that state in Phases 1–5; final Phase 7
uses held exec for a plain externally launched candidate. Admission does not
allow a protected effect. `session-start-attested` proves an authenticated
managed hook descended from that enrolled Codex runtime. `prompt-ready` means
the selected ingress source may create a policy-bearing prompt node. Every
transition carries the runtime identity, requirements hash, hook profile hash,
executable fingerprint, namespace/cgroup identity, and health epoch.

An existing Codex process manually attached through `session adopt` did not
cross the V1 launch boundary and is never promoted to strict. It may be
action-governed where safe, terminated, or reported unavailable; later evidence
never repairs that missing boundary. A new process launched through `session
run` may become strict after the normal certification path, and a plain process
launched under final Phase 7 must first pass held exec and startup attestation.

## Native Identity And Routing

| Identity | V1 use | Never substitute |
| --- | --- | --- |
| Erebor session id | Policy and review owner selected by the normal session plan or a final Phase 6–7 auto-adoption route. | Codex session id or Linux login session. |
| Erebor runtime id | One governed Codex process lifetime. | PID alone. |
| PID start identity plus pidfd | Linux process lifetime and reuse-safe liveness. | PID or parent PID alone. |
| Executable object and profile fingerprint | Verified Codex source identity: object metadata, build/version, architecture, hash/signature evidence, argv profile. | Path, basename, CWD, IDE name, or prompt text. |
| Derived `LaunchContextId` | Exact route selection before exec. It is an Erebor-owned opaque value derived from a supported context kind and its full kernel evidence. | A caller-provided label, arbitrary environment variable, CWD, raw parent PID, timing, or a “most recent session” guess. |
| Mount namespace/cgroup identity | Session containment and hook/runtime membership. A controller-owned scope may contribute to a derived context only after its fixture passes. | A raw cgroup name or a process tree inferred only from timing. |
| Codex `session_id`, `turn_id`, `tool_use_id` | Native semantic routing facts after hook or broker authentication. | Erebor scope or process identity. |
| App Server `threadId`, `turnId`, `itemId` | Exact brokered native facts for the selected transport profile. | Hook timing or JSON-RPC request id alone. |
| Hook process lifetime | Authenticated lifecycle event source. | Caller-supplied event JSON. |
| fanotify permission event | Phase 7 held-exec admission source while the privileged host service is healthy. | Invocation identity or durable route ownership. |
| Approved Linux physical event | Process/file effect source bound to an invocation lease. | Command text or nearest active lease. |

### Deferred Final Phases 6–7: Durable Routes And Derived Launch Context

This is the final optional extension, not a prerequisite for the following
normal `session run` governance phases. It is specified here so its eventual
contract cannot blur the semantics of `session run` or manual `session adopt`.

Erebor—not the later `codex` command—owns labels. The privileged host service,
not the registration CLI process or an unrelated `session run` child, owns the
fanotify marks and route registry. A context route captures an opaque
`LaunchContextId` when its owning session is registered. A candidate's
held-exec collector derives the same kind of id from kernel-observable facts.
The first profile supports only kinds proven by a pinned source-profile fixture:

| Context kind | Derived evidence | Intended source profile |
| --- | --- | --- |
| `terminal` | Registered shell process lifetime and controlling PTY object identity. | CLI and TUI launched from that shell or its verified descendants. |
| `app-server` | Verified IDE/root process lifetime and inherited client pipe/socket FD topology. | Brokered IDE App Server. |
| `desktop` | Verified desktop-app root process lifetime. | Desktop-launched Codex. |
| `managed-scope` | Erebor-controller-owned systemd/cgroup scope identity and verified membership. | A source profile that has a proved controlled scope. |

Each process lifetime contains pidfd/start identity, executable identity, and
namespace evidence; it is never a raw PID label. A live `session run` worker
registers its authenticated control endpoint and lifetime with the host
service. The service records the context facts while the relevant root lives
and removes the route when its root or session expires. A candidate with only a
UID and executable profile may still be auto-admitted through a default profile
route, but it cannot honestly join an existing session without an exact derived
context.

There are two route types:

| Route | Match | Result |
| --- | --- | --- |
| Context route | Exact eligible profile plus exact healthy derived context. | Join the route's existing session. |
| Default profile route | Eligible UID/user namespace plus exact executable profile, with no selected context route. | Create one fresh governed session from the declared session template. |

Resolution is deterministic and safe:

1. Verify the candidate's UID/user namespace and exact executable profile.
2. Derive every fixture-certified launch context from the held candidate.
3. One exact healthy context route joins its existing session.
4. A matching context route that is unhealthy, expired, or conflicts with
   another route denies; it never falls through to a fresh session.
5. With no matching context route, one healthy default profile route creates a
   fresh session.
6. No route or more than one equally valid route denies or reports unavailable.

The registry rejects duplicate context keys and overlapping default profile
routes at registration time. Priority, registration sequence, and stable
session ids are audit facts, not a way to guess a user's intended session.
Prompt text, CWD, raw parent PID, untrusted environment, and timing never
select a session.

`session auto-adopt add` returns an opaque route id. Context routes expire with
their joined session or captured root. Default routes survive CLI and host
service restart until `session auto-adopt remove` or trusted profile/template
invalidation. On restart the service revalidates default routes and rebuilds
context routes only from authenticated live-session registrations; candidates
deny while required state is unavailable.

The root-owned host-service socket authenticates CLI and session-worker peers
with Unix peer credentials plus pidfd/start identity. A non-root caller may
register only its UID, its live sessions, and root-approved profile/template
references. The privileged service never opens a caller-supplied configuration,
namespace, executable, hook, or mount path. The CLI may use `--config` to build
an untrusted request, but the service independently resolves the named profile
digest and fresh-session template from its trusted registry.

Auto-adopt limits are hard root-owned profile policy, not CLI overrides. V1
defaults per UID/profile are 32 routes, 8 held candidates, 2 concurrent fresh
session builds, 16 active auto-created sessions, and a launch token bucket of
12 per minute with burst 4. The total held-exec admission deadline is 15
seconds, the live-session control RPC deadline is 3 seconds, and SessionStart
attestation is due within 10 seconds after resume. A profile may tighten these
values. Capacity, rate, or deadline exhaustion denies the candidate and writes
a stable audit reason; it never resumes the process unmanaged.

## Prompt Ingress Rules

### Brokered App Server

For a brokered `session run` profile, Erebor directly owns the child transport
before the first Codex instruction. A separately certified auto-admitted
profile may use the same broker only after Phase 7 proves an approved transport
interposition mechanism. The transport broker is authoritative:

```text
complete client JSONL turn/start or turn/steer
  -> durable pending context node
  -> policy decision
  -> exact original bytes forwarded to Codex
  -> exact native response/notification binds thread, turn, and item facts
```

The broker also governs sensitive direct client methods such as `command/exec`,
`process/spawn`, `fs/*`, and `thread/shellCommand`. An event hook cannot see all
client protocol methods and does not replace this boundary.

`UserPromptSubmit` for a brokered runtime verifies that Codex loaded the pinned
hook profile and records a matching semantic event. It must reconcile to the
existing prompt node through exact native facts; it does not append a second
original prompt or override the broker's observation order.

### Hook-First Profile

When no verified pre-work transport exists, `UserPromptSubmit` is the prompt
source only after a signed binary fixture proves the required order:

- SessionStart and runtime authentication occur before the selected prompt;
- no model request carrying the new prompt, PreToolUse event, or protected
  process/file/network effect occurs before the hook allow returns;
- queued, steered, resumed, cancelled, subagent, and concurrent prompt cases
  preserve exact IDs and observed order.

If only before-tool ordering passes, the runtime is action-governed but cannot
claim strict prompt confidentiality. Missing rich IDE context stays unavailable
rather than reconstructed from later transcripts, model traffic, or output.

## Tool Invocation Lease

One authenticated `PreToolUse` event creates an exact, short-lived capability:

```text
InvocationKey
  Erebor session id
  Erebor runtime id
  exact Scope Context DAG scope ref/item node stream
  Codex session_id
  Codex turn_id
  Codex tool_use_id

InvocationLease
  key, tool name, structured input, effect class, allowed targets
  bound Scope Context DAG node stream and decision-time head
  hook process identity, profile/health epoch, expiration
  physical process roots, descriptors, file identities, and flows when bound
```

Lease state is shared with macOS V1:

```text
preparing -> response-issued -> armed -> effect-bound
  -> dispatch-complete -> closed
```

Linux V1 determines the `response-issued` to `armed` barrier with the held
hook-child exit and ptrace event order proven in Phase 0. No protected action
may consume a response-issued, failed, expired, mismatched, or unbound lease.

The first strict profile maintains one armed, unbound handoff lane per exact
context and effect class, not per runtime. Different context lanes proceed
concurrently. Within one context, command handoff serializes only until the
first physical child is bound; already-bound descendants may overlap later
leases. In-process mutations in different contexts proceed concurrently only
when their operation/target capabilities are disjoint and the physical adapter
can distinguish them. Ambiguous or overlapping mutations serialize or deny.
No lane selects an item from command text, CWD, timestamp, or nearest-prompt
guesses.

### Linux Command Handoff

```text
armed command lease C
  -> Codex reaches pinned command-launch shape
  -> ptrace stops fork/clone before child executes freely
  -> validates child against C's already-selected structured input
  -> binds child process lifetime to C's node stream
  -> resumes child
  -> copies binding across fork/clone/exec/reparent/background
```

The launch shape validates the lease; it never chooses among leases. A shell
that later launches Python retains the originating invocation association.

### In-Process Mutation Handoff

For apply-patch or another supported in-process path, the runtime's guarded
filesystem operations consume a capability derived from the exact structured
tool input. The lease restricts operation, target identity, mutation class, and
lifetime. It is not permission for arbitrary writes by the Codex process.

`PostToolUse` records dispatch completion and tool output. It closes authority
to bind a new command root or begin a new Codex-process mutation for that
lease. It cannot authorize an earlier effect or erase a living child, open
writable descriptor, mapping, or in-flight network flow. Already-bound
resources retain only their original invocation capability until resource
exit, explicit cancellation/revocation, session closure, or health-epoch loss;
they cannot be relabelled to a later context.

## Linux Physical Enforcement

Linux V1 retains native mechanisms that macOS cannot transparently duplicate:

```text
ptrace
  -> validates final image, controls child process creation, traces process
     lineage, denies unleased syscalls, and binds descendants for the normal
     session-run path and any later auto-admitted process

final Phase 7 fanotify permission event
  -> holds a plain externally launched candidate before userspace

mount namespace + OverlayFS session view
  -> gives selected launched processes the governed workspace view; Phase 7
     extends that view to a verified auto-admitted candidate

cgroup/process registry
  -> membership, cleanup, and runtime-to-effect routing
```

The Linux filesystem surface remains the owner of layer manifests, checkpoint,
promotion, and rollback. This Codex plan only supplies the runtime/invocation
context used when it asks the filesystem surface to allow a protected action.
The namespace/overlay is containment, not a replacement for hooks or lease
validation.

Network enforcement is a separate native Linux adapter. It must offer the same
contract as the macOS Network Extension profile: default deny for profiled
Codex runtime identities without a current session/lease rule, explicit direct
and loopback coverage, and no request-level attribution for a reused connection
without an owned gateway or direct handoff.

## Coverage States

Every runtime reports semantic and physical coverage independently:

| State | Prompt ingress | Managed hook lifecycle | Physical process/file/network enforcement | Meaning |
| --- | --- | --- | --- | --- |
| `strict` | Certified broker or hook-first source | Pinned, attested, complete for profile | Required effect matrix passed and healthy | Exact prompt-scoped action policy is available. |
| `action-governed` | Missing or partial | Partial or unavailable | Session/process effects constrained | Effects are governed; exact prompt attribution is unavailable. |
| `prompt-governed` | Certified | Pinned | Physical matrix incomplete | Codex can be stopped semantically; non-bypassable effects are not claimed. |
| `degraded` | A known gap | A known gap | Conservative deny or documented partial coverage | First gap remains durable; later events do not repair it. |
| `unavailable` | Unsupported | Unsupported or unhealthy | Unsupported or unhealthy | Strict admission is denied. |

No report reduces this to a single `managed = true` field.

## Current-Code Grounding

The current repository provides reusable Linux pieces, but none is the V1
Codex owner yet:

- `crates/erebor-runtime-session/src/interception_backend.rs` has only the
  `LinuxPtrace` backend bundle and produces Linux-host manual-adoption options.
- `crates/erebor-runtime-session/src/os/linux/process_guard.rs` and its module
  family own current ptrace process-tree and file interception, not fanotify
  held exec, Codex profiles, hook leases, or FD splice lifecycle.
- `crates/erebor-runtime-session/src/adoption.rs` implements the current
  `session adopt` PID/process-match resolver for manual adoption. It is not the
  owner of `session auto-adopt`, verified executable-profile routing, or
  pre-exec admission.
- `crates/erebor-runtime-session/src/session_side_resources.rs` assembles
  interception, filesystem overlay wrappers, session resources, and Linux host
  runner wiring. Those resources live with the blocking `session run` process;
  no current persistent process owns fanotify routes across CLI invocations.
- `crates/erebor-runtime-session/src/runtime_interception_broker/platform.rs`
  exposes a Unix socket with a shared session token. It does not authenticate a
  hook through peer credentials, executable identity, ptrace lineage, cgroup,
  or mount namespace.
- `crates/erebor-runtime-filesystem/src/linux_overlay_session.rs` prepares the
  Linux OverlayFS session wrapper. Its namespace view is reusable containment,
  but no V1 hook or Codex requirements artifact is injected today.
- `crates/erebor-runtime-core/src/config/session/interception.rs` defines the
  `LinuxPtrace` backend selection; current config has no Codex executable
  profile, forced requirements, hook profile, or coverage-state contract.
- `crates/erebor-runtime-ipc` owns versioned IPC framing and is the correct
  home for shared hook/auto-adoption wire contracts rather than ad hoc JSON.
- `experiments/codex-stdio-mitm-probe/` records Linux V0 held-exec/FD-splice
  feasibility evidence. It is not a production owner.

## Target Ownership

```text
crates/erebor-runtime-core/
  Codex governance config, profile validation, coverage state, run/adopt/
  plan facts; Phase 6 adds auto-adopt plan facts, route declarations, trusted
  template references, and bounded profile limits

crates/erebor-runtime-cli/src/cli/session/
  command parsing and request translation only; Phase 6 adds distinct
  Linux-host `session auto-adopt add/list/remove` wiring without moving route
  selection here

crates/erebor-runtime-ipc/
  versioned host-service, live-session registration, auto-adoption,
  hook-attestation, lease, and physical-effect contracts

crates/erebor-runtime-session/src/codex/
  profile registry, normal session-run admission state, hook broker, native
  bindings, transport broker, lease owner, and recovery; Phase 6 adds live
  session registration and the user-scoped fresh-session worker owner

erebor-runtime-host-service
  privileged persistent service owning fanotify marks, trusted route registry,
  peer authorization, hard admission limits, and held-candidate dispatch

crates/erebor-runtime-session/src/os/linux/codex/
  ptrace, pidfd, namespace/cgroup session admission, and Linux physical-effect
  binding; Phase 7 adds fanotify held exec, launch-context evidence, and only
  the currently approved profile-specific transport mechanism

crates/erebor-runtime-session/src/os/linux/process_guard/
  existing general ptrace guard stays a sibling collaborator, not a dumping
  ground for Codex protocol and profile ownership

crates/erebor-runtime-e2e/
  real Linux Codex source-profile, auto-adoption, hook, filesystem, network, and
  recovery fixtures
```

Phase 0 confirms names and may choose a more readable module split. It must not
add `cfg` branches or Codex-specific state throughout existing generic Linux
guard code.

## Non-Negotiables

- Do not implement a phase without explicit user approval.
- Keep Linux V0 as historical evidence; do not silently redefine a V0 pass as
  V1 proof or architecture selection.
- Do not modify, patch, inject into, re-sign, or replace Codex or an IDE.
- Do not require an IDE setting, shell wrapper, alias, environment variable, or
  special Codex invocation for `session auto-adopt` routing.
- Do not conflate `session run`, manual `session adopt`, and proposed
  `session auto-adopt`; only the last creates a route for a later normal exec.
- Do not use a path, command text, CWD, PID, parent PID, timing, or nearest
  prompt as an identity substitute.
- Do not treat a static requirements file as proof that Codex loaded the
  effective hook profile.
- Do not change the host-global Codex requirements file; project the verified
  profile only into the dedicated Erebor session filesystem.
- Do not trust broad ancestry or a genuine hook executable without its exact
  one-use launch ticket and Codex-owned input/output pipe provenance.
- Do not treat `UserPromptSubmit` as a second prompt source when a brokered
  request already owns the original prompt boundary.
- Do not allow protected process, filesystem, or network effects merely because
  a hook returned success; a matching armed lease is required.
- Do not promote existing runtimes to strict after the fact.
- Do not call an auto-admitted IDE App Server brokered unless its current
  profile proves an approved pre-work transport interposition mechanism.
- Do not let an unowned/reused network connection claim exact tool attribution.
- Do not call a profile strict if an entitlement, kernel capability, hook event,
  descriptor, pre-opened-FD, mmap, crash, or concurrency fixture is skipped.
- Do not collapse the filesystem-overlay plan into this plan. The shared
  interface is a context-bearing action authorization request.

## Implementation Phases

- [Phase 0: Linux V1 Profile And Ordering Feasibility](./codex-attribution-v1/phase-0-feasibility.md)
- Phase 1: Unified Managed Profile And Hook Trust Root (phase document not recovered)
- [Phase 2: Prompt Ingress And Transport Broker Reconciliation](./codex-attribution-v1/phase-2-prompt-ingress-and-transport.md)
- Phase 3: Invocation Leases And Linux Physical Effects (phase document not recovered)
- [Phase 4: Filesystem And Network Governance Integration](./codex-attribution-v1/phase-4-filesystem-and-network-integration.md)
- [Phase 5: Network Bypass Closure](./codex-attribution-v1/phase-5-network-bypass-closure.md)
- [Phase 6: Auto-Adopt Host Service, Routes, And Limits](./codex-attribution-v1/phase-6-auto-adopt-host-service-routes-and-limits.md)
- [Phase 7: Auto-Adopt Held Exec, Derived Context, And Runtime Attestation](./codex-attribution-v1/phase-7-auto-adopt-held-exec-derived-context-and-runtime-attestation.md)
- [Linux V1 lifecycle probe](./codex-attribution-v1/lifecycle-probe.md)

## Verification Contract

Every approved implementation phase reports:

- exact files and owner boundaries changed;
- the V1 behavior added and unchanged V0/Linux behavior preserved;
- crate-local and e2e tests added or updated;
- the applicable live-probe result and required kernel/privilege state;
- the pinned Codex client, executable fingerprint, App Server schema fingerprint,
  requirements/profile hash, kernel version, and tool coverage;
- strict/action-governed/prompt-governed/degraded/unavailable outcome;
- explicit `Done`, `Not done`, or `Blocked` state.

Before a phase is marked done, run the relevant focused checks and then:

```sh
cargo fmt
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

The lifecycle probe is mandatory for source profiles that cross process,
namespace, FD, hook, filesystem, or network boundaries. A non-privileged host
may skip a local probe only when it records the exact missing capability; the
required release fixture cannot skip it.

## Research Basis And Boundaries

V1 is derived from the recorded Linux V0 held-exec/stdio-splice evidence and
the macOS V1 managed-hook/lease model. It does not claim that a future Codex
binary preserves any hook schema, event order, or App Server transport. Every
enabled profile pins and tests its actual executable and schema.

The current public Codex manual could not be refreshed in this environment
because DNS access to `developers.openai.com` is unavailable and the official
docs MCP is not installed. The local V0/macOS plans contain the source-pinned
research references used here; Phase 0 must refresh the official documentation
and signed-binary evidence before implementation.

## Stop Point

Stop after creating V1. Do not start Phase 0 until the user explicitly approves
it. Phase 0 may update later phase files from current Linux kernel, Codex,
requirements, and source-profile evidence; it does not approve production
adoption, hook installation, filesystem enforcement, or fleet rollout.
