# Codex Linux V1 Lifecycle Probe

Status: Phase 0 has an initial requirements-projection fixture and one required
real App Server turn proving five managed events. The lifecycle fixture remains
blocked for certification; it does not certify a source profile yet. See [the
Phase 0 result](./phase-0-result.md).

## Purpose

Prove that a Codex process launched through normal `session run` receives the
certified V1 governance profile before it can perform a protected action. Final
Phase 6 proves the persistent auto-adopt control plane and Phase 7 separately
proves held-exec admission for an otherwise plain external Codex launch. The
core probe chain is:

```text
session-run admission
  -> session namespace/workspace view
  -> runtime SessionStart attestation
  -> selected prompt ingress
  -> authenticated PreToolUse
  -> armed invocation lease
  -> process/file/network effect binding
  -> checkpoint/promotion/rollback evidence where filesystem is enabled
  -> dispatch closure and recovery
```

Unit tests cannot replace this probe because the properties cross kernel event
ordering, pidfds, ptrace, namespace entry, FD topology, Codex hooks, real client
transport, filesystem sessions, and network effects.

## Safety Boundary

- The fixture uses disposable directories, a dedicated test user/session when
  practical, and a uniquely identified session root.
- It never invokes manual `session adopt` for an arbitrary developer IDE or
  modifies the host-global Codex requirements file. The verified test profile
  is projected only into the disposable session filesystem.
- Test requirements, hook binaries, sockets, cgroups, mounts, and processes
  include a run id and ownership marker before cleanup is allowed.
- Cleanup refuses a path, process, mount, or cgroup whose identity does not
  match the recorded fixture.
- Failure preserves the evidence required for diagnosis and reports manual
  cleanup steps; it does not guess and recursively delete a path.

## Required Gate

```text
default local mode
  -> privileged live tests may report blocked when ptrace, namespace,
     mounted OverlayFS, or the pinned Codex profile is unavailable

required profile/release mode
  EREBOR_REQUIRE_CODEX_LINUX_V1_PROBE=1
  -> every missing capability or fixture is a failing typed result
```

Required mode records the exact kernel, distribution, security policy,
capabilities, Codex executable, IDE extension/Desktop version, App Server
schema fingerprint, requirements hash, hook hash, and source-profile name.
Phase 6 additionally requires the privileged host-service fixture. Phase 7
requires its fanotify held-exec, derived-context, architecture/mechanism, and
first-instruction fixtures.

## Fixture Inputs

The core `session run` profile uses:

```text
one Erebor session S
one disposable OverlayFS workspace
one root-owned verified test requirements source artifact projected into S
one root-owned test hook binary and stable broker endpoint
one pinned Codex CLI profile
one pinned IDE App Server profile when an approved transport fixture is enabled
one allowed and one denied command/apply-patch tool fixture
one direct and one loopback network fixture
```

Phase 6 additionally uses the privileged host service, one registered live
session with a context route, and one default-profile `session auto-adopt` route
with a root-approved fresh-session template. Phase 7 uses plain matching Codex
launches against those routes.

Record before every run:

- kernel release, distribution, fanotify/ptrace capabilities, LSM/seccomp and
  user-namespace state;
- test user uid/gid, cgroup, mount namespace, workspace mount identities, and
  overlay lower/upper/merged paths;
- executable object/profile fingerprint, argv, hash/signature evidence, Codex
  version, client/IDE version, and App Server schema fingerprint;
- effective requirements composition, all enabled hooks, managed directory,
  hook binary object identity, and profile hash;
- hook broker, host service, live-session worker, fanotify supervisor, tracer,
  filesystem, and network health epochs.

Phase 6 records route ownership, peer authorization, profile/template epoch,
and effective limits. Phase 7 also records derived
terminal/IDE/Desktop/scope context evidence, the owning root process lifetime,
architecture/mechanism support, and the route-resolution result.

## Phase 0: V1 Capability And Ordering

1. Run each normal `session run` target Codex surface with the test requirements
   profile.
2. Capture every lifecycle hook event, exact JSON schema, shell/interpreter and
   hook exec history, original stdin/stdout pipe identities, peer evidence, and
   relative order.
3. For a brokered App Server, show that a `turn/start` line is persisted before
   forwarding and that a matching UserPromptSubmit does not create a second
   prompt node.
4. For a hook-first CLI/TUI profile, prove or reject before-model and
   before-tool ordering with an observed provider/effect fixture.
5. Run identical commands in distinct contexts concurrently, then exercise
   same-context handoff and disjoint/overlapping mutations. No first effect may
   outrun the hook-child exit barrier.
6. Kill hook, broker, tracer, filesystem owner, and network owner at every
   normal-session transition. Record whether the session fails closed.
Promotion requires an explicit result for each claim. An upstream source read,
fake target, or later App Server history does not promote a hook/order claim.

## Phase 1: Hook Trust Root

For each hook event, attempt:

- direct execution of the hook binary;
- genuine-hook execution from an effect-bound tool/subagent descendant;
- forged session/turn/tool JSON;
- same-uid unrelated process connection;
- malicious `SHELL`, `BASH_ENV`, `ENV`, `ZDOTDIR`, and shell startup files;
- rewritten stdin/stdout descriptors and hook result;
- wrong executable/argv chain, namespace, cgroup, pid start identity, and
  profile;
- stale/replayed broker connection;
- altered requirements/hook binary/managed directory;
- oversized and malformed input;
- broker timeout and restart.

Every negative case returns no usable runtime/prompt/lease state. Capture the
one-use ticket, peer credential, exact exec chain, pipe objects, pidfd, cgroup,
namespace, and profile evidence for the positive case without relying on
caller-provided fields.

## Phase 2: Prompt Ingress

### Brokered IDE/App Server

Run normal `session run` IDE traffic through Erebor-owned child transport and
prove:

- Erebor owned the client/Codex transport before the Codex image ran;
- no byte of `turn/start`/`turn/steer` reaches Codex before the broker persists
  the pending prompt and releases policy;
- exact request/response/notification facts bind native session/thread/turn/item
  ids;
- UserPromptSubmit reconciles to the existing scope rather than creating one;
- malformed/missing/late hooks downgrade coverage rather than repairing it;
- direct `thread/shellCommand`, `command/exec`, `process/spawn`, `fs/*`, and
  other sensitive client methods are denied or independently scoped;
- framing, disconnect, reconnect, split/coalesced JSONL, cancellation, queued
  input, steer, resume, and concurrent windows retain exact ordering.

### Hook-First CLI/TUI/Desktop

Prove the actual UserPromptSubmit ordering for each profile. It is a strict
prompt source only when no prompt-bearing model request or protected effect can
precede its allow. Otherwise it is action-governed or prompt-governed according
to the observed matrix.

## Phase 3: Lease And Effect Binding

For an admitted prompt and one exact PreToolUse:

1. Verify runtime/session/turn/tool IDs and structured input.
2. Freeze the decision-time context and issue allow or deny.
3. Confirm allow is only `response-issued` until the proven hook-exit barrier.
4. Confirm the next allowed command child or in-process filesystem operation
   consumes that exact lease.
5. Confirm distinct context lanes proceed concurrently while the same-context
   unbound handoff remains deterministic.
6. Confirm PostToolUse rejects new roots and Codex-process mutations but does
   not relabel or erase already-bound descendants, descriptors, mappings, or
   flows.

Required negative matrix:

- hook failure, malformed input, denial, timeout, missing post event, and
  cancellation;
- two identical commands in distinct contexts, same-context handoff, disjoint
  concurrent mutations, overlapping mutations, and tool reordering;
- shell-to-Python-to-unlink, fork-before-exec, background/reparent, and exec
  replacement;
- lower/upper workspace paths, pre-opened writable descriptors, descriptor
  reuse, mmap, clone, rename, hardlink, symlink, xattr, and metadata mutation;
- attempt to borrow an armed patch lease from an old command descendant.

Audit evidence must show native hook event, policy decision, lease state,
physical source, final allow/deny, and exact DAG node separately.

## Phase 4: Filesystem And Network

With the Linux filesystem surface enabled:

- write allowed changes through the merged OverlayFS workspace;
- try raw host, lower, upper, workdir, namespace, symlink, inherited-FD, and
  pre-opened-descriptor bypasses;
- checkpoint session layer, promote after committed preimages, roll back, and
  verify host state and context references;
- inject unsupported metadata/second-volume failure and prove no partial host
  promotion.

With the selected Linux network owner enabled:

- allow an effect-bound command descendant to establish its approved flow;
- deny direct Internet, IPv4/IPv6 literal, DNS, proxy/helper, loopback raw CDP,
  Unix-local service, and out-of-lease child attempts;
- test connection reuse across two leases and label it session-governed unless a
  direct request handoff proves exact invocation identity;
- kill/restart the network owner and prove stale/unknown state defaults deny.

## Phase 5: Recovery And Certification

Run failure and update at every durable state:

```text
session-run admission
  -> process-admitted
  -> SessionStart
  -> prompt pending/accepted
  -> lease preparing/armed/effect-bound
  -> filesystem checkpoint/promotion/rollback
  -> network flow
  -> dispatch close
```

Assert:

- no process, hook, prompt, lease, or flow is reconstructed solely from PID or
  historical output after restart;
- changed Codex/IDE binary, requirements composition, hook executable, schema,
  or transport profile becomes unavailable until re-certified;
- strict, action-governed, prompt-governed, degraded, and unavailable reports
  preserve their first coverage gap;
- cleanup releases only fixture-owned processes, pidfds, sockets, cgroups,
  mounts, and session artifacts.

## Phase 6: Auto-Adopt Host Service, Routes, And Limits

Only after the normal `session run` profile has passed Phase 5 certification:

1. Start the root-owned host service and authenticate CLI and live-session
   worker connections with peer credentials plus pidfd/start identity.
2. Register live session S, add a context route without a user label, and add
   one root-approved default fresh-session route. List both as the owning user.
3. Reject cross-UID operations, arbitrary config/profile/template/resource
   paths, stale worker/session ids, duplicate contexts, and overlapping
   defaults.
4. Remove and expire routes, then restart the service. Prove defaults are
   revalidated and context routes return only after authenticated worker
   re-registration.
5. Hit the configured route, pending-candidate, build, active-session, launch
   rate, RPC, and deadline limits. Every case returns a stable fail-closed
   reason and audit record.
6. Confirm route status remains `not-active`; Phase 6 alone does not claim that
   a plain Codex launch is intercepted.

## Phase 7: Auto-Adopt Held Exec, Derived Context, And Startup

Only after Phase 6 passes:

1. Select no mechanism from V0 by default. Run the current held-exec,
   namespace, process-control, descriptor, and transport candidates on the
   approved architecture/profile and record supported, unsupported, or
   unproven results.
2. Activate the host service's fanotify owner, launch plain `codex` from the
   registered terminal context, and prove the exec remains held before the
   target first-instruction marker.
3. Verify the held candidate derives the registered launch context and joins S.
   Expire the route and prove a later launch cannot join through stale PID or
   PTY state.
4. Launch a matching plain Codex process with no context route and prove one
   default route creates exactly one fresh session.
5. Exercise duplicate default, conflicting/unhealthy context, no route,
   copied/renamed executable, changed image, PID reuse, wrong argv, unsupported
   architecture/mechanism, concurrent candidates, and existing-process cases.
   None may use priority, CWD, environment, or a “most recent session” fallback.
6. Verify namespace, cgroup, dedicated requirements view, descriptor/transport
   policy, process guard, and `process-admitted` state before final resume.
7. Require the end-to-end authenticated SessionStart hook before any protected
   effect. Test a malicious shell chain, pipe replacement, descendant-launched
   genuine hook, missing event, replay, mismatch, and timeout.
8. Kill the host service, session worker, fanotify worker, tracer, context root,
   and route owner at every transition. A profile that cannot prove denial
   before first instruction cannot claim strict auto-adoption.

The distinct final-phase admission path is:

```text
authenticated host service + context route or default profile route
  -> held exec
  -> process-admitted
  -> SessionStart
```

## Final Evidence Bundle

Required runs retain:

- profile/version/schema/requirements/hook fingerprints;
- process and executable identity, registration, namespace/cgroup, pidfd, and
  descriptor evidence;
- host-service peer authorization, route lifecycle, limits, architecture, and
  mechanism evidence;
- broker request/response/notification ordering evidence;
- authenticated hook lifecycle and peer evidence;
- lease/action/filesystem/network audit records;
- filesystem checkpoint/promotion/rollback artifacts when enabled;
- failure/recovery/update results;
- explicit coverage-state matrix and cleanup inventory.

## Final Acceptance

A normal `session run` Linux source profile is strict only when the real fixture
proves:

- the managed profile is both forced and attested;
- prompt ingress is certified through the broker or a tested hook-first path;
- each protected effect consumes an exact current invocation lease;
- namespace/OverlayFS and network bypasses are covered by their selected native
  owners;
- crash, update, descriptor, concurrency, and recovery gaps fail closed;
- every missing proof is reported as a coverage limitation rather than inferred.

An auto-adopted source profile additionally proves the Phase 6 host-service and
route contract plus Phase 7 resolution before target userspace: an exact
derived context joins its existing session, or one default profile route
creates a fresh session. It also proves its current architecture and physical
mechanism instead of inheriting Linux V0's result. Auto-adopt remains outside
the requirements for the certified normal `session run` profile.
