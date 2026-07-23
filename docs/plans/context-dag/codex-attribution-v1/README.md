# Codex App Server Attribution Linux V1 Implementation Subplan

Status: Phase 0 is **done** as a conservative feasibility result and certifies
no strict Linux profile. Phase 1 is **done** with a live managed-hook profile.
Phase 2 is **done** for the explicit direct-child App Server stdio profile;
it provides prompt provenance only. Phase 3 is **done as conservative
enforcement**: its shared Context DAG writer persists every authenticated hook
and pins the associated audit facts; its lease owner and physical router gate
are live. Phase 0 did not prove the hook-exit/ptrace barrier, so every
non-bootstrap tool effect seen by the configured process/file interception
routes still fails closed and the profile is not strict.

Parent design:

- [Codex App Server Attribution And Governance — Linux V1](../codex-attribution-v1.md)

Related historical and sibling plans:

- [Linux V0 implementation subplan](../codex-app-server-attribution/README.md)
- [macOS V1 implementation subplan](../codex-app-server-attribution-macos-v1/README.md)
- [Linux filesystem OverlayFS implementation](../../revert/filesystem-surface/linux-ostree-overlay-v3-implementation/README.md)

## Goal

Implement a Linux Codex governance profile whose hook protocol, runtime
admission state, invocation lease, coverage vocabulary, audit facts, and
fail-closed behavior match macOS V1 wherever the operating system permits.

Linux V1 uses the approved Linux process-control profile, mount namespace
entry, and OverlayFS session views in the normal path. Its final optional
auto-adopt phases add a persistent privileged host service and then fanotify
held exec. Pre-execution IDE App Server transport interposition is enabled only
for a current profile that separately proves an approved mechanism; Linux V0's
FD-splice experiment does not select it for V1.

Automatic adoption is intentionally the final optional phase group. The normal
`session run` governance path is implemented and certified first; no earlier
phase depends on a plain user `codex` launch being intercepted or routed.

## CLI Contract

The implementation keeps three different session operations distinct:

- Current `session run` launches the caller's new command in a governed
  session; it is not an auto-adoption registration for a later independent
  Codex exec.
- Current Linux-host `session adopt --pid` or `--match` manually attaches one
  existing selected process. It remains non-strict because it missed the
  pre-exec boundary.
- Final Phases 6–7 add Linux-host `session auto-adopt add --profile <name>` as
  an Erebor-owned route for future plain Codex execs. `--join-session <id>`
  captures the calling command's derived context for that existing session;
  `--create-per-exec` installs a default profile route that creates a fresh
  session. It has no command, PID, or process-match target and is the only path
  in this plan that may start strict V1 admission for a future plain launch
  outside `session run`. `session auto-adopt list` and `remove --route <id>`
  make the persistent route lifetime explicit.

The CLI remains request wiring. The later user never supplies a route label:
context derivation, route selection, held-exec admission, and runtime state
belong to the Codex session and Linux platform owners.

## Non-Negotiables

- Implement only one explicitly approved phase at a time.
- Phase 0 is a probe and contract refresh, not production authorization.
- Linux V0 evidence is input to V1; it is not an automatic V1 pass.
- Do not patch, inject into, re-sign, replace, or configure an IDE to launch
  Codex differently.
- Do not require a wrapper, alias, PATH change, special flag, or environment
  variable for `session auto-adopt` routing.
- Do not trust a candidate environment variable as strict route-selection
  evidence. It is at most a reported cooperative hint.
- Do not merge `session auto-adopt` into `session run` or manual `session
  adopt`.
- Do not trust hook JSON, session id, PID, CWD, argv, or path until the hook
  process, exact shell/interpreter exec lineage, Codex-owned stdin/stdout pipe
  objects, and enrolled runtime are authenticated with a one-use ticket.
- Do not change the host-global Codex requirements file. Project the verified
  profile read-only into the dedicated Erebor session filesystem.
- Do not infer prompt/item/action associations from command text, timing, or
  nearest active work.
- Do not make UserPromptSubmit create a duplicate scope for a brokered App
  Server prompt.
- Do not grant a protected effect without an exact armed lease.
- Do not call a profile strict when the pinned executable, hook schema,
  requirements composition, namespace/descriptor state, kernel capability, or
  required negative fixture is unproven.
- Keep filesystem layer/promotion/rollback ownership in
  `erebor-runtime-filesystem`; this plan supplies context-bearing admission.
- Every production phase adds real Rust tests. Cross-process, namespace, FD,
  hook, filesystem, and network behavior also requires e2e/live proof.

## Existing Baseline

The repository currently has:

- `LinuxPtrace` interception in
  `crates/erebor-runtime-session/src/interception_backend.rs`;
- Linux process guard ownership under
  `crates/erebor-runtime-session/src/os/linux/process_guard/`;
- manual `session adopt` PID/process-match resolution in
  `crates/erebor-runtime-session/src/adoption.rs`;
- session lifecycle and side-resource assembly in
  `crates/erebor-runtime-session/src/session_side_resources.rs`, owned for the
  lifetime of the blocking `session run` process;
- a token-authenticated Unix runtime-interception broker;
- Linux OverlayFS session views in `erebor-runtime-filesystem`;
- the isolated V0 held-exec/FD-splice experiment under
  `experiments/codex-stdio-mitm-probe/`.

The repository does not have:

- `session auto-adopt` route registration, derived launch-context collector,
  or default session factory; normal `session run` now has a Codex executable
  profile registry, artifact projection, guarded ticket issuer, authenticated
  hook broker, and a live fixture, but not auto-admission;
- a fanotify permission owner in production;
- a persistent privileged host service or live-session registration protocol;
- production pidfd/FD transfer or auto-admitted App Server descriptor
  replacement;
- a signed/root-owned Linux managed-hook artifact or requirements profile;
- end-to-end hook input/result authentication through the shell/interpreter;
- a strict V1 runtime-admission or physical-effect profile: Phase 3 now has a
  V1 invocation-lease owner and a fail-closed process/file router gate, but no
  production lease can arm until the hook-exit/ptrace barrier and physical
  matrix are certified;
- hook-first prompt authority, IDE-inherited transport interposition, or a
  production broker outside the explicit direct-child App Server stdio profile;
- Codex-to-filesystem/network effect bindings;
- real Linux V1 CLI/TUI/Desktop source-profile fixtures beyond the pinned
  direct-child App Server fixture.

## Target Ownership

```text
erebor-runtime-core
  validated Codex governance configuration, profile declarations, coverage
  state, and run/adopt plan facts; Phase 6 adds auto-adopt route declarations,
  trusted session-template references, hard profile limits, and plan facts

erebor-runtime-cli/src/cli/session
  request parsing only; Phase 6 adds `session auto-adopt add/list/remove`
  wiring to the privileged host service

erebor-runtime-ipc
  versioned hook, host-service, live-session registration, auto-adoption,
  lease, and physical-effect requests/responses

erebor-runtime-session/src/agents/codex
  profile registry, normal session-run admission state, hook broker, prompt/item
  bindings, transport broker, invocation-lease owner, audit/recovery; Phase 6
  adds live-session registration and user-scoped fresh-session workers

erebor-runtime-host-service
  persistent privileged fanotify and durable-route owner, peer authorization,
  bounded admission dispatch, and trusted profile/template registry

erebor-runtime-session/src/os/linux/codex
  ptrace, pidfd, namespace/cgroup session admission, and Linux
  process/file/network physical-effect adapter; Phase 7 adds fanotify held exec,
  launch-context evidence, and only an approved profile-specific transport
  mechanism

erebor-runtime-filesystem
  governed session filesystem view, layer, checkpoint, promotion, rollback;
  accepts an action/context authorization request at a narrow seam

erebor-runtime-e2e
  pinned real Codex/IDE/CLI source profiles and privileged lifecycle fixtures
```

Do not create every target module in Phase 1. Phase 0 confirms the narrowest
current-code seam and later phases add only live owners.

## Phase 0 Baseline

Phase 0 reads the isolated V0 probe as historical capability evidence. Phase 7
may re-run it as one candidate against a pinned current Linux Codex executable
and requirements profile, not only a fake target. Phase 0 establishes:

- exact hook event availability, input schemas, effective requirements
  composition, and forceability;
- SessionStart/UserPromptSubmit/PreToolUse/PostToolUse ordering;
- brokered-versus-hook prompt reconciliation;
- which process-control claims support the normal path, and which final Phase 7
  fanotify, transport-interposition, and derived-context claims need a live
  fixture, without assuming x86-64 or FD-splicing;
- hook-child exit to first physical-effect barrier;
- process/file/network bypass and failure behavior;
- whether an authenticated stable broker endpoint can prove the hook's exact
  Codex-owned shell/interpreter and pipe chain without a caller-supplied session
  route in the normal session path.

## Required Evidence Per Phase

Every phase result includes:

- exact changed files, owners, and compatibility impact;
- pinned Linux distribution/kernel, privilege model, Codex binary/profile,
  App Server schema, requirements hash, and hook schema fingerprint;
- unit, integration, e2e, and live-probe commands actually run;
- required negative cases and their audit evidence;
- strict/action-governed/prompt-governed/degraded/unavailable classification;
- explicit `Done`, `Not done`, or `Blocked` state and next stop point.

## Verification

All production phases require focused checks first, then:

```sh
cargo fmt
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Privileged source-profile validation is defined by
[the lifecycle probe](./lifecycle-probe.md). It may be omitted from a local
unprivileged host only with an explicit blocked result; it cannot be omitted
from a required release fixture.

## Phase Index

- [Phase 0: Linux V1 Profile And Ordering Feasibility](./phase-0-linux-v1-profile-and-ordering-feasibility.md)
- [Phase 1: Unified Managed Profile And Hook Trust Root](./phase-1-unified-managed-profile-and-hook-trust-root.md)
- [Phase 2: Prompt Ingress And Transport Broker Reconciliation](./phase-2-prompt-ingress-and-transport-broker-reconciliation.md)
- [Phase 3: Invocation Leases And Linux Physical Effects](./phase-3-invocation-leases-and-linux-physical-effects.md)
- [Phase 4: Filesystem And Network Governance Integration](./phase-4-filesystem-and-network-governance-integration.md)
- [Phase 5: Surface Certification, Recovery, And Rollout](./phase-5-surface-certification-recovery-and-rollout.md)
- [Phase 6: Auto-Adopt Host Service, Routes, And Limits](./phase-6-auto-adopt-host-service-routes-and-limits.md)
- [Phase 7: Auto-Adopt Held Exec, Derived Context, And Runtime Attestation](./phase-7-auto-adopt-held-exec-derived-context-and-runtime-attestation.md)
- [Linux V1 lifecycle probe](./lifecycle-probe.md)

## Stop Point

Stop after Phase 3. Wait for explicit approval before Phase 4.
