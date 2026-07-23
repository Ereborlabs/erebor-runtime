# Phase 0: Linux V1 Profile And Ordering Feasibility

Status: Done — feasibility concluded on 2026-07-15. No Linux source profile is
strict-certified or approved for production. The completed evidence package
identifies the limited pinned surfaces and assigns remaining prompt/effect gates
to their owning later phases.

## Purpose

Prove the V1 contract on a pinned Linux host and signed/current Codex source
profiles before production code or package artifacts are approved.

## Scope

- Inventory exact current code owners named by the parent plan and revise later
  phases when the real seam differs.
- Preserve the V0 held-exec, namespace-entry, and FD-splice evidence as
  historical input for final Phase 7. It selects neither the V1 mechanism nor
  an x86-64 deployment profile and is not a Phase 0 or normal-path gate.
- Create an isolated test requirements artifact with the complete V1 event
  family and a test hook binary. Do not install a fleet or system policy.
- On pinned Codex CLI, TUI/exec, IDE App Server, and the first Desktop profile,
  record effective requirements composition, event availability, schema, hook
  process exec history, stdin/stdout pipe identities, requirements hash, hook
  binary identity, architecture, and current enforcement-mechanism support.
- Prove that the verified `/etc/codex/requirements.toml` and managed hook path
  are projected read-only inside the dedicated Erebor session filesystem while
  a Codex process outside that session continues to see its ordinary host view.
- Prove SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, Permission,
  subagent, and Stop order where the signed profile supports them.
- For a brokered App Server, prove one prompt becomes one scope even when the
  transport broker and UserPromptSubmit observe it; test mismatch, missing
  hook, steer, queued input, resume, cancellation, and concurrency.
- Prove hook-child exit ordering against the first command child and first
  in-process mutation effect in the normal `session run` path. A race that
  cannot be closed blocks strict.
- Prove an authenticated stable local broker can consume a one-use ticket for
  the exact Codex-owned shell/interpreter-to-hook exec chain. Bind peer
  credentials, executable/argv history, pidfd lifetime, cgroup/mount namespace,
  and original stdin/stdout pipe objects.
- Exercise user-controlled `SHELL`, `BASH_ENV`, `ENV`, `ZDOTDIR`, shell startup
  files, stdin/stdout replacement, genuine-hook execution from a governed tool
  descendant, duplicate connection, replay, and result rewriting. Any path
  that can forge either event input or the hook result blocks strict.
- Exercise command, apply-patch, pre-opened descriptors, mmap, fork-before-exec,
  raw filesystem, direct/loopback network, plugin/client-method, hook failure,
  broker failure, tracer death, and restart negative cases.
- Record exact supported and unsupported tool paths. Do not infer coverage from
  an upstream source tree alone.

## Deliverables

- A `phase-0-result.md` or result section with command output references,
  profile fingerprints, and every pass/fail gate.
- A current-code inventory and revised target module shape when needed.
- One explicit user decision package covering the first certified Linux source
  profile, delivery/trust root, supported hook events, broker precedence, and
  remaining strict blockers.

## Original Pre-Phase-1 Gates

These gates were originally written as a precondition to Phase 1. The user
explicitly approved Phase 1 before this discovery result was complete. They are
therefore recorded as strict-certification blockers owned by Phases 2–4, not as
a reason to leave this evidence phase open:

- the complete selected hook event set can be forced and attested on the pinned
  profile;
- the complete hook input/result channel, not only ancestry or executable
  identity, cannot be spoofed by a same-user process or governed descendant;
- a brokered prompt and hook observation reconcile deterministically;
- no covered physical effect outruns the lease barrier;
- the required process/file/network matrix has a real native decision path;
- requirements/profile composition has no unaccounted administrator conflict;
- requirements delivery is confined to the dedicated session filesystem.

## Checkpoint

```sh
cargo test -p erebor-runtime-session --all-targets --all-features
EREBOR_REQUIRE_CODEX_LINUX_V1_PROBE=1 \
EREBOR_CODEX_LINUX_V1_PROFILE=<profile-name> \
EREBOR_CODEX_LINUX_V1_CLI=/absolute/path/to/codex \
  cargo test -p erebor-runtime-e2e --test codex_linux_v1_lifecycle \
  profile_and_ordering -- --test-threads=1 --nocapture
git diff --check
```

The exact privileged command, capabilities, and fixture paths are recorded in
the result. A fake target proves only mechanics; a signed/current Codex profile
is required for hook and prompt claims.

## Acceptance

- Every V1 claim is separated into verified, unsupported, and unproven.
- The result records the architecture/profile support matrix without adopting
  the V0 experiment's architecture as a V1 default.
- The user receives the explicit Phase 1 architecture choices and blockers.
- No production runtime, system package, or global requirements change is made.

## Stop Point

Stop after evidence and user decisions. Wait for Phase 1 approval.

Current dependency note: the user explicitly approved Phase 1 on 2026-07-15.
Phase 1 completed the trust root. Phase 0 now ends with a conservative
feasibility finding: no profile may claim strict coverage until the remaining
Phase 2–4 gates pass.

## Phase Result

State: Done — no strict Linux profile certified.

The implemented requirements artifact and privileged-profile probe are recorded
in [Phase 0 result](./phase-0-result.md). The required pinned-AppServer and
non-interactive `codex exec` probe passed on 2026-07-15 with
`EREBOR_CODEX_LINUX_V1_PROFILE=vscode-app-server-and-exec-0.144.2` and the
recorded VS Code Codex executable. Both isolated paths accept the complete
managed configuration and record `SessionStart`, `UserPromptSubmit`,
`PreToolUse`, `PostToolUse`, and `Stop` in order; `thread/start` alone only
queues the start hook. The strengthened Phase 1 production-hook fixture
separately completed `SessionStart`, `UserPromptSubmit`, `PreToolUse`, and
`Stop`, then received terminal `turn/completed`; it did not emit `PostToolUse`.
This five-event isolated-probe versus four-event guarded-session divergence is
explicitly not certified. Permission and subagent events, TUI and Desktop
profiles, broker reconciliation, lease barrier, physical-effect matrix, and
signed-source evidence remain unavailable or unproven. Those findings complete
the Phase 0 feasibility result; they do not approve strict production use.
