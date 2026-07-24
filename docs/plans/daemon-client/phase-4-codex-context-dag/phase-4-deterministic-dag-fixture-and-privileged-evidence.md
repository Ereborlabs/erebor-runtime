# Phase 4: Deterministic DAG Fixture, Lifecycle, And Privileged Evidence

Status: Proposed. Depends on nested Phases 1–3 and explicit approval.

## Purpose

Prove the complete child-agent Context DAG through the public daemon/client
path, real daemon-owned processes, Codex-adapter capability mapping, recovery,
and Linux physical-effect enforcement.

## Deterministic Scenario

The pinned fixture suite has two modes. The `codex-v1` observer fixture emits
the source-pinned native logical collaboration facts. The separate delegation
fixture owns the approved pre-spawn bridge and creates this physical-child
topology through the private delegation contract:

```text
P: outer App Server prompt / parent scope
  ├─ B: `fork_turns=all`; two child prompts
  │    ├─ B-1 -> lease -> shell -> ls
  │    ├─ B sends queued message m1 -> P inbox
  │    ├─ P explicitly accepts m1 -> merge B:m1 into P
  │    ├─ P sends follow-up -> B's next turn
  │    └─ D: `fork_turns=last(1)`
  │         ├─ lease -> shell -> ls
  │         ├─ D result -> B inbox
  │         └─ B accepts D result -> merge D:r1 into B
  └─ C: `fork_turns=none`; child prompt -> parent cancellation
```

B publishes a final result to P after it has accepted D's result. P's immutable
edge policy auto-integrates that terminal result, producing a second P merge.
C produces a cancellation fact and no success result. P continues while B and
C run. The test submits exact typed App Server frames and fixture commands; it
does not infer prompts from terminal echo or manufacture a graph by writing
directly to ContextRepository.

The fixture suite also exposes the capability matrix. It must prove `list_agents`, a
queued message, a follow-up turn, descendant cancellation, automatic completion
delivery, and all three frozen-context modes. It must reject direct sibling or
ancestor control, raw nested `codex`, `thread/fork`, resume/foreign-thread
operations, and unsupported source option overrides.

## Required Assertions

- Reopen the daemon-owned context-family repository and validate all refs,
  commits, selected blobs, pins, and parent order with ContextRepository APIs.
- Assert P is the causal ancestor of B and C, B is the causal ancestor of D,
  and B/C are siblings. Assert no unexpected scope/ref exists.
- Assert the parent-owned inbox distinguishes received, accepted, rejected,
  and auto-integrated deliveries. The B message does not change P before P's
  explicit acceptance. C's cancellation is retained but never becomes a
  successful integration.
- Assert every accepted child delivery creates one two-parent merge into its
  fixed parent, with a deterministic contribution receipt and no child-ref
  mutation. Assert the D result merges into B first, then B's final result
  merges into P. Assert no grandchild result bypasses B.
- Assert the selected fork pin and bounded spawn projection for `none`, `all`,
  and last-one-turn are exact, immutable, and free of forbidden internal tool,
  inter-agent, credential, socket, and ambient-environment content.
- Assert graph listing is daemon-derived and family scoped; queued message and
  follow-up are distinct; only P can cancel C; P cannot be woken by a child
  follow-up; and no child can address a sibling or ancestor as a control target.
- Assert the source observer creates only `native-logical` nodes and pins their
  physical effects to P's outer invocation. It must be impossible to turn its
  hook/App Server/thread facts into B or D daemon sessions. Assert the
  delegation fixture creates `daemon-physical` nodes before their workloads
  start, with separate child guard/hook/session identities.
- Assert the delegation fixture's child `ls` audit records validate pins in B
  or D respectively, never P merely because P spawned them. Assert physical
  descendants survive their immediate shell's exit according to the existing
  lease contract.
- Assert controller/TTY, daemon-socket absence, package identity, hook ticket,
  input lease, cancellation, detach, child failure, and daemon-loss contracts
  remain intact for every session in the family.
- Assert direct nested fixture execution, forged child spawn, forged child
  contribution, replay, wrong edge, wrong parent, wrong peer, sibling access,
  exhausted depth/fan-out, malformed output, App Server peer-thread request,
  forbidden spawn option, and lost daemon all fail closed.

## Evidence Lanes

- Crate-local context, daemon, session, and IPC tests cover validated types,
  transaction/recovery states, and adapter translation.
- `erebor-runtime-e2e` owns the deterministic multi-session daemon/client
  fixture, repository inspection, two-UID isolation, and negative matrix.
- The privileged Linux installed-product lane proves the guard's real fork,
  exec, reparent, cancellation, daemon-loss, and descendant evidence for B and
  D. The foreground host lab remains a manual diagnostic aid only and never
  substitutes for those tests.

## Acceptance

Phase 4 may use this evidence only when the deterministic fixture proves a
real Git DAG, not just a parent ID in JSON; parent-owned integration of repeated
child deliveries; complete supported/denied collaboration routing; and real
guarded descendant attribution. A real vendor Codex source profile still remains
Phase 5 evidence because it requires private state projection.

## Stop Point

Stop after the Phase 4 result and update the parent Phase 4 status honestly.
Do not begin Phase 5 without explicit approval.
