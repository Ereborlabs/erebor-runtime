# Phase 4: Deterministic DAG Fixture, Lifecycle, And Privileged Evidence

Status: In progress. Depends on completed nested Phases 1–3. The fixture is
being corrected to prove a single session with nested logical scopes; a
daemon-derived graph-listing client view and renewed privileged evidence remain
required.

## Purpose

Prove the complete child-agent Context DAG through the public daemon/client
path, real daemon-owned processes, Codex-adapter capability mapping, recovery,
and Linux physical-effect enforcement.

The deterministic fixture has a guarded `ls` command and one long-lived `q`
command. A logical child fork creates B's same-session scope from P's exact
pin. A later command from B is a physical descendant of the one root session's
guarded process tree, attributed by B's invocation lease. q similarly uses its
own logical operation scope. Hook evidence and deliveries advance only their
source scopes; a parent changes only when the public receive operation creates
its two-parent merge.

## Runner Boundary And Future Docker Contract

This phase proves the Linux-host runner only. It must not enable the deferred
Docker runner or expand this acceptance lane into Kubernetes implementation.

The future Docker design is recorded in the separate
[Container and Kubernetes execution architecture](../../container-orchestration/README.md).
It preserves the same Context DAG and daemon ownership model:

```text
erebor client
  -> erebord: session, policy, context DAG, runtime-guard listener
       -> Docker runner/controller
            -> container
                 -> erebor-linux-process-guard (PID 1)
                      -> admitted Codex/agent and its descendants
```

The Docker runner—not the client—will create and recover the physical
container. The guard will be the application container's entrypoint and use
only the daemon-owned, per-session runtime-guard channel. The container must
not receive `daemon.sock` or the Docker socket. A sidecar is not the primary
guard: even with a shared PID namespace it cannot become the parent of the
application process tree or reliably decide before `exec`.

Docker implementation needs its own approved phase because the current
deferred driver does not yet register this runtime guard or make it the
container entrypoint. Its acceptance must separately prove immutable image and
command admission, UID/user-namespace mapping, stable endpoint reconnect after
daemon recovery, interactive TTY behavior, and real descendant interception.

## Deterministic Scenario

The pinned `codex-v1` fixture emits source-pinned logical collaboration facts.
It has one interactive root process and no delegation bridge:

```text
P: outer prompt / parent scope in one Erebor session
  ├─ B: logical child scope from `fork_turns=all`; two child prompts
  │    ├─ B-1 -> lease -> shell -> ls
  │    ├─ B starts long command q -> continues B-2 -> q writes partial/final deliveries
  │    ├─ B polls q -> receives each selected q delivery by merge into B
  │    ├─ B sends queued message m1 -> P derived inbox
  │    ├─ P explicitly receives m1 -> merge B:m1 into P
  │    ├─ P sends follow-up -> B's next turn
  │    └─ D: `fork_turns=last(1)`
  │         ├─ lease -> shell -> ls
  │         ├─ D result -> B derived inbox
  │         └─ B receives D result -> merge D:r1 into B
  └─ C: logical child scope from `fork_turns=none`; child prompt -> parent cancellation
```

B publishes a final result to P after it has received D's result. P explicitly
receives that terminal delivery, producing a second P merge. C produces a
cancellation fact and no success result. P continues while B and C run. The
test submits exact typed App Server frames and fixture commands; it does not
infer prompts from terminal echo or manufacture a graph by writing directly to
ContextRepository.

The fixture suite also exposes the capability matrix. It must prove `list_agents`, a
queued message, a follow-up turn, descendant cancellation, completion delivery
that remains unmerged until a parent receive, and all three frozen-context
modes. It must reject direct sibling or
ancestor control, raw nested `codex`, `thread/fork`, resume/foreign-thread
operations, and unsupported source option overrides.

It must also prove the command lifecycle: B receives an initial yielded command
response, continues with unrelated B work, receives bounded client stream/end
evidence, then explicitly polls and receives q deliveries. q's partial/final
output must not advance B, wake P, or reach P's context until B later sends m1
through the normal child-delivery path.

## Required Assertions

- Reopen the root session's existing `ContextRepository` and validate all refs,
  commits, selected blobs, pins, parent order, edge blobs, source-scope
  delivery blobs, and merge/rejection receipts with ContextRepository APIs.
- Assert P is the causal ancestor of B and C, B is the causal ancestor of D,
  and B/C are siblings. Assert no unexpected scope/ref exists.
- Assert the derived direct-child inbox distinguishes published, received, and
  rejected deliveries from scope blobs and receipts. The B message does not
  change P before P's explicit receive. C's cancellation is retained but never
  becomes a successful integration.
- Assert every received child delivery creates one two-parent merge into its
  fixed parent, with a deterministic delivery receipt and no child-ref
  mutation. Assert the D result merges into B first, then B's final result
  merges into P. Assert no grandchild result bypasses B.
- Assert edge/delivery/rejection metadata remains only under
  `erebor/context-dag/` and is never selected by the adapter prompt projection;
  a receive merge adds only its selected bounded result at the declared
  model-visible result path.
- Assert the selected fork pin and bounded spawn projection for `none`, `all`,
  and last-one-turn are exact, immutable, and free of forbidden internal tool,
  inter-agent, credential, socket, and ambient-environment content.
- Assert q has one B owner, launch pin, invocation/lease, adapter source
  operation key, exact process identity, and child operation scope. Its
  terminal event leaves B's ref unchanged; B's explicit polls receive bounded
  partial/final delivery pins as
  separate two-parent merges after B's intervening work. Replayed receive,
  forged PID, late output, cancellation, owner replacement, and parent/sibling
  receive attempts fail closed.
- Assert graph listing is daemon-derived and root-scope scoped; queued message and
  follow-up are distinct; only P can cancel C; P cannot be woken by a child
  follow-up; and no child can address a sibling or ancestor as a control target.
- Assert P, B, C, D, and q are scopes under exactly one session. It must be
  impossible to turn hook/App Server/thread facts into another daemon session.
- Assert B or D's guarded `ls` audit records validate the exact logical source
  scope and invocation lease while remaining physical descendants of P's one
  process guard. Assert descendants survive their immediate shell's exit under
  the existing lease contract.
- Assert controller/TTY, daemon-socket absence, package identity, hook ticket,
  input lease, cancellation, detach, child failure, and daemon-loss contracts
  remain intact for the one root session.
- Assert direct nested fixture execution, forged child spawn, forged child
  delivery, replay, wrong edge, wrong parent, wrong peer, sibling access,
  exhausted depth/fan-out, malformed output, App Server peer-thread request,
  forbidden spawn option, and lost daemon all fail closed.

## Evidence Lanes

- Crate-local context, daemon, session, and IPC tests cover validated types,
  transaction/recovery states, and adapter translation.
- `erebor-runtime-e2e` owns the deterministic single-session daemon/client
  fixture, repository inspection, two-UID isolation, and negative matrix.
- The privileged Linux installed-product lane proves the guard's real fork,
  exec, reparent, cancellation, daemon-loss, and descendant evidence for
  logical B and D scopes. The foreground host lab remains a manual diagnostic
  aid only and never substitutes for those tests.

## Acceptance

Phase 4 may use this evidence only when the deterministic fixture proves a
real Git DAG, not just a parent ID in JSON; parent-owned integration of repeated
child deliveries; exactly one session for the nested scopes; and real guarded
descendant attribution. A real vendor Codex source profile still remains Phase
5 evidence because it requires private state projection.

## Stop Point

Do not begin Phase 5: nested Phase 4 needs renewed single-session privileged
evidence and its required daemon-derived graph listing.

## Phase 4 Result

The former privileged result was for the discarded physical-child bridge model
and is not Phase 4 evidence. Renew the deterministic and privileged matrix
after the single-session fixture proves P/B/C/D/q as scopes, then add the
daemon-derived graph-listing command. Docker/Kubernetes execution remains the
separately deferred design described above, and real authenticated Codex state
projection remains Phase 5 work.
