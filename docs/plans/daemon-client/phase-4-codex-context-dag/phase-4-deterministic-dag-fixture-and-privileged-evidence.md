# Phase 4: Deterministic DAG Fixture, Lifecycle, And Privileged Evidence

Status: Done. Depends on completed nested Phases 1–3. The checked-in fixture
drives one session with P/B/C/D/q scopes through the public daemon/client path,
and a read-only ContextRepository inspector validates the resulting refs, edge
blobs, pins, and causal ancestry. The fixture also drives source-authenticated
`list_agents`, follow-up, and interruption through the existing hook broker.
The privileged two-UID Linux installed-product execution passed in the
systemd-container evidence lane.

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

The fixture exposes the capability matrix: source-derived `list_agents`, a
queued message, a parent-to-child follow-up turn, and
ancestor-to-descendant interruption, as well as completion delivery that
remains unmerged until a parent receive and all three frozen-context modes.
The deterministic profile uses `erebor_context_control` only as its pinned
native control shape. The existing ticketed hook broker resolves the requester
and target from exact daemon-bound thread/turn identities, not a supplied scope
ref; it calls the daemon through an in-process startup-bound handler, records
the action in the requester's Git scope, refreshes the adapter's cursor, and
returns the allow result on that same hook response. It opens no listener or
second socket. `list_agents` returns only strict descendants. Follow-up stores
only a SHA-256 of its bounded source text; source code resumes the target only
after the allow result. Interruption likewise requires an ancestor target; the
fixture then emits C's cancellation delivery only after P's interruption is
accepted. The durable coordinator rejects a sibling, ancestor, self, unknown
identity, malformed control shape, or non-descendant target.

The fixture's `fixture/switch` remains local deterministic input routing only:
it creates no session, guard, or daemon control path. It is used only where the
scenario needs to model an already-active native thread; it is not used to
claim parent-to-child follow-up or interruption.

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
- Assert `erebor session context graph <session>` is daemon-derived and renders
  the complete durable scope tree with each branch's current head, exact fork
  parent pin, binding, authenticated source identity, and retained
  scope-local hook and physical activity (for example `tool bash command="ls"`
  and `exec /bin/ls allowed pid=…`). A native operation scope must render
  beneath its exact authenticated `PreToolUse` activity, while an ordinary
  command's physical effects remain beside that activity in the issuing scope.
  Published child deliveries and parent receipt/rejection facts must render as
  queued delivery and received-merge/rejection activity in their respective
  scopes. It must read these leaves only from the root-owned Git
  `ContextRepository`, subtract facts inherited at the fork pin so descendant
  branches do not duplicate ancestor activity, and walk each scope's Git
  first-parent commit history from its head back to its fork pin. It must not
  derive causal order from final-tree path names: an admitted command's guarded
  `exec` facts appear after its `PreToolUse` and before its `PostToolUse`,
  even though those durable blobs live under different directories. It must not read
  either the repository or JSONL audit files in the client. JSONL is a
  parallel audit sink, never a graph input. Queued message and follow-up are
  distinct; only P can cancel C; P cannot be woken by a child
  follow-up; and no child can address a sibling or ancestor as a control target.
- Assert P, B, C, D, and q are scopes under exactly one session. It must be
  impossible to turn hook/App Server/thread facts into another daemon session.
- Assert B or D's guarded `ls` writes both its parallel audit record and an
  exact Git physical-effect blob in the source scope, bound to the invocation
  lease and observed process identity, while remaining a physical descendant
  of P's one process guard. Assert the explicitly admitted retained q operation
  writes its own physical-effect blob only in q's operation scope, never in B,
  and is admitted before its shell launches rather than inferred from a later
  alive-process observation. Assert descendants survive their immediate shell's
  exit under the existing lease contract.
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

Phase 4 is complete. Do not begin Phase 5 without its separate approval and
scope; real authenticated Codex state projection remains deferred there.

## Phase 4 Result

Current result: **Done.** The implementation records a lease-validated guard
observation as a Git blob in the exact B or operation scope and the
daemon-derived graph renders that blob without consulting JSONL. Every active
native tool use has its own exact invocation lane, so B may start retained q
and then issue `ls` without leaving the second command unleased. The retained
edge records the source tool use for a native operation, so the graph nests q
below its exact Bash activity while rendering B's `ls` effects beside B's `ls`
activity. An ordinary descendant such as q's `sleep` remains an effect in q's
admitted operation scope, rather than creating a spurious process scope.

The deterministic lane is `.github/scripts/daemon-codex-runtime.sh`. It starts
one live typed App Server fixture session, drives B/C/D/q as scopes, validates
the resulting Git DAG through the test-only `codex-context-dag-inspector`, and
checks the public graph view. The fixture's `fixture/switch` is local
deterministic input routing only: it creates no session, guard, or daemon
control path. Its App Server events are JSON-RPC notifications, so the protocol
probe remains valid JSONL rather than TTY text. The inspector opens the
existing repository read-only and validates direct edge records, exact parent
pins, and causal ancestry with ContextRepository APIs.

The completed code path is owned by `ContextDagCoordinator`, the session's
existing Codex hook service, and its startup-bound daemon callback. It has no
new daemon socket or process-guard message. The coordinator validates action
shape, source-known identities, session namespace, strict descendant topology,
and the follow-up digest before writing the Git evidence; the graph projection
renders those records from Git. Focused tests cover source binding, malformed
fixture controls, unsupported non-effect hook handling, strict-descendant
authorization (including sibling rejection), durable graph activities, and the
broker cursor refresh after a daemon write. The privileged script now exercises
the successful P list/interruption/follow-up flow together with C's resulting
cancellation receipt.

The installed-product evidence is
`EREBOR_DAEMON_SYSTEMD_IMAGE=erebor-daemon-systemd:phase4-context-dag cargo test -p erebor-runtime-e2e --test daemon_control_plane daemon_control_plane_and_codex_context_dag_run_in_systemd_container -- --ignored --nocapture`.
It built the local image, booted systemd, created the service socket group and
two unprivileged users, exercised daemon recovery and generic Linux sessions,
then ran the deterministic Codex fixture with real guarded descendants. The
test completed successfully. The container assertions were updated alongside
the CLI table migration: scripts extract a short session ID from the table and
assert table state values rather than the removed `session_id=`/`state=` output.

`bash .github/scripts/verify-rust-ci.sh` passed on the final Rust and script
source state.

Docker/Kubernetes execution remains the separately deferred design described
above, and real authenticated Codex state projection remains Phase 5 work.
