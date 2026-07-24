# Codex Child-Agent Context DAG Lifecycle Probe

Status: Proposed. This probe is required evidence for the nested Phase 4 plan;
it does not replace committed Rust tests.

## Purpose

Exercise one root session's daemon-owned context repository across nested
sessions and verify the Git topology, frozen forks, routed communication,
parent-owned integration, and Linux physical effects under real process
lifecycle conditions.

## Safety Boundary

- Use only a deterministic pinned fixture, disposable workspace, and uniquely
  marked daemon state root.
- Retain all artifacts on failure for diagnosis. Cleanup may stop only the
  fixture-owned daemon and processes whose recorded identities still match; it
  must not recursively delete a broad or guessed path.
- Do not use a developer's vendor Codex login, `HOME`, `CODEX_HOME`, host
  requirements file, default daemon socket, or unrelated running session.

## Required Run

1. Start one root-owned foreground or installed-product daemon with isolated
   state/runtime/log roots and a pinned deterministic package.
2. Load the fixture, create parent P through typed App Server input, and record
   its immutable prompt decision pin.
3. Run the stock-Codex observer fixture and record its native logical child
   facts. Prove that its thread/hook/App Server facts create no child daemon
   session and that its physical effects remain under P's invocation.
4. Request B (`all`) and C (`none`) through P's private child-delegation
   endpoint. Request D (`last(1)`) through B. Record every admission, scope
   ref, derived root scope, package, hook registration, guard registration,
   parent pin, frozen-projection digest, and explicit parent-receive contract.
5. Have B queue a delivery for P. Verify P's ref is unchanged, then have P
   receive it. Have P send B a follow-up; B requests D; D queues a result for
   B; B receives it. Have B publish a final result and have P explicitly
   receive it. Cancel C from P. Run the declared shell-to-`ls` effect in B and
   D.
6. In B, start a long command with a short initial yield, append unrelated B
   work while it remains alive, and retain its stream/end evidence. Verify the
   partial/final delivery blobs enter only B's operation scope; then poll and
   receive each selected delivery through the daemon coordinator.
   Attempt parent/sibling receive, replay, forged PID, owner restart, and
   completion after cancellation.
7. Exercise root-scope-scoped graph listing, permitted parent-to-child messaging,
   follow-up, and cancellation. Reject child-to-parent wake, sibling routing,
   child-to-ancestor control, App Server `thread/fork`, thread resume, raw
   nested execution, and child option/config escalation.
8. Reopen and inspect the root session repository. Verify exact scope ancestry,
   derived inbox sequence, receive identities, parent ref sequence, child ref
   stability, ordered two-parent merges, operation launch/delivery/receive
   sequence, and all delivery/physical-effect pins.
9. Repeat with concurrent delivery publication, daemon restart at each durable
   transition, child crash, hook replay/wrong-peer/wrong-session, forged parent
   pin, stale receive, received-delivery replay, and two-UID attacker
   attempts.

## Required Evidence

- daemon/client requests and responses with secrets, tickets, and workload
  payloads redacted;
- root-scope/ref inventory, commit parent lists, selected blobs, pin validation
  results, derived delivery/inbox sequence, and merge/rejection receipts;
- child session/admission/endpoint identities and package/installation hashes;
- hook, lease, process-guard, fork/exec/reparent, and final allow/deny audit
  records for P, B, C, and D;
- explicit outcome for each daemon-loss and recovery point; and
- host kernel/distribution, UID, containment, ptrace, and systemd/direct-mode
  facts for the privileged lane.

## Pass Condition

Every asserted DAG edge and merge is durable and validated from repository
objects, every protected child effect names its exact child context pin, and
every unsupported or forged path fails before it can create trust or mutate a
scope ref outside its root subtree.
