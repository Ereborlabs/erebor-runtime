# Codex Child-Agent Context DAG Lifecycle Probe

Status: Proposed. This probe is required evidence for the nested Phase 4 plan;
it does not replace committed Rust tests.

## Purpose

Exercise one daemon-owned context family across nested sessions and verify the
Git topology, frozen forks, routed communication, parent-owned integration,
and Linux physical effects under real process lifecycle conditions.

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
   ref, family ID, package, hook registration, guard registration, parent pin,
   frozen-projection digest, and integration policy.
5. Have B queue a contribution for P. Verify P's ref is unchanged, then have P
   accept it. Have P send B a follow-up; B requests D; D queues a result for B;
   B accepts it. Have B publish a final result that P's predeclared policy
   auto-integrates. Cancel C from P. Run the declared shell-to-`ls` effect in B
   and D.
6. Exercise family-scoped graph listing, permitted parent-to-child messaging,
   follow-up, and cancellation. Reject child-to-parent wake, sibling routing,
   child-to-ancestor control, App Server `thread/fork`, thread resume, raw
   nested execution, and child option/config escalation.
7. Reopen and inspect the family repository. Verify exact scope ancestry,
   parent inbox sequence, acceptance identities, parent ref sequence, child ref
   stability, ordered two-parent merges, and all contribution/physical-effect
   pins.
8. Repeat with concurrent contribution delivery, daemon restart at each durable
   transition, child crash, hook replay/wrong-peer/wrong-session, forged parent
   pin, stale acceptance, accepted-delivery replay, and two-UID attacker
   attempts.

## Required Evidence

- daemon/client requests and responses with secrets, tickets, and workload
  payloads redacted;
- context-family/ref inventory, commit parent lists, selected blobs, pin
  validation results, delivery/inbox sequence, and integration decisions;
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
family ref.
