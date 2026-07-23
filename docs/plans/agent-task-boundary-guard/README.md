# Erebor Agent Task Boundary Guard Plan

Plan type: productization, architecture, and validation plan.

Status: planning document. This plan is separate from the governed OpenClaw
pilot and does not change that implementation track.

Related plans:

- [`docs/plans/session-hypervisor/README.md`](../session-hypervisor/README.md)
  owns the governed session model, session runner contract, enforcement tiers,
  and platform guard direction.
- [`docs/governed-browser-and-terminal-plan.md`](../../governed-browser-and-terminal-plan.md)
  owns browser, terminal, endpoint, OpenClaw, and bypass-validation work that
  consumes the session model.
- [`docs/plans/governed-openclaw-pilot/README.md`](../governed-openclaw-pilot/README.md)
  owns the current pilot-call demo track. That pilot continues independently.
- [`docs/plans/agentic-incident-demo/README.md`](../agentic-incident-demo/README.md)
  owns the flagship multi-surface incident demo track.

## Summary

Erebor Agent is the buyer-facing security product. Security engineers should be
able to understand and buy the product as a persistent task-boundary guard for
other agents, not as a raw runtime API.

Erebor Runtime remains the trusted enforcement engine underneath it. The runtime
owns the execution path where authority changes hands: file reads, file writes,
deletes, process launches, browser actions, tool calls, network requests, and
later SaaS or internal-system effects.

The first product story is:

```text
Worker agents can forget the task boundary.
Erebor Agent remembers it.
Erebor Runtime enforces it.
```

Erebor Agent should govern worker agents by keeping a small durable task
contract and asking Erebor Runtime to allow, deny, challenge, or hold effects
before those effects execute.

## Product Thesis

Main agents optimize for completing the user's task. They carry a large working
context, follow tool results, respond to external content, and can drift as a
session gets long. They may try to inspect one more file, run one more command,
or click one more button even when that action exceeds the user's original
intent.

Erebor Agent optimizes for preserving the boundary. It should have a smaller
context, a narrower role, and durable memory of the confirmed task contract. It
does not need to solve the worker's task. Its job is to remember what authority
was granted and prevent the worker from turning curiosity, tool output, or
prompt injection into new authority.

Erebor Runtime is the enforcement boundary. Erebor Agent can reason, explain,
and challenge, but the runtime must be the part that catches substrate effects
and enforces the final decision before the effect happens whenever the active
backend supports that.

Core product decision:

- Erebor Agent is the persistent governance guardrail.
- Erebor Runtime is the trusted enforcement boundary.
- Worker agents are untrusted and may forget context.
- Erebor Agent keeps a smaller durable task contract and cannot silently expand
  it.

## Terminology

- Worker agent: the governed agent trying to complete the user's task. It may
  be OpenClaw, Codex-like, Claude Code-like, a browser agent, a custom script,
  or another agent runtime.
- Erebor Agent: the governance guardrail for the session. It remembers the task
  contract, interprets attempted effects against that contract, challenges the
  worker when needed, and escalates to a human for new authority.
- Erebor Runtime: the enforcement engine and session substrate. It starts or
  adopts worker agents, observes effect attempts, normalizes events, enforces
  decisions, and writes audit records.
- Task contract: the confirmed boundary for the session. It describes what the
  worker is trying to accomplish, which files and actions are allowed, which
  paths and effects are forbidden, and when to challenge or ask a human.
- Challenge: a lightweight interruption where Erebor Agent asks the worker agent
  why an action is necessary. A challenge can clarify intent, but it cannot
  grant new authority outside the confirmed task contract.
- Human approval: an explicit decision by the user or operator to allow a held
  action or expand the task contract. Human approval is required for new scope.

## Task Contract

The task contract is created before the worker starts. Erebor Agent drafts it
from the user's request, policy context, workspace context, and any security
defaults available for the session. The human confirms the contract before the
worker receives authority.

The first contract should contain:

- task goal
- worker identity
- session workspace
- allowed read roots or exact files
- denied paths, including secrets and credentials
- write policy
- delete policy
- allowed process, browser, or tool action classes when known
- challenge rules for ambiguous in-scope actions
- human approval rules for new scope or high-risk effects

The task contract must be durable session state. It should not live only in the
worker agent's prompt or chat history. A worker reconnect, context reset, tool
call, or long-running session must not erase the boundary.

Default filesystem posture for the first product:

- Reads are allowed only inside confirmed task scope.
- Secret and credential reads are denied by default.
- Writes require human approval.
- Deletes are denied by default unless explicitly approved.
- New file scope requires human approval, even if the worker provides a
  plausible explanation.

## Decision Model

Erebor Agent should expose four product-level decisions:

- `allow`: the attempted effect is inside the confirmed task contract and may
  proceed.
- `deny`: the attempted effect violates policy or the task contract and must not
  execute.
- `challenge_worker`: the attempted effect is ambiguous but may fit the current
  task. Erebor Agent asks the worker to justify the action against the existing
  contract.
- `require_human_approval`: the attempted effect needs new authority or carries
  high risk, so a human must approve before the runtime permits it.

Deterministic policy and task-contract matching decide authority. Model
reasoning may draft the contract, summarize risk, explain decisions, or ask the
worker a challenge question. Model reasoning must not silently grant new
authority.

After a challenge, Erebor Agent can allow only if the action fits the already
confirmed contract. If the worker's answer implies new scope, new files, new
credentials, new write authority, or a new tool surface, Erebor Agent must hold
for human approval or deny.

Failure behavior should be fail-closed for high-risk actions:

- If Erebor Agent is unavailable, high-risk or out-of-scope effects are denied
  or held.
- If the worker gives no justification, the challenged action is denied.
- If the active backend cannot enforce the decision, the session must report
  the control as cooperative or observed instead of claiming hard enforcement.

## First Filesystem Boundary Demo

The first Erebor Agent demo should focus on filesystem authority because it
isolates the new product idea from the OpenClaw pilot and makes the task
boundary easy to see.

Demo shape:

1. The user asks a worker agent to perform a narrow task, such as inspect one
   bug in a specific module.
2. Erebor Agent drafts a task contract with the likely allowed files and denied
   sensitive paths.
3. The human confirms the contract.
4. The worker reads an allowed task file and proceeds normally.
5. The worker attempts to read an unrelated file. Erebor Agent challenges or
   denies based on the contract.
6. The worker attempts to read a secret or credential file. Erebor Agent denies
   before file contents are revealed.
7. The worker attempts to write or delete a file. Erebor Agent requires human
   approval or denies before the mutation happens.
8. The audit trail shows the task contract, attempted action, target path,
   challenge if any, final decision, and reason.

Expected operator story:

```text
The worker agent tried to leave the task boundary.
Erebor Agent remembered the boundary and stopped it.
The runtime enforced the decision before the file effect happened.
```

## Runtime Relationship

Erebor Runtime intercepts file, process, browser, tool, network, SaaS, and
internal-system effects. It normalizes those effects into runtime events with
session identity, actor identity, target, payload, risk metadata, and audit
context.

Erebor Agent interprets those events against the task contract and policy. It
returns a product-level decision that maps to the runtime decision model:

- `allow` maps to `Decision::Allow`.
- `deny` maps to `Decision::Deny`.
- `require_human_approval` maps to `Decision::RequireApproval`.
- `challenge_worker` is a product-level hold-and-ask step before the final
  runtime decision.

Runtime enforcement must happen before the effect executes when the backend
supports pre-effect enforcement. Examples:

- A filesystem backend should prevent an out-of-scope read before contents are
  returned.
- A filesystem backend should prevent writes and deletes before the mutation is
  committed.
- A process backend should prevent dangerous child processes before `exec`
  completes.
- A browser backend should block dangerous actions before Chrome receives the
  command.

If the active backend can only observe or cooperatively steer behavior, the UI,
audit, and documentation must label the control honestly:

- Enforced: Erebor prevented the effect before execution.
- Held: Erebor paused the effect while waiting for challenge or approval.
- Cooperative: integration or configuration guided the worker, but bypasses
  remain possible.
- Observed: Erebor recorded the behavior but did not prevent it.
- Deferred: no current claim.

## Product Surface

The product should lead with Erebor Agent:

- "Erebor Agent governs other agents so they do not forget the task boundary."
- "Erebor Runtime enforces the decisions at the execution path."
- "Worker agents do the work; Erebor Agent remembers the rules."

The buyer-facing UI should make the task boundary visible:

- current task contract
- allowed and denied paths
- pending challenges
- pending human approvals
- recent denied actions
- backend capability status
- audit records for the session

The worker-facing UX should be concise:

- say what was blocked
- say why it was blocked
- ask for justification when a challenge is allowed
- explain when human approval is required
- never reveal denied file contents in the error message

## Architecture Direction

This plan does not require the first implementation to build a full filesystem
surface immediately. It does require the architecture to preserve filesystem
authority as a first-class product concept.

Implementation may proceed in layers:

1. Product contract and audit shape.
2. Deterministic task-contract matcher for path and action classes.
3. Challenge and human-approval state machine.
4. Filesystem event normalization through the best available backend.
5. Stronger platform enforcement through Docker/OCI, Linux, macOS, or future
   guards.

The first implementation should reuse the existing session model, policy
evaluation, approval decisions, and audit model wherever possible. It should not
create a second session concept or a separate OpenClaw-specific enforcement
path.

## Non-Goals

- Do not replace the governed OpenClaw pilot.
- Do not make an LLM the security boundary.
- Do not claim host-wide filesystem enforcement until a backend proves it.
- Do not allow worker-agent justification to expand scope without human
  approval.
- Do not hide enforcement tier limits from security engineers.
- Do not put the task contract only in the worker agent's prompt.
- Do not build a generic approvals dashboard as the product identity.

## Acceptance Criteria

Product acceptance:

- A security engineer can explain the product in one sentence.
- The product story distinguishes Erebor Agent from Erebor Runtime.
- The task contract is visible and confirmed before the worker starts.
- Worker-agent justification cannot silently expand the task contract.

Demo acceptance:

- The demo prevents out-of-scope file reads from revealing contents.
- Secret reads are denied by default.
- Writes and deletes do not happen before approval.
- The worker can continue productively after an allowed denial or challenge.
- Audit records are clear enough to reconstruct why an action was allowed or
  blocked.

Architecture acceptance:

- Runtime remains the enforcement boundary.
- Erebor Agent remains a governance layer over the runtime, not a replacement
  for it.
- Filesystem authority is represented as a first-class product concept even if
  an early backend initially reports it as cooperative or observed.
- The active enforcement tier is reported honestly in session state, UI, docs,
  and audit.

