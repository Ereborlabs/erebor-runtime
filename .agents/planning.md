# Planning Rules

## Phase-Plan Style

Use `docs/plans/session-interception-backend-refactor/runtime-interception-broker-module-split/`
as the style model for implementation plans.

Active implementation plans should have:

- a README with status, parent plan, goal, non-negotiables, existing problem,
  target shape or module ownership, phase baseline summary, phase list, and
  verification commands
- one file per phase when the work is non-trivial
- each phase file with purpose, scope, checkpoint, acceptance, and a phase
  result once complete
- an explicit stop point when later phases require user approval
- a lifecycle or live probe file when runtime behavior must be proven outside
  unit tests

## Current-Code Grounding

- Rewrite plans from the current source tree, not from stale historical text.
- Name exact files, modules, symbols, commands, and behavior contracts.
- If an old phase filename remains for link stability, keep the phase style but
  update the content so future agents do not follow obsolete code paths.
- Keep historical facts only when they explain an existing decision,
  compatibility break, or follow-up risk.

## Architectural Simplification

- Prefer the simpler design only when it removes a real durable owner,
  listener, protocol, or runtime model and preserves the entire correctness and
  enforcement contract.
- A simplification proposal must state the removed architecture, the remaining
  owner, the invariants that remain true, and the code-backed proof required.
- Do not describe hardening, code movement, a renamed abstraction, or a new
  feature as simplification.
- Do not merge distinct control, enforcement, authentication, lifecycle,
  recovery, evidence, or physical-effect boundaries merely to reduce a process
  or type count. Correctness is the deciding constraint.

## Verification Claims

- A plan can list required verification without claiming it was run.
- Only mark a command as passed when it was actually run for that phase or
  current rewrite.
- If verification is blocked by the host, record the exact command and error.
- Do not mark future mediation, IPC, config, or surface stories complete until
  the code and tests for that story exist.
