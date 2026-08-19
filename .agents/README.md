# Agent Instruction Map

`AGENTS.md` defines repository scope and document custody. This directory owns
the detailed rules. Read the guide that matches the work before editing.

## Working Guides

- [engineering.md](engineering.md): Rust code, crate ownership, CLI boundaries,
  errors, logging, tests, and handoff.
- [planning.md](planning.md): plans, phase files, simplification proposals, and
  truthful status claims.
- [browser-cdp.md](browser-cdp.md): browser/CDP enforcement, state authority,
  protocol handling, and browser-client acceptance.
- [verification.md](verification.md): required quality gates, e2e evidence, and
  final reporting.
- [worktrees.md](worktrees.md): required repository-local worktree location,
  creation, relocation, and verification.

## Discover Documentation And Plans

Start with [docs/README.md](../docs/README.md) and
[docs/plans/README.md](../docs/plans/README.md). Then use
`rg --files docs docs/plans` to discover the current material for the task.

Read every applicable parent document, design, README, master plan, nested
plan, phase, result, lifecycle probe, manual acceptance record, and example.
The indexes help discovery; they do not replace linked documents. Research and
recovered material can explain a decision, but they do not prove current
implementation state.

Do not add a catalogue of document names, plan titles, phases, or statuses to
agent instructions. Keep this file stable; plans own their own scope and
status.

For the required ASD-STE100 writing standard, see
[AGENTS.md](../AGENTS.md#documents-and-comments).
