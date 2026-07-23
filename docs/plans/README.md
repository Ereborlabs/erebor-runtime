# Recovered Plans

The tree follows the recovered plan shape where it could be proven from
headings and relative links: a master plan lives at the family root, and an
implementation subplan has its own `README.md` and phase files. Files without a
recovered master plan are grouped in a named family rather than having a new
master plan invented for them.

## Recovered Master Plans

- [Governed browser and terminal](../governed-browser-and-terminal-plan.md)
- [Managed browser launch interception](managed-browser-launch-interception.md)
- [Agent task boundary guard](agent-task-boundary-guard/README.md)
- [Governed OpenClaw pilot demo](governed-openclaw-pilot-demo/README.md)
- [Session review and LLM governance](session-review-and-llm-governance.md)
- [Context DAG](context-dag.md), including the Codex and Claude Attribution V1
  subplans
- [Ownership-oriented module cleanup](ownership-oriented-module-cleanup/README.md)
- [Session interception backend refactor](session-interception-backend-refactor/README.md)
- [Linux OSTree OverlayFS V3 implementation](revert/filesystem-surface/linux-ostree-overlay-v3-implementation/README.md)

## Recovered Phase Families Without Their Original Master

- `daemon-client/` — Phase 1 through Phase 10 daemon/client migration work.
- `codex-adoption/`, `codex-surface-profiles/`, and `codex-exec-mediation/`.
- `context-dag/` — the Context DAG implementation tree: current governed-
  surface integration plus nested Codex and Claude Attribution V1 subplans.
- `error-and-logging/`.
- `revert/filesystem-surface/macos-fskit-overlay-v1-implementation/`.

`docs/plans/recovery/superseded/` retains earlier named plan revisions. Do not use a
file there as an active phase without deliberately comparing it to the
canonical copy and the source tree.
