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

## Proposed Master Plans

- [Araphor observability](araphor-observability/README.md) — CLI-first SQL and
  bpftrace capture, shared console APIs, and optional finite Trace CRD. Reuses
  shared DuckDB data/query facilities and existing execution owners.
  Capture does not require discovery enablement. The plan requires unit,
  mithril-e2e and paired physical proof before production enablement.
- [Mithril 7: Control, discovery, and detection](mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/README.md) — source-grounded
  evidence and context for agents, simple SQL query/follow, classification,
  and governed policy tools. Response tools retain the master plan's owner and
  physical-proof gates. Local or hosted clients need explicit export permission.
  Ten subphases cover contracts, DuckDB storage, query/follow, profiles,
  findings, methods/preview, agent classification, publication, optional remote
  placement and qualification.
- [Araphor console](araphor-console/README.md) — one interface for agent and
  workload protection, policy review, action evidence, and recorded platform
  verification. Araphor is the new product name for Erebor and Mithril. The
  plan keeps current repository and technical identifiers. Public operator
  reports, project documentation, and incident studies inform its workflows.
- [Mithril Hugging Face intrusion prevention](mithril-hugging-face-intrusion-prevention/README.md)
  — phased single-gatherer Linux/Kubernetes/provider prevention, causal
  correlation, and verified response built around the published incident
  acceptance chain.

## Draft Architecture Lines

- [Container and Kubernetes execution](container-orchestration/README.md) — a
  separate, not-yet-approved design for Docker runners and Kubernetes
  controller/node-agent execution. It does not expand the daemon-client phase
  scope.

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
