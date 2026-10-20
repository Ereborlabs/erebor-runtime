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

- [Araphor packages and managed jobs](araphor-package-jobs.md) records the
  current native SQL pipeline, reactive execution, new Discovery packages,
  and code reduction criteria. Definition files and running instances are the
  first required work, recorded as three separate TODOs: OCI image, Compose
  file, and running Discoveries. Definitions support package calls, PRQL, and SQL
  with metadata. Earlier controller and storage proposals in
  that file remain draft material. The first native SQL package and selected
  query-RPC proof pass. OCI image storage and installation now pass focused
  qualification. Image installation creates no activation. Definition
  admission and inspection also pass focused qualification. The current YAML
  authoring design keeps metadata for SQL, PRQL, and direct calls. Native
  package-call physical execution is implemented. Read the
  [Analysis migration record](araphor-analysis-migration.md) for its current
  qualification. Finite managed state and atomic publication pass focused
  checks. The current final Rust gate, running-instance lifecycle, and complete
  replacement remain open.
- [Araphor performance simplification TODO](araphor-performance-simplification-todo.md) —
  the user approves all 17 source-audit items. The file records implementation
  and verification status for each item.
- [Araphor component redesign](araphor-component-redesign.md) — the user
  approves one Arrow query operation and retained package admission. DataFusion
  replaces query execution. DuckDB retains durable storage. The source studies
  and coherence review are complete; implementation and parity remain open.
- [Araphor Query and Analysis feature parity TODO](araphor-feature-parity-todo.md)
  compares the accepted graph, SDK, package, Wasm, and native features with
  current callers. It lists preserved behavior and the remaining restorations.
- [Araphor Data test runtime reduction](araphor-data-test-runtime-reduction.md) —
  the seven approved corrections and final Rust qualification are complete.
  The record preserves the complete inventory and observed timing limits.
- [Araphor production data flow simplification](araphor-production-dataflow-simplification.md) —
  raw executable storage, one SQL operation engine, and the revised typed
  graph handoff with buffered DuckDB appends are implemented and pass final
  Rust CI. Local OCI transport, typed Discovery commits, bounded graph
  preparation, shared executable admission, and finding-row accounting pass
  qualification at `ab6b5da3`. Native Data and the exact native E2E retry pass;
  the first E2E failure remains recorded, and reproducibility is unresolved.
  The Data runtime target below ten minutes is not met.
  The [graph format review](araphor-graph-binary-duckdb-review.md) compares
  typed values, binary formats, and DuckDB input APIs. The user requires
  current-format storage and no backward compatibility. New timing workloads
  and DataFusion work require explicit approval.
- [Araphor observability](araphor-observability/README.md) — CLI-first SQL and
  bpftrace capture, shared console APIs, and optional finite Trace CRD. Reuses
  shared segment-backed data and DuckDB query facilities and existing execution owners.
  Capture does not require discovery enablement. The plan requires unit,
  mithril-e2e and paired physical proof before production enablement.
- [Mithril 7: Control, discovery, and detection](mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/README.md) — source-grounded
  evidence and context for agents, simple SQL query/follow, classification,
  and governed policy tools. Response tools retain the master plan's owner and
  physical-proof gates. Local or hosted clients need explicit export permission.
  Ten subphases cover contracts, segment/derived-state storage, query/follow, profiles,
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
