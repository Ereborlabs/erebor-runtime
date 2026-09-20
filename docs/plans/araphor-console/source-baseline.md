# Araphor Console Source Baseline

This record binds the proposed console to inspected source. It separates
implemented contracts, historical test records, and UI samples so that later
work cannot turn a design example into a protection claim.

## Intended end state

An implementer can trace each major screen decision to an existing owner or
an explicit integration gap. A historical test pass retains its exact scope.

## Source checkpoints

- Inspection date: 2026-09-20.
- UI worktree after rebase: `bc090201c1d2bd96b1b098d2f7bd6c104867b4db`.
- Included main: `787c03233ea1cf1593fd487b086c2e467e855a21`.
- The primary checkout had unrelated uncommitted changes. They are not part
  of this baseline or evidence for a completed feature.
- The Araphor website is an untracked local input at
  `/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/.gstack/araphor-website`.
  It is not present inside the UI worktree. Its files were inspected in place.
  The [interface specification](interface-design.md) records the selected
  tokens and asset source so implementation does not depend on that directory
  at runtime.

## Existing console

Read the [console README](../../../ui/mithril-console/README.md),
[implementation guide](../../../ui/mithril-console/IMPLEMENTATION_REVIEW.md),
and [prior UX audit](../../../ui/mithril-console/UX_AUDIT.md).

- `src/Console.tsx` defines eight workspace links and a cluster-only header.
  Operations starts with Kubernetes workloads. The Agent workspace is a
  canned question-and-answer fixture, not an inventory of governed agents.
- `OperationsView` changes a workload to `Protected` after local confirmation.
  The page discloses that this is a fixture. It sends no policy request.
- `PoliciesView` and `OperationsView` keep separate local policy copies.
  Route changes can discard view-local state. A shared review must use one
  local draft owner so the same rule does not differ between screens.
- `src/consoleData.ts` supplies sample counts, policy syntax, provider
  coverage, response, and release claims. Its `131 / 133` count and release
  candidate are not current qualification evidence.
- `src/data.ts` supplies a cross-node incident graph. Its operation outcome
  combines decisions, observations, and verification in one union.
- `src/graph.ts` supplies reusable pure visibility and layout functions.
  `src/App.tsx` supplies the graph, ledger, counterfactual, and stop review.
- The implementation guide records incomplete replay-state restoration.
  Preserve route compatibility and verify actual reload and Back behavior.
- The prior audit records mobile and accessibility checks for the old UI.
  Those checks are a baseline, not a pass for the Araphor design.

## Website inputs

The local website `index.html` presents one product for agents and workloads.
It says to start in Observe, review suggested policy from real activity, and
approve the policy before Protect. The console must make those steps usable.

`DESIGN.md`, `COLOR-THEMES.md`, and `color-schemes.css` define Forged Silver 6.
`index.html` selects that scheme. Use its silver, graphite, violet, fired-clay,
green, ochre, and information colors with distinct meanings.

Use the actual `assets/araphor-mark.svg` crown-and-fortress asset. The older
Gate recommendation in the design document is superseded by its later
decision and the current asset. The website product images remain images of
the older console fixture, even where their display name says Araphor.

## Recent qualification changes and UI consequences

Read [qualification rules](../../../crates/mithril-e2e/README.md) and the
[migration ledger](../../../crates/mithril-e2e/SCENARIO_MAINTAINABILITY_TODO.md).

| Inspected source | Fact | Console consequence |
| --- | --- | --- |
| `mithril-e2e/src/platform.rs`, `src/platform/lifecycle.rs`, and `mithril-e2e-macros/src/lib.rs` | Standard Rust tests use one scenario with explicit platform and lifecycle selection. Privileged tests require physical prerequisites. | Keep behavior, platform, lifecycle, run, and test type separate. A skipped privileged test is not a physical pass. |
| `src/identity/scenarios/runtime_entries.rs` | Initial and later runtime entries have distinct task, process, execution, role, and admission identities. | Show entry type and role. Do not join by executable or PID alone. An execution allow rule does not admit an undeclared entry. |
| `src/identity/scenarios/lifetime_result.rs` | A leader can exit while the process still has a live worker and owned references. | Keep task exit, process lifetime, and session lifetime separate. |
| `src/identity/scenarios/retained_host.rs` | Retained maps and links have an exclusive owner and checked recovery. | Show owner health and recovery evidence. A restart is not a new successful qualification. |
| `src/effect/process_control.rs` | Protected and unmatched ptrace and signal cases retain controller and target identity, policy state, result, and reason. | Show both actors in a process-control action. Separate exact policy denial from an unsupported relationship. |
| `src/effect/file_effect.rs` | The managed proc read checks an exact actor, denied result, and `UNRESOLVED_OBJECT`. | Do not describe every denied read as a matched secret-file policy. |
| `src/effect/privilege.rs` | The namespace case requires actor `EPERM`, kernel `-EACCES`, `UNSUPPORTED_OBJECT`, and `CAP_SYS_ADMIN`. | Keep actor errno and kernel result in separate fields. |
| `src/process/tests.rs`, commit `153c24d4` | An actor can exit successfully while its transport returns code 1. The fixture retains the distinct transport result. | Transport failure is not proof of policy denial or actor failure. |
| `src/effect/bpf.rs`, commit `787c0323` | The BPF scenario records the syscall result independently of the transport. Its platform attribute lists Host and runc only. | Preserve source result channels. Do not show a qualified Kubernetes result for this checkpoint. |
| `src/capability_matrix.rs` | The named kernel-qualification matrix marks only three capabilities supported when supplied a physical evidence digest. | Do not replace a capability record with a green state inferred from nearby tests. Expose the exact record and its scope. |

The older [platform-scope guide](../../../crates/mithril-e2e/PLATFORM_SCOPE_REVIEW.md)
describes `#[scope]` and a removed `scope.rs` owner. Current source and the
migration ledger use `#[lifecycle]` and `platform/lifecycle.rs`. Do not copy
the older scope scheduler into the console model.

### Recorded results, not new test runs

The migration ledger records a complete matrix at `50910f48`: 50 Host,
41 direct-runc, and 41 Kubernetes cases passed on 2026-09-19. A later record
reports 52 Host, 43 direct-runc, and 43 Kubernetes cases after the signal
migration. The Host run required a focused retry after a Node startup timeout.
Keep that retry visible. Neither record qualifies every later source change.

At the inspected main checkpoint, managed proc and namespace cases have
recorded passes on all three platforms. BPF map denial has recorded Host and
direct-runc passes; the Kubernetes gate remains unchecked. These are document
records. No physical result was reproduced during this planning work, and the
retained artifacts were not validated.

The wider migration ledger and
[backend closure record](../mithril-hugging-face-intrusion-prevention/phase-6-2-closure-matrix.md)
still contain incomplete work. A new focused pass does not close that work.

## Existing production contracts

| UI data | Source to read | Limit |
| --- | --- | --- |
| Workload policy source, targets, candidates, acknowledgements | [policy/kubernetes.rs](../../../crates/mithril-control/src/policy/kubernetes.rs) | CRD status is a projection, not activation authority. Keep exact candidate and target identity. |
| Bounded exception | [policy/kubernetes_exceptions.rs](../../../crates/mithril-control/src/policy/kubernetes_exceptions.rs) and `WorkloadProtectionExceptionSpec` in `kubernetes.rs` | One declared grant, exact target, duration, and use bound. A generic allow-once switch is not equivalent. |
| Kernel observation and coverage | [evidence/model.rs](../../../crates/mithril-control/src/evidence/model.rs) | Retain reason, decision, operation, configured errno, kernel result, source epoch, sequence, boot, and coverage interval. |
| Durable intake and acknowledgement | [evidence.rs](../../../crates/mithril-control/src/evidence.rs) | A node observation is not proof of durable Control intake. |
| Node-facing services | [control.proto](../../../crates/mithril-control/proto/erebor/mithril/control/v1/control.proto) | These authenticated node contracts are not a browser API. |
| Runtime sessions, policies, surfaces, evidence, and context | [daemon.proto](../../../crates/erebor-runtime-ipc/proto/erebor/runtime/ipc/v1/daemon.proto) | Session association fields can be absent. `SurfaceRecord` reports name and type, not current protection health. |
| Runtime session projection | [session_api/response.rs](../../../crates/erebor-runtime-daemon/src/session_api/response.rs) | Preserve absent agent/policy associations and owner-scoped session IDs. Do not expose private host paths. |

The [backend master](../mithril-hugging-face-intrusion-prevention/README.md)
defines Control, Node, and Interceptor ownership. The
[daemon plan](../daemon-client/README.md) and
[context integration plan](../context-dag/current-governed-surface-integration.md)
explain Runtime ownership and attribution limits. Some recovered status text
predates implemented source. For this UI plan, the source contracts above
establish available fields; the narrowest retained acceptance record
establishes the proven claim.

No inspected Control service supplies the complete old console's incident,
finding, suggestion, and response application API. Runtime `ContextService`
does supply a context graph contract. That graph is not interchangeable with
the sample cross-node incident graph, and it does not prove kernel attribution.
