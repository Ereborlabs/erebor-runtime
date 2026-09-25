# Araphor Console Plan

This plan replaces the Mithril console design with one Araphor interface for
agent and workload protection. It uses the Araphor website identity and the
current Runtime and Mithril source contracts. The new interface must explain
what is protected, what needs review, and what the evidence proves.

## Intended end state

An operator can select an agent session or workload, inspect recorded actions,
review a proposed policy, and inspect its activation state. An investigator
can trace a denied action to its actor, target, policy, result, and evidence.
An evaluator can inspect the exact platform and source revision covered by a
verification record.

The console uses Araphor throughout its product text. It has five workspaces:
Protection, Activity, Policies, Evidence, and System. Agent sessions and
workloads use the same navigation, but keep their separate identities and
policy owners.

The first delivery is an interactive design fixture in
`ui/mithril-console`. It includes the failure and partial states described
below. It does not connect browser controls to privileged services. A live
connection requires a separate implementation plan with authentication,
authorization, read contracts, and mutation contracts.

## Implementation flow

```text
Operator opens Araphor
  -> App restores the selected environment and route
  -> ConsoleShell identifies the data as Sample data or a recorded capture
  -> Protection shows agent sessions and workloads in the selected scope
  -> each row shows its mode, activation, evidence health, and last update
  -> the attention list links to the exact item that needs review

Operator selects an agent session
  -> Protection opens its owner-supplied session identity and lifecycle
  -> the detail shows its policy set and reported execution surfaces
  -> a related workload appears only when a source record proves the binding
  -> absent attribution appears as Not attributed
  -> Activity opens the actions for this exact session

Operator selects a workload
  -> Protection opens its runtime identity and declared entries
  -> the detail separates application entry from additional runtime entries
  -> the detail shows policy activation for each exact target
  -> evidence health remains separate from enforcement state
  -> an unavailable source shows the last update and an unknown current state

Operator reviews a suggestion
  -> Policies shows the source actions, observation interval, and coverage gaps
  -> the review shows the proposed rule and its affected targets
  -> the operator accepts, edits, or rejects the suggestion in a local draft
  -> a draft edit does not change the active policy
  -> unsupported rule types cannot enter the Protect confirmation

Operator requests protection in the design fixture
  -> Policies validates the selected source family and required fields
  -> the review names the exact draft revision and target snapshot
  -> the operator confirms the displayed change
  -> the sample transition records Submitted, then per-target activation states
  -> Protection changes only from the matching sample acknowledgement
  -> the persistent Sample data label remains visible

Target rejects a candidate or a source becomes unavailable
  -> the detail keeps the requested revision separate from the last active one
  -> the failed target shows its reason and last acknowledged state
  -> the summary shows Partial, Rejected, or Unknown as applicable
  -> Retry refreshes the draft and target snapshot before a new confirmation
  -> a late acknowledgement for an older candidate cannot complete the retry

Operator cancels or leaves a policy review
  -> the console discards only the unsaved review state after confirmation
  -> a saved local draft remains available during navigation
  -> the console performs no backend cleanup or policy retirement
  -> Reset sample clears only the local sample state

Investigator opens an action
  -> Activity shows the request and source policy decision
  -> the detail shows the actor result separately from the kernel result
  -> transport status appears in diagnostics when a source supplies it
  -> Evidence shows the source record and its coverage interval
  -> missing result evidence prevents a Verified outcome

Investigator opens a related session or incident
  -> the replay restores the selected revision, event, and view
  -> the graph shows only relationships present in that source graph
  -> a contextual relationship remains visibly weaker than a direct one
  -> a hypothetical continuation remains outside the evidence graph
  -> an incorrect-stop review creates a local request, not an allow decision

Evaluator opens Evidence > Verification
  -> the view groups recorded checks by behavior and platform
  -> each result retains its source revision, test identity, and run identity
  -> a later retry does not remove the earlier failure
  -> an absent artifact shows Evidence unavailable
  -> a source mismatch shows Historical result
  -> a missing Kubernetes check cannot inherit a Host or direct-runc pass
```

## Status and scope

- Plan status: Proposed, 2026-09-20.
- Implementation result: **Not done**. No Araphor UI change is included in
  this planning change.
- Worktree: `worktrees/mithril-ui`, branch `codex/mithril-ui`.
- Inspected UI revision: `bc090201c1d2bd96b1b098d2f7bd6c104867b4db`.
- Included `main` revision: `787c03233ea1cf1593fd487b086c2e467e855a21`.
- Product naming authority: the user's instruction to merge Erebor and
  Mithril into Araphor. Existing product-separation text remains a historical
  architecture input; it does not define the new console navigation.
- Repository, crate, CLI, wire, API-group, and resource identifiers retain
  their current names. The product rename does not merge security owners.

Read [source-baseline.md](source-baseline.md) for the inspected facts and
[interface-design.md](interface-design.md) for the screen and visual contracts.
The website is a brand and product input. Its sample images are not evidence
of connected production features.

## Research basis and operator priorities

Read [research-and-design-inputs.md](research-and-design-inputs.md) for the
2026-09-20 review of Reddit reports, upstream projects, and incident accounts.
The review includes KubeArmor, Tetragon, Falco/Talon, Tracee, Cilium/Hubble,
Kyverno, NeuVector, AccuKnox Discovery Engine, and NVIDIA OpenShell. It also
examines the Hugging Face incident and contrasting agent incidents.

KubeArmor and Tetragon already provide enforcement. Learning workflows also
exist elsewhere. The proposed product difference is an operator workflow that
connects actual coverage, safe change, effects, and remaining access. This is
a hypothesis to validate, not a proven competitive claim.

| Priority journey | Operator question | Required result |
| --- | --- | --- |
| Coverage diagnosis | Why is this target not protected? | Explain target resolution, capability, activation, source age, and missing proof. |
| Policy review | Will this change stop valid work? | Show observed lifecycle cases, known impact, unobserved behavior, and exact review scope. |
| Investigation and response | What happened, and what access remains? | Separate attempt, effect, external denial, response execution, and checked postcondition. |

The [interface design](interface-design.md#research-driven-operator-journeys)
specifies these journeys. Research requirements R1 through R8 map to the four
existing phases; no additional workspace is required. External authority,
provider result, and tool metadata remain sample or unavailable where the
current backend has no complete contract. No new connector is authorized.

## Discovery engine dependency

The [Araphor discovery engine plan](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/README.md)
defines agent-ready context, bounded detection methods, security assessments,
review-only suggestions, native policy proposals, and missing-test requests. Its
[console contract](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/console-and-api.md) adds Behavior
detail, investigation review, and Suggestions within the same five workspaces.
Local defenders and the console share query/follow reads, scoped tools, and
exact subject/finding references. Submitted assessments, approvals, action
results, escalation deadlines, and open branches stay in one investigation
view. No agent report transfer or separate case database is required.
Query is not the entire product interface. Qualified exception and response
tools retain their own authorization and execution owners. Facts, hypotheses,
requirements, preview, publication, activation, and verified containment stay
separate. Local or hosted clients need an export grant. Show counterevidence,
missing checks, unavailable capabilities, blast radius, and open response branches.

Use those proposed records for new discovery fixtures. Do not replace existing
source-backed UI records with guessed live contracts. Connecting the fixture
requires approval and implementation of the engine plan's authenticated API
and publication boundary. A synthetic check or background scan must remain
distinct from historical replay and actual physical effects.

## Product decisions

| Decision | Required behavior |
| --- | --- |
| One product | Use Araphor in navigation, titles, help, and accessible names. Do not ask users to choose Mithril or Erebor. |
| Protection is the home view | Lead with items that need attention and the agent or workload inventory. Do not lead with test totals or a synthetic risk score. |
| Observe, Suggest, Protect | Observation supplies a reviewable proposal. A human approves a concrete revision. Activation remains a separate result. Suggest is a review stage, not a new backend policy mode. |
| Agent protection is explicit | Show actual governed sessions, their policy set, surfaces, and lifecycle. The existing canned chat is not the Agents view. |
| Workload protection stands alone | A workload can be protected without an attributed AI agent. Do not infer an agent from a process name. |
| Verification is inspectable | Put qualification records in Evidence and link them from the applicable protection detail. Keep engineering test controls out of the normal protection workflow. |
| Response stays in context | Show an exception or response review beside its action or investigation. Do not require a separate top-level Response workspace. |
| Reuse the current implementation | Keep React, TypeScript, Vite, native SVG, Vitest, Playwright, and axe. Keep the pure graph projection and layout. Add no UI kit, graph engine, router, or state library for this work. |

## State and result contracts

These are display contracts, not a new protocol or policy engine. Preserve
the source enum, identifier, and reason in the evidence detail. Missing data
must not become an empty string, zero, allow decision, or healthy result.

| Dimension | Display rule | Source or limit |
| --- | --- | --- |
| Data origin | Sample data, Recorded capture, or Live connection | This delivery supports samples and checked records only. A capture is not a live connection. |
| Subject | Agent session or Workload, with an owner-qualified ID | Session IDs, workload UIDs, and task cookies are different identities. A display name is not a join key. |
| Environment | Host, direct runc, or Kubernetes; optional runner and node detail | An environment is not an enforcement surface. |
| Surface | File access, execution, process control, network, privilege, or a reported Runtime surface | Show availability per owner and target. A surface name alone does not prove enforcement. |
| Mode | Observe or Protect where the source supports those modes | A Runtime session does not inherit a Mithril mode without a mapping. Show its reported governance state instead. |
| Activation | Pending, Delivered, Staged, Active, Rejected, Stale, Unknown | Use Control rollout states. Keep target counts, candidate ID, source revision, and last active revision. |
| Decision | Source decision plus reason | `EXACT_POLICY_DENY`, `UNRESOLVED_OBJECT`, and `UNSUPPORTED_OBJECT` remain distinct. |
| Physical result | Actor return value or errno, kernel result, and verification evidence | Do not infer physical denial from a failed transport or infer success from an allow decision. |
| Evidence health | Healthy, Gapped, Unknown, Closed, with interval and source | Local enforcement can remain active during evidence delay. A gap prevents claims about absent later actions. |
| Attribution | Direct, Contextual, or Not attributed | Runtime context graphs and kernel causal graphs keep their own edge meanings. Time proximity is not proof. |
| Qualification | Recorded pass, Recorded failure, Not run, Not applicable, Historical result, Evidence unavailable | Keep exact platform, source, attempt, and artifact provenance. This is not current workload health. |

Protection must not reduce these dimensions to one green badge. For example,
show `Protect requested · 2 of 3 targets active · Evidence delayed`. A stale
read shows `Last known active` and its time. It cannot claim current protection.

An `UNSUPPORTED_OBJECT` decision can accompany a real fail-closed denial.
Show both the denied operation and the unsupported object reason. Do not
render it as a successful policy match or as permission to retry the action.

## Ownership and integration limits

| Concern | Existing owner | Console responsibility |
| --- | --- | --- |
| Workload policy source, compilation, signing, and rollout | `mithril-control/src/policy/` | Display separate source, candidate, and per-target activation records. Do not compile or sign in the browser. |
| Identity, local activation, effect evidence, and recovery | `mithril-node` | Present the reported target, lifecycle, and evidence. Do not read BPF maps from the UI. |
| Kernel lifecycle | `erebor-interceptor` | Preserve the one-loader and exclusive-lease boundary. No console-owned agent or loader. |
| Runtime session, policy set, surface, and context | `erebor-runtime-daemon`, session owners, and typed IPC | Preserve owner-scoped identity and source provenance. Do not attach a browser directly to privileged local IPC. |
| Evidence intake and coverage | `mithril-control/src/evidence.rs` and `evidence/model.rs` | Display retained records and missing intervals. Do not synthesize durable acknowledgements. |
| Test execution and physical qualification | `mithril-e2e` and its existing harness | Read checked records. Do not add a test runner or a Run on cluster button. |
| Local UI state | `App.tsx`, existing views, and fixture data | Keep shared sample drafts and selections consistent across routes. Local state has no enforcement authority. |

The Control node services are not a public console API. Runtime IPC already
defines session and context reads, but that does not provide a browser-safe,
cross-owner console connection. Existing evidence and graph types do not
prove a complete production investigation or response service.

The fixture must label unavailable connected actions at the action itself.
For example: `Preview protection` and `Save local draft`. It must not show
`Protection enabled` after a browser-only edit.

## Implementation order

Follow the [combined implementation order](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/README.md#combined-implementation-order).
Start these fixture phases after Phase 7.1 freezes the shared records.
Complete them in order alongside the Phase 7 backend subphases. Phase 7.8 then
connects the same screens to shared protobuf gRPC-Web owner contracts; it does
not repeat this shell implementation. Browser data reads and mutations do not
use JSON/HTTP routes. Static assets and login redirects still use HTTPS.
Phase 7.10 qualifies the first live workflow.
Mithril 8–10 own later exception, response, and provider UI integration and
their tests. Fixture controls cannot enable those capabilities early.

| Phase | Deliverable | Dependency | Result |
| --- | --- | --- | --- |
| [1: Araphor shell and protection](phase-1-araphor-shell-and-protection.md) | Brand, navigation, shared view state, agent and workload inventory | Phase 7.1 record contracts | Not done |
| [2: Policy review and activation](phase-2-policy-review-and-activation.md) | Suggestions, typed policy review, target activation, bounded exception review | Phase 1 | Not done |
| [3: Activity and evidence](phase-3-activity-and-evidence.md) | Action result detail, agent context, causal replay, evidence health | Phases 1 and 2 | Not done |
| [4: Verification and acceptance](phase-4-verification-and-acceptance.md) | Source-bound verification views, System detail, complete journey checks | Phases 1 through 3 | Not done |

Each phase has its own scope, acceptance, and result record. Review the first
rendered Protection view before extending the visual treatment to all screens.
Complete the approved phase and record its result before the next phase.

## Verification

Run the existing UI commands from `ui/mithril-console` after the applicable
implementation change:

```sh
npm run check
npm test
npm run build
npm run test:e2e
```

Use the existing browser suite for end-user journeys and accessibility. Use
small pure tests for route parsing, result mapping, and qualification status
where incorrect logic could produce a false protection claim. A new page does
not need a duplicate test for each presentational component.

UI checks do not qualify the enforcement product. If later work changes a
Rust owner, follow the owning backend plan, run its paired lightweight and
physical checks, and run `bash .github/scripts/verify-rust-ci.sh` after the
final covered edit.

## Exclusions and next boundary

This plan does not rename the repository or technical APIs, create a unified
backend authority, introduce a browser gateway, execute policies or response,
run a Kubernetes qualification, build an AI chat assistant, or complete an
unfinished backend plan. It does not make the historical Hugging Face sample
into a live incident record.

Before live integration, define the console's authenticated read boundary,
tenant and owner authorization, retention and redaction rules, supported
mutations, and exact source-to-display mappings in a separate approved plan.
Do not weaken these requirements to make a sample control appear live.

## Planning result

Result: **Done** for the proposed plan and screen specification.
Implementation: **Not done** for all four phases.
Verification: Source inspection, public-source review, and document checks
only. The research amendment retains 24 external source links. Before the
discovery-plan links were added, a Node check passed for 33 local links and
section anchors across eight plan files, balanced
code fences, all eight research requirement IDs, and Not done implementation
results. Whitespace checks passed. No UI, competitive deployment, participant
study, or physical test pass is claimed.
The current combined check includes the changed master notification/response
plans: 27 files and 154 local links and anchors. It does not replace UI checks.
Remaining work: Validate the proposed operator journeys and implement the
selected phase.
