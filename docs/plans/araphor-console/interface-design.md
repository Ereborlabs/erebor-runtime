# Araphor Console Interface Design

This specification defines the proposed screens and interactions for the
[console plan](README.md). It uses the website's industrial evidence design
for an operational interface with readable tables and explicit result states.

## Intended end state

The first screen answers three questions: What is protected? What needs my
decision? What evidence supports the result? Detail screens preserve context
as the operator moves from a subject to a policy, action, or evidence record.

## Screen flow

```text
Operator selects an attention item on Protection
  -> the console opens the subject and relevant tab
  -> Review suggestions opens its local draft in Policies
  -> Review activation opens the exact policy target list
  -> Investigate action opens its result in Activity
  -> Inspect evidence opens the matching record or missing-source explanation
  -> Back restores the preceding filter, selection, and scroll position
```

## Navigation and route ownership

| Workspace | Views | Main action | Existing material to reuse |
| --- | --- | --- | --- |
| Protection | All, Agent sessions, Workloads; subject detail | Review the selected subject | Operations inventory and policy disclosure |
| Activity | Actions, Sessions, Investigations; action and replay detail | Inspect an action | Sessions, Findings, replay, and ledger |
| Policies | Suggestions, Policies, Exceptions; draft and activation detail | Review a proposal | Policy editor, workload rule review, and confirmation |
| Evidence | Records, Source health, Verification | Inspect supporting proof | Evidence workspace and release detail |
| System | Environments, Nodes, Connections | Inspect readiness or a reported limit | Existing node rollout and source metadata |

Use hash routes and the existing `App` route owner. Native `URLSearchParams`
can carry environment, view, subject, revision, and selection. Validate values
against the selected source. An unknown ID shows Not found and a return link;
it must not silently open the sample incident.

Preserve `#/sessions/session-hf-xnode-021` as an alias to its sample replay.
Map old Operations to Protection, Findings to Activity > Investigations,
Release to Evidence > Verification, and Response to its sample investigation.
The old Agent route opens a short explanation and the Agent sessions view.
It must not relabel the canned assistant as a real managed agent.

The header contains environment, data origin, last update, and a view search.
`All environments` includes Host, direct runc, and Kubernetes. Kubernetes adds
cluster and namespace filters. A Host view does not show an empty namespace
field. Search filters actual displayed subjects or actions. Do not present the
old workspace-name shortcut as a search of retained evidence.

## Protection

Use an attention list above the inventory. Each item states one condition,
the affected subject, and one useful action. Examples are `Review proposed
rules`, `1 target rejected this revision`, and `Evidence has a gap`. Counts
come from the same selected dataset as the rows.

The following layout uses sample data. It is a design example, not a claim
about the current deployment.

```text
ARAPHOR       All environments v              Sample data   Updated 14:32
------------------------------------------------------------------------
Protection    Protection
Activity      Needs attention
Policies      datasets-worker   Proposed rules              Review
Evidence      payments-api      1 of 3 targets not active    Inspect
System        worker-b          Evidence delayed            Inspect

              All | Agent sessions | Workloads       Find in this view
              ---------------------------------------------------------
              Subject           Environment    Protection       Evidence
              code-review       Host           Governed session Current
              datasets-worker   Kubernetes     Observe          Current
              payments-api      Kubernetes     Partial          Delayed
              ---------------------------------------------------------
              Selected: datasets-worker
              Overview | Actions | Policy | Entries | Evidence
              File access       Observe        Review proposed policy
              Process control   Protect        Inspect active revision
              Network           Unknown        View missing source
```

Each row has name, subject type, environment, reported governance or policy
mode, activation summary, evidence health, and last update. The default sort
puts actionable items first. The operator can filter by these dimensions.
Do not combine a session and its related workload into one count. Report
session and workload totals separately.

An agent-session detail shows the agent association when supplied, session
lifecycle, policy set, runner, surfaces, recent decisions, and evidence links.
It can show a workload relationship only with an explicit source binding.
Prompt and turn attribution appear only when the evidence contains them.
Without them, the action remains attributed to its session or process.

A workload detail shows its immutable runtime identity, application entry,
additional entries, external role, policy source, target activation, and recent
actions. Each entry has its declared command and argv constraints when
available. A process that entered later is not automatically an application
child. A recovered or unknown root retains that classification.

Separate File access, Execution, Process control, Network, and Privilege in
the detail where the source reports them. Show Browser, Terminal, and
Filesystem for Runtime sessions only where the owning session reports those
surfaces. API, SaaS, MCP, and desktop surfaces remain absent or explicitly
unavailable until a supported owner supplies them.

## Policy review

The suggestion list states the proposed behavior, affected subjects, source
actions, observation window, and coverage limits. Use those facts instead of
an invented confidence percentage. An operator-authored draft has no claimed
observation provenance.

```text
Policies / datasets-worker / Review                  Sample data
------------------------------------------------------------------
Current revision 11              Proposed local draft 12
Observed interval                Source actions             Inspect
Known gap                        14:21-14:24                 Inspect

Rule                             Current       Proposed
Read approved cache              Observe       Allow
Read protected credential path   Observe       Deny

Targets                          3 workloads / exact snapshot
Entry admission                  1 application / 2 additional entries
Unsupported changes              None in this sample
------------------------------------------------------------------
Save local draft                 Review protection preview
```

Keep human-readable rule summaries and a source view. Workload rules map to
the existing `WorkloadProtectionPolicy` fields. Runtime rules map to the
existing policy package and policy-set model. Do not create a shared policy
language from the old sample strings such as `deny provider.repository.write`.

The review order is scope, entries, rules, expected effect, evidence limits,
then exact confirmation. Suggestions are selected individually. A rule edit
invalidates a prior confirmation. Confirmation names the candidate draft,
target count, denied operations, and known limits.

In the fixture, use `Preview protection` and `Confirm preview`. Activation
states come from explicit sample acknowledgements, not a success timer. A
controllable sample can demonstrate Staged, Active, Rejected, and unavailable
acknowledgement states. The live design uses a source-authorized submission;
that connection is outside this implementation.

The rollout view shows desired revision, current revision, target identity,
candidate, state, reason, and last acknowledgement. It preserves a partial
rollout and the last valid generation. No rollback or retry may silently
activate a different source or widen the target set.

Exceptions start from the denied action. Ask what operation should have been
allowed, then show the available predeclared grant, exact target, duration,
and use count. An unsupported exception type has an explanation. Saving a
local request does not allow an action. Distinguish Pending, Active,
Consumed, Expired, Revoked, and Failed; keep the detailed source reason.

## Activity and investigation

Default to an action table. Its columns are time, subject, action, target,
decision, physical result, and evidence state. Process-control actions name
both controller and target. A policy allow with no observed result says
`Allowed · Result not recorded`.

An action detail has this order:

```text
Namespace change denied                          Recorded result
Actor: runtime-added Python process               Exact task identity
Operation: request CAP_SYS_ADMIN                  Target: namespace
--------------------------------------------------------------------
Policy decision      Denied          Reason: UNSUPPORTED_OBJECT
Actor result         EPERM           Reported by the actor
Kernel result        -EACCES         Reported by the kernel observation
Evidence             Recorded       Source epoch, sequence, and interval
--------------------------------------------------------------------
Inspect record       Related workload       Diagnostics
```

Diagnostics can expose transport status, boot identity, policy generation,
raw reason, operation argument, and source sequence. It must retain the source
label for every field. A successful actor with a failed transport does not
become a denied action. A record with no exact policy object says so.

Sessions list governed Runtime sessions and their execution state. Incident
investigations list evidence-backed findings or clearly labeled sample cases.
Do not call every workload event an agent session. An action can exist without
a session or finding.

Reuse the current stable machine lanes, native SVG edges, operation selection,
and synchronized ledger. Start a newly opened investigation at the selected
action with playback paused. Keep explicit Play, First event, Current event,
Stopped effect, and All events controls. Honor existing explicit replay URLs.

Show source-backed Runtime context as a separate context view. Label forks,
deliveries, and decisions according to that source. Do not attach a Runtime
context edge to a kernel action because their times or names are similar.

Keep direct edges solid and contextual edges dashed, with text labels and
keyboard inspection. Preserve missing or contradictory evidence. A selected
edge inspector names the actual join fields. Counterfactual nodes have a
separate Hypothetical label and never change graph data or counts.

Show response review inside its investigation with exact target, effect,
shared-identity impact, expiry, and required postcondition. The fixture can
preview this review. It cannot execute a response or claim recovery.

## Evidence and Verification

Records shows source, observed time, ingestion time when supplied, owner,
identity, result, and coverage interval. Source health shows gaps, lag,
retained cursor, restart, and current availability. A reconnect cannot erase
an earlier gap or produce a healthy continuous interval by itself.

Render record content as text. Use synthetic identifiers in samples. Preserve
upstream redaction for command arguments, paths, and sensitive identifiers;
do not load credentials, environment contents, or secret file bytes to explain
a denial. A local artifact reference is not an unrestricted file-read request.

Verification answers `What was tested for this behavior and environment?`.
It does not answer `Is this workload protected now?`. Use one row per
behavior and columns for Host, direct runc, and Kubernetes. A cell opens its
source revision, exact test name, lifecycle, prerequisites, attempts, result
channels, cleanup result, and artifact references.

Use the namespace-result mismatch, actor/transport mismatch, and incomplete
BPF Kubernetes qualification as initial design cases. Do not turn a document
checkmark into a verified imported artifact. A missing artifact remains
visible as Evidence unavailable. A pass for another revision remains a
Historical result. Do not extrapolate test coverage across platforms.

The old Release workspace becomes this read-only verification view. Remove
the synthetic `131 / 133` release score and hard-coded release readiness.
Capability records retain their own result, evidence digest, and narrow scope.

## System

Show environments and the owners that report their state: Control, Node,
Runtime daemon, runtime integration, and evidence connections as applicable.
Each has identity, version when supplied, last contact, readiness reason, and
capability limits. Put raw internal names in detail, not the main navigation.

Separate connection health from local enforcement. A Control outage can
coexist with a last acknowledged local generation. Show both facts with time
and source. The UI must not claim current node state after contact is lost.

This view contains no cluster installer, remote shell, or test runner.

## Research-driven operator journeys

The [research record](research-and-design-inputs.md) defines R1 through R8.
The following contracts extend the screens above. They keep the existing
five workspaces. Each added field must retain its source or say `Sample
metadata`, `Not reported`, or `Not available in this connection`.

### Explain missing protection: R1 and R7

Protection detail adds a `Coverage` tab beside its existing tabs. It answers
`Why is this target not protected?` without sending the operator to raw logs.
Use the same detail in System; do not maintain a second readiness model.

```text
Protection / payments-api / Coverage                  Sample data
--------------------------------------------------------------------
Requested: Protect r12     Active: 2 of 3 targets      Evidence: Gapped
Target       File access       Execution       Network       Updated
worker-a     Active r12        Active r12      Not reported  14:32
worker-b     Rejected r12      Active r11      Not reported  14:31
worker-c     Active r12        Active r12      Not reported  14:32
--------------------------------------------------------------------
worker-b / File access
Source accepted      r12 / candidate c12
Target selected      exact workload UID and runtime identity
Capability           Required capability unavailable [source reason]
Activation           Rejected / last active revision r11
Result evidence      No current check for the requested revision
Next step            Inspect reported prerequisite
```

For each selected surface, show source acceptance, resolved target set,
reported capability, delivery, activation acknowledgement, and available
effect evidence. This is a diagnostic sequence, not one progress percentage.
`Zero matching targets` is a distinct result, not a successful empty rollout.
If selection changes, require a new snapshot before policy confirmation.

Show the reported enforcement owner and mechanism, kernel/runtime version,
image revision, effective mode, and last check when supplied. Do not infer
mechanism or support from an OS name. A change of node image or policy source
does not inherit an earlier compatibility result without an explicit match.
Expose declared selector and resolved identity together. Show a canonical
path or policy-precedence explanation only if its owner provides it.

Add a small `Other controls` section with reported admission, network, and
identity controls. Each row names its source and owner. Unknown is not Absent.
This section is not a new compliance scanner. It must not imply that Araphor
installed, verified, or can edit an external control.

### Review valid-work impact: R2

Add `Observation coverage` and `Expected impact` to the existing policy review.
Keep the final confirmation short, but retain links to this evidence.

| Review field | Required behavior |
| --- | --- |
| Input scope | Exact workload/image revision or session policy source, interval, and source IDs. |
| Lifecycle cases | Show startup, steady traffic, deployment/restart, scheduled work, and maintenance/debug as Observed, Not observed, or Not applicable, with supporting records. Elapsed time alone is insufficient. |
| Observation trust | Distinguish an observation from an approved requirement. Let the reviewer exclude suspect records from the suggestion without deleting evidence. |
| Expected impact | Show recorded actions that the proposed rule would change only when a supported evaluator or explicit sample supplies that result. State that unseen behavior is not predicted. |
| Valid-work evidence | Link the paired allowed-control and denied-operation checks when available. Keep exact revision, platform, and missing artifacts visible. |
| Change scope | Show exact targets, changed operations, policy owner, author/reviewer when supplied, and remaining gaps. |
| Recovery plan | Identify the prior revision and required acknowledgement for a later reversal. Do not call a browser draft reset a rollback. |

Do not add a browser policy evaluator or a universal rule translator. The
first delivery uses deterministic examples for impact. An unsupported preview
says `Impact unavailable`; it cannot say `No impact`.

Missing lifecycle evidence produces a visible caution, not a false claim
that every rollout is impossible. A supported bounded policy may still be
reviewed with a recorded reason. Unsupported rules, zero targets, stale
confirmation, or absent required authority remain blocking conditions.
No elapsed-time rule automatically promotes a suggestion to Protect.

### Handle alert volume without weakening policy: R3

The attention list shows subject, reason, first/last observation, count,
source, review state, and next action. Show a responsible person or team only
when supplied; otherwise say `Unassigned`. Local assignment is sample state,
not an external ticket or notification.

Group only by explicit stable fields: subject identity, rule/source revision,
operation class, and a bounded interval. Keep distinct targets and results
inspectable. A deployment association is contextual unless a source proves
the relation. Never auto-dismiss a denial because a deployment occurred.

`Acknowledge` changes review state. `Suppress notifications` changes only a
bounded notification rule and requires a supported owner; it is unavailable
in this delivery. `Request exception` uses the existing exact grant review.
`Change policy` creates a new draft. None of these labels is interchangeable.
All raw sample records remain reachable after acknowledgement or grouping.

### Inspect a boundary crossing: R4, R5, and R8

An investigation adds `Summary`, `Timeline`, `Boundaries`, and `Response`
views inside Activity. Reuse the existing map and ledger rather than build a
second graph engine. Summary starts with the affected subjects, known effects,
unresolved questions, owner, and next required decision; not a threat score.

`Boundaries` groups the selected records by session/process, workload, node,
cluster, and remote service where those identities exist. Each transition
names the source, join fields, time, control owner, and result. A missing
source ends the proven path. A source-backed remote edge does not make a
local Runtime context edge into kernel causality.

The following outcome labels refine physical results without replacing them:

| Label | Required basis |
| --- | --- |
| Attempt recorded | A request or observation exists; completion is not established. |
| Prevented before effect | The owner's result contract and evidence establish that the specified effect did not occur. A deny decision alone is insufficient. Retain actor and kernel channels separately. |
| Process terminated | Termination is reported. The triggering effect may already have occurred or remain unknown. |
| External control denied | A provider, admission, or other control reports denial. Name that owner. |
| Effect recorded | An owner reports the effect. A local connection alone cannot establish a remote write. |
| Result unknown | Required result evidence is absent, stale, or contradictory. |

A declared agent task, approved environment, or approved target set appears
as context only when recorded. It is not inferred from a prompt or process
name. Compare declared scope with reported execution paths. Unsupported
Browser, API, SaaS, or MCP control remains unavailable, even in a case with
those activities. Treat tool descriptions and artifact text as untrusted
data. Do not execute links, render active HTML, or follow embedded directions.

For a credential-related action, use a redacted `Authority` card: principal
reference, issuer, granted scope, known consumers, expiry, revocation state,
and evidence source. Do not fetch token values or claim complete consumer
discovery. Separate configured permission from observed use. In this delivery,
fields without an inspected owner contract are synthetic or unavailable.

For a supported remote-action review, show tool/API identity and revision,
destination, safe argument summary, destructive effect, and required approval.
Hide secret values, not the target or effect that the operator must approve.
Changing any supported bound field invalidates approval. This is a display
contract for a future owner, not authority to add a connector now.

### Verify response, not just execution: R6

Response remains a local review within the investigation. Its table contains
exact target identity, proposed action, authority, shared impact, status,
postcondition, evidence source, and checked time. Keep requested, acknowledged,
effect recorded, verification pending, verified for stated scope, failed, and
unknown distinct. No source result means no success animation.

```text
Activity / incident-study / Response preview            Sample data
--------------------------------------------------------------------
Action                  Exact target       Result        Verification
Stop workload           pod UID A          Recorded      Replacement B seen
Revoke shared identity  principal ref C    Not supplied  Unknown consumers
Restrict execution      workload UID D     Rejected      Not verified
--------------------------------------------------------------------
Remaining exposure: replacement workload and unresolved identity
Case state: response incomplete
Save local review       Inspect evidence       Cancel
```

Each postcondition states its scope and interval. A deleted pod, a stopped
session, and a revoked credential are different effects. Preserve replacement
resources, surviving task references, delegated credentials, and unresolved
consumers where records show them. Absence of new alerts cannot establish
containment during an evidence gap.

Show a case-wide verified result only when every declared required target has
a supported postcondition result for the stated scope. A missing or stale
required check keeps the result incomplete. Even then, say `Verified for this
scope and interval`, not `All access removed`.

### Required deterministic research cases

Add these cases to existing sample data and journeys. Do not create a remote
test runner, a separate scenario framework, or exploit payloads.

| Case | Required distinction |
| --- | --- |
| Mixed-readiness workload | Policy accepted; one target cannot activate; a changed selector matches nothing. |
| Deployment and maintenance | Repeated startup events, a valid debug action, and an unobserved scheduled task do not become one malicious finding or an automatic allow rule. |
| In-process resource read | A denied read is inspectable without a new child process. Exact policy match and unresolved object remain separate. |
| Public incident study | Synthetic resource/authority transitions with known, contextual, and missing edges. External denials retain their owner. |
| Partial response | One target stops, a replacement remains, and credential verification is unavailable. The case stays incomplete. |
| Allowed external service | The connection is permitted; remote effect and task authorization are unknown. No invented API protection. |

## Visual system

Use a graphite navigation rail and a silver main work area. Reserve dark
surfaces for the evidence graph and code detail. Use compact tables, rules,
and selected rows. Do not copy the website's large marketing typography into
operational controls.

| Token | Light surface | Dark surface | Meaning |
| --- | --- | --- | --- |
| Canvas | `#F1F3EF` | `#0B100E` | Main background |
| Surface | `#FAFBF8` | `#151C19` | Detail and grouped content |
| Primary text | `#101512` | `#F1F3EF` | Main text |
| Secondary text | `#515D57` | `#A8B6B0` | Supporting text |
| Brand and focus | `#6D4D8D` | `#C39CDF` | Selection, focus, and Araphor detail |
| Denied | `#954735` | `#F2A08A` | Stopped operation |
| Verified | `#17654C` | `#63D0A0` | Verified result with supporting evidence |
| Warning | `#76520D` | `#E1B35A` | Gap, unknown, stale, or degraded state |
| Information | `#2B6075` | `#82BED6` | Neutral recorded information |

Use Source Sans 3 for body and controls, IBM Plex Sans Condensed for headings,
and IBM Plex Mono for IDs and code. Use the website fallback stack when fonts
are unavailable. Prefer local font assets with retained licenses if available;
do not require a public font service to use the console. Body text is 16 px,
table and control text is at least 14 px, and secondary metadata is at least
12 px. Long IDs wrap or disclose the full value.

Use 4 px spacing increments, square structural sections, 4 px control corners,
and one-pixel separators. A three-pixel violet rule marks selection; a denied
rule marks a stopped action. Do not reuse green for brand controls or add
glow, gradient, decorative shields, and large status-card grids.

Copy the inspected crown-and-fortress SVG into the console's tracked public
assets during implementation. Use a legible variant against the dark rail.
Retain the existing package path; no repository rename is needed.

## Responsive and accessible behavior

At 1280 px and above, use a labeled rail, inventory, and adjacent selected-item
detail where space permits. At tablet size, make detail a full-width route.
Below 768 px, use a labeled navigation menu and stacked subject rows. Keep the
same fields and decision steps; never remove Protect review or evidence limits
to fit the viewport.

The graph can scroll in its own region. The page cannot require horizontal
scroll. Offer the ledger beside the graph selector at every width. Preserve
filters and selection when moving between them.

Use native buttons, links, tables, form labels, and disclosure controls. Each
interactive target is at least 44 by 44 px. Result labels and edge styles
supplement color. Keyboard focus remains visible; close and Back restore focus
to the initiating control. Escape cancels a dialog without submitting it.
Announce form errors and completed local actions without moving focus.

Verify contrast for actual text/background pairs. Require at least 4.5:1 for
normal text and 3:1 for large text and essential control graphics. Check
keyboard use, 200% zoom, reduced motion, and accessible graph/ledger parity.
Automatic graph motion is off under reduced motion.

## Required failure and empty states

| State | Required screen behavior |
| --- | --- |
| No connected environment | Explain the missing connection and offer the sample environment. Do not show production counts. |
| No subjects or no search match | Distinguish an empty inventory from a filtered result. Offer Clear filters where applicable. |
| Loading | Retain route and filter context; disable dependent decisions. Do not show zero counts as measured facts. |
| Source unavailable or stale | Keep the last capture with its time and source. Mark current state unknown. |
| No permission | Explain which operation is unavailable without exposing other owners' data. |
| Draft conflict | Keep the local draft and require review against the newer source revision. |
| Activation incomplete | Show each target and last active revision. Do not promote the entire set to Protected. |
| Evidence missing | Show the decision that is known and the result that is not known. |
| Unknown route or revision | Show Not found or Revision unavailable. Do not substitute a different subject or current graph. |
| Retry or cleanup failure | Keep earlier attempts and diagnostics. A later pass does not remove the failure. |

These states use deterministic samples in this delivery. Their presence in
the fixture does not claim that a connected production implementation exists.
