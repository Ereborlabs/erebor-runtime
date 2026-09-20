# Phase 4: Verification And Acceptance

This phase replaces the old sample release score with inspectable
qualification records. It completes System detail and verifies the full
Araphor console journey against the new screen contracts.

## Intended end state

An evaluator can identify the behavior, source revision, platform, and proof
behind a recorded check. An operator can inspect environment readiness
without confusing a service connection with active enforcement. The full
console works at desktop, tablet, and mobile sizes.

## Implementation flow

```text
Evaluator selects a behavior in Evidence > Verification
  -> the view selects a recorded source revision and platform
  -> each cell shows its actual test applicability and recorded result
  -> the detail shows test identity, lifecycle, attempts, and artifact source
  -> a missing record remains Not run or Evidence unavailable

Evaluator compares a later run
  -> the view retains the earlier attempt and its diagnostics
  -> a changed source or environment creates a separate comparison
  -> an incompatible record cannot qualify the selected source or platform

Operator opens an environment in System
  -> the view shows its reported owners, capabilities, and last contact
  -> an unavailable owner shows its last known state and missing current data
  -> local enforcement and evidence connection remain separate facts

Operator finishes a sample journey
  -> the test records the visible result and underlying sample state
  -> Reset sample removes the local edits and selections
  -> the retained test result records the exact UI source revision
```

## Scope, owners, and changes

Replace the old Release view with Evidence > Verification. Reuse the current
console's node and evidence-source detail for System. Keep its initial inputs
as checked local records next to the existing fixture data. Do not build an
artifact upload service or a parser for the TODO document.

Each checked verification record needs behavior ID, exact test name, platform,
test type, lifecycle when applicable, source revision, run/attempt identity,
recorded time, result, and evidence references. Include kernel, architecture,
runtime, image, and cluster versions only when the source supplies them.
Missing manifest fields remain unknown; the console cannot invent them.

A record derived only from a documentation entry must say `Recorded in
documentation`. It cannot use the stronger `Artifact verified` label. A checked
artifact needs retained provenance and an explicit mapping to its source
schema. Stop that mapping if the schema is absent or incompatible; keep the
raw source reference and the unsupported state.

Update the console README and implementation review guide after the UI is
implemented. Record the actual source owners, commands, screenshots, limits,
and remaining connected-backend work. Preserve the prior UX audit as history;
add current evidence without replacing its original findings.

## Acceptance

- Host, direct-runc, and Kubernetes results remain separate. A platform not
  declared by the scenario cannot inherit a pass from another platform.
- Ordinary lightweight tests, privileged physical tests, and UI tests retain
  their distinct proof limits. Ignored and unrun tests do not count as passes.
- The matrix keeps a failed first attempt and a successful retry. Cleanup
  failure remains visible even when the security assertion passed.
- The BPF map example at `787c0323` has no qualified Kubernetes result.
- A result for `50910f48` cannot qualify a later revision. The older aggregate
  counts cannot replace a current result set or a capability record.
- A current deployment is never labeled Protected from a qualification pass.
- System shows identity, last contact, and readiness reasons per owner. A
  missing connection does not imply that a previously installed deny stopped
  working or that it is still currently verified.
- Product labels say Araphor. Existing CLI, API-group, and source identifiers
  remain exact in technical details.
- Every workspace supports loading, empty, unavailable, and invalid-selection
  states. A sample change cannot leak into a recorded capture.
- The complete journey works by keyboard and at 1440, 768, and 375 px widths,
  with a 320 px overflow check, 200% zoom, and reduced motion.
- Normal text and control contrast meets the interface specification. Axe
  reports no serious or critical violations. Manual keyboard and focus checks
  supplement that automated result.
- Research R7: System reuses the Protection coverage detail. Node image or
  source drift cannot silently retain a compatibility claim from older data.
- Evidence loss remains separate from enforcement readiness. A quiet stream
  and a successful reconnect cannot close an earlier unknown interval.
- All six research cases in the interface specification have deterministic
  journey checks. None depends on a cloud account or a live exploit.
- The five operator tasks in the research record have an acceptance record.
  State whether a person or only an automated check performed each task.
  Do not claim a user study or usability improvement from browser tests.

## Verification

Run from `ui/mithril-console` after the final UI edit:

```sh
npm run check
npm test
npm run build
npm run test:e2e
```

Add one pure qualification-status test that rejects source/platform mismatch
and absent evidence. Extend the browser suite through Protection, suggestion
review, partial activation, action detail, evidence, and Verification. Include
an agent-session path and a workload path. Retain screenshots for Protection,
policy confirmation, denied-action detail, replay/ledger, and Verification.

Extend those journeys with the research cases; do not add a parallel test
framework. Add focused assertions for zero targets, impact unavailable,
acknowledgement without policy change, and incomplete response verification.
For manual operator review, record task completion, incorrect conclusions,
backtracking, and time to evidence. Leave participant validation Not done
until a person performs the tasks.

Record the exact commit and any uncommitted UI diff covered by the run. Record
each command and result. A browser check proves the UI behavior only; it does
not replace `mithril-e2e` physical evidence or close the backend master plan.

## Exclusions and stop point

No remote test execution, cluster deployment, release certification, public
API, or backend migration is in scope. The completed result is the redesigned
interactive fixture. Live integration requires the separate contracts named
in the parent plan.

## Result

Result: **Not done**.
Changed owners: None.
Verification: Not run; this file is a proposed implementation plan.
Remaining work: All implementation and acceptance items above.
Next phase: None in this plan; live integration is not authorized by this result.
