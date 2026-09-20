# Phase 2: Policy Review And Activation

This phase turns Observe, Suggest, and Protect into an exact review workflow.
It removes the implication that a local button press proves enforcement.

## Intended end state

The operator can review a proposed rule with its evidence, save a local draft,
confirm an exact preview, and inspect partial target activation. Runtime and
workload policies retain their separate source contracts.

## Implementation flow

```text
Operator opens a suggestion from Protection
  -> Policies selects the same subject and shared draft
  -> the review shows recorded actions, time window, and coverage limits
  -> the operator edits or selects supported rules
  -> Save local draft stores only the reviewed local state

Operator selects Preview protection
  -> the view validates fields for the selected policy source family
  -> the confirmation names the draft revision and exact target snapshot
  -> Confirm preview starts the selected deterministic sample transition
  -> only a matching target acknowledgement changes its activation display

Target rejects the draft or its acknowledgement is missing
  -> the view keeps the last active revision
  -> the aggregate remains partial or unknown
  -> retry requires a refreshed target snapshot and a new confirmation

Operator requests an exception for an incorrect stop
  -> the review selects an existing compatible grant and exact target
  -> the review checks duration and remaining use bounds
  -> Save local request leaves the denied action unchanged
  -> expiry or a source change invalidates the pending confirmation
```

## Scope, owners, and changes

Update the existing Operations and Policies view owners, their shared sample
state, and the affected tests. Reuse the current inline editing and explicit
removal confirmation. Add source-family distinctions to the local view model;
do not implement a universal rule language or client-side policy compiler.

Use `WorkloadProtectionPolicySpec`, `PolicyRolloutStatusV1`, and the exact
candidate/acknowledgement fields for workload samples. Use the existing
Runtime policy package and policy-set contract for Runtime examples. Keep
entry admission separate from a role's execution permissions.

## Acceptance

- Accepting a suggestion changes a draft only. Coverage gaps and missing
  observations remain visible. No confidence percentage is invented.
- A changed rule or target invalidates a previous confirmation.
- Protection and Policies show the same local draft during navigation.
- A three-target sample can show Active, Staged, and Rejected together.
  Neither a click nor elapsed time changes all targets to Protected.
- A late acknowledgement for a prior candidate cannot complete a retry.
- Existing active policy remains distinct from desired policy after rejection
  or source loss. The UI does not silently switch to Observe.
- An exception cannot change the base policy, omit its use or time bound,
  use an undeclared grant, or claim active access from a saved request.
- Every local action is labeled as local or sample at the decision point.
- Research R2: Review shows application revision, observation interval,
  lifecycle cases, excluded suspect observations, and missing evidence.
  Exclusion from a suggestion does not delete the source record.
- A deterministic impact preview names the changed recorded actions and its
  limits. An unsupported evaluation says Impact unavailable, not No impact.
- Target changes and zero selector matches prevent stale confirmation. No
  observation timer automatically promotes a proposal to Protect.
- A missing maintenance observation requires visible review of the limit;
  the UI cannot claim that all valid behavior has been tested.
- Alert acknowledgement, unavailable notification suppression, bounded
  exception review, and policy changes remain separate operations.

## Verification

Run all four UI commands in the parent plan. Extend the existing protection,
policy-edit, suggestion, and incorrect-stop browser journeys. Add a small
pure-state test for partial activation and a stale acknowledgement. Test
confirmation with keyboard input and at 375 px width.

## Exclusions and stop point

No policy compilation, signature, CRD mutation, exception activation, live
approval, or recovery change is in scope. Review the complete local policy
journey and recorded result before the next phase.

## Result

Result: **Not done**.
Changed owners: None.
Verification: Not run; this file is a proposed implementation plan.
Remaining work: All implementation and acceptance items above.
Next phase: Not authorized by this result.
