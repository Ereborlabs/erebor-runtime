# Phase 3: Activity And Evidence

This phase connects an observed action to its decision, physical result,
attribution, and source evidence. It retains the useful causal replay while
making individual actions usable without a complete incident graph.

## Intended end state

An investigator can move from a protected subject to an action and its
supporting records. The interface keeps actor, kernel, and transport results
separate. A source-backed relationship remains distinct from a contextual
join or a hypothetical continuation.

## Implementation flow

```text
Investigator opens an action from a subject
  -> Activity selects the exact action in the current environment
  -> the detail shows actor, operation, target, decision, and reason
  -> result fields retain their source and unknown values
  -> Inspect evidence opens the matching record and coverage interval

Investigator opens a session or incident graph
  -> App restores its graph kind, revision, event, selection, and view
  -> graph.ts projects only the selected source graph
  -> the map and ledger share the same cursor and selected operation
  -> an edge inspector shows the source join fields

Investigator enables a hypothetical continuation
  -> the view draws separate hypothetical nodes
  -> recorded graph edges, counts, and evidence remain unchanged
  -> closing the continuation removes only the local view state

Evidence is incomplete or the selected revision is unavailable
  -> the detail states the missing source or interval
  -> no absent action is presented as a verified prevented continuation
  -> a reload cannot substitute a newer graph revision silently

Investigator reviews response
  -> the selected investigation supplies exact targets and source revision
  -> the local preview shows shared impact, expiry, and postcondition
  -> cancellation removes the preview without changing the evidence
```

## Scope, owners, and changes

Update `src/App.tsx`, the Activity and Evidence view owners in the console,
`src/data.ts`, and related tests. Reuse `src/graph.ts` and its existing tests.
Keep the graph layout pure. Separate result dimensions in typed sample data
without introducing a new backend event schema.

Use `KernelEffectEvidenceV1` and `ObservationEnvelopeV1` for kernel record
examples. Use the Runtime `SessionRecord` and context graph contract for
session and context examples. Do not convert one graph family into the other.
Fields available only in test artifacts belong in Verification detail or
diagnostics, not in every live-event contract.

## Acceptance

- Namespace denial shows actor `EPERM` and kernel `-EACCES` with labels.
- An actor success with transport exit code 1 does not become a policy deny.
- `UNRESOLVED_OBJECT`, `UNSUPPORTED_OBJECT`, and `EXACT_POLICY_DENY` retain
  their distinct reasons. A missing exact object stays absent.
- Process-control detail names the exact controller and target where supplied.
  A leader's exit does not imply that all process threads or the session ended.
- An action without an attributed agent or incident remains inspectable.
- Runtime context, direct causal evidence, contextual joins, and hypothetical
  nodes have distinct labels and source contracts.
- Replay reload and Back restore revision, event, selected operation, machine
  focus, and map/ledger view. Invalid values fail visibly.
- An evidence gap cannot become a `no later action` conclusion. A reconnect
  preserves earlier gaps and source epochs.
- Incorrect-stop and response previews cannot mutate recorded evidence or
  change the denied result.
- Research R3 through R6 and R8: A repeated-event group retains each target,
  result, and source record. Deployment context does not dismiss a denial.
- A denied in-process read is visible without a process-spawn alert. Process
  termination alone cannot produce Prevented before effect.
- Public incident studies are labeled synthetic reconstructions. Their
  boundary views do not imply that Araphor observed the real incident.
- External denials name the actual control owner. A permitted connection
  without provider evidence leaves a remote effect unknown.
- Authority detail contains references and scope, not credentials. Unknown
  consumers and unsupported tool/API fields remain visibly unavailable.
- Partial response, replacement resources, and missing credential checks
  prevent a case-wide verified result. Verification retains scope and time.
- Tool descriptions and source artifact content render as untrusted text.
  They cannot execute UI actions or hide the reviewed target and effect.

## Verification

Run all four UI commands in the parent plan. Preserve the graph projection,
counterfactual-isolation, edge-inspection, and map/ledger browser checks.
Add focused result-mapping checks for the two distinct result-channel cases
above. Add reload and Back coverage to the existing replay journey.
Check action detail, edge inspection, and response preview with keyboard input
and on a 375 px viewport.

## Exclusions and stop point

No graph-construction service, AI attribution inference, provider connector,
live response, or exception authority is in scope. Review the complete
subject-to-evidence journey before the next phase.

## Result

Result: **Not done**.
Changed owners: None.
Verification: Not run; this file is a proposed implementation plan.
Remaining work: All implementation and acceptance items above.
Next phase: Not authorized by this result.
