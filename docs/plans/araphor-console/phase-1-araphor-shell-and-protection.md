# Phase 1: Araphor Shell And Protection

This phase gives the console its Araphor identity and makes agent sessions
and workloads visible in one protection workflow.

## Intended end state

The operator can open Protection, select an environment, filter agent
sessions or workloads, and inspect the selected subject without losing scope.
The interface uses the website's visual system and labels sample data.

## Implementation flow

```text
Operator opens a new or existing console link
  -> App parses the route and validates its selected IDs
  -> ConsoleShell renders the Araphor brand and five workspace links
  -> Protection projects subjects from the selected sample environment
  -> a subject selection opens its identity, surfaces, policy, and evidence

Operator changes environment or navigates Back
  -> App restores the matching filter and subject selection
  -> an invalid selection clears with an explanation
  -> sample drafts remain in one App-owned state value

Source is empty, unavailable, or unauthorized
  -> the view renders its explicit state and available next action
  -> no source absence is converted to a protected or healthy result
```

## Scope, owners, and changes

Start after Discovery 1 freezes the shared records, as specified in the
[combined order](../araphor-discovery-engine/README.md#combined-implementation-order).
This fixture work can run alongside backend work. It does not require live
findings or public APIs. Complete console phases 1–4 before Discovery 5 wires
these screens to production owners.

- Update `ui/mithril-console/src/Console.tsx`, `src/App.tsx`,
  `src/consoleData.ts`, `src/styles.css`, and `index.html`.
- Copy the inspected website mark to tracked console public assets. Apply
  the tokens and typography in [interface-design.md](interface-design.md).
- Use Araphor for product text and accessible names. Retain technical source
  identifiers where the detail refers to the actual backend contract.
- Replace the top-level canned Agent workspace with real session concepts.
  Move its useful explanatory text into contextual help.
- Keep sample data in ordinary typed records. Use one shared App-owned value
  for sample state that must survive navigation. Do not add a store framework.
- Keep subject kind, environment, execution surface, lifecycle, activation,
  and evidence health separate. Split a view module only when its screen
  responsibility needs a clear owner.

## Acceptance

- Agent sessions and workloads can appear in the same selected environment.
  They retain separate identities and counts.
- A session with no agent association says Not attributed. A surface name
  does not produce a Protected badge.
- The attention list derives its counts and links from the displayed data.
- Sample data, source time, and connection state remain visible on detail
  routes and mobile screens.
- Existing session links still open the named sample. Invalid routes cannot
  open an unrelated incident.
- The new home view is reviewable at desktop, tablet, and mobile sizes.
  Keyboard access and readable text remain intact.
- Research R1, R3, and R8: Coverage detail explains an unready target and zero
  selector matches. Per-surface state cannot inherit a workload summary.
- The attention list preserves raw record access, review state, and an
  unassigned owner. Acknowledgement cannot change policy or evidence.
- Declared task scope and external baseline controls retain their source.
  Missing input says Not reported; it does not become a protection claim.

Use the [research-driven journeys](interface-design.md#research-driven-operator-journeys)
for fields and deterministic cases. New application metadata is explicitly
sample data, not an extension to a production protocol.

## Verification

From `ui/mithril-console`, run `npm run check`, `npm test`, `npm run build`,
and `npm run test:e2e`. Update the existing navigation and responsive tests.
Add one focused route/state regression for invalid IDs and Back restoration.
Retain screenshots of Protection and an agent-session detail at 1440, 768,
and 375 px widths. Do not claim the earlier UX audit as current proof.

## Exclusions and stop point

No policy submission, live connection, backend rename, new agent daemon, or
test execution is in scope. Review this rendered visual direction before the
next phase extends it to the policy and investigation screens.

## Result

Result: **Not done**.
Changed owners: None.
Verification: Not run; this file is a proposed implementation plan.
Remaining work: All implementation and acceptance items above.
Next phase: Not authorized by this result.
