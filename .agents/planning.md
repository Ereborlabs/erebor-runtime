# Planning Rules

## Purpose

A plan turns an approved outcome into executable work. It states the problem,
the target behavior, the owner of each change, the proof, and the stop point.
It is not a feature wish list, a history of exploration, or permission to do
later work.

Write for engineers who will implement and review the work. Use exact owners,
behavior, inputs, outputs, limits, commands, examples, and proof. Remove
management-report language, generic strategy statements, boilerplate lists,
and filler. A short concrete example is better than an abstract summary.

## Planning Hierarchy

Use the smallest level that can own the decision. Do not create a new level
only to repeat its parent.

1. **Product or architecture record**: Defines a durable product boundary,
   problem, principles, alternatives, and decisions. It does not authorize
   implementation by itself.
2. **Master plan**: Owns one approved body of work. It defines the goal,
   constraints, baseline, target ownership, implementation increments,
   verification model, and stop points.
3. **Phase**: Owns one independently reviewable change. It
   names purpose, scope, owners, changes, acceptance, verification, exclusions,
   and the next approval boundary.
4. **Expanded phase**: When a phase needs its own ordered phases, make a
   directory with the exact phase name. For example, `phase-N-name` becomes
   `phase-N-name/README.md`. The README is the nested plan for that parent
   phase and owns its child phases, verification, and stop points. A phase is
   either a leaf file or an expanded directory; do not keep both forms. Do not
   make a generic sibling `subplan/` directory.
5. **Recursion**: A child phase extends its parent identifier. For example,
   children of `phase-2-name` use `phase-2-1-name` and `phase-2-2-name`.
   An expanded child uses its full identifier as its directory name and
   contains its own `README.md` and child phases.
6. **Phase result**: Lives with the phase. It records what changed,
   what proof ran, what remains, and `Done`, `Not done`, or `Blocked`.
7. **Supporting evidence**: A design, decision record, lifecycle probe, manual
   acceptance record, fixture catalogue, runbook, or review guide supports its
   parent plan or phase. It must not silently become a second plan.

```text
master-plan/
  README.md
  phase-1-small-change.md
  phase-2-large-change/
    README.md
    phase-2-1-first-child.md
    phase-2-2-large-child/
      README.md
      phase-2-2-1-grandchild.md
```

## Start With Facts

- State the user outcome, the current behavior, the boundary that must remain
  true, and what is out of scope.
- For shared-component work, identify every product that consumes the component
  and state its exclusive owner, policy authority, and proof responsibility.
- Separate verified facts, assumptions, open questions, and deferred work.
  Resolve a material uncertainty before the phase that depends on it.
- Name exact owners, files, modules, symbols, commands, and behavior contracts.
  Keep historical facts only when they explain an active decision, compatibility
  break, or follow-up risk.

## Choose The Smallest Useful Shape

- A small, independent change can use a short ordered checklist with an
  acceptance test.
- Non-trivial work needs a master document with status, goal, constraints,
  baseline, target ownership, phases, verification, and explicit stop points.
- Give each non-trivial phase its own purpose, scope, owners, changes,
  acceptance criteria, verification, and result. Add a lifecycle or live probe
  when unit tests cannot prove runtime behavior.
- Each phase must be independently reviewable and executable. Do not combine
  unrelated owners or future work only to reduce the number of phase files.

## Preserve Boundaries

- A plan does not add a second durable owner for policy, protocol, lifecycle,
  recovery, evidence, or physical effect without an explicit decision.
- A simplification must name what durable owner, listener, protocol, or runtime
  model it removes; the owner that remains; the invariants that remain true;
  and the code-backed proof. A rename, code move, hardening change, or new
  feature is not simplification.
- Do not merge control, enforcement, authentication, lifecycle, recovery,
  evidence, or physical-effect boundaries merely to reduce process or type
  count. Correctness decides the shape.

## Execute And Record Truthfully

- Implement only the approved phase. A completed phase does not approve the
  next phase or an architecture change.
- Keep the plan current as work changes. Preserve link-stable paths, but update
  stale instructions so later work cannot follow an obsolete path.
- A phase result records changed owners, completed and remaining work, exact
  verification evidence, and `Done`, `Not done`, or `Blocked`.
- A plan may require verification without claiming it passed. Record a pass
  only after running that check for the current work. If blocked, record the
  exact command and error.
- Write plans, phase results, runbooks, and planning notes in **ASD-STE100**.
