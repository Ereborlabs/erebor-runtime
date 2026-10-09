# Phase 7.5.7: Package Qualification

Prove installation of new algorithms and detectors through production owners.
Keep detection, correlation, and prevention claims separate. Parent:
[7.5](README.md). Require 7.5.1–7.5.5, plus 7.5.6 if Python is advertised.

## Intended end state

An operator can install, inspect, run, and update a new detector without an
Araphor rebuild or a new probe when its inputs exist. Reusable algorithms work
through the same package interface. Recorded results show exact inputs, selected
implementation, evidence, coverage, state, and notification outcomes.

## Implementation flow

```text
The Rust qualification runner starts the production package and data owners
  -> the runner installs fixture packages under explicit test grants
  -> authenticated evidence intake supplies the selected cases
  -> production extraction, execution, validation, and commit owners process them
  -> the runner checks expected results, revisions, state, and cleanup

The runner injects late data, loss, restart, or an execution failure
  -> production owners preserve the retry and coverage contracts
  -> the runner checks replacements and rejects unsupported causal conclusions

The lightweight incident case passes
  -> the paired physical harness runs the same qualified case
  -> the harness checks the physical effect and retained evidence
  -> a mismatch becomes a lightweight regression before implementation changes
```

## Scope and owners

Keep lightweight cases in `crates/mithril-e2e/src` and their command entry points
in `src/bin`. Use production APIs. Test doubles supply only external inputs.
Keep physical harnesses and fixtures in their existing directories. Add no long
shell test program, external source-tree edit, or linked worktree.

Verify every current `AR-*` algorithm migrated in 7.5.4. Use the production
packages and contract fixtures delivered by 7.5.3 through 7.5.5. This phase
adds integrated proof and regression cases; it does not first implement an
algorithm required by its own entry gate. Full Discovery Engine development
belongs to [7.5.8](phase-7-5-8-discovery-engine-algorithms.md); full Security
Analytics algorithm development belongs to [7.5.9](phase-7-5-9-security-analytics-algorithms.md).
Neither upstream phase is a prerequisite for this runtime qualification.

| Case | Required proof |
| --- | --- |
| Install a detector | A new file or folder adds a detector over existing evidence. CLI and agent inspection show the same descriptor. Invalid grants and missing inputs remain visible. |
| Reuse an algorithm | The migrated behavior-atom result feeds display grouping and baseline comparison. Verify named dependencies, bounded output, and reuse of one committed dataset. Full path-tree development is in 7.5.8. |
| Correlate evidence | Use the migrated HF-DW-001 credential and local-channel cases. Include unrelated identities, wrong node lifetimes, late input, and missing proof. Full Security Analytics joins are developed in 7.5.9. |
| General computation | Exercise graph traversal, multiple inputs, variable output counts, and a native dependency. Record exactly which upstream algorithms are covered; do not claim whole-product parity. |
| Switch execution targets | The same Rust source passes Wasm/native output, evidence, checkpoint, cancellation, and replay fixtures. Python parity applies only if advertised. No silent failure fallback. |
| Recover and update | Interrupt before and after commit. Check identical receipts, changed-retry rejection, state/output agreement, empty replacements, failed upgrade, rollback, and expired rebuild input. |
| Enforce isolation | Reject undeclared reads and external effects. Check malformed outputs, resource exhaustion, grant revocation, worker crash, and cleanup with real execution adapters. |
| Preserve mandatory detection | Disable optional discovery, fail a required package, and restore it. Check protected progress, coverage, retention, notifications, and unchanged human deadlines. |
| Hugging Face incident | Run the existing incident fixtures through the installed detector. Map each claimed observation and pre-effect guard to its acceptance case. Assert physical prevention only where the enforcement owner blocks the action before its effect. |

The existing physical record proves a protected file-open denial and a benign
read through the kernel, Node, Control, graph, and notification path. It does not
prove every Hugging Face attack step, all in-process actions, or cross-node
prevention. Retain those limits. New algorithm support cannot supply missing
sensors, identity bindings, policy, or enforcement paths.

## Acceptance and verification

Add `analysis-packages` to the existing `mithril_discovery_test` runner. Run it
and `graph-notification`, then the paired physical incident case. Record source,
commands, nonzero assertions, package revisions, selected targets, result paths,
coverage, effects, and cleanup. Run the shared Rust procedure after the final
source or test edit. Update each child result with exact proof and limits.

Performance is **UNQUALIFIED**. Before adding benchmarks, obtain separate
approval for the workload, runtime, and pass/fail limits. Include compilation,
startup, batch copies, state commits, and memory when that work is approved.
Do not label native or Wasm faster from correctness tests.

## Exclusions and stop point

No new incident fixture ID, policy publication, automatic response, provider
binding, or cross-node physical claim. Those remain with the later owners.
Close the core package scope only after every required child and this matrix
pass. Optional Python can remain Not done if the release does not advertise it.
This closes the package runtime and current migration scope only. Completion of
7.5 also requires the upstream algorithm phases and their coverage inventories.

## Result

**Not done.** All package, target-parity, and incident checks here are required
future evidence. Earlier graph qualification does not satisfy them.

## End scope and example

Complete when the current migration, package lifecycle, SQL/Wasm/native targets,
and paired incident case pass through production owners. Include Python only
if advertised. This qualifies the platform for new algorithm packages. Full
Discovery Engine and Security Analytics coverage remains in 7.5.8 and 7.5.9.

Example at completion: interrupt a migrated detector after it computes output
but before commit. Restart leaves neither a partial finding nor an advanced
checkpoint. Retry commits one complete result. Another identical retry returns
that receipt, and required notification processing resumes without resetting
the human deadline. The physical incident pair verifies its existing guard.
