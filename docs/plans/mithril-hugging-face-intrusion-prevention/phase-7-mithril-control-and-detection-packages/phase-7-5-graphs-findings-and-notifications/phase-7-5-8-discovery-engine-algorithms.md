# Phase 7.5.8: Discovery Engine Algorithm Packages

Implement all analysis algorithms from the pinned local Discovery Engine source
as SDK packages. Parent: [7.5](README.md). Require the package runtime and current
algorithm migration to pass 7.5.7. Use the source inventory established in 7.5.2.

## Intended end state

Operators install packages for system and network behavior discovery, path
aggregation, candidate merging, summaries, insights, and recommendations. Each
algorithm consumes typed authorized inputs and returns queryable results with
evidence and limits. The [Discovery Engine inventory](algorithm-coverage.md#discovery-engine-algorithms)
has an implementation and verification result for every source algorithm and
variant. No Araphor rebuild is required to install a completed package.

## Implementation flow

```text
An implementer checks the pinned source against the contract inventory
  -> the inventory confirms each algorithm, helper, variant, and delegated computation
  -> the implementer completes each package against its declared SDK interface
  -> reference fixtures record expected behavior and intentional security differences

An operator installs a discovery package
  -> AnalysisPackageOwner validates its exports, dependencies, and input requirements
  -> the host supplies authorized evidence, workload context, and pinned template data
  -> the selected SQL, Wasm, or native implementation computes the result
  -> DiscoveryOwner validates attribution, coverage, and candidate limits
  -> AnalysisStore commits the datasets and checkpoints through the existing path

Evidence or workload context changes
  -> the package owner selects the affected input revisions
  -> the algorithm replaces affected summaries and candidates
  -> missing coverage produces Unknown for conclusions that require complete input

A package fails or lacks an input
  -> the host retains its last complete commit and reports the exact failure or missing field
  -> the result cannot become an approved or active policy
```

## Scope and owners

The SDK packages own computation. Existing data owners own extraction, trusted
identity, result validation, and storage. Control retains policy authority.
The inventory owns detailed source mappings; do not copy its checklist here.

Implement its families in this order:

1. `DE-01`, `DE-02`, and `DE-05`: system process/file/protocol discovery, file
   path trees, source constraints, and candidate deduplication and merging.
2. `DE-03`, `DE-04`, and network parts of `DE-05`: source/destination grouping,
   label aggregation, ingress/egress, DNS/FQDN/CIDR, services, ports, protocols,
   entities, and HTTP method/path aggregation.
3. `DE-06`: process, file, and network summaries and workload insights.
4. `DE-07`: pinned-template hardening recommendations, admission conditions,
   and service-account token-use analysis.
5. `DE-08`: recorded-log analysis and semantic candidate conversion for the
   upstream policy forms. Preserve fields or report explicit conversion loss.

Represent generic policy candidates as analysis outputs. Repetition, path
aggregation, or matching labels cannot grant authority. Identify generalized
selectors and the authority they could add. Exact policy permission comparison
and preview belong to 7.6. Incomplete observations cannot prove that a
service-account token is unused. Do not copy assumptions that one observed pod
proves behavior for every pod in a workload.

Use existing shared algorithms when their semantics match. Compile one Rust
implementation for qualified Wasm and native targets. Use SQL for computations
that fit the existing evaluator. Keep host adapters and package functions small.
Do not create a second discovery engine, scheduler, store, or collector.
Required algorithms must work with SQL or compiled targets. Python is optional
and cannot become an undeclared prerequisite for completing this inventory.

## Acceptance and verification

- Verify and complete implementation mappings for the source inventory from
  7.5.2. Trace helpers, converters, and database queries as well as named entry
  points. A newly found interface gap requires a contract update and affected
  runtime checks before the dependent package can pass.
- Map upstream tests and deterministic reference fixtures to package tests.
  Include thresholds, recursive paths, label combinations, same-name workloads,
  DNS and service changes, empty input, duplicates, and contradictory evidence.
- Test candidate broadening, from-source constraints, incremental overlap and
  replacement, template preconditions, and missing token-use coverage.
- Extend `mithril_discovery_test` with `discovery-engine-algorithms`. Install the
  packages and call production owners. Verify queries, state, quotas, retries,
  restart, late data, and each advertised execution target. Reference binaries
  are development tools; runtime installation must not require Go or Kubernetes.
- Record computation coverage separately from live evidence availability and
  policy activation. Every algorithm needs positive execution proof even when
  a deployment lacks its live inputs. Rerun shared package cases and the final
  Rust procedure after relevant source changes.

## Exclusions and stop point

Policy preview belongs to 7.6 and approval/publication to 7.8. Candidate
generation and export here do not apply KubeArmor, Cilium, Kubernetes, or Kyverno
policy. Source acquisition and live network calls stay with existing authorized
owners. Do not edit or embed the upstream checkout as a separate service.

Stop when every in-scope Discovery Engine algorithm has a working package and
the inventory's coverage gate passes. An omitted algorithm keeps this phase
Not done. Unsupported deployment inputs remain visible and do not count as
algorithm implementation. No benchmark runs without separate workload approval.

## Result

**Not done.** Source families and the implementation owner are recorded. The
complete function/variant audit, package development, and qualification remain.

## End scope and example

Complete when every pinned Discovery Engine analysis algorithm and variant has
an installed package implementation and passing semantic, replay, and failure
checks. Its candidates and summaries are queryable. Deployment input readiness
is reported separately. These outputs do not depend on 7.6 preview being built
and cannot activate policy.

Example at completion: an authorized fixture records `frontend` connecting to
`database` on TCP port `5432`, with qualified workload identities and service
context. Installed packages produce a connection summary and reviewable network
policy candidate with the source evidence. A change in service identity replaces
the affected result. No policy is applied. A later preview rejects any candidate
operation that its policy owner does not support.
