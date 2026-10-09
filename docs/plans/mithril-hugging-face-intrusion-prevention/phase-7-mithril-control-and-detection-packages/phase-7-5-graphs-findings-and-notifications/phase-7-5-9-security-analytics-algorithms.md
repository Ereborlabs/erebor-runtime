# Phase 7.5.9: Security Analytics Algorithm Packages

Implement all analysis algorithms from the pinned local OpenSearch Security
Analytics source as SDK packages. Parent: [7.5](README.md). Require 7.5.7 and use
the source inventory from 7.5.2. This phase has no algorithm dependency on 7.5.8.

## Intended end state

Operators install rule, correlation, aggregate, and threat-indicator packages
without an OpenSearch cluster or a JVM. The
[Security Analytics inventory](algorithm-coverage.md#security-analytics-algorithms)
maps every source algorithm, supported variant, and bundled rule to an explicit
implementation or remaining gap. All algorithm entries must pass before closure.
Findings retain exact evidence, input requirements, and coverage.

## Implementation flow

```text
An implementer checks the pinned detection paths against the contract inventory
  -> the inventory confirms rule semantics, helper functions, and delegated operations
  -> reference fixtures fix expected values, ordering, timing, and numeric behavior
  -> the package implementation maps each operation to existing SQL or SDK code

An operator installs a rule or algorithm package
  -> admission checks its format, field mappings, dependencies, and required data
  -> the host supplies authorized evidence and pinned rule or indicator data
  -> the package evaluates conditions, aggregates, correlations, or indicator matches
  -> GraphAndFindingOwner validates finding evidence and proof limits
  -> AnalysisStore commits result datasets, findings, and next checkpoints
  -> NotificationRouter applies mandatory delivery and acknowledgement rules

A source window, rule revision, or indicator snapshot changes
  -> the package owner evaluates the affected dependency revisions
  -> the result replaces superseded contributions under the existing replay contract

A rule needs missing fields or an unsupported semantic operation
  -> admission or evaluation reports the exact rule and missing requirement
  -> incomplete input does not produce a clean negative result
  -> an unimplemented required operation remains an open implementation item
```

## Scope and owners

Use one SDK and package loader. A Sigma importer can translate the pinned
source's supported rule semantics into admitted SQL or reusable compiled
operators. It does not introduce another authoring requirement for general
algorithms. Do not split a rule's calculation between SQL and unrelated manifest
fields. Reuse mature parsers and libraries that satisfy the contract.

Implement these inventory families:

1. `SA-01`: conditions, selectors, value and field matching, every registered
   modifier, and built-in/custom log-field mappings.
2. `SA-02`: time windows, grouping, thresholds, count, average, min/max, sum,
   terms, and median absolute deviation. Check source count and null semantics;
   SQL `COUNT(*)` is not a substitute for every upstream value-count operation.
3. `SA-03` and `SA-04`: explicit finding joins, filters, correlation triggers,
   and automatic ATT&CK-tag and intrusion-set correlation.
4. `SA-05`: source correlation vectors, orphan handling, nearest-neighbor
   queries, filtering, and scoring/ranking. Keep these numeric operations in
   packages under current storage limits; add no external vector service.
5. `SA-06`: supported feed parsing and schema extraction, indicator types and
   matching, finding construction, and threat-intelligence trigger conditions.
6. `SA-07`: detector/rule composition and delegated monitor decision semantics.
   Package the pinned built-in rules with source metadata and input requirements.

Host input adapters retain authorization and field provenance. Package code has
no live feed or cluster credentials. Supply pinned feed snapshots through the
authorized input path. Existing owners retain durable state and delivery.
Required algorithms must work with SQL or compiled targets. Optional Python
support cannot become an undeclared dependency of this phase.
Similarity, shared tags, time proximity, and indicator matches remain distinct
from causal proof. Retain these result types when joining them to the graph.

## Acceptance and verification

- Verify the algorithm, operator, and variant inventory established in 7.5.2.
  Trace behavior delegated to OpenSearch, Lucene, and Alerting. Record a tested
  local semantic equivalent. A newly found interface gap requires a contract
  update and affected runtime checks before the dependent package can pass.
- Use a corpus report for all tracked rule files and rule IDs. Require parse,
  mapping, and supported-semantic checks for each applicable rule, with positive
  and negative fixtures for each operator and algorithm. Do not replace the
  source corpus with a few demonstration rules or claim coverage from parse alone.
- Check missing/null/multivalue fields, regex and encoding behavior, group counts,
  numeric precision, boundary timestamps, late data, and empty replacements.
  For approximate search, define and test the correctness tolerance and tie
  behavior; do not promise byte-identical rankings without proof.
- Include automatic and explicit correlation, filter counterexamples, orphan
  findings, indicator type collisions, changed feeds, and trigger decisions.
- Add `security-analytics-algorithms` to `mithril_discovery_test`. Install the
  packages and verify production extraction, execution, validation, query,
  commits, restart, and notification behavior. Test both targets where advertised.
  Reference JVM runs are development checks, not runtime prerequisites.
- Apply the inventory closure rules, rerun shared package cases, and run the
  final Rust procedure after the final implementation edit. Record live-input
  availability separately from algorithm correctness.

## Exclusions and stop point

Do not port OpenSearch storage, REST administration, dashboards, schedulers, or
notification delivery as parallel services. Preserve their required analysis
semantics through Araphor's existing owners. All upstream algorithms at the
pinned revision remain in scope; missing operations keep the phase Not done.

No unqualified Sigma-version compatibility, all-source detection, physical
prevention, or performance claim follows from this port. Stop after the complete
algorithm inventory and package checks pass. Benchmarks need separate approval.

## Result

**Not done.** Source families and the implementation owner are recorded. Full
source/variant enumeration, rule compatibility, development, and proof remain.

## End scope and example

Complete when every pinned Security Analytics algorithm and supported semantic
variant runs through installed packages and passes its required checks. Every
bundled rule is accounted for in the compatibility report. A missing live field
can make a rule unavailable on one deployment; it cannot hide an unimplemented
operator or count as positive detection proof.

Example at completion: two authorized findings satisfy an installed correlation
rule's exact field filters and 60-second window. The package returns a correlation
with both evidence references, and the host applies the required notification
route. A replacement window that removes one finding removes that correlation.
The result reports correlation; it does not prove causality or block an action.
