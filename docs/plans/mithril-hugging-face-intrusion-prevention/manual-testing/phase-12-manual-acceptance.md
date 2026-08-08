# How To Manually Evaluate Phase 12

Status: Proposed evaluation runbook; no Phase 12 prototype or test has been
run. This guide cannot authorize or qualify production implementation.

Phase: [Optional Ecosystem Compatibility](../phase-12-optional-ecosystem-compatibility.md)  
Setup: [`OPTIONAL-SURFACE`](./environment-setup.md)

## Outcome

Produce a reproducible, prerequisite-aware `ADOPT`, `DEFER`, or `REJECT`
dossier for each separately approved optional surface. If its physical
prerequisite is absent, record `BLOCKED_ON_PREREQUISITE`. `ADOPT` creates a new
approved implementation phase; it does not ship from Phase 12 or alter the
Phase 11 claim.

## Automated Companion

```text
IMPLEMENTATION COMMAND REQUIRED: run the separately approved optional-surface
prototype's legitimate, failure, bypass, performance, absence, and exact
allocated-fixture suites against its completed prerequisite profile.
```

## Common Procedure

1. Confirm the surface has separate user approval and every physical
   prerequisite named by Phase 12 is `Done`.
2. Record its owner, security/mediation boundary, installation path, exact
   hooks/APIs, contracts, failure result, fixture IDs, performance budget,
   deployment change, and effect on existing claims.
3. Run the unchanged core product with the optional component absent and prove
   Phase 11 behavior is unchanged.
4. Install only the prototype, run its legitimate control, exact fixtures,
   failure/bypass cases, and performance comparison with equal evidence load.
5. Remove it and repeat the core control. Seal the raw results before choosing
   `ADOPT`, `DEFER`, or `REJECT`.

## Seccomp Fixture

| Fixture | Operator stimulus | Required oracle and control |
| --- | --- | --- |
| `SECCOMP-QUAL-001` | launch direct and qualified OCI/NRI variants with exact allow/deny, multithread/TSYNC, failed-install, and workload-load cases | filter is installed before user code with exact identity/scope; denied syscall physically fails, allowed control works, failure posture and measured budget are explicit |

Seccomp is adopted only if it adds material defense and stays within the
approved measured budget. Schema or filter generation alone is insufficient.

## Checkpoint And Stream Fixtures

| Fixture | Operator stimulus | Required oracle and control |
| --- | --- | --- |
| `CHECKPOINT-CREATE-001` | create a checkpoint through a supported stock authorization/runtime interface | exact authorization, object/task coverage, store result, and unsupported gaps are visible; no runtime patch is assumed |
| `ENTRY-RESTORE-001` | restore a checkpoint into an isolated target | restored root/identity is created at the qualified first-effect boundary; no stale process lineage is inherited |
| `ENTRY-STREAM-001` | attach or port-forward through the stock stream interface | exact API/runtime evidence limit and stream result are reported; no rejection is claimed from audit-only evidence |

Do not insert an unapproved stream proxy or claim full byte/semantic authority
when the stock interface supplies only request/audit facts.

## Named CI Fixture Matrix

Evaluate one named platform at a time. Every active row requires an official,
supported identity/join and a physical lowering oracle.

| Fixture | Operator stimulus | Required oracle and control |
| --- | --- | --- |
| `CI-CACHE-001` | write/read identical cache keys from isolated jobs | cache identity and consumers remain explicit; no invented step/process join |
| `CI-CONTAINER-001` | run a job step inside the platform's supported container mode | official job/step/container/native joins and physical rule scope are proven |
| `CI-DEBUG-001` | enter the platform's supported debug path | debug is a new explicit root/authority; normal job remains restricted |
| `CI-DIND-001` | start a nested container through supported Docker-in-Docker behavior | nested runtime boundary and coverage gaps are explicit; no false host ancestry |
| `CI-FANOUT-001` | fan one job into parallel/reusable children | every child has distinct supported IDs and cannot borrow sibling authority |
| `CI-GITHUB-TOKEN-001` | use the platform-issued repository token in allowed/denied scopes | issuance/scope/expiry/provider result are exact and secret bytes are absent |
| `CI-NATIVE-001` | run an official native step and its descendants | first-effect native identity and platform join are exact; unrelated step is separate |
| `CI-OFFICIAL-STEP-JOIN-001` | exercise the platform's documented job-to-step join | only the official join creates an exact edge; lookalike timing/argv does not |
| `CI-OIDC-001` | exchange an official OIDC assertion for sandbox authority | job/claim/audience/session/request joins and expiry are exact |
| `CI-OUTPUT-001` | pass an output between official steps/jobs | output identity is an artifact/data edge, not automatic process parentage |
| `CI-POST-001` | run post/cleanup after the main step | post-step identity, ordering, failure, and authority are independent and exact |
| `CI-PR-001` | run trusted and untrusted pull-request variants | event/fork/trust boundary physically lowers different authority without secret exposure |
| `CI-RETRY-001` | retry the same logical job/step | retry has a new execution identity while preserving the supported logical join |
| `CI-RUNNER-REUSE-001` | reuse a runner after cleanup and injected failure | no credential, task, policy, or artifact authority leaks to the next job |
| `CI-STATE-001` | carry platform-supported state across steps | state ownership/lifetime is explicit; unsupported shared state stays contextual |
| `HF-GRAN-CI-BUILDRS-001` | run the safe HF build/run branch through the named CI adapter | exact official joins and physical restrictions hold without patching the runner or inventing step identity |

## Surfaces Without Active Fixture IDs

Operator-owned L7 mediation, host/developer/non-Kubernetes enrollment, and
optional external evidence adapters currently have no active Appendix C IDs.
An exploratory dossier may identify hooks and measurements, but an `ADOPT`
implementation cannot be approved until one change adds exact IDs to the
validated architecture, fixture registry, criterion mapping, and new owning
phase together.

For L7, verify explicit operator ownership, client/upstream authentication,
semantic policy/result, failure posture, credentials/CA handling, and
deployment. Never silently inject a proxy, redirect traffic, replace DNS, or
install a workload CA.

For host agents, prove system-manager/cgroup/executable identity before the
first protected effect and reuse the shared Interceptor. PID-delayed userspace
enrollment is ineligible.

For external evidence, preserve source-native IDs, health, loss, policy/version,
and proof quality. It may enter Mithril Control only as independent evidence;
it cannot become node identity, policy authority, prevention proof, or a
second loader.

## Required Artifacts And Decision Rule

Retain prerequisite proof, allocation ledger, prototype/artifact digests,
installation inventory, exact fixture and controls, physical oracles, bypass/
failure results, equal-load performance comparison, absence/removal run, claim
impact, and sealed evidence digest. Record exactly one:

- `ADOPT`: measured value justifies a separately approved implementation phase;
- `DEFER`: evidence is valid but value/readiness does not justify adoption;
- `REJECT`: the measured surface cannot meet its security/performance contract;
  or
- `BLOCKED_ON_PREREQUISITE`: a physical prerequisite is not yet implemented.

No decision changes a production claim by itself.

## Troubleshooting

- Do not decide from schemas or upstream documentation when the prerequisite
  needed for a physical prototype is absent.
- An official CI event without an official step/native join cannot support
  exact per-step enforcement.
- Optional evidence that reports a deny is not proof that Mithril physically
  prevented the effect.

