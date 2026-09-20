# Verification And Release Gates

This record defines required checks. None of the engine, model, operator, or
physical checks below ran as part of the planning change. A proposed gate is
not a measured product capability.

## Test ownership

Pure schema, grouping, transformation, and state tests belong with their
Control owner. Lightweight end-to-end cases belong in `crates/mithril-e2e/src`
and call supported production APIs. Their command entry points belong in
`crates/mithril-e2e/src/bin`. Physical Kubernetes harnesses belong in
`crates/mithril-e2e/harness`, with inputs in `fixtures`.

Run the lightweight case before its paired physical case. Both must report
the same transitions, decisions, and semantic result fields. Environmental
identities and timestamps can differ. If a physical case reveals a missing
condition, add that condition to its lightweight pair before implementation
changes or physical reruns. Automated harnesses must not read `examples/`.

## Required case families

| ID | Cases | Required result |
| --- | --- | --- |
| `DE-IDENTITY` | Same Pod name after recreation; PID reuse; new boot/epoch; two image digests under equal labels; changed mount; init vs application vs external entry | Separate lifetime/cohort or explicit unresolved binding. No inferred role. |
| `DE-CONTEXT` | Old record; new WAL/upload/store round trip; reused role handle across generations; raw object/digest mismatch; missing selector; context quota; kernel sequence differs from WAL cursor | Preserve qualified fields and positions. Old or absent context stays unresolved. No current-state repair. |
| `DE-BOOT` | Discovery disabled; old-store migration; interrupted migration; unsupported downgrade; failed derivation; shutdown during seal | Preserve primary state. Recover or explicitly fail discovery without stopping policy and evidence owners. |
| `DE-OUTCOME` | Success, permission denied, unrelated failure, would deny, absent actor result, absent physical result | Preserve distinct outcomes. No failed/unknown attempt silently becomes required behavior. |
| `DE-GAP` | Missed startup; ring/WAL gap; intentional sampling; stale source; clock reset; delayed coverage update | Partial interval and limited claims. No clean profile from an empty stream. |
| `DE-REPLAY` | Permuted arrival; duplicate; conflicting duplicate; changed algorithm; missing context; recorded context error; unexpected lookup; expired evidence | Equal deterministic input yields equal output. Mismatch/expiry fails explicitly. No live fallback lookup. |
| `DE-AGGREGATE` | Duplicate page; overlapping pages; same ID/different bytes; repeated independent observation; changed page size/thread order; late event; upstream sampling; absent intake time; integer overflow | Count each accepted identity once. Preserve outcome and instance identity. Included + unresolved + excluded equals unique accepted input. Late input creates a new revision. Unknown multiplicity stays unknown. |
| `DE-INDEX` | Crash between exported-page/SQL/head/index commits; corrupt SQL; interrupted rebuild; long reader; WAL limit; disk full; unsupported engine/filesystem; foreign cursor; index behind head; selected-engine query plans | Recover exact counts from retained artifacts. No index row becomes authority. Stable keyset pages after rebuild. Index unavailable is not empty/healthy; policy and evidence owners continue. |
| `DE-WIDEN` | Four sibling files; `/tmp` resources; read vs write; exact vs recursive path; symlink/mount ambiguity; label group with unobserved member; changed DNS membership | Exact default. Broadening has a receipt and separate review. Unknown scope is not equivalence. |
| `DE-PREVIEW` | Exact compiled key; missing cell; hard safety condition; incomplete policy generation; absent dynamic exception binding; held-out valid-work case; synthetic scan; unsupported TLS/provider semantics | Existing static simulator result preserved. Unsupported runtime authority stays Unknown even if a compiled cell says Allow. No physical effect claim. |
| `DE-POISON` | Repeated credential read; attack inserted early in training; benign-looking command name; gradual behavior change; path flood; malicious tool description | No automatic allow, authority inference, or silent baseline update. Forbidden case remains visible. |
| `DE-STORE` | Crash before/after artifact sync and head commit; corrupted artifact; orphan; disk full; restart during seal; incompatible schema | Valid prior/new state or integrity failure. No acknowledged missing artifact. |
| `DE-RETENTION` | Shared consumer advances during export; reclaim before/after page open; review bundle; expired bundle; deleted training export; quota reached | Discovery never advances the shared watermark. Missing source ranges make the interval Partial. Copied bundles survive source reclamation within their own quota/expiry. |
| `DE-TENANT` | Foreign profile ID, evidence link, cursor, model artifact, report ID, and publication request | Reject before content access. No identifier, timing-detail, or audit-content leak. |
| `DE-LIMIT` | Every byte/row/interval/page/worker limit at N and N+1; cancellation; slow reader; concurrent policy rollout | Bounded work, clear quota result, no priority inversion or wildcard fallback. |
| `DE-MODEL` | No model; low confidence; unseen workload; schema mismatch; bad digest; malformed output; NaN; absent evidence with high score; label/token collision; failed calibration; initialization/inference hang; unapproved callback; cross-tenant cache; changed provider model alias | Deterministic fallback and unchanged core digests. Explicit abstention/failure and score semantics; no authority or unapproved disclosure. Retained-response replay does not rerun inference. |
| `DE-NOISE` | Repeated routine controller work; rare required recovery; benign release change; repeated forbidden credential read; one new malicious member; changed entry/result/coverage; expired prior review | Repetition reduces review items, not exact evidence. Rare valid work is not automatically malicious; frequent forbidden work is not required. New risk remains visible. Measure review errors/time, not only row reduction. |
| `DE-TEST-REQUEST` | Missing shutdown; unsupported platform; destructive suggested test; unavailable fixture; fabricated model fixture ID | Valid request or unsupported reason. No arbitrary command execution. |
| `DE-REVIEW` | Edit after preview; expired approval; changed target; conflicting reviewers; self-approval on protected widening | Old approval cannot authorize new content. Enforce current reviewer policy. |
| `DE-AUTH` | Wrong OIDC issuer/audience/nonce; missing grant; grant removal; administrative-exec token presented as console session; CSRF; restart/logout; session limit | Reject without source writes or scope disclosure. Existing administrative-exec behavior still passes its own tests. |
| `DE-PUBLISH` | Source resourceVersion conflict; source recreated with same name; lost reply; duplicate retry; request-key/content conflict; partial activation; stale acknowledgement; rollback | One exact source operation or explicit conflict. Source accepted is not target active. |
| `DE-CONSOLE` | Loading, empty, unauthorized, stale, partial, expired evidence, model off, synthetic preview, keyboard-only review | Correct labels, bounded queries, accessible controls, and no false success. |
| `DE-PACKET` | Stale owner document; conflicting context; missing source; future review; wrong lifetime; foreign handle; oversized text; omitted counterevidence; expired evidence; changed runbook | Deterministic selection, explicit omissions/conflicts, scoped provenance, and frozen revisions. No future-label leakage or current-state repair of history. |
| `DE-DETECT` | Exact predicate; partial positive; incomplete negative; count threshold; changed revision; same-name different lifetime; unsupported ordering; four-step sequence; invalid model-drafted spec | Matched/NotMatched/Unknown with field-level reasons and replayable evidence. No negative claim without required coverage, no temporal match reported as causality, and no detector auto-install. |
| `DE-ASSESS` | Benign positive; configuration fault; attack; insufficient context; valid-but-irrelevant citation; fabricated evidence; conflicting hypotheses; unsupported response; stale policy draft | Separate match, classification, impact, requirements, and suggestion validation. Preserve counterevidence. No automatic closure, exception, approval, or effect. |
| `DE-AGENT` | HTTP/MCP equivalent reads/drafts; service audience; repeated calls; role escalation; injection; revoked grant; cancelled follow; scope change; client-reported model/cost; request quota N/N+1 | Same owner results, current grants, bounded reads/reports, no self-approval or unauthorized effects. External client state is not a Control-owned run or verified model trace. |
| `DE-DISCLOSE` | Unapproved recipient/purpose; secret-bearing path; hidden-column predicate; foreign-row count; pseudonym join; redaction failure; revoked export during wait; changed export policy; external-client onward disclosure | Only authorized/redacted data enters query evaluation and leaves Araphor. Failure sends no original payload. Revocation stops later reads; onward use and past-copy deletion are not claimed enforceable. |
| `DE-QUERY` | Read-only syntax escape; nested forbidden function; catalog/field leak; file/network/extension access; recursive query; expensive join; worker crash/hang; projection overflow; output limit; incomplete negative; stale view | Isolated bounded execution or explicit rejection. Scope applies before evaluation; aggregate input is never silently truncated. No SQL result becomes policy authority or a complete absence claim. |
| `DE-FOLLOW` | Initial retained history; empty predicate; full output batch; retry; lost wake-up; late evidence; coverage correction; restart/rebuild; expiry; schema/query/export change; slow client; cancellation; aggregate follow | Stable committed positions or explicit invalidation. No skipped matching row, hidden reset, source-order fiction, or policy stall. Reject unsupported follow shapes; collection continues without clients. |
| `DE-PROTECTION` | In-process token read; already-resident credential; same-TLS semantic ambiguity; policy activation gap; missing response owner; self-approval; stale/wider target; shared process/socket; replacement workload; provider revoke versus device/session state | Preserve master HF result/authority boundaries. Local enforcement has no SQL/model dependency. Typed owner actions require exact authorization and readback/watch. Unfinished owners remain Unsupported, not simulated protection. |
| `DE-DEFENDER` | Self-hosted model; hosted fallback attempt; local CLI with remote inference; model refusal; encoded hostile fixture; secret in decoded output; client restart | Local-mode proof includes actual model location and restricted egress. Refusal is a failed check, not benign. ClientDerived analysis retains provenance/sensitivity and never executes a payload. |
| `DE-ESCALATION` | Critical finding with benign model label; no model; missing route; delivery failure; duplicate; agent-only acknowledgement; overdue human receipt; restart/clock change; late revision | Approved priority floor and routing deadline remain active. Agent receipt is not human acknowledgement. Missing route is unhealthy, not silent success. No notification or acknowledgement grants execution. |
| `DE-LOOP` | Evidence to assessment to approval to action/readback; console/agent equivalence; agent replacement without chat; lost mutation reply; stale proposal; late branch; missing backend owner | Same tenant/subject/input and immutable parent references at every step. No file handoff, copied case state, duplicate effect, or synthetic full-loop pass. Actual postconditions and unfinished obligations remain visible. |

Each family needs concrete input, expected output, commands, and result artifact
paths when implemented. The identifiers above reserve case intent; they are
not existing test names or proof records.

## Corpus

Build a small versioned corpus before collecting a large production dataset.
Include at least:

- a service with startup, read-only steady work, probes, and graceful shutdown;
- a stateful worker with scheduled work and a rarely used recovery path;
- an application update that changes a legitimate dependency;
- two replicas with unequal observation coverage;
- an administrative/external entry that resembles an application command;
- a poisoned learning window with credential access and new outbound activity;
- a missing metadata binding and a deliberately gapped stream;
- a recorded context exchange whose lookup fails;
- a synthetic configuration check without historical caller information;
- a governed agent action fixture, marked unsupported for native policy output
  when its action owner cannot supply an exact contract.
- repeated controller API activity and known application traffic that a broad
  heuristic could label suspicious; no provider semantics inferred from a port;
- 10,000 repeated benign observations with one distinct forbidden action;
- a late record and a revised coverage interval after a review is sealed.
- a detector that correctly matches expected activity, distinct from a false match;
- an incident-inspired credential attempt with absent provider audit evidence;
- a runbook, log field, and prior case note that each contain injected instructions;
- competing maintenance and intrusion hypotheses with discriminating evidence;
- a plausible but unsupported explanation whose citations exist but do not support it;
- a critical finding whose model assessment is benign or refused, with an
  unacknowledged human route and a failed first notification delivery;
- a safe encoded-payload analysis whose decoded text has synthetic secrets and
  injected instructions; no recovered payload is executed;
- a local defender that exits after submission and resumes through another
  client, with a lost response reply and a replacement workload.

Use synthetic credentials and isolated targets. Retain build/image/configuration
digests and case labels. Do not use real secret values, copy private production
traces without permission, or relabel an illustrative incident as actual data.

Keep training, tuning, held-out valid-work, and forbidden-case partitions
separate. Split by workload and time. Store the split manifest before tuning.
Measure the frequency and severity of incorrect requirements as well as model
classification mistakes. A model can classify correctly and still be irrelevant
to safe policy review.

## Initial resource limits

These are proposed pilot limits, not measured capacity or final service-level
commitments. Phase 1 can revise them with recorded measurements before a live
contract depends on them. Enforce both count and byte limits; use the first
one reached.

| Resource | Initial limit | Limit behavior |
| --- | --- | --- |
| Active derivation intervals | 4 per process, 2 per tenant; 32 pending per process, 8 per tenant | Internal bounded work only. Backpressure discovery, not evidence intake; preserve gaps if retention expires. |
| Input per interval | 1 million accepted records or 256 MiB decoded input | Seal the interval with exact stopping position and coverage; continue in a new interval. No hidden sample or completeness beyond that interval. |
| Exact behavior atoms | 50,000 per profile | Partial result; no wildcard compression to evade the limit. |
| Artifact segment | 16 MiB | Split into checked immutable segments with a bounded manifest. |
| Discovery heads | 1,024 per tenant, 4,096 per process, and 8 MiB serialized total | Reject new work before the first limit; preserve existing audit records and the overall 64 MiB store limit. |
| Retained discovery artifacts | 2 GiB per tenant and 8 GiB per process | Reserve quota before admission; expire only eligible bundles or reject. Source evidence keeps its separate limits. |
| Profile/proposal artifact set | 128 MiB per interval | Stop before commit with a typed size reason. |
| Pending-review evidence retention | 7 days and 512 MiB per tenant | Reject a new pin or expire a review explicitly; do not block intake. |
| In-memory derivation working set | 256 MiB total process budget | Backpressure/cancel assistance; prioritize evidence and policy owners. |
| Embedded DB and rebuild disk | 2 GiB total, including DB, WAL, temporary files, and replacement index | Reserve rebuild space before work. Reject or stop discovery before exhausting the shared store; do not delete authoritative artifacts to repair an index. |
| SQL connections and queues | 1 writer, 2 readers; 8 pending page writes, 16 pending reads | Backpressure inside discovery, then typed limit. No wait under the ControlStore lock. |
| SQL memory and WAL | 64 MiB initial engine memory/cache target within the 256 MiB working budget; 64 MiB WAL stop threshold | Measure native allocation and spill; an engine setting is not an RSS cap. Suspend new DB work if checkpointing cannot bound growth. Resolve any needed budget change with measurements before store selection. |
| SQL read and apply work | 1 second read deadline; at most 4,096 records/8 MiB of durably exported pages per apply transaction | Interrupt over-budget reads; bounded retry or typed failure. Measure the batch size. No transaction spans client I/O. |
| API result | 200 rows and 1 MiB | Normal output overflow is explicit; follow returns the last-scanned cursor without skipping a match. Oversized row gets a typed error. |
| Untrusted SQL | 16 KiB statement; 64 MiB authorized projected input; 2 active workers/process, 1/tenant | Reject unsupported syntax or input overflow; require a narrower query. Do not partially evaluate an aggregate. |
| Query worker | 256 MiB OS memory cap and 1 CPU/worker, no network; 1-second evaluation deadline | Terminate over-budget worker without stopping Control. Maximum worker memory is 512 MiB, separate from Control derivation's 256 MiB budget. |
| Follow wait | 20 seconds; 16 waiting calls/process, 4/tenant; bounded scan per evaluation | No transaction/worker retained while waiting. Return empty progress or limit; no client queue or durable subscription. |
| Evidence export page | 256 records, 1 MiB, 4 open segment handles | Stop at the first bound. Release the store lock before decoding or client I/O. |
| Node decision context | 16 KiB per event; 16 MiB lookup snapshot | Keep the base event with an unavailable-context reason when optional context exceeds the bound. Respect the existing total record limit. |
| Optional classifier artifact | 128 MiB | Reject oversized artifact; no runtime download. |
| Optional native inference worker | 512 MiB memory, 1 CPU allocation, 2 worker threads | Terminate over-budget worker; report assistance unavailable. |
| Classification batch | 256 rows, 2 seconds execution deadline | Timeout/abstain; no policy-path delay. Initialization has a separate 10-second limit. |
| Offline compact-classifier comparison | 8 GiB RAM, 4 CPU threads, 1,024 input tokens, 60 seconds/request | Experiment only. This does not authorize deployment or constrain a separately approved hosted investigation model. |
| Context document and initial packet | 64 KiB per document; 256 KiB packet with at most 100 evidence handles | Return omission counts and handles for progressive reads. No silent truncation of required facts. Charge artifacts to existing tenant limits. |
| Assessment report | 64 KiB; 100 claims/references; existing artifact quota | Reject oversized/invalid reports; no model transcript or job registry. |
| Agent experiment | Evaluator limit: 12 tool calls, 120 seconds, fixed token/cost budget per task | Report incomplete tasks and retries. These are client/evaluation limits, not Control-enforced provider spend. |
| Qualified recipe | Admitted SQL bounds and fixed input revisions | Matched/NotMatched/Unknown requires declared coverage/preconditions. No automatic finding or detector install. |

Input limits include decoded size and nested collection counts to prevent a
small encoded request from causing large allocation. Validate before expensive
parsing/inference. In-memory accounting includes queues, catalogs, and caches.
Head and artifact quotas include all revisions, intervals, approvals, and idempotency
records, not just active profiles. Check configured disk capacity before live
enablement. No unbounded history may enter the fixed-size Control state image.
DB reservations include pending writes and rebuild copies. Charge each tenant's
indexed data against its existing discovery quota as well as the global DB
bound; do not assume a shared file has free per-tenant capacity. Preserve input
needed for active-interval recovery before evicting any derived working rows.

## Performance experiment

Before the durable implementation, run SQLite and DuckDB over the same sealed
input and operation schedule. Measure native batch sizes and qualified layouts,
not a row-by-row SQLite workload imposed on DuckDB. Correct counts, canonical
replay, crash recovery, bounded interruption, and available memory are gates.
Among passing candidates, compare context joins, evidence lookup, profile
comparison, and ingestion while console reads run. Record the selection in the
existing feasibility phase. Keep one production engine and no generic driver.

Use a declared 4-vCPU, 8-GiB test host initially, with CPU architecture, disk,
kernel, build profile, and background load recorded. Run no-model and selected
model modes against the same sealed input. Include 10,000 and 50,000 exact-atom
profiles and the full admitted input bound. Record throughput, elapsed time,
peak RSS, bytes written, checkpoint latency, and cancellation latency.
Include committed profile list/filter/compare queries during aggregation and
rebuild. Record query plans, cold/warm p50/p95/p99, WAL peak, DB size, replay
throughput, and time to restore query service. Proposed indexed-page gate:
p95 at most 500 ms for a 200-row page over a 50,000-atom profile on this host.
Queries that time out return a typed failure, not an incomplete count.

Proposed interactive gate: a 10,000-atom supported preview completes within
5 seconds at p95 on the declared host. The API returns the proposal's Pending revision and
does not hold an HTTP request open for all work. Query reads the result. This is a pilot target only.
Record cold and warm runs separately; do not exclude failures or model startup.

Run primary evidence and rollout workloads concurrently. Compare their latency
and completion with discovery disabled. Investigate a reproducible regression
above 5%; the release must not accept unbounded stalls at any percentage.
Repeat runs and report variability. Test disk-full and noisy-neighbor cases
independently from nominal throughput.

Compare raw-event review, deterministic recipes, context-only AI, specialized
read wrappers, SQL, and SQL plus context on the same operator tasks. Report duplicate reduction separately from false
positive correction. All seeded forbidden groups must remain reachable and
visible in their required queue class. Show missed groups, incorrect approvals,
rare valid-case failures, abstention, sample size, and task time. A model that
only makes a shorter list does not pass.

Freeze expected supporting and refuting evidence for each investigation. Score
retrieval recall at the admitted context budget, citation validity and actual
support separately, classification confusion by severity, correct abstention,
useful suggestions, task completion, and operator corrections. Report tool
calls, context bytes, tokens, cost, and wall time. Compare the same model with
and without context and SQL access to isolate the value of the engine. Human reviewers and
executable assertions own safety labels; an LLM judge is supplementary only.
Use workload/time holdouts and repeated model runs; preserve failures. Reviewed
history must predate the task cutoff. A model/prompt/runbook update needs fresh
evaluation and shadow results, not inherited accuracy.

Also measure query admission/projection/worker startup end to end. The 500-ms
indexed-result target includes isolation overhead; do not report only in-engine
query time. Follow waits are measured separately from evaluation latency. Test
read revocation during the wait, filtered progress, retention expiry, and
projection rebuild. A result-row limit is not an input or CPU limit.

The broader tool workflow must pass policy proposal/publication and qualified
response tasks under distinct grants. Use master owner tests as dependencies,
not test-only replacement owners. Record Unsupported for absent capabilities.
A smaller read surface cannot compensate for missing enforcement or recovery.

## One-system acceptance

Apply the [combined implementation order](README.md#combined-implementation-order).
Freeze the required capability set in the run manifest before execution.
Do not choose tests from whichever services happen to be available.

| Delivery gate | Required positive loop | Required unavailable boundary |
| --- | --- | --- |
| Discovery 6 | Accepted evidence, real finding/escalation, assessment, approved exact policy change, activation, and allowed/forbidden physical effects | Exception requests, cross-node causality, response execution, and provider actions remain Unsupported. |
| Mithril 8 | Extend the shared context with qualified cross-node evidence; prove the bounded exception request/approval/use/expiry path | Response execution remains Unsupported. |
| Mithril 9 | Agent and console use the same authorized local/Kubernetes response with physical readback and healthy watch | Unqualified provider actions remain Unsupported. |
| Mithril 10 | Extend the same loop for each advertised provider source and typed action | Unqualified actions do not inherit another capability's result. |
| Mithril 11 | Rerun all advertised cases, installation, migration, load, and complete HF conformance on the release revision | Optional Phase 12 work cannot satisfy a missing core result. |

For the first bounded release, `DE-LOOP` ends in the qualified policy-change
result, not a simulated response. Every delivery gate retains negative
authorization and unavailable-owner cases. An absent required graph,
notification, or policy owner blocks Discovery 6. Positive response and
provider cases belong to their later gates, not to an omitted first-release
requirement. Record deterministic and assisted results separately.

Use one retained run manifest for the complete available-owner path. Record
subject/finding and evidence revisions, assessment, proposal, approval,
operation request, activation/readback, notification receipt, human
acknowledgement, watch interval, and late branches. Agent and console must
resolve the same references through the same API. These are linked existing
owner records, not another durable workflow database.

Run the local defender on declared hardware with the declared self-hosted model.
After provisioning, admit only Araphor and the approved in-network model endpoint
as network destinations. Record network observations and failed fallback attempts.
A locally running client or a recorded-response stub does not prove local inference.

Measure receipt-to-escalation, human acknowledgement, authorized dispatch,
physical verification, and remaining-open-branch time separately. Test model
refusal and incorrect benign classification without postponing mandatory routing.
Neither delivered notification nor a stopped process closes the incident.

An absent graph, notification, or response owner leaves the corresponding loop
incomplete. Do not manufacture its records in a test helper and call the product
complete. Use lightweight owner-API tests before the paired physical test; retain
the master's unchanged-workload and legitimate-control requirements.

## Physical proof and limitations

For the first native path, observe and review exact file/execute behavior,
publish through the normal source owner, verify target acknowledgement, and
run both allowed and forbidden effects. Include open-before-policy-change,
additional entry, restart, and partial rollout cases where the claimed policy
family supports them. Record unsupported conditions instead of adapting the
test to hide them.

Admission checks, configuration scans, simulator results, source writes, node
activation, and physical effects are separate proof classes. A successful
background audit or replay cannot inherit a physical effect result. Local
filesystem qualification cannot establish remote provider authorization.

Existing Hugging Face-related fixtures supply relevant case definitions. Pin
the exact source and fixture revision used; do not claim full incident
prevention from this discovery path. The primary checkout's later BPF test
records do not become discovery test results.

## Implementation verification commands

Run from the implementing worktree after the relevant source change:

```sh
cargo test -p mithril-control
cargo test -p mithril-e2e
bash .github/scripts/verify-rust-ci.sh
```

Run from `ui/mithril-console` after UI changes:

```sh
npm run check
npm test
npm run build
npm run test:e2e
```

The phase files specify the new case, harness, and evaluator command interfaces
to implement. Those commands are not available yet. Record nonzero test counts,
actual arguments, revision, result path, and output digests in the phase result.
Full Rust verification runs after the final covered Rust edit; a focused check
cannot replace it.

## Planning change checks

Planning result: **Done** for the source study and proposed plan.
Implementation result: **Not done** for every phase.

On 2026-09-20, `rtk proxy node /tmp/araphor-discovery-doc-check.mjs` passed
across the discovery/console families, their index, and the changed master
owner plans: 27 files, 154 local links and anchors, six complete discovery phase
structures, and 33 defined case
families. The check also passed balanced code fences, trailing whitespace,
and explicit Not done implementation results. It counted 119 external links;
that count is not an HTTP availability or competitive-product test.

`rtk proxy git diff --check` also passed in `worktrees/mithril-ui`. The Node
check includes untracked plan files that Git's diff check does not inspect.
No code, model, UI, cluster, or upstream deployment test is claimed.
