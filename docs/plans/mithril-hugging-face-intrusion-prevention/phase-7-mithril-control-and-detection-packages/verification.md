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

The [observability phases](../../araphor-observability/README.md#implementation-order-and-ownership)
own `OBS-*` CLI, capture, API, and optional CRD cases. The combined release
reruns applicable cases on its source revision. HTTP and the foreground CLI
are required client paths; MCP is optional and has checks only when delivered.

| ID | Cases | Required result |
| --- | --- | --- |
| `DE-IDENTITY` | Same Pod name after recreation; PID reuse; new boot/epoch; two image digests under equal labels; changed mount; init vs application vs external entry | Separate lifetime/cohort or explicit unresolved binding. No inferred role. |
| `DE-CONTEXT` | Old record; new WAL/upload/store round trip; reused role handle across generations; raw object/digest mismatch; missing selector; context quota; kernel sequence differs from WAL cursor | Preserve qualified fields and positions. Old or absent context stays unresolved. No current-state repair. |
| `DE-BOOT` | Discovery disabled; data-store upgrade; interrupted upgrade; unsupported downgrade; failed derivation; shutdown during commit | Recover durable data or report unavailable. Policy/control state and local enforcement remain independent. No ACK from a failed data store. |
| `DE-OUTCOME` | Success, permission denied, unrelated failure, would deny, absent actor result, absent physical result | Preserve distinct outcomes. No failed/unknown attempt silently becomes required behavior. |
| `DE-GAP` | Missed startup; ring/WAL gap; intentional sampling; stale source; clock reset; delayed coverage update | Partial interval and limited claims. No clean profile from an empty stream. |
| `DE-REPLAY` | Permuted arrival; duplicate; conflicting duplicate; changed algorithm; missing context; recorded context error; unexpected lookup; expired evidence | Equal deterministic input yields equal output. Mismatch/expiry fails explicitly. No live fallback lookup. |
| `DE-AGGREGATE` | Duplicate page; overlapping pages; same ID/different bytes; repeated independent observation; changed page size/thread order; late event; upstream sampling; absent intake time; integer overflow | Count each accepted identity once. Preserve outcome and instance identity. Included + unresolved + excluded equals unique accepted input. Late input creates a new revision. Unknown multiplicity stays unknown. |
| `DE-INDEX` | DuckDB WAL recovery, corrupt DB, failed backup/restore, long reader, temp/WAL limit, disk full, query-worker crash, selected-engine plans | Preserve authoritative data or stop ACK and dependent reads. Worker failure alone does not stop intake. No empty-store fallback or recovery claim after raw expiry. |
| `DE-WIDEN` | Four sibling files; `/tmp` resources; read vs write; exact vs recursive path; symlink/mount ambiguity; label group with unobserved member; changed DNS membership | Exact default. Broadening has a receipt and separate review. Unknown scope is not equivalence. |
| `DE-PREVIEW` | Exact compiled key; missing cell; hard safety condition; incomplete policy generation; absent dynamic exception binding; held-out valid-work case; synthetic scan; unsupported TLS/provider semantics | Existing static simulator result preserved. Unsupported runtime authority stays Unknown even if a compiled cell says Allow. No physical effect claim. |
| `DE-POISON` | Repeated credential read; attack inserted early in training; benign-looking command name; gradual behavior change; path flood; malicious tool description | No automatic allow, authority inference, or silent baseline update. Forbidden case remains visible. |
| `DE-STORE` | Crash before/after DB commit and before ACK; result/reference/progress commit failure; unsupported schema; retained duplicate conflict; expired duplicate; stale backup | Complete prior/new transaction, no double count, exact durable ACK. Restore reports source data lost since backup. Policy/control persistence is unchanged. |
| `DE-RETENTION` | Stall required processor; unexpired witnesses; delete/retained-floor crash; disable/retire; quota; late context; raw expiry; DELETE without physical reuse | Delete only eligible data in one transaction. Optional discovery expiry records a gap and does not block intake. Required security input blocks reclamation and intake only at protected age/byte or physical capacity bounds. Summaries and exact pinned witnesses survive raw expiry. No external cursor pins history. |
| `DE-TENANT` | Foreign profile ID, evidence link, cursor, client attachment, report ID, and publication request | Reject before content access. No identifier, timing-detail, or audit-content leak. |
| `DE-LIMIT` | Every byte/row/interval/page/worker limit at N and N+1; cancellation; slow reader; concurrent policy rollout | Bounded work, clear quota result, no priority inversion or wildcard fallback. |
| `DE-MODEL` | No external client; malformed assessment; NaN; absent evidence with high score; client timeout/refusal; forged citations; unapproved disclosure; foreign references; unverified model/cost claims | Deterministic fallback and unchanged core digests. Explicit abstention/failure and score semantics; no authority or unapproved disclosure. Retained-response replay does not rerun inference. |
| `DE-NOISE` | Repeated routine controller work; rare required recovery; benign release change; repeated forbidden credential read; one new malicious member; changed entry/result/coverage; expired prior review | Repetition reduces review items, not exact evidence. Rare valid work is not automatically malicious; frequent forbidden work is not required. New risk remains visible. Measure review errors/time, not only row reduction. |
| `DE-TEST-REQUEST` | Missing shutdown; unsupported platform; destructive suggested test; unavailable fixture; fabricated model fixture ID | Valid request or unsupported reason. No arbitrary command execution. |
| `DE-REVIEW` | Edit after preview; expired approval; changed target; conflicting reviewers; self-approval on protected widening | Old approval cannot authorize new content. Enforce current reviewer policy. |
| `DE-AUTH` | Wrong OIDC issuer/audience/nonce; missing grant; grant removal; administrative-exec token presented as console session; CSRF; restart/logout; session limit | Reject without source writes or scope disclosure. Existing administrative-exec behavior still passes its own tests. |
| `DE-PUBLISH` | Source resourceVersion conflict; source recreated with same name; lost reply; duplicate retry; request-key/content conflict; partial activation; stale acknowledgement; rollback | One exact source operation or explicit conflict. Source accepted is not target active. |
| `DE-CONSOLE` | Loading, empty, unauthorized, stale, partial, expired evidence, model off, synthetic preview, keyboard-only review | Correct labels, bounded queries, accessible controls, and no false success. |
| `DE-PACKET` | Stale owner document; conflicting context; missing source; future review; wrong lifetime; foreign handle; oversized text; omitted counterevidence; expired evidence; changed runbook | Deterministic selection, explicit omissions/conflicts, scoped provenance, and frozen revisions. No future-label leakage or current-state repair of history. |
| `DE-DETECT` | Exact predicate; partial positive; incomplete negative; count threshold; changed revision; same-name different lifetime; unsupported ordering; four-step sequence; invalid model-drafted spec | Matched/NotMatched/Unknown with field-level reasons and replayable evidence. No negative claim without required coverage, no temporal match reported as causality, and no detector auto-install. |
| `DE-ASSESS` | Benign positive; configuration fault; attack; insufficient context; valid-but-irrelevant citation; fabricated evidence; conflicting hypotheses; unsupported response; stale policy draft | Separate match, classification, impact, requirements, and suggestion validation. Preserve counterevidence. No automatic closure, exception, approval, or effect. |
| `DE-AGENT` | CLI/HTTP equivalent reads; HTTP drafts; optional MCP parity; service audience; repeated calls; role escalation; injection; revoked grant; cancelled follow; scope change; client-reported model/cost; request quota N/N+1 | Same owner results, current grants, bounded reads/reports, no self-approval or unauthorized effects. External client state is not a Control-owned run or verified model trace. |
| `DE-DISCLOSE` | Unapproved recipient/purpose; secret-bearing path; hidden-column predicate; foreign-row count; pseudonym join; redaction failure; revoked export during wait; changed export policy; external-client onward disclosure | Only authorized/redacted data enters query evaluation and leaves Araphor. Failure sends no original payload. Revocation stops later reads; onward use and past-copy deletion are not claimed enforceable. |
| `DE-QUERY` | Read-only syntax escape; nested forbidden function; catalog/field leak; file/network/extension access; recursive query; expensive join; worker crash/hang; projection overflow; output limit; incomplete negative; stale view; sqlparser/DuckDB agreement; SQL-derived window; OR/CTE/self-join counterexamples; exact timestamps and nulls | Isolated bounded execution or explicit rejection. Scope applies before evaluation. Proven AST bounds return the same result as full authorized-input evaluation; unsafe narrowing is not applied. Aggregate input is never silently truncated. No SQL result becomes policy authority or a complete absence claim. |
| `DE-FOLLOW` | Initial-snapshot race; empty predicate; full frame; retry; lost/coalesced wake; unrelated commit; late correction; restart; expiry; scope/schema change; slow client; aggregate replacement; time-window expiry without traffic | No skipped retained append row. Complete replace equals a normal query at that revision. One active evaluation, bounded frames, explicit errors and revocation. No polling job API or summed replacement counts. |
| `DE-REMOTE` | Embedded/remote direct CLI parity for SQL/trace/assessment/publication; graph and notification recovery; lost commit/effect reply; Control/data partition; forged/expired delegation; frame-time grant revocation; double writer; transfer; stale backup | Same data/algorithm and authority results through either endpoint. Analysis owners move together. Control authorizes reads and executes trace/policy commands. ACK only after the sole durable commit. No local raw mirror, hidden fallback, split-brain writer or false complete recovery. |
| `DE-PROTECTION` | In-process token read; already-resident credential; same-TLS semantic ambiguity; policy activation gap; missing response owner; self-approval; stale/wider target; shared process/socket; replacement workload; provider revoke versus device/session state | Preserve master HF result/authority boundaries. Local enforcement has no SQL/model dependency. Typed owner actions require exact authorization and readback/watch. Unfinished owners remain Unsupported, not simulated protection. |
| `DE-DEFENDER` | Recorded external client; refusal; encoded hostile fixture; secret in decoded output; client restart; optional real local-client compatibility | Core proof uses production APIs with recorded replies and no model. A separate advertised local-inference claim needs actual model location and restricted egress. Refusal is a failed check, not benign. ClientDerived analysis retains provenance/sensitivity and never executes a payload. |
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
commitments. Phase 7.1 can revise them with recorded measurements before a live
contract depends on them. Enforce both count and byte limits; use the first
one reached.

| Resource | Initial limit | Limit behavior |
| --- | --- | --- |
| Derivation intervals | 4 active/process, 2/tenant; 32 pending/process, 8/tenant | Bounded queue; report lag and preserve required-consumer obligations. |
| Input per interval | 1 million records or 256 MiB decoded | Seal at exact position; continue a new interval. No hidden sampling. |
| Exact atoms | 50,000/profile | Partial or explicit limit; no wildcard substitution. |
| Data disk | 8 GiB/process and 2 GiB/tenant logical data; reserve at least 25% free maintenance capacity | Count actual DB, native WAL, temp, backups and pending writes. Reject configurations without measured recovery headroom. |
| Raw/profile/finding retention | 24 hours / 30 days / 90 days | Apply byte limits and exact reference rules as well as age. No unlimited history. |
| Pending-review witnesses | 7 days, 512 MiB/tenant | Reserve exact dependencies before review; reject or explicitly expire. |
| Required security input | Raw retention age (24 hours initially) and reserved bytes within the tenant's 2-GiB data budget | Raise health on failure. Pause affected intake before protected expiry or reserved-byte exhaustion, not at a separate lag timer. Explicit retirement records missing coverage. |
| Optional discovery progress | No raw-history reservation | Resume retained input; commit gaps for expired ranges. Existing exact witness pins keep their own bounds. |
| Retained revisions | 1,024 per tenant, 4,096/process for each analysis record family | Reject new work or expire eligible revisions. Audit expiry remains explicit. |
| Canonical record body | 16 MiB; at most 8,192 dependencies | Split only through a bounded manifest. No growing JSON history array. |
| Sealed profile set | 128 MiB | Typed failure before commit. |
| Analysis working memory | 256 MiB/process, including queues and caches | Cancel/backpressure analysis; measure native RSS. |
| Data engine | 1 writer, 2 trusted readers; 8 queued writes, 16 reads | Bounded admission; no wait under ControlStore locks. |
| Intake batch | 4,096 records, 4 MiB encoded or 50 ms | Commit first bound reached; decoded data must fit working memory. |
| Engine memory/WAL | 128 MiB memory target; 64 MiB WAL checkpoint threshold | Measure RSS; checkpoint before reserve exhaustion. If it fails, backpressure data writes. |
| Trusted extraction | 256 rows/1 MiB pages; 64 MiB admitted input after safe scope/column/AST-range selection; 1 second | Complete input or explicit rejection; never truncate COUNT/joins. No unproven predicate pushdown. |
| SQL input/result | 16 KiB SQL; 200 rows/1 MiB output | Explicit limited normal result; oversized replacement fails without changing the displayed snapshot. |
| Isolated query workers | 2/process, 1/tenant; 256 MiB OS memory and 1 CPU each; 1-second evaluation deadline | No network/credentials/live DB; terminate over-budget evaluation. Worker memory is separate from analysis memory. |
| Follow | 16 streams/process, 4/tenant; one evaluation and one queued frame/stream | One dirty flag coalesces changes. No read transaction while waiting. |
| Follow timing | 15-second heartbeat, 500-ms minimum replacement interval, 10-second output-stall timeout | Recheck grants/health; close slow readers without blocking intake. |
| Moving-window follow | 1–86,400-second lower window, one-second expiry resolution | Bind one evaluation clock; timer removes expired rows without new commits. Other volatile forms reject. |
| Node context | 16 KiB/event; 16 MiB immutable lookup snapshot | Keep base event with explicit missing-context reason. |
| Pinned Control context | 32 KiB/record | Explicit CONTEXT_LIMIT before copying. |
| Context document/packet | 64 KiB document; 256 KiB packet; 100 handles | Keep omission counts; no hidden truncation of required facts. |
| Assessment | 64 KiB and 100 claims/references | Reject malformed/oversized reports; no transcript store. |
| Agent experiment | 12 calls, 120 seconds, fixed token/cost budget per task | Record incomplete tasks; no claim to enforce an external client's onward use. |
| Trace | Observability 1 source/probe/output limits; separate Node spool reserve | Stop diagnostics before exhausting enforcement reserve; local expiry remains active. |

These limits are pilot defaults. Freeze any measured adjustment before dependent
phases qualify. Test N and N+1 for both encoded and decoded limits. Store record
families include immutable revisions and idempotency receipts, not only current
heads. Check physical free bytes before admission; logical tenant charging alone
does not bound a shared DuckDB file. Keep a separate filesystem reserve for
policy/control-state commits; the data budget cannot consume that reserve.

Backups need enough capacity for a complete validated copy. Reserve that space
before backup; use a separately configured owned backup directory if necessary.
Never overwrite the last good backup to satisfy a disk quota. If DELETE and
checkpoint cannot recover capacity, stop new data writes and report the reason.
An engine setting is not an OS RSS cap or a durability proof.

## Performance experiment

Qualify DuckDB with the sealed corpus and actual production batch schedule.
Do not repeat backend selection or infer throughput from OLAP benchmarks.
Correct counts, canonical replay, durable ACK, recovery, isolated evaluation,
bounded cancellation and memory are gates. Compare embedded intake with analysis
off/on and with query/trace load; record the bottleneck and configured capacity.
Do not add a second production engine for a benchmark.

Use a declared 4-vCPU, 8-GiB test host initially, with CPU architecture, disk,
kernel, build profile, and background load recorded. Core measurements require
no model. If an external-client capability is advertised, measure its additional
load separately against the same input. Include 10,000 and 50,000 exact-atom
profiles and the full admitted input bound. Record throughput, elapsed time,
peak RSS, bytes written, checkpoint latency, and cancellation latency.
Include committed profile list/filter/compare queries during aggregation and
recovery. Record query plans, cold/warm p50/p95/p99, WAL peak, DB size, replay
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

Compare raw-event review and deterministic recipes on the same operator tasks.
For optional external-client claims, compare SQL with and without exact context.
Specialized-read wrappers are not a required experiment. Report duplicate reduction separately from false
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
projection recovery. A result-row limit is not an input or CPU limit.

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
| Phase 7.10 | Accepted evidence, real finding/escalation, assessment, approved exact policy change, activation, and allowed/forbidden physical effects | Exception requests, cross-node causality, response execution, and provider actions remain Unsupported. |
| Mithril 8 | Extend the shared context with qualified cross-node evidence; prove the bounded exception request/approval/use/expiry path | Response execution remains Unsupported. |
| Mithril 9 | Agent and console use the same authorized local/Kubernetes response with physical readback and healthy watch | Unqualified provider actions remain Unsupported. |
| Mithril 10 | Extend the same loop for each advertised provider source and typed action | Unqualified actions do not inherit another capability's result. |
| Mithril 11 | Rerun all advertised cases, installation, migration, load, and complete HF conformance on the release revision | Optional Phase 12 work cannot satisfy a missing core result. |

For the first bounded release, `DE-LOOP` ends in the qualified policy-change
result, not a simulated response. Every delivery gate retains negative
authorization and unavailable-owner cases. An absent required graph,
notification, or policy owner blocks Phase 7.10. Positive response and
provider cases belong to their later gates, not to an omitted first-release
requirement. Record deterministic and assisted results separately.

Use one retained run manifest for the complete available-owner path. Record
subject/finding and evidence revisions, assessment, proposal, approval,
operation request, activation/readback, notification receipt, human
acknowledgement, watch interval, and late branches. Agent and console must
resolve the same references through the same API. These are linked existing
owner records, not another durable workflow database.

Core acceptance uses a recorded external client through production CLI/HTTP.
No model, provider credential or inference runtime is installed in Araphor.
Only an advertised local-agent compatibility claim requires the operator's
actual self-hosted configuration, restricted egress and recorded observations.
A recorded client does not prove local inference or model quality. Optional
compatibility failure cannot block a core-only release or count as a pass.

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
to implement. Record nonzero test counts,
actual arguments, revision, result path, and output digests with the test output.
Full Rust verification runs after the final covered Rust edit; a focused check
cannot replace it.

## Phase-to-case map

Add new case values to the existing binaries; names below are implementation
requirements, not claims that all commands exist today. Each case writes
result.json with revision, capability set, assertion count, owner transitions,
IDs/digests, coverage, limits and cleanup. A filter that runs zero tests fails.
Use external clock/runtime/network doubles only; call production owner APIs.

| Phase | Crate-local unit test families | mithril-e2e case |
| --- | --- | --- |
| 7.1 | schema, exact aggregation, DuckDB transaction and SQL-isolation tests | offline-exact; storage-contract |
| 7.2 | analysis_store_, analysis_upgrade_, control_retention_ | data-store-recovery; data-store-upgrade |
| 7.3 | query_admission_, query_scope_, query_follow_ | query-follow |
| 7.4 | discovery_derivation_, discovery_context_, discovery_comparison_ | context-roundtrip; profile-restart |
| 7.5 | control_graph_, control_notification_, control_authority_ | graph-notification |
| 7.6 | discovery_detection_, discovery_proposal_, discovery_suggestion_ | detection-context; proposal-preview; poisoned-window |
| 7.7 | discovery_assessment_, discovery_disclosure_, assessment HTTP validation | assessment-loop |
| 7.8 | discovery_http_, discovery_publish_, UI review tests | review-publish |
| 7.9 | remote delegation, request identity, placement/transfer tests | remote-placement |
| 7.10 | full relevant crate suites | all for the frozen capability set; paired physical harness |
| Observability 1 | observability_backend_ | backend-lifecycle; real backend pair |
| Observability 2 | observability_target_, observability_recovery_, measurement validation | owned-capture; existing owned/pods/disk-full physical pairs |
| Observability 3 | observability_cli_, observability_http_, UI stream tests | query-trace-client |
| Observability 4 | observability_crd_ | trace-crd; physical Kubernetes pair |

Keep discovery cases in `src/discovery/` and their entry point in
`src/bin/mithril_discovery_test.rs`. Keep observability cases in the existing
`src/observability.rs` family and `src/bin/mithril_observability_test.rs`.
Physical harnesses stay in `harness/`, inputs in `fixtures/`; never execute
`examples/`. Require lightweight results from the same revision before physical
runs. A physical mismatch must first become a failing lightweight assertion.

## Plan checks

Check local links, anchors, code fences, whitespace and dependency order.
The desired data store is DuckDB; policy/control-state persistence is unchanged.
Storage, query and trace work with discovery disabled. A failed query worker
does not stop data commits; a failed authoritative data store does stop ACK.
Follow is a committed-change stream, not repeated long-poll responses.
Keep generic public producer ingestion outside scope. No implementation pass
or deployment follows from this documentation check.
