# Phase 3: CLI, API, And Console

Expose SQL and diagnostic capture through one CLI and the existing console.
Require Observability 2 and Phase 7.3 Done.
Reuse shared query code; do not reimplement SQL evaluation or tracing in a client.

## Intended end state

An agent runs `araphor sql` or `araphor trace` in its terminal. Both commands
print their own results. The console calls the same APIs and shows the same
source, provenance, limits, and outcomes. MCP is not a release dependency.
This phase also adds production SQL admission and asynchronous execution to
the trusted internal engine from 7.3. Do not enable public SQL before both pass.

## Query boundary before client access

1. Extend `araphor-data` QueryOwner with client SQL admission. Use the pinned
   `sqlparser` DuckDbDialect and a closed relation/function allowlist. Resolve
   columns and aliases against the available relation schemas. Require one
   current `investigate` permission for the authenticated tenant. This
   permission allows SQL reads and any supported trace in that tenant.
   Do not add separate column, Pod, Node, query or trace permissions.
   Tenant selection remains mandatory. SQL predicates and optional targets
   select input; they do not create permission checks. Apply only the proved AST time bounds
   in [engine-design.md](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/engine-design.md#sql-derived-input-bounds).
   Keep unsupported shapes explicit; do not implement a general optimizer.
2. Run queries inside the host's existing Tokio runtime. Make
   `QueryOwner::query_client` an asynchronous operation. Reserve evaluation,
   input and output capacity before `spawn_blocking`; DuckDB's synchronous
   calls must not block an asynchronous runtime thread. Use the same evaluator
   and temporary table adapter for trusted and client plans. Register only
   available relations with tenant-selected rows. Pass complete bounded input, not segment
   paths or a persistent database connection. Disable external access and
   extension loading. Apply DuckDB memory and thread limits and the existing
   deadline and interrupt owner. Future drop and stream cancellation request
   interruption. Keep capacity charged until native evaluation and cleanup
   return. Return query errors and task failures as typed errors. A query
   error or cancellation must leave trace output upload available. Do not
   add a query executable, IPC, namespace setup or AppArmor prerequisite.
3. Use ordinary result metadata and an unsigned resume bookmark. Recheck the
   current tenant permission before every frame and after waits; permission
   loss stops disclosure. A bookmark contains schema version, store UUID,
   recovery epoch, operation, read revision and position. Validate size,
   structure, store identity, future positions and retention bounds. A
   bookmark grants no access. The client saves the exact SQL, parameters and
   selection with the bookmark and clears the bookmark when these change.
   Do not add query signing keys, signed receipts or query/result hashes. Map
   the tenant replay-floor failure to `OUT_OF_RANGE`; it means replay is
   unavailable, not proof that this filter lost a matching row. Keep limits
   in the data crate so the optional remote host uses the same contract.

QueryPlan owns one trusted selection or one immutable client grant. The client
grant contains the tenant input selection. Plan copies and query sessions
share that grant; they do not copy the selection into another plan field.
Dependency selection uses a separate mutable copy to narrow the input.

Permission changes still wake pending reads and each disclosure checks current
authority. An immutable grant does not make current permission immutable.
The [structural ownership result](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/phase-7-3-query-and-follow.md#structural-ownership-result)
records current workspace and native client proof at `244ac567`.

QueryTransport retains one checkpoint guard. The guard stores the authorized
frame or owns the pending final-check future. That future returns the same
frame. Derive its wire header and bookmark when a local duration ends.
New rows without a checkpoint do not change that saved frame.
Check retained-read validity and current
permission before the final response. Keep row delivery, Error-before-status
order and trace lifecycle separate. Decode a trace bookmark once and pass
its validated QueryCheckpoint to QueryOwner.
TraceTransport builds each output envelope through its existing frame method.
Use one conversion for error positions and retention floors.

Frames do not need a separate frame ID or result digest. Append replay uses
exact row positions within one query and store epoch. Replacement output
is one complete bounded result. An edited bookmark can replay or skip rows
that the current caller can read; it cannot grant access. The server does not
prove that the SQL or selection is unchanged. Policy signatures and signed
Control-to-Node execution leases remain required.

`QueryStream` implements `futures::Stream<Item = Result<QueryFrame>>`.
QueryStream owns production and returns frames when the consumer polls it.
Construction starts no SQL. Committed changes wake a pending follow read.
One evaluation future returns bounded append rows or one complete replacement.
The stream returns frames in order, then waits for the next relevant commit
or expiry. Do not add a separate producer task or output channel. Paused
consumption starts no further evaluation. An admitted native task can finish;
keep its capacity charged through cleanup. Stream drop interrupts pending
work and releases retained frames.
Existing stream admission bounds the number of capacity waiters. An admitted
stream waits for evaluation, input and output capacity within its existing
extraction deadline. Stop, reader closure and authority changes also wake
this wait. Check current authority and cancellation before native work.
Direct query admission still returns Busy when its capacity is full.
The shared client transport checks the configured output-stall deadline on
the next demand after a returned frame. A quiet pending read is not a stalled
client. Expired demand returns DEADLINE_EXCEEDED and drops the read stream.
This timeout does not cancel trace execution. No idle cleanup task or second
subscription driver is required.
Use the notification, evaluation-future and output-stream pattern in
`mangroves/src/sql/src/execution/subscribe.rs`; do not add DataFusion or copy
its buffer and error behavior.

The client work below starts after this boundary passes. Trusted 7.3 tests
alone do not qualify client SQL. DuckDB memory limits are not a hard process
memory limit. This design does not claim process-level crash containment.

## Implementation flow

```text
Caller starts a CLI command or uses the console
  -> ClientGrpcOwner authenticates the principal and checks the tenant investigate permission
  -> query requests go to the active QueryOwner; trace requests go to TraceOwner in Control
  -> owner returns bounded data and explicit quality/limit state
  -> CLI renders output or console updates the same selected scope

Follow receives a committed change
  -> server emits append or complete replace protobuf frames on the same gRPC stream
  -> owner rechecks the tenant investigate permission before each frame
  -> client applies the declared operation and saves a complete checkpoint
  -> only a broken connection needs a resumed request

Connection drops or authentication expires
  -> follow and trace clients reconnect only with valid current credentials and the same cursor
  -> a one-shot SQL client reports a partial read if the final record is absent
  -> a one-shot SQL client does not send its checkpoint as a resume bookmark
  -> expired history produces an explicit gap error
  -> read failure cannot be shown as completed execution

Initiating CLI receives Ctrl-C
  -> CLI requests cancellation under the caller's tenant investigate permission
  -> CLI reads the bounded final result or reports cancellation uncertainty
  -> Node's independent deadline still bounds execution
```

Status: **Done**.

## Scope, owners, and changes

1. Implement the shared query/trace authentication foundation. Add
   `ClientGrpcOwner` in `mithril-control/src/client_grpc.rs` and the service in
   `proto/erebor/mithril/control/v1/client.proto`, and configuration/wiring in
   the existing Control process. Convert the current optional administrative
   TLS listener into the shared client listener; do not open a second client
   port. Reuse extracted OIDC validation, not administrative-exec authority.
   Browser sessions need CSRF metadata and exact origin checks on gRPC-Web
   mutations; CLI service tokens
   need the dedicated audience and tenant investigate permission. Recheck reads after
   waits. Preserve existing administrative enablement. When the existing
   administrative listener is configured, the shared listener can run while
   query and trace methods remain disabled. Enable those methods only with
   their configuration and the same investigate permission. Enabling admin callbacks does not grant
   query or trace access.
   Keep the investigation browser login membership check. Administrative
   activation keeps its existing request-bound OIDC flow and separate
   approval rules. Both flows use the same OIDC validation owner. An
   administrative login does not create an investigation session.
2. Implement the parent plan's five query/trace RPCs. Use server-streaming
   protobuf frames for one-shot queries, follow and trace output. Implement native gRPC
   for CLI/service clients and gRPC-Web `grpcwebtext` server streaming for the
   browser on the same owner. [gRPC-Web](https://github.com/grpc/grpc-web/blob/master/README.md#streaming-support)
   supports server streaming only in this mode. Use
   [tonic-web](https://github.com/grpc/grpc-rust/blob/master/tonic-web/README.md)
   on the Control listener; it must accept browser HTTP/1.1 and native gRPC
   HTTP/2. Dispatch only registered protobuf service paths to gRPC and
   gRPC-Web. Dispatch only assets and the named protocol-required callbacks
   to HTTPS handlers. Unknown paths fail closed. Do not add a REST/JSON API
   or external proxy. Generate both clients from the pinned protobuf schema.
   Keep 200-row/1-MiB frames and QueryOwner's heartbeat, cancellation and
   stalled-output limits. Trace cancellation is a mutation;
   query cancellation only ends a read. Close DB readers before network I/O.
   Cursor identity, source digest, and target references must survive retries.
   Before a native read-revocation check, reserve one existing AnalysisStore
   reader slot. Keep that slot until the check and cleanup return. Do not
   charge this fixed metadata read as a client SQL evaluation. If a read
   ends after rows but before their checkpoint, report a partial result;
   do not report completion with an older checkpoint.
3. Add SQL and Trace command parsing/rendering to the existing
   `araphor-cli` command tree. Provide the `araphor` entry point without
   copying the tree. Put the generated Control gRPC client in a focused module of
   `erebor-runtime-client`; keep its local-daemon gRPC client unchanged.
   Wire types come from the shared protobuf schema, not client-owned duplicates.
   Use --endpoint or a configured profile for the TLS gRPC endpoint. Phase 7.9
   qualifies direct connection to the remote deployment with these same RPCs;
   do not add another CLI or expose internal Node/delegation endpoints.
4. Implement file/stdin/inline source, recipe references, table/JSONL output,
   SIGINT, broken-pipe handling, transparent follow and trace reconnect, and
   read-only `--resume`. Keep credentials out of argv, source and stdout.
   Normal commands do not create a background job or require a second command.
   Automatic submit retries reuse a key; a newly invoked command is a new
   request. Return the accepted trace ID before lengthy output.
   Keep one retry transition in each SQL and trace read loop. Preserve retry
   limits, delays, credential refresh, interruption and resume rules. For
   ordered append replay, remove the duplicate prefix from rows and positions
   together. Validate order and equal counts before this removal. Use shared
   Output methods for query and trace coverage, health and error text. Keep
   table layout, escaping and JSONL records unchanged.
   QueryRequest.duration_ns holds the prepared SQL duration. Derive the local
   deadline once before retries. Use generated Snafu selectors for CLI errors;
   keep the existing variants, sources, status mapping and exit codes.
5. Extend `catalog` with authorized targets, query fields, recipe source,
   parameters, capability status and examples. SQL `--target` narrows tenant
   inputs before evaluation, including joins and aggregates. Use this phase's
   AST-derived SQL time bounds; no duplicate window flag is required.
   Follow declares append or replace semantics from Mithril 7.3.
   An aggregate uses complete bounded replacements on relevant commits.
   Neither normal nor followed aggregates count a truncated input.
   Reuse 7.3 segment extraction and qualify the asynchronous evaluator here.
   The CLI and console cannot open segments or the metadata database. Both
   SQL follow and trace output use committed store positions and the same
   expiry contract; neither needs a separate subscription store.
6. Extend `ui/mithril-console/src/Console.tsx` and its planned API client.
   Add a trace panel inside Activity/investigation or workload Behavior, not
   another workspace. Show source, requested and resolved targets, Run/Stop,
   output, final aggregate, coverage, and cleanup. Use the same SQL editor/read
   endpoint for retained analysis. An SQL query cannot attach a probe.
   Navigation cancels pending reads, not the trace. A stale reply cannot update
   another target. Render scripts/output as text, not HTML or executable links.
7. Package the CLI client and qualified bpftrace dependency separately from
   browser assets. The user's workstation needs no root, kernel access,
   bpftrace installation, or Node credential. Existing Control serves assets
   and the gRPC/gRPC-Web service on its optional TLS listener. OIDC redirects
   and static assets remain HTTPS; no product data uses a JSON/HTTP API. Do
   not add a database Service, privileged debug Job, remote MCP gateway, or
   general shell endpoint.
8. Move the existing administrative-exec and node-decommission client
   operations from `administrative_http.rs` and `decommission.rs` to typed
   methods on `AraphorAdministrativeService` in the same protobuf package:
   `CreateAdministrativeExecRequest`,
   `PollAdministrativeExecRequest`, `GetAdministrativeExecActivation`,
   `ApproveAdministrativeExec`, `SubmitNodeDecommission`, and
   `GetNodeDecommission`. The activation page uses gRPC-Web for request details
   and approval after login; only its page and OIDC redirect remain HTTPS.
   Preserve one-time poll-token delivery and activation-token separation.
   Migrate `kubectl_mithril` and the current e2e clients before removing their JSON
   routes. Expose this service only on Control, not the optional remote data
   endpoint. Keep `AdministrativeApprovalOwner`, its one-use approval rules,
   and its separate credentials; console membership grants no exec authority.
   Keep the activation page and authorization redirect, OIDC callback, and
   Kubernetes admission/token-review webhooks on HTTPS because those external
   protocols require HTTP. Mount the existing administrative callbacks on the
   shared TLS listener and update their redirect and webhook configuration.
   The separate policy-admission webhook remains a Kubernetes HTTPS callback,
   not a client API. Remove `serve_administrative_http` and its separate
   listener configuration. Remove the old administrative-exec and
   node-decommission JSON routes in this phase; do not leave a parallel
   business transport.

## Acceptance and verification

Pass `OBS-CLI`, `OBS-API`, `OBS-CONSOLE`, and existing `DE-QUERY`, `DE-FOLLOW`,
`DE-AUTH`, `DE-DISCLOSE` cases through production owners. Test invalid/conflicting
flags, stdin EOF, source edit after submission, empty output with terminal
success, missing terminal result, JSON escaping, foreign-tenant trace reads, revoked
token, CSRF, read-only resume, duplicate submit, cursor expiry and slow clients.
API success must not conceal a partial trace or failed cleanup.
For one-shot SQL, disconnect after a complete checkpoint but before the final
record. Require a partial read and no second request. Cover normal EOF and
retryable transport errors. Follow and trace reads must retain their existing
checkpoint replay behavior.

Add `query_admission_` and asynchronous execution tests beside the data owner.
Compare each accepted SQL bound with full authorized-input evaluation in the
pinned DuckDB. Cover OR, aliases, CTE reuse, self-joins, outer joins, quoted
and shadowed names, nulls, timestamp offsets/precision and bound endpoints.
Reject unsupported moving predicates. Accept predicates and aggregates on all
available columns, including `policy_rule_id`. Check foreign-tenant row counts.
Use the same permission for recipe and supported script submission. Reject nested forbidden functions and file/network/extension
access. Test native SQL errors, task panic, deadlines, future drop and stream
cancellation. Prove that evaluation capacity remains charged until cleanup.
With discovery analysis disabled, cause an actual native SQL error during a
trace. Require fresh output and a durable ACK after the query failure.
Run this lightweight case before its paired physical Kubernetes case.
Test configured N/N+1 input, output and concurrency bounds with small fixtures.
These are correctness checks, not authorization for new performance workloads.

Run a terminal-agent task that starts one CLI command and reads it with the
agent's existing terminal mechanism. No provider call is required for the
recorded interaction proof. Phase 7.7 defines optional external-agent
compatibility evaluation. Live model evaluation is not a core completion gate;
the external operator owns the model and its execution.
Run the same trace from the console and compare source digest, target snapshot,
owner result and output schema. Browser tests cover keyboard-only use, Stop,
navigation during reads, disconnection and explicit partial results.

Add `observability_cli_` and `observability_grpc_` tests. Migrate the existing
`control_tls.rs` decommission and `kubernetes_approval.rs` business-client
calls to native gRPC or gRPC-Web as appropriate. Prove the old administrative
and decommission JSON routes are absent, unknown paths are rejected,
the OIDC and Kubernetes callbacks still work, and approval/decommission
decisions are unchanged. Check protobuf frame fields, operation order,
complete checkpoint replay and trace terminal results through both native
gRPC and gRPC-Web clients. Run focused tests,
the existing UI check/test/build/e2e scripts, Helm checks, and full Rust CI.
Record exact versions and nonzero case counts. A fixture-only UI cannot pass.

### End-to-end deliverable

Add `query-trace-client` to
`crates/mithril-e2e/src/bin/mithril_observability_test.rs` and implement the
case in the existing `src/observability.rs` module family. Start production
ClientGrpcOwner and invoke the built araphor binary from mithril-e2e.
Submit a file, change that local file after submission, and verify the
accepted bytes/digest remain fixed. Require one command to print its own trace
through cleanup; SQL is not a mandatory second command.

Follow an aggregate while commits arrive and while a window expires. Verify
replace semantics through both CLI and browser. Interrupt the initiating CLI,
then a resumed viewer; only the first requests execution cancellation.
Restart the gRPC connection, revoke access during a quiet stream, expire a
cursor and change console scope. No stale frame may enter another view.
Unit tests cover argument rejection, protobuf framing, escaping, auth and CSRF.
Browser tests use the built Control assets and generated gRPC-Web client, not
fixture-only data. Require one-shot and server-streaming parity with native
gRPC, including browser reconnect and terminal error handling. Prove that a
browser receives a follow frame before the stream closes; buffering the full
stream does not pass.

## Implementation result

Status: **Done**. Implementation uses the primary `main` checkout.
The shared TLS listener, typed administrative migration, native CLI and
generated browser client are implemented. The investigation login membership
check remains required. Native and live-browser checks pass at their recorded
source revisions. The current release images pass the paired capture case and
the migrated administrative approval case. An earlier startup failure remains
unexplained. The final Rust procedure passes at `3e8a4349` after the accepted
review corrections. Read their result below. Performance remains
**UNQUALIFIED**. Deployment diagnostics stay disabled.

The data crate changes use the closed SQL binder, tenant-selected input and
current-authority checks for query and follow. The approved rewrite removes
column and target grants, query signatures and result hashes. The
asynchronous execution and standard stream changes pass the 85 query owner
tests. All available columns are readable; the `policy_rule_id = 42`
aggregate passes without a column grant. Foreign-tenant sources reject.
These earlier query tests do not qualify the later transport integration.
The trace owner now uses the shared tenant investigate permission for reads,
cancellation and supported source submission. Signed Node leases, source
validation, exact target lifetimes, bounds and cleanup checks remain required.

The query-failure trace-upload case must call the production in-process
QueryOwner, TraceOwner, Node capture and mTLS upload with discovery disabled.
Its external fixtures supply the backend and target identity. The lightweight
`observability_query_upload` case passes: a native SQL conversion error is
followed by new output, durable ACK, exact replay and reopen checks. The paired
physical case must keep Control's non-root user and security settings.
No process-isolation or performance result is required by this query design.

The final Rust CI procedure passed at `55b804b3` on 2026-10-05:
format check, workspace check, all-feature clippy with warnings denied, and
all-target, all-feature workspace tests. The data crate passed 216 tests,
including the 85 query tests; the shared trace crate passed 23 tests. The
lightweight query-failure trace-upload case also passed in this procedure.
This result does not cover later client integration edits.
Ignored physical and performance cases did not run. At that source, the paired
physical client case, shared listener, route migration, CLI and console were
not qualified. The
[implementation review](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/implementation-review.md#public-query-boundary-review)
links the present owners and tests. Continue with public client work only
after the query boundary passes.

An earlier browser source passed its type check, 16 unit tests and production
build on 2026-10-06. Generated clients use the shared protobuf schema,
gRPC-Web 2.0.2 and `grpcwebtext`. Assets include
`assets/administrative.js` and `assets/administrative.css`. The strict content
security policy remains unchanged. Unit tests do not prove TLS, OIDC login,
browser streaming or live trace execution. Those checks remained open at that
source. The later live-browser result is recorded below.

An earlier source passed 24 existing browser layout and accessibility tests
on 2026-10-06. These tests use the production asset build, but do not connect
to Control. They do not qualify live gRPC-Web or OIDC behavior.

The current TLS fixtures passed `observability_oidc_login`,
`observability_query_upload` and `https_decommission_keeps_status` on
2026-10-06. Each command passed one enabled test. The first two commands
failed before the fixture set its standard socket to nonblocking mode.
The production listener needed no socket change. The decommission test
checks native TLS gRPC and absent JSON business routes. The authentication
suite passed 12 tests, including `client_auth_membership`. A non-member
cannot create a session. Removed membership prevents a new session.
The administrative HTTP owner suite passed seven tests. These checks do not
replace the built-CLI, live-browser or paired physical cases.
`control_context_retained_targets` also passed one test. It checks retained
target contexts, exact input selection, duplicate publication and reopen.

The current shared transport filter passed nine tests on 2026-10-06.
`observability_grpc_missing_data` also passed as an exact single-test command.
It opens the real configuration fallback with a corrupt temporary data store.
All five investigation RPCs return `UNAVAILABLE` after authentication. Missing
credentials, missing mutation CSRF and removed membership still reject.
The policy owner remains available. The corrupt input file remains unchanged.

The built-CLI `query-trace-client` case passed on 2026-10-06. The exact
`observability_cli_client` test also passed: one enabled test, zero failures.
It checks fixed submitted source, identical retry, durable output ACK, SQL
replacement, viewer interruption without capture cancellation, and initiating
interruption with cancellation. SIGINT returns 130. The retained terminal
has `complete: true`, `cleanup_complete: false` and `output_incomplete: true`.
This is not proof of verified native BPF cleanup. A prior run reached a query
deadline. The unchanged rerun passed; no deadline limit changed. The fixture
now rejects an unexpected typed error before an expected startup frame.
At `e79f3084`, the native case passed all ten checks and its exact ignored
wrapper passed one test. The additional checks cover natural completion,
timer-only window expiry, listener restart and cursor expiry. Natural completion
reports complete output but unknown cleanup; the CLI returns a partial result.
The live Control-backed browser case passed one test. These results do not
prove native BPF cleanup.

An earlier data-owner suite passed 239 enabled tests on 2026-10-06. Five
tests were ignored. Two ignored process-isolation tests were then removed;
they do not test the approved in-process query owner. The remaining ignored
tests are performance qualification cases. No performance case ran. The
earlier Control owner suite passed 204 tests with zero failures and two
ignored tests. These runs do not replace the final workspace procedure.

An earlier paired VM run passed all three lightweight prerequisites and the
physical Pod replacement case on 2026-10-06. The harness returned exit zero,
including its receipt checks and teardown. Both captures reported Verified
cleanup. Original output remained unchanged after replacement and retry.
A native TLS SQL error was followed by fresh output and durable ACK.
The query ran in-process with discovery disabled. The platform was Linux
x86_64, kernel 6.8.0-142 and K3s v1.35.5+k3s1, with stock bpftrace 0.20.2
as a checked private test input. Diagnostic admission was synthetic-test-only;
performance remains unqualified. The receipt is
`/tmp/araphor-pod-retry.d6g9SNwz/result.json`.

The physical case at the final client build failed before capture. Python startup returned
`EACCES` for `/usr/local/lib/python3.13/encodings/aliases.py`. The cause is
unknown. No capture receipt was produced. The three lightweight prerequisites
passed; the physical case failed. The retained log is
`/tmp/araphor-pod-final-close.eUKgZKea/test.log`. The earlier physical pass does
not qualify this later source. No security setting or protected-start owner
was changed after this failure. The user approved investigation into
protected-start owners. This approval does not authorize an enforcement change.
The diagnostic result is recorded below.

The first physical run failed after its Control child exited 101. Its error
text was lost during teardown; the cause remains unknown. The second run
used the same images and limits. Its fixture adds bounded current/previous
Control logs and preserves failed capture files. The exact
`observability_capture_cleanup` regression passed one test before that run.

The current Helm lint and template checks passed on 2026-10-06. They check
the shared client port, administrative enablement and query-only deployment
shape. They do not prove a running deployment.

The browser asset Docker stage passed on 2026-10-06 on Linux x86_64 with
Node 24.15.0 and protoc 3.21.12. It regenerates the clients from the shared
schema and builds the assets without host `node_modules`. Control packages
these assets at `/usr/share/araphor/console`; configure `client.assets` with
that absolute path. Current Control, Node and CLI release images also built
on 2026-10-06. Each image returned exit code zero for `--help`. These checks
prove packaging and executable startup. They do not qualify a deployment,
browser connection or capture.

### Current client qualification

Production implementation source: `878de63e`. Qualification source: `6cb2de82`.
Status: **Done**. The final Rust procedure returns zero at this source.
Shared listener, typed administrative migration,
in-process SQL, asynchronous follow, CLI and live console checks pass.
The login membership check remains required. Administrative approval remains
separate from the tenant investigate permission.

| Check | Result on 2026-10-06 |
| --- | --- |
| Final Rust procedure | PASS at `6cb2de82`. Format check, workspace check, all-feature Clippy with warnings denied, and all-target, all-feature tests return zero. Across 77 top-level suites, 1,617 tests pass, zero fail and 545 are ignored. Ignored cases are not passes. |
| Built native client | PASS at `6cb2de82`. All ten receipt checks pass with the current CLI and fixture. Natural completion preserves complete output and unknown cleanup, with exit 4. Cancellation and viewer interruption remain distinct. This fixture does not prove native BPF cleanup. |
| UI and live browser | PASS. Type check, production build, 23 unit tests, 24 layout/accessibility tests and one live Control test pass. The current live case proves timer-only COUNT expiry and keyboard submit/Stop. Non-member login, streaming, reconnect, CSRF and quiet revocation pass. No page or content-security-policy error occurs. |
| Helm and release images | PASS. Existing lint/template checks pass. Control, Node and client images build. Read-only, network-disabled startup and native-library checks pass. Control and client keep UID 65532. Console assets are present. The current images are imported into the owned VM. |
| Physical client failure at the final build | FAIL. Three lightweight prerequisites pass. Python startup fails before capture with the error recorded above. The cause is unknown. No capture receipt exists for that run. |
| Protected-start diagnostic rerun | PASS. The same failed-run production images and pinned actor complete the case in 203.23 seconds. Both captures report Verified cleanup. This rerun does not establish the earlier failure cause. |
| Current-image physical capture | PASS. The three lightweight prerequisites and the physical case pass. The harness returns zero after receipt checks and teardown. The physical case takes 205.51 seconds. Both captures report Verified cleanup. Enforcement resources remain unchanged. |
| Migrated administrative approval | PASS. The cluster-free owner case passes one test. The existing Kubernetes case passes one test in 100.49 seconds on the current images. OIDC, typed approval, missing-CSRF rejection, separate activation/poll tokens, one-use delivery and Kubernetes exec decisions pass. |
| Query task panic | PASS. Sixteen focused client owner tests pass, including `query_client_panic`. The test proves typed failure, reservation release and a subsequent query on the same owner. No production panic hook exists. |
| Terminal-agent interaction | PASS. One built SQL-follow command emits metadata, replacement rows and a checkpoint. The agent polls the same terminal handle; the command exits zero. The fixture then exits zero. This interaction does not create a monitoring job. |
| Performance | UNQUALIFIED. No new performance test or benchmark ran. Diagnostic deployment remains disabled. |

The final Rust command is:

```sh
CXXFLAGS='-O2 -g0' CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_NET_OFFLINE=true RUST_TEST_THREADS=1 \
  bash .github/scripts/verify-rust-ci.sh
```

Read `/tmp/araphor-client-completion-ci.log` for the current procedure.
The data crate passes 248 tests. The shared observability crate passes 23
tests. The top-level counts exclude nested recovery subprocess summaries.
The earlier `/tmp/araphor-startup-rust-ci.log` returns exit zero at
`13816cbb`, before the later qualification edits. The earlier
`/tmp/araphor-client-final-rust-ci.log` covers implementation commit `878de63e`.
The recovery test now includes the approved `selection` and `finding_reference`
fields. Its source-copy exclusion, round-trip and binding checks remain.
The owner review finds no new service, queue, store or payload copy.

The native command is:

```sh
target/debug/mithril-observability-test --case query-trace-client \
  --output-directory /tmp/araphor-client-count-native.Yq0erazU \
  --client-executable /home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target/debug/araphor
```

The receipt directory must be empty before this command starts. Keep the
command log outside that directory. Read `result.json` in the named directory
and `/tmp/araphor-client-count-native.log`. The receipt declares
`sql_execution: in-process`, `physical: false` and `performance_claim: false`.
The earlier committed `observability::client::tests::observability_cli_client`
wrapper passes one enabled test at `878de63e` with `ARAPHOR_CLI` set to that CLI.
Read `/tmp/araphor-client-final-native-wrapper.log`. Its command uses
`cargo test --workspace --all-targets --all-features` with that exact test name
and `-- --exact --ignored`. Other filtered test binaries do not count as proof.
The current CLI SHA-256 is
`e839ca4800a4fb354b888a2e016da808b6a0f4d1751d90c13de062df22200d06`.
The current fixture SHA-256 is
`fed400e04c972e24a9580e7d84977da3b61ff1eec97eb59212fb12ce154d651b`.
These hashes identify qualification artifacts; the product does not calculate
query or result hashes.

The UI commands are `npm run check`, `npm run test`, `npm run build` and
`npm run test:e2e` in `ui/mithril-console`. Their logs are in
`/tmp/araphor-console-checks.Y9qZ50rC`. The live command is:

```sh
ARAPHOR_CLIENT_FIXTURE=/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target/debug/mithril-observability-test \
  npm run test:control -- --output=/tmp/araphor-browser-window-keyboard.eccMgKVa/results-final
```

Read `/tmp/araphor-browser-window-keyboard.eccMgKVa/control-browser-final.log`.
The current live case passes one test in 20.7 seconds. The browser uses built assets,
generated gRPC-Web and real TLS/OIDC fixture endpoints. The browser test does
not mock page responses or disable HTTPS or content-security-policy checks.
Fixture shutdown returns zero. Production build warnings from `google-protobuf`
and chunk size remain explicit; the live test reports no policy error.

The browser sends one acknowledged raw event before capture. COUNT changes
from 1 to 0 without a new commit. The displayed read revision stays unchanged,
and the same gRPC-Web request stays open. Tab, Enter and Space operate SQL and
trace submit/Stop controls. The list reporter does not retain exact timer
values on success. The native receipt separately records advancing server
evaluation time at unchanged read revision 2. Retained cursor expiry runs
through native TLS `WatchTrace`; `observability_cli_exit_codes` checks CLI
exit 4 for `CursorExpired`. Do not describe that cursor check as a launched
CLI command.

The terminal-agent command is:

```sh
target/debug/araphor --profile /tmp/araphor-agent-terminal.rtH304SL/client.json \
  --output jsonl sql 'SELECT count(*) AS count FROM catalog' \
  --follow --duration 5s
```

Read `/tmp/araphor-agent-terminal.rtH304SL/agent-sql-follow.jsonl`. The agent
uses the normal terminal execution handle and polls that same handle.
The local read duration ends after a complete checkpoint. No server terminal
frame is retained for this interaction; this result is not capture completion.

The physical command uses `harness/observability/pods.sh`, the current
workspace test binary, `--test-admission` and the checked private runtime.
Node and Control tags are `20261006-verified-close`. Their image IDs are
`93bff57290eab691ac9dafe1bb2da6fe0e4fc133d7c07d3c91727c137ba5a5e2`
and `c0590583166696cd9d872ed4432b6d98b534a7000ce2668ca720e4a06c33f0b2`.
The actor uses the pinned Python digest recorded below. Read
`/tmp/araphor-release-pods.9KWhYNOX/result.json` and its four case logs.
After the SQL error, output sequence advances from 2 to 3, read revision from
19 to 21 and output bytes from 85 to 134. The Node acknowledges that output.
The receipt proves no process isolation or native query interruption.

The migrated approval case is
`effect::admin_exec::approved_exec_consumes_once::identity_kubernetes`.
Read `/tmp/araphor-admin-release-light.log` and
`/tmp/araphor-admin-release-physical.log`. The case uses the same current
Node, Control and actor images. Both physical fixtures remove their Pods.
They do not change enforcement configuration or enable deployment diagnostics.

Earlier qualification attempts are not passes. One browser attempt reaches
the unchanged filesystem reserve; another uses an unsupported moving-clock
projection. One native attempt reaches the query deadline during concurrent
verification. The unchanged standalone native case passes. No reserve,
deadline, authorization or production SQL rule changes for these reruns.

The packaging command is `bash packaging/mithril/helm/tests/verify.sh`.
Read `/tmp/araphor-client-final-helm.log` and the `verified-close-*` build and
startup logs in `/tmp/araphor-physical-images.tAbN8Ggz`.
The images contain the final production changes. The later recovery correction
changes a `cfg(test)` assertion only. No protected-start or security change is
part of this packaging result.

Versions: rustc/cargo 1.97.1, pinned DuckDB sys crate 1.10505.0,
Node 24.15.0, npm 11.12.1, TypeScript 7.0.2, Vite 8.2.2, Vitest 4.1.11,
Playwright 1.62.1, Chromium 151.0.7922.34, gRPC-Web 2.0.2, protobuf 4.0.3,
protoc 3.21.12 and Helm 3.8.0. The earlier physical platform and private
bpftrace version remain as recorded above. Those versions do not convert
the recorded physical failure into a pass.

### Protected-start investigation

Diagnostic source: `13816cbb`. Result: **Not done**. The original failure cause
is not identified. The diagnostic owner and its correctness tests are complete.
The final Rust procedure passes at this source with 1,616 enabled tests,
zero failures and 545 ignored tests. Read `/tmp/araphor-startup-rust-ci.log`.

The pinned Python image starts without Mithril on the same VM. Python
3.13.15 reads all 16,011 bytes of `encodings/aliases.py` and exits zero.
The diagnostic Pod uses the same interpreter and container security settings.
The fixture removes this Pod after the check. This check does not prove
protected startup or the cause of the earlier denial.

The retained failure log shows policy activation and declared-entry approval
before the failed Python startup. Earlier policy-pending responses do not
release that startup. The original diagnostics retain only 16 recent effects;
those effects are allows. The first denied read is not available.

`Kubernetes::capture_result` now saves the full bounded Node snapshot and health
in `node-snapshot.pb` before failure cleanup. It saves the original error in
`capture-failure.txt`. An unavailable observer produces
`node-snapshot-error.txt`; the original failure remains the returned error.
The owner uses the existing snapshot API. It adds no kernel reader.
`observability_startup_failure` passes on the host and VM without Kubernetes.
This test proves diagnostic retention for a failure before a capture receipt.
It does not reproduce the kernel denial. The existing capture cleanup test
also passes.

The protected diagnostic rerun uses Node and Control tags
`20261006-final-close`, not the later `20261006-verified-close` images.
The actor remains pinned to
`docker.io/library/python@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285`.
All three lightweight prerequisites and the physical case pass. Both intended
denials have errno 13, zero read bytes and `EXACT_POLICY_DENY`. The receipt
reports unchanged enforcement resources, query recovery and Verified cleanup
for both captures. The fixture removes its Pods and Mithril links.
Read `/tmp/araphor-startup-investigation.GoAtyn/result.json`, `test.log` and
`startup-effects-20261006.log`. The observer stops when cleanup closes its
socket. Its bounded snapshots do not prove the absence of an earlier denial.

No Node, kernel, policy or authorization code changes in this investigation.
A mount-cache failure is a candidate cause, not a result. A matching denied
event must identify its reason and `operation_argument` before an enforcement
fix is selected. The earlier failure remains unexplained. This diagnostic
run alone does not qualify the later release images. The separate current-image
result is recorded above. Performance remains **UNQUALIFIED**.

### Accepted review corrections

Status: **Done** at source `3e8a4349`. The client retry correction is commit `79af516f`.
The CLI reports exit 4 instead of sending a one-shot resume request. The
browser retains the last complete rows and reports a partial read. Follow
and trace retry behavior remains supported. The new CLI and browser
regressions fail before the correction and pass after the correction.
Commit `3e8a4349` removes both client follow wrappers and the duplicate test
fixture method. All clients use the same stream entry point. The missing-grant
check remains tested. The supporting query plan uses unsigned bookmarks and
bounded Tokio execution. No query process is required.

The CLI filter passes 13 tests. The client query-owner filter passes 37 tests.
The UI passes 27 unit tests, its type check, production build, 24 layout and
accessibility tests, and one live Control browser test. The current native
client passes all ten receipt checks. The complete Rust procedure returns zero:
77 top-level suites, 1,618 passed tests, zero failures and 545 ignored tests.
The counts exclude nested recovery helpers. Ignored cases are not passes.

Read `/tmp/araphor-review.77Y1JsTg/rust-ci.log`, `browser.log`,
`browser-results/` and `native/result.json`. These results cover source
`3e8a4349` and the current browser assets. One-shot disconnection is a
component proof; the live cases preserve existing follow and trace behavior.
No physical case or performance test ran. The earlier physical proof limits
remain unchanged. Performance remains **UNQUALIFIED**.

### CLI crate rename

Rename the shared CLI package and source directory to `araphor-cli`.
Status: **Done**.

#### Intended end state

Build only `araphor` from `crates/araphor-cli`. Use one root parser, one command
dispatch path and one error handler. Keep every command feature, output record
and exit code. Put `catalog`, `sql` and `trace` at the root with the existing
Runtime commands. Do not keep an `erebor` executable or a nested `araphor`
command. Keep the existing transport and execution owners.

Keep profile, endpoint and query-output options in one shared argument type.
Use that type for the root parser and the query/trace owner. Reject a local
daemon socket on query, catalog and trace commands. Reject the TLS profile,
endpoint and query-output options on Runtime commands. Do not select a transport
by a fallback. Replace selector conversion with `TryFrom`. Use `From` for the
shared CLI error conversion.

Follow uses table output by default, including when stdout is a pipe. Keep
the existing stdout-based default for other commands. Use the same table layout
for Runtime lists, one-shot query rows and follow rows. Print each row batch
when it arrives. Do not keep a growing row list or add a second follow renderer.
Keep append and replace markers, coverage, limits and errors visible.
`--output jsonl` retains the full structured records for agents and scripts.
Test default table follow with the built executable and production query owner.

```text
Cargo builds araphor-cli
  -> the workspace selects crates/araphor-cli
  -> one executable entry point calls the araphor_cli library
  -> existing command owners retain their behavior

An operator selects query or trace input
  -> TryFrom validates the existing selector bounds
  -> the CLI sends the same InputSelection through the existing client

A selector is invalid
  -> TryFrom returns the existing invalid-input error
  -> the CLI returns exit code 2
```

Update packaging, executable test helpers, active source links and runnable
examples. Do not change archived recovery documents, prior test counts or source
revisions. Run all CLI tests, build the executable, run the built native client case,
and run `bash .github/scripts/verify-rust-ci.sh` after the last code edit.
No new performance test or physical-capture claim is part of this change.
The retry-counter and trace-lifetime review findings remain separate work.

#### Verification

On 2026-10-06, all 58 CLI tests passed. Cargo metadata lists one CLI executable:
`araphor`. The built native client case passed with the production query and
trace owners. It checked default table follow through a pipe, explicit JSONL,
reconnect, window expiry, selected output and trace lifecycle.

`bash .github/scripts/verify-rust-ci.sh` passed after the last code edit.
Formatting, workspace check, Clippy and workspace tests passed. Existing ignored
tests remained unchanged. Syntax checks passed for the changed shell scripts.
The workspace gate used `TMPDIR=/dev/shm` to keep Unix socket paths short.

Read `/tmp/araphor-cli-rename.02oJID66/rust-ci-final-gate.log` and
`/dev/shm/araphor-cli-rename.WJf822e3/native-table/result.json`.
`table.stdout` in the native result directory contains the built follow output.
Temporary stores used tmpfs. These checks do not qualify disk durability,
physical capture or performance. Performance remains **UNQUALIFIED**.

### Consumer-driven stream correction

Implementation: `7b828c0a`. Final code corrections: `11b3a725`.
Qualification: **Done** for scoped correctness. The final workspace procedure
passed after the last code edit.
The data owner returns one lazy QueryStream. All existing clients poll that
stream through the same transport. No producer task or output channel remains.

ClientGrpcOwner uses one output adapter for query and trace reads. The adapter
checks elapsed time on the next request for a frame. Slow demand closes that
read; it does not cancel the trace execution. A quiet pending read remains
valid. Grant and retained-read checks still apply before disclosure.

The 131 data query tests, 14 Control gRPC tests and eight standalone follow
cases pass. The transport tests check slow demand, a quiet pending read and
continued trace output after a read timeout. Read
`/tmp/araphor-profile-follow.tPl3zk/query-follow-final/result.json` and
`/tmp/araphor-profile-follow.tPl3zk/rust-ci-final-5.log`.
The full Rust procedure passed at `11b3a725` after the last code edit. It returned
zero: 1,626 tests passed, zero failed and 544 were ignored. The counts exclude
nested recovery helpers. Ignored tests remain unqualified.
No browser, physical case or performance test ran for this correction.
Earlier browser and physical proofs retain their recorded source limits.

### Owner composition result

Source: `be7f411c`. Commit `504fe5d8` retains one native query checkpoint and
decodes trace bookmarks once. Commit `36c30113` uses one retry transition in
each CLI read loop, removes replay prefixes with paired drains, and shares
coverage, health and error text. No command feature or wire field changes.
Commit `be7f411c` copies QueryHealth directly in one test; production code is
unchanged.
Status: **Done** for scoped correctness.

On 2026-10-07, all 58 CLI tests passed. The affected-library command also
passed the full-header duration and trace-bookmark validation tests. Use the
[query result](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/phase-7-3-query-and-follow.md#owner-composition-result)
for the build command, environment and library counts.

```sh
target/debug/mithril-observability-test --case query-trace-client --output-directory /tmp/araphor-owner-simplify.ht265y/native-client --client-executable /home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target/debug/araphor
```

The built-client command passed. It checked default table follow through a
pipe, reconnect, exact retry, selected output, normal completion, initiator
cancellation and viewer interruption. The printed table was also inspected.
Read `/tmp/araphor-owner-simplify.ht265y/native-client/result.json` and
`table.stdout` in that directory. The command uses production TLS clients,
query and trace owners, and a runtime/backend fixture. It does not prove
physical BPF cleanup or performance. Earlier browser and physical results
retain their named source limits.

The final Rust procedure passed at `be7f411c` after the last Rust edit.
Formatting, workspace compilation, strict Clippy and all-target/all-feature
tests passed: 1,629 passed, zero failed and 544 existing tests were ignored.
Counts exclude nested subprocess helpers. Ignored cases remain unqualified.
Read `/tmp/araphor-owner-simplify.ht265y/rust-ci-final.log`.

### Accepted simplification result

Source: `667209fe`. Control reuse is commit `d101aad3`; CLI reuse is commit
`667209fe`. Status: **Done** for implementation and scoped correctness.
Trace output uses the existing frame and position conversions. The CLI derives
one local deadline from QueryRequest.duration_ns. Generated Snafu selectors
replace seven error-factory methods. Permissions, retries, output and trace
cancellation rules do not change.

All 25 Control adapter tests and 58 CLI tests pass. The built native client
case passes all ten receipt checks. Default follow still prints tables through
a pipe. Reconnect, exact retry, timer expiry, selected output, initiator
cancellation and read-only interruption pass. Read
`/tmp/araphor-five-cuts.Gor7fD/control.log`, `cli.log`,
`native-client/result.json` and `native-client/table.stdout`.
The [query result](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/phase-7-3-query-and-follow.md#accepted-simplification-result)
records the data-owner proof. These are component and lightweight end-to-end
checks, not physical or performance qualification.

The final Rust procedure passes at `667209fe` after the last Rust edit.
Formatting, workspace compilation, strict Clippy and all-target/all-feature tests
return zero: 1,630 tests pass, zero fail and 544 existing tests are ignored.
Counts exclude nested recovery helpers. Ignored cases remain unqualified.
Read `/tmp/araphor-five-cuts.Gor7fD/rust-ci.log`.

### Checkpoint guard result

Source: `5f885e2d`. Status: **Done** for implementation and scoped correctness.
QueryTransport uses one QueryGuard slot. Stored owns the last disclosed complete
checkpoint. Checking owns a future that returns the same frame after its
retained-read check. Current access checks, pending rows and trace state remain.

The Control library passes 167 tests, with one existing ignored test. Zero tests
fail. `observability_grpc_duration_wait` checks revocation and drop while the
final read check waits. Existing duration, incomplete-row and trace tests pass.
The built CLI still prints default follow tables through a pipe. Read the
[field ownership result](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/phase-7-3-query-and-follow.md#field-ownership-result)
for the native client receipt, commands and limits.

## Stop point

Stop before CRD delivery and arbitrary-script tenant isolation claims.
Phase 7.7 adds assessment submission. Phase 7.8 adds review/publication to
this same listener; neither builds it again.
