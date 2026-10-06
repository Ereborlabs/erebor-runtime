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

Frames do not need a separate frame ID or result digest. Append replay uses
exact row positions within one query and store epoch. Replacement output
is one complete bounded result. An edited bookmark can replay or skip rows
that the current caller can read; it cannot grant access. The server does not
prove that the SQL or selection is unchanged. Policy signatures and signed
Control-to-Node execution leases remain required.

`QueryStream` implements `futures::Stream<Item = Result<QueryFrame>>`.
Committed changes wake follow. An evaluation future returns bounded append
rows or one complete replacement. The stream returns frames in order, then
waits for the next relevant commit or expiry. Keep one bounded output channel.
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
  -> client reconnects only with valid current credentials and the same cursor
  -> expired history produces an explicit gap error
  -> read failure cannot be shown as completed execution

Initiating CLI receives Ctrl-C
  -> CLI requests cancellation under the caller's tenant investigate permission
  -> CLI reads the bounded final result or reports cancellation uncertainty
  -> Node's independent deadline still bounds execution
```

Status: **Not done**.

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
3. Add SQL and Trace command parsing/rendering to the existing
   `erebor-runtime-cli` command tree. Provide the `araphor` entry point without
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

Status: **Not done**. Current changes use primary `main` based on `cec19dd0`.
The client listener, administrative gRPC migration, CLI and console are not
implemented. Do not enable public SQL from this partial result.

The data crate changes use the closed SQL binder, tenant-selected input and
current-authority checks for query and follow. The approved rewrite removes
column and target grants, query signatures and result hashes. The
asynchronous execution and standard stream changes pass the 85 query owner
tests. All available columns are readable; the `policy_rule_id = 42`
aggregate passes without a column grant. Foreign-tenant sources reject.
No client listener, administrative gRPC migration, CLI or console result is
proved by these partial changes.
The existing trace owner still uses scoped execution/read grants and custom
source approval. Replace those user permission checks with the shared tenant
investigate authority during client integration. Keep signed Node leases,
source validation, exact target lifetimes, bounds and cleanup checks.

The query-failure trace-upload case must call the production in-process
QueryOwner, TraceOwner, Node capture and mTLS upload with discovery disabled.
Its external fixtures supply the backend and target identity. The lightweight
`observability_query_upload` case passes: a native SQL conversion error is
followed by new output, durable ACK, exact replay and reopen checks. The paired
physical case must keep Control's non-root user and security settings.
No process-isolation or performance result is required by this query design.

The final Rust CI procedure passed on the current source on 2026-10-05:
format check, workspace check, all-feature clippy with warnings denied, and
all-target, all-feature workspace tests. The data crate passed 216 tests,
including the 85 query tests; the shared trace crate passed 23 tests. The
lightweight query-failure trace-upload case also passed in this procedure.
Ignored physical and performance cases did not run. The paired physical client case,
shared listener, route migration, CLI and console remain unqualified. The
[implementation review](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/implementation-review.md#public-query-boundary-review)
links the present owners and tests. Continue with public client work only
after the query boundary passes.

## Stop point

Stop before CRD delivery and arbitrary-script tenant isolation claims.
Phase 7.7 adds assessment submission. Phase 7.8 adds review/publication to
this same listener; neither builds it again.
