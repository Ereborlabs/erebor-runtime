# Phase 3: CLI, API, And Console

Expose SQL and diagnostic capture through one CLI and the existing console.
Require Observability 2 and Phase 7.3 Done.
Reuse shared query code; do not reimplement SQL evaluation or tracing in a client.

## Intended end state

An agent runs `araphor sql` or `araphor trace` in its terminal. Both commands
print their own results. The console calls the same APIs and shows the same
source, provenance, limits, and outcomes. MCP is not a release dependency.

## Implementation flow

```text
Caller starts a CLI command or uses the console
  -> ClientGrpcOwner authenticates the principal and checks current grants
  -> query requests go to the active QueryOwner; trace requests go to TraceOwner in Control
  -> owner returns bounded data and explicit quality/limit state
  -> CLI renders output or console updates the same selected scope

Follow receives a committed change
  -> server emits append or complete replace protobuf frames on the same gRPC stream
  -> owner rechecks scope and disclosure before each frame
  -> client applies the declared operation and saves a complete checkpoint
  -> only a broken connection needs a resumed request

Connection drops or authentication expires
  -> client reconnects only with valid current credentials and the same cursor
  -> expired history produces an explicit gap error
  -> read failure cannot be shown as completed execution

Initiating CLI receives Ctrl-C
  -> CLI requests cancellation under the caller's trace grant
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
   need the dedicated audience, scope, and export grant. Recheck reads after
   waits. Preserve existing administrative enablement. When the existing
   administrative listener is configured, the shared listener can run while
   query and trace methods remain disabled. Enable those methods only with
   their own configuration and grants. Enabling admin callbacks does not grant
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
   parameters, capability status and examples. SQL `--target` narrows allowed
   inputs before evaluation, including joins and aggregates. Reuse Mithril 7.3
   for AST-derived SQL time bounds; no duplicate window flag is required.
   Follow declares append or replace semantics from Mithril 7.3.
   An aggregate uses complete bounded replacements on relevant commits.
   Neither normal nor followed aggregates count a truncated input.
   Reuse DuckDB and the qualified isolated worker.
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
success, missing terminal result, JSON escaping, foreign trace reads, revoked
token, CSRF, read-only resume, duplicate submit, cursor expiry and slow clients.
API success must not conceal a partial trace or failed cleanup.

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

## Stop point

Stop before CRD delivery and arbitrary-script tenant isolation claims.
Phase 7.7 adds assessment submission. Phase 7.8 adds review/publication to
this same listener; neither builds it again.
