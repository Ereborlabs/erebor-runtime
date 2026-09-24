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
  -> ConsoleHttpOwner authenticates the principal and checks current grants
  -> query requests go to the active QueryOwner; trace requests go to TraceOwner in Control
  -> owner returns bounded data and explicit quality/limit state
  -> CLI renders output or console updates the same selected scope

Follow receives a committed change
  -> server emits append or complete replace frames on the same HTTP response
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

1. Implement the shared query/trace authentication foundation. Add `ConsoleHttpOwner` in `mithril-control/src/console_http.rs` and
   configuration/wiring in the existing Control process. Reuse extracted OIDC
   validation, not administrative-exec authority. Browser sessions need CSRF
   and origin checks; CLI service tokens need the dedicated audience, scope,
   and export grant. Recheck reads after waits. Default listener stays off.
2. Implement exactly the parent plan's five routes. Use normal JSON for a
   bounded query and JSONL response streams for follow and trace output.
   Keep 200-row/1-MiB frames and QueryOwner's heartbeat, cancellation and
   stalled-output limits. Trace cancellation is a mutation;
   query cancellation only ends a read. Close DB readers before network I/O.
   Cursor identity, source digest, and target references must survive retries.
3. Add SQL and Trace command parsing/rendering to the existing
   `erebor-runtime-cli` command tree. Provide the `araphor` entry point without
   copying the tree. Put the typed Control HTTP client in a focused module of
   `erebor-runtime-client`; keep its local-daemon gRPC client unchanged.
   Wire types come from the shared API schema, not client-owned duplicates.
   Use --endpoint or a configured profile for the HTTPS base URL. Phase 7.9
   qualifies direct connection to the remote deployment with these same routes;
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
   and HTTPS. Do not add a database Service, privileged debug Job, remote MCP
   gateway, or general shell endpoint.

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

Add `observability_cli_` and `observability_http_` tests. Run focused tests,
the existing UI check/test/build/e2e scripts, Helm checks, and full Rust CI.
Record exact versions and nonzero case counts. A fixture-only UI cannot pass.

### End-to-end deliverable

Add `query-trace-client` to
`crates/mithril-e2e/src/bin/mithril_observability_test.rs` and implement the
case in the existing `src/observability.rs` module family. Start production
ConsoleHttpOwner and invoke the built araphor binary from mithril-e2e.
Submit a file, change that local file after submission, and verify the
accepted bytes/digest remain fixed. Require one command to print its own trace
through cleanup; SQL is not a mandatory second command.

Follow an aggregate while commits arrive and while a window expires. Verify
replace semantics through both CLI and browser. Interrupt the initiating CLI,
then a resumed viewer; only the first requests execution cancellation.
Restart the HTTP connection, revoke access during a quiet stream, expire a
cursor and change console scope. No stale frame may enter another view.
Unit tests cover argument rejection, parser framing, escaping, auth and CSRF.
Browser tests call the built Control assets, not fixture-only data.

## Stop point

Stop before CRD delivery and arbitrary-script tenant isolation claims.
Phase 7.7 adds assessment submission. Phase 7.8 adds review/publication to
this same listener; neither builds it again.
