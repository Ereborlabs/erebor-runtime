# Phase 7.9: Optional Remote Data Placement

Run the same data component outside Control when the operator selects it.

## Intended end state

Embedded and remote modes have equal storage, query, follow and discovery
results. The full data, graph and notification component moves together.
CLI and console can connect directly to either deployment through the same API.
Control keeps policy authority, final authorization, publication and trace
dispatch. There is one authoritative data store, not a durable raw mirror.
Entry: 7.8. Status: **Not done**. Embedded release does not require this option.

## Implementation flow

```text
Operator configures remote placement
  -> Control validates the endpoint identity and schema/capability agreement
  -> remote data process obtains the only data-directory lease
  -> Control forwards bounded authenticated input
  -> remote AnalysisStore commits before Control returns a Node ACK
  -> either API endpoint routes query/follow and discovery to the same owners
  -> the remote endpoint forwards trace and authority mutations to Control
  -> Control rechecks the caller and returns the authoritative owner result

Remote connection fails
  -> no new data ACK is issued
  -> Node keeps bounded unacknowledged data and reports any eventual loss
  -> reads and new dependent operations return Unavailable
  -> active captures stop at their local lease deadline
  -> installed protection continues without SQL or model access

Operator changes placement
  -> stop new work and finish or expire active traces
  -> drain, checkpoint and close the former writer
  -> transfer a validated complete store under planned downtime
  -> fence the former deployment before the new writer starts
  -> resume with preserved positions, or a new recovery epoch after rollback
```

## Changes in implementation order

1. Reuse the existing `araphor-data` library without moving its owners.
   Graph results/references/progress remain one local database transaction.
   Add an optional binary in `crates/araphor-data/src/bin/`; do not fork
   algorithms, schemas or retention code.
2. Add Embedded/Remote placement configuration. Remote mode must not open a
   local analysis DB. Keep policy/trust/approval, publication and TraceOwner
   dispatch in Control. Give NotificationRouter only its scoped sink credentials.
3. Reuse `ClientGrpcOwner` at the remote TLS gRPC endpoint, with gRPC-Web for
   browser clients. Reuse and qualify the
   --endpoint/profile selection from Observability 3; do not add another CLI
   selection mechanism or command tree. Both endpoints
   accept the same SQL, trace, assessment and qualified mutation RPCs.
   `AraphorAdministrativeService` remains Control-only; the remote data
   endpoint must not register administrative-exec or decommission methods.
   Direct SQL/analysis reads run locally; trace submit/cancel and authority
   mutations forward to Control without a user redirect or second command.
4. Implement the canonical mTLS delegation contract in engine-design.md.
   Authenticate the client at either endpoint; Control checks current grants
   per request and before each stream frame. Forward exact principal, scope,
   operation, digest and expiry, not broad service-account authority.
   Fail closed when authorization is unavailable. Control rechecks targets and
   approvals before effects. Internal domain operations accept evidence batches,
   context and trace transitions; no generic table CRUD or transaction RPC.
   The data process must never call its public trace RPC to record a trace
   result; use the private owner-qualified commit operation to avoid a loop.
5. Preserve transaction request keys and exact payload digests across retries.
   Lost commit replies reconcile through receipts before ACK. Do not retry
   non-idempotent work blindly or acknowledge an in-memory forwarding queue.
   Flow control stays bounded end to end; a partition creates no local archive.
6. Package the optional process and its single-writer PVC using the existing
   image/chart patterns. Embedded remains the default. No shared DuckDB file
   across pods, database network filesystem, automatic failover or broker.
   Reject deployments that configure both local and remote writers.
   Configure TLS, API audience, allowed origins and Control delegation peer for
   the remote listener. Reuse shared browser-session/CSRF checks. Do not expose
   internal intake or delegation RPCs on the public listener.
7. Implement the stopped-writer transfer command in the data owner. Validate
   manifest, store UUID, schema, references and receipt/progress positions.
   Keep a recoverable source backup. An orchestration gate must stop the old
   deployment; a local file lock does not fence a writer on another host.

## Unit tests and end-to-end proof

Unit tests cover placement exclusivity, delegation expiry, foreign tenant,
unsupported schema, payload conflict, response loss, bounded buffering and
data-store refusal. Reuse all embedded owner tests; no remote-only algorithm.

Add `remote-placement` in mithril-e2e. Start the production Control and data
binaries as separate processes with test mTLS identities. Run intake, duplicate
retry, query/follow, profile, graph/finding, notification and assessment cases
against both placements. Point the actual CLI directly at each endpoint for
SQL, trace submit/output/cancel, assessment and reviewed policy publication.
Require equal semantic IDs/counts/digests; permit transport timing differences.
Drop the link after data commit, trace intent, source write and notification
delivery. Restart each process; retain one capture/source effect and notification
deduplication state with the original deadline. Notification delivery itself
can repeat if the external sink lacks idempotency. Verify no local raw mirror.
Revoke grants during a quiet stream, forge delegation, use a foreign tenant,
and make Control authorization unavailable while data remains reachable.
No remote RPC may grant wider access or conceal an unavailable action owner.

Test stopped-writer transfer, refusal while old writer remains active, schema
mismatch, interrupted copy and older-backup restore with source loss. Require
explicit cursor epoch behavior. The paired physical case uses the existing
two-node harness and Helm assets after the lightweight result passes.

```sh
cargo test -p mithril-control
cargo test -p araphor-data
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case remote-placement --output-directory /tmp/araphor-remote
bash .github/scripts/verify-rust-ci.sh
```

## Completion gate

Pass DE-REMOTE plus all shared recovery, query, tenancy and trace parity cases.
Record both placements, request/receipt positions and partition results.
No remote mode is advertised until this gate passes. External read-only
consumers already use query/follow and do not need this deployment option.
