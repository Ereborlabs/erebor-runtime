# Araphor CLI, SQL, And Tracing

Add one CLI for retained-data queries and live diagnostic capture. Agents run
the CLI through their terminal. The console calls the same authenticated
APIs at the selected Control or remote endpoint. Use upstream bpftrace for
scripts, not a new tracing language.
Capture belongs to Mithril Control. It uses the shared processing foundation
owned by Mithril 7; it does not require discovery analysis to be enabled.
This plan does not replace prevention or response.

Read the shared [implementation review guide](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/implementation-review.md)
for the current non-UI code. The guide covers Discovery and diagnostic capture
as one data path, with separate authority and resource owners.

## Intended end state

An operator or agent runs `araphor sql` or `araphor trace` and receives output
in that command. No start/query/stop tool sequence is required. A console user
can inspect the same source, targets, measurements, and collection failures.
An optional Kubernetes `Trace` resource requests one bounded capture through
the same owner. Kubernetes is not required for CLI or API use.

## Implementation flow

```text
Agent runs araphor sql
  -> CLI reads one statement from an argument, file, or stdin
  -> selected endpoint authenticates the caller and obtains current Control authorization
  -> active QueryOwner checks disclosure, target scope, and SQL admission
  -> QueryOwner evaluates the bounded query through the active data component
  -> CLI prints rows, receipt, coverage, and limits
  -> --follow receives commit-driven append or replace frames on one response stream
  -> Ctrl-C ends reads; it does not stop evidence collection

Agent runs araphor trace
  -> CLI reads source bytes or a saved recipe reference
  -> selected endpoint routes the request to TraceOwner in Control
  -> Control resolves an authorized immutable source and target snapshot
  -> TraceOwner records one accepted request before dispatch
  -> Node rechecks the exact target lifetimes and execution grant
  -> Interceptor starts the approved bpftrace child and owns its cleanup
  -> Node retains bounded output and sends authenticated batches to Control
  -> active AnalysisStore commits output before Control acknowledges it
  -> selected endpoint exposes the committed resumable delivery position
  -> CLI prints output while the same command remains active

Browser starts a trace
  -> console sends the same request to the selected endpoint without executing a shell
  -> endpoint routes the request to the same TraceOwner in Control
  -> console follows the same bounded output stream as the CLI
  -> Stop requests cancellation; closing a view only ends that viewer's reads

Trace expires, loses its execution lease, or exceeds a limit
  -> Node stops collection and allows a bounded final-output drain
  -> Interceptor terminates remaining child processes and checks cleanup
  -> TraceOwner records reason, retained output, coverage, and cleanup separately
  -> a missing final result stays Unknown; transport EOF is not completion

Submission reply is lost
  -> client retries the same source and request key
  -> Control returns the existing trace; changed content returns Conflict
  -> Node does not start a second execution for the same dispatch identity

Kubernetes reconciles a Trace resource
  -> controller submits its immutable spec under an explicit namespace grant
  -> Control uses cluster UID and resource UID as the stable request identity
  -> status refers to the existing execution; reconciliation never reruns it
  -> deletion requests cancellation and waits for the cleanup condition
```

## Decisions and source facts

| Decision | Reason and evidence |
| --- | --- |
| CLI first; API shared with console | [Inspektor Gadget](https://inspektor-gadget.io/docs/latest/api/golang/) separates local and remote runtimes. [Pixie](https://docs.px.dev/reference/api/overview/) uses one API for CLI, UI, and clients. Reuse this separation, not their runtimes or query languages. |
| Real bpftrace scripts | The [bpftrace CLI](https://bpftrace.org/docs/release_026/cli) accepts files/stdin and emits JSON lines. Pin and qualify one build. Do not implement a compiler, AST rewriter, or script-to-YAML conversion. |
| Pod selection is not script confinement | [kubectl-trace](https://github.com/iovisor/kubectl-trace#running-against-a-pod-vs-against-a-node) explicitly describes pod selection as context resolution, not containment. A target predicate cannot authorize arbitrary host-memory reads. |
| Reviewed recipes by digest; arbitrary scripts need wider authority | [Inspektor Gadget restrictions](https://inspektor-gadget.io/docs/latest/reference/restricting-gadgets/) include digest allowlists. [PCP's bpftrace integration](https://raw.githubusercontent.com/performancecopilot/pcp/main/src/pmdas/bpftrace/README.md) distinguishes production scripts from dynamic submission. Araphor uses default-deny grants. |
| One response stream with bounded frames | QueryOwner wakes on committed table changes. Durable cursors recover missed notifications. No extra streaming service, WebSocket, or agent-job protocol is needed. |
| State the result operation | Follow appends immutable rows or replaces a complete bounded result. Metadata declares the operation. Aggregate snapshots are never added together. Recompute on relevant commits, not unconditional polling. |
| Optional finite Trace CRD | [Tetragon](https://tetragon.io/docs/concepts/tracing-policy/) supports CRD, gRPC, and static inputs. Adopt declarative input, but use one execution authority. Do not store output in etcd or make Kubernetes objects mandatory for interactive use. |

## CLI contract

These commands and schemas are proposed. Add `araphor` as an entry point to
the existing CLI command tree; retain `erebor` compatibility. Do not rename
crates, API groups, or repositories. The selected HTTPS endpoint is distinct from the local Runtime daemon socket.
Reject a daemon-socket option on these commands. --endpoint or the configured
profile can select Control or the optional remote deployment. Keep commands,
tokens' intended API audience, routes and output unchanged. The remote endpoint
routes trace and authority mutations to Control; it does not execute them.

```sh
araphor sql 'SELECT * FROM catalog' --output jsonl
araphor sql -f investigate.sql --target pod/payments/api-7c9d --cluster prod
araphor sql 'SELECT * FROM events' --target pod/payments/api-7c9d \
  --cluster prod --follow --duration 60s --output jsonl
araphor trace --target pod/payments/api-7c9d --cluster prod \
  --recipe syscall-errors@1 --duration 30s --output jsonl
araphor trace --target pod/payments/api-7c9d --cluster prod \
  --container api --file errors.bt --duration 30s --output jsonl
araphor trace --resume TRACE_ID --output jsonl
```

- SQL takes exactly one positional statement or `--file`; `--file -` reads
  stdin. Trace takes exactly one of `--recipe`, `--file`, or `--expression`.
  Resume cannot include a new script, target, or duration.
- `--target` accepts a supported human locator or an owner-issued target ID.
  Names are resolved server-side to UIDs. `--cluster` is required for ambiguous
  locators. An optional container selector narrows a pod. Unknown, unsupported,
  ambiguous, and empty targets fail; none means all hosts.
- Both commands support `--output table|jsonl`. Default to table on a TTY and
  JSONL on a pipe. JSONL includes metadata, data, diagnostic, and terminal
  records. Service logs and human progress go to stderr. Escape terminal
  control bytes; do not treat observed text as agent instructions.
- The CLI stays in the foreground. The agent uses its existing terminal
  execution and output-read mechanism. There is no required MCP adapter,
  custom agent wait tool, or background shell job created by Araphor.
- A new trace defaults to 30 seconds of collection, with an initial maximum
  of 300 seconds. An absolute server deadline also bounds preparation and
  dispatch. SQL `--duration` bounds follow only. Neither command extends a
  deadline because a reader reconnects.
- Ctrl-C cancels a trace started by that CLI, then drains its bounded final
  result. Ctrl-C on a resumed viewer only stops that viewer. A broken stdout
  pipe ends reads and requests cancellation only for the initiating CLI.
  If cancellation cannot reach Control, report uncertainty; Node expiry is
  still mandatory. Browser navigation never cancels another client's trace.
- `--resume` replays retained trace output and follows until terminal state.
  It never executes the script again. Normal use needs no resume command.
  SQL reconnection reuses its cursor internally; expiry is an error, not a
  silent fresh query.
- Exit codes: 0 completed within its declared limits; 2 invalid input;
  3 denied or approval required; 4 partial, limited, or uncertain result;
  5 execution/transport failure; 130 interrupted. Zero rows can be valid, but
  never establish absence without qualified coverage. Collection quality is
  separate from process success, including in exit-0 output.

The CLI sends source bytes, not a remote path. It reads local files once and
binds their digest to the request. No server URL fetch, shell interpolation,
user-controlled bpftrace flags, or automatic dependency download is allowed.
Agents can inspect source with their normal file tools. Saved recipe source,
parameters, limits, and permitted targets are available through `catalog` and
the trace detail response; opening a source never starts it.

For example, the reviewed syscall-error recipe can contain real bpftrace:

```bpftrace
tracepoint:raw_syscalls:sys_exit
/cgroup == $1 && args.ret < 0/
{
  @errors[args.id, args.ret] = count();
}
interval:s:1 { print(@errors); }
```

Node supplies `$1` from one verified container lifetime; the caller cannot
override it. The periodic map output is cumulative, not a one-second delta.
The source, its interval clause, and its parameter contract are reviewed as
one artifact. This example is not a sandbox for other scripts. Do not assume
that a different probe attributes work to the current cgroup correctly.

## Shared APIs and output

Reuse the planned `ConsoleHttpOwner`, audience checks, browser sessions, and
service-principal grants. Observability 3 owns query/trace authentication and
transport; Phase 7.8 extends it. The CLI is not a privileged proxy. Mithril 7.3 owns QueryOwner; this plan
owns its transport and client adapters.
Console JavaScript calls these APIs; the server does not run the CLI.
The remote deployment reuses this listener and API implementation. Follow the
[Mithril placement contract](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/engine-design.md#optional-remote-placement)
for direct clients, current authorization and delegated Control operations.
No client redirect, second monitoring command or remote-specific tool is needed.

| Route | Contract |
| --- | --- |
| `POST /v1/discovery/query` | Normal mode returns bounded JSON. Follow returns one `application/x-ndjson` response with metadata, append/replace, checkpoint, health and error/terminal frames. Optional target scope narrows authorized input before evaluation. |
| `POST /v1/observability/traces` | Source or recipe, target, duration, parameters, optional finding reference. Required idempotency key. Returns ID, accepted spec digest, state, and output reference. The CLI automatically follows output. |
| `GET /v1/observability/traces/{id}` | Authorized source, resolved scope, accepted limits, per-target state, and result references. |
| `GET /v1/observability/traces/{id}/output` | Optional cursor; one JSONL response replays retained output and follows to the trace terminal state. Use QueryOwner's bounded append reader with trace-specific grants. No SQL text or second user command is needed. |
| `POST /v1/observability/traces/{id}/cancel` | Idempotent cancellation intent under an execution-owner or administrative grant. Acceptance is not cleanup proof. |

Use typed Rust request/response contracts and generated browser schemas.
Normal query and trace submission use JSON. Follow and trace output use the
[canonical stream envelope](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/engine-design.md#commit-driven-follow).
This section defines only trace-specific payloads and grants.

A trace frame has schema version, trace ID, committed delivery sequence, node
execution ID, source sequence, kind, and bounded payload. Kinds are metadata,
data, diagnostic, and terminal. Data declares its source and schema before
typed rows. Preserve unknown bpftrace JSON variants as bounded raw output;
never infer a trusted schema from printf text. Per-node sequence is not a
global causal clock. A terminal frame includes per-target outcomes, source
quality, output limits, and cleanup state. An absent terminal frame is not
success. This follows [Pixie's explicit end-of-stream lesson](https://docs.px.dev/reference/api/overview/).

Trace cursors bind the caller's authorized scope, trace ID, output schema,
export policy, and committed position. Recheck permissions after every wait.
Return 410 if retained output is no longer available. No silent gap skipping.
Slow readers do not block Node collection or enforcement. Storage exhaustion
stops that diagnostic capture and retains a bounded failure record.

## Execution, targets, and authority

Stock bpftrace performs BPF loading. The approved architecture amendment lets
Interceptor supervise that delegated diagnostic loader under its exclusive
ownership. It does not claim that stock bpftrace uses Interceptor's existing
object loader. No second daemon, Kubernetes debug Job, or host shell is added.
Keep this exception disabled until lifecycle and interference tests pass.

`TraceOwner` in Control owns intent, authorization, dispatch, and aggregate
result. Node owns exact runtime identity and the local execution record.
Interceptor owns the child process, BPF resource inventory, and cleanup.
Control/Node traffic extends the existing authenticated gRPC service families;
no HTTP endpoint or agent credential is placed on Node.

Reuse `WorkloadTargetFactV1` and Node lifetime identities. Resolve controller
targets to a fixed current cohort. A target without a protection policy is
allowed only if authenticated inventory proves its runtime identity. Do not
create a fake policy binding. Missing inventory means Unsupported. Do not
interpret a general agent session ID as a traceable process automatically.

The first release has two authority paths through the same trace operation:

1. A reviewed recipe digest plus bounded parameters can have a pod/container
   grant. Its qualified probes must filter before collection and must not read
   unrelated memory or emit other tenants' data. Reject unsupported probe/target
   combinations. Script source supplied inline can use this path only when
   its exact digest matches a reviewed artifact.
2. New or changed source requires explicit host-diagnostic authority for each
   affected node and an exact approval or preauthorization. Pod selection is
   context, not a reduction of that grant. Its output retains host sensitivity;
   a pod-only reader cannot retrieve it through SQL, detail, or output APIs.

No AST sandbox is promised. Do not insert predicates with string replacement.
Pass approved typed parameters as arguments, never as script source. Bind a
reviewed cgroup recipe to one container lifetime per execution initially;
fan-out has a fixed ceiling and keeps separate results. Stop on identity loss
or replacement. Block-I/O and asynchronous kernel-worker attribution require
separate recipes; current-task cgroup matching is not universally correct.

Review the complete script environment: builtin helpers, imports/includes,
debug information, symbols, maps, probes, and output. Sanitize environment and
disable network symbol lookup. No `--unsafe`, child-command option, arbitrary
pinning, or enforcement action is supported. Do not describe compiler success,
the BPF verifier, namespaces, or `--unsafe` absence as tenant isolation.
Upstream [`--dry-run` attaches probes](https://bpftrace.org/docs/release_026/cli);
it is not an unprivileged preflight. A read-only source check must not use it.

Each Node execution has a boot-bound dispatch ID, immutable digest, deadline,
and durable state. Record intent before spawn. Duplicate delivery cannot spawn
again. A restart reconciles or terminates the old execution; it never silently
restarts a measurement interval. A partition expires the signed execution
lease locally. A Control deadline alone cannot stop an isolated node.
Require verified parent-death/process-group cleanup and lease expiry. Reserve
separate diagnostic buffers and disk quotas. Kernel BPF runtime is not fully
bounded by a userspace CPU cgroup; approved probe limits and physical overhead
tests are release gates, not optional tuning.

## Evidence and storage

Use the shared AnalysisStore and DuckDB transactions from Mithril 7.2.
TraceOwner remains in Control and stores accepted source, grant, target,
dispatch intent, output and result through that data owner. A trace requires
healthy durable data storage, not an enabled DiscoveryOwner. A query-worker
failure does not block output upload; failure of the authoritative data store
does block its ACK. Node keeps bounded diagnostic output until ACK or explicit
quota loss. Reserve enforcement evidence capacity separately.

Commit each batch's deduplicated output, trace state, source receipt and
relation revisions together before ACK or reader notification. Trace output
positions never advance the enforcement source cursor. Retain sources and
measurement semantics while output references them. The same data component
can run remotely; Control dispatch and Node expiry do not move.

Expose `traces`, `trace_output`, and `trace_measurements` through the existing
query admission and disclosure path when their owners exist. The first two
retain provenance and raw output. Only reviewed output schemas populate typed
measurements. Append trace-state revisions to `events`; follow raw output through
`trace_output`. An aggregate
snapshot is not an additional observed syscall. Findings retain their own owner.

Count/histogram recipes declare units, keys, cumulative versus interval meaning,
reset epoch, sample policy, and map/output losses. Repeated cumulative snapshots
must not be summed. bpftrace documents asynchronous printing and mutable map
reads in its [standard library](https://bpftrace.org/docs/release_026/stdlib).
Label live snapshots non-atomic unless qualified. Final output after a forced
kill can be absent. Unknown loss counters remain unknown; zero stdout is not
proof that no events occurred. Compare repeated captures as separate intervals.

## Optional Kubernetes interface

Add one namespaced `Trace` CRD only in Observability 4. Keep the current group
`mithril.erebor.dev`; product naming does not require an API-group migration.

```yaml
apiVersion: mithril.erebor.dev/v1alpha1
kind: Trace
metadata:
  name: api-errors
  namespace: payments
spec:
  target:
    kind: Pod
    name: api-7c9d
    uid: exact-pod-uid
  recipeRef:
    name: syscall-errors
    digest: sha256:reviewed-content-digest
  durationSeconds: 30
```

This is a proposed example; placeholder UIDs and digests must be replaced.
The resource requests one finite capture, not an always-on tracing policy.
Its spec is immutable. A completed object does not restart after reconciliation
or controller restart. A new capture requires a new object UID. Expire admission
at creationTimestamp plus a configured start window, so an old GitOps object
cannot unexpectedly start much later.

Only reviewed recipe references are accepted initially. Require Kubernetes
RBAC plus a Control grant keyed to cluster and namespace UID, recipe digest,
target kinds, and limits. A creator annotation or controller service account
alone cannot grant host-diagnostic access. Record the controller as execution
principal and the resource UID as source; do not invent the original human
identity from a watch event. Trace creation never grants evidence-read access.

Status contains observedGeneration, trace ID, spec digest, conditions and
bounded per-target summaries, not raw output. A finalizer requests cancellation
and records cleanup before removal. Node expiry must work even if the object
or finalizer is forcibly removed. Follow Kubernetes
[status-subresource](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#status-subresource)
and [finalizer](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/)
semantics. CLI/API runs never create CRs implicitly. Kubernetes owns desired
spec; Control owns execution; the controller is only an adapter.

## Implementation order and ownership

This is Control's diagnostic capability and its client work. It does not own
another ingestion, persistence, query, or discovery engine. Use the
[combined order](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/README.md#combined-implementation-order)
for cross-plan sequencing.

| Phase | Entry gate | Output |
| --- | --- | --- |
| [1: Contracts and backend](phase-1-contracts-and-backend.md) | Approved delegated-loader boundary | Exact source/target contracts and real bpftrace lifecycle proof. Can run alongside Mithril 7.1–7.3. |
| [2: Owned capture](phase-2-owned-capture.md) | Observability 1 and Mithril 7.2 | Durable capture/output in shared DuckDB; discovery-disabled and physical lifecycle proof. |
| [3: CLI, API and console](phase-3-cli-api-and-console.md) | Observability 2 and Mithril 7.3 | Shared authentication, SQL/trace streams, CLI and console integration. |
| [4: Declarative capture](phase-4-declarative-captures.md) | Observability 3 | Optional finite Trace CRD adapter. |

Use the linked combined order as the single cross-plan sequence. Discovery
profiles, classification and publication are not prerequisites for SQL/trace
delivery. Mithril 7.7 adds assessment transport; 7.8 adds review/publication.
Mithril 7.10 reruns the advertised observability cases. Optional CRD delivery
does not block the embedded SQL/trace release.

Status: **Not done** for the complete target. Existing backend tests must run
on the implementing revision; they do not prove shared DuckDB or streaming
contracts. Each phase records unit tests, production-owner mithril-e2e cases,
paired physical results, and an explicit completion result in that phase.
No separate gap-review document is required.

The initial recipe set is syscall errors and failed file opens. Connection
outcomes and latency follow only with explicit asynchronous/entry-return
semantics and paired tests. Stacks and selected uprobes/USDT are later recipe
increments, not prerequisites or an unbounded feature promise. No general
profiler, continuous CRD deployment, multi-tenant arbitrary-script sandbox,
custom compiler, new inference runtime, or new response owner is included.
