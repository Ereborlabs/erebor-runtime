# Discovery Engine contract inventory

This record supports [the contract and SDK](phase-7-5-2-analysis-contract-and-sdk.md),
[the coverage index](algorithm-coverage.md), and
[the Discovery Engine ports](phase-7-5-8-discovery-engine-algorithms.md).
It identifies computations from source. It does not prove an installed package,
a runtime port, or policy prevention.

## Source and result

The source is `accuknox/discovery-engine`, revision
`0b5b73425c5aec89b803e737b188b2a331d0e218`.
The local clone was clean when this audit started. All source references below
use that revision. The audit includes all 412 tracked files: 131 Go files,
25 Go test files, configuration, fixtures, deployment files, and generated files.
The source tree was read only. No upstream service or test was run.

**Done:** identify the source computations, variants, delegated operations,
contract requirements, and exclusions. The 58 record IDs are unique. All 31
local and pinned source links resolve against the checked-out files. **Not done:** implement or qualify any
Discovery Engine package. Each computation below belongs to the later Discovery
Engine port owner. Each port must have a descriptor, source revision, positive
and negative fixtures, and a declared result for each expected difference.

The active network entry point uses per-event conversion and rule merge. The
source also retains a label, destination, and protocol aggregation pipeline.
Both are in scope. System discovery has a per-pod pipeline and a workload
process/file-set pipeline. Both are in scope. A helper that is not called by the
active entry point still has an inventory row.

## Shared portable data requirements

Each dataset has a versioned schema. Fields have declared types and null rules.
Use signed 64-bit integers for time and source signed integers. Use unsigned
64-bit integers for counts. Check narrower source ranges when an export needs
them. Keep integer values exact. Use text for protocol port expressions, names,
paths, addresses, patterns, and labels. Use Boolean values for flags. Use child
relations for repeated values and maps. Use bytes only for a declared artifact
or checkpoint encoding. A map iteration order is not an output order.

Each source record also needs an immutable row identity, qualified subject
identity, evidence references, source revision, and event time where available.
The host supplies the input window, coverage, parameter values, clock, seed,
and resource limits. A source record without a timestamp must state this fact.
It must not receive an invented event timestamp.

| Dataset | Required fields and relations |
|---|---|
| `system_events` | All `KnoxSystemLog` fields: `LogID`, `ClusterName`, `HostName`, `Namespace`, `ContainerName`, `PodName`, `SourceOrigin`, `Source`, `Operation`, `ResourceOrigin`, `Resource`, `Data`, `ReadOnly`, and `Result`. Keep process arguments and original resource text. |
| `network_events` | All `KnoxNetworkLog` fields: `FlowID`, cluster and container, source and destination namespace/pod/reserved-label relations, `EtherType`, protocol, source/destination IP and port, ICMP type, SYN and reply flags, L7 protocol, DNS query/response/IP relations, HTTP method/path, direction, and action. |
| `raw_system_events` | All `KubeArmorLog` fields, including PID/PPID/host PID/UID, process and parent names, category, action, container image/ID, labels, and source times. This input supports normalization and summary variants. |
| `raw_network_events` | Cilium flow or stored `CiliumLog` fields: verdict, IP version/encryption, TCP/UDP ports, ICMP v4/v6 type/code, endpoint labels/namespace/pod, node, L7 DNS and HTTP data, event type/subtype, services, direction, trace point, drop reason, reply, start/update time, and total. Preserve fields before a conversion discards them. |
| `workloads` | Qualified cluster/namespace/workload/pod/container identity, kind, IP, labels, owner references, container image, and pinned inventory revision. Child relations contain containers, projected service-account volumes, mounts, volume names, mount paths, and token paths. |
| `services`, `endpoints`, `nodes` | Qualified identity, inventory revision, label/selector relations, service type, cluster/external/node IPs, protocol, port, named or numeric target port, node port, endpoint IP and target reference. Named ports must remain distinct from numeric zero. |
| `resource_sets` | Cluster, namespace, container, labels, source, set type, resource child rows, prior policy identity, and prior result revision. A changed set is a separate output fact. |
| `candidates` | Stable candidate identity, API version, kind, cluster/namespace, metadata and selector relations, action, severity/tags/message, generated/update times, latest/outdated/replacement references, and evidence relations. System rule children preserve process/file paths or directories, recursive/read-only/owner-only flags, protocols, and all source paths/directories. Network rule children preserve direction, peer labels, CIDRs and exceptions, entities, services, FQDNs, ICMP family/type, ports/protocols, and HTTP method/path/aggregated flag. |
| `summaries` | All `SystemSummary` identity, workload, process/file/network, source/destination, label, address/port/protocol, action, count/time, bind, severity/tags/message/enforcer/policy fields. Preserve counts and timestamps before string export. Separate process/file/bind/ingress/egress outputs can have different row counts. |
| `templates` | Template ID, version, digest, name, kind, precondition relations, description and reference relations, tags, annotations, system spec, and a bounded schema-labelled Kyverno policy artifact. Template index and referenced files form one pinned input revision. |
| `insights`, `recommendations`, `withdrawals`, `exports`, `conversion_losses` | Named outputs with variable row counts. Insights have qualified workload/selector, operation or network rule, source, resource/peer, and candidate/evidence references. Recommendations and withdrawals refer to candidate identities. Exports contain format, schema/version, bytes, and input references. Conversion losses contain candidate, unsupported field/rule, target, and reason. |

The field sources are [log schemas](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/types/logData.go),
[policy schemas](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/types/policyData.go),
[observability schemas](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/types/observability.go),
[inventory schemas](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/types/k8sData.go),
and [insight schemas](https://github.com/accuknox/discovery-engine/blob/0b5b73425c5aec89b803e737b188b2a331d0e218/src/types/insightData.go).
These source types define required information. They do not require Go,
Kubernetes, Kyverno, database, or gRPC dependencies in the SDK.

All rows below inherit these host checks: authorize every input revision and
window; validate schemas, full identities, evidence references, and prior
results; enforce cancellation, row/byte/depth/time/output bounds; validate
candidate semantics and conversion losses; commit outputs and progress through
the existing host owner. A missing inventory or coverage input gives an explicit
incomplete result. It does not prove that an activity or token use is absent.

A package export is a named computation over the listed datasets and typed
parameters. An export can return zero, one, or many rows in each named output.
It cannot query a live cluster, download a template, call DNS, modify storage,
publish a policy, or change enforcement. These operations remain host operations.
The default execution targets are compiled Wasm and native Rust under the same
contract. A later port can use SQL where its complete computation fits SQL.
This audit does not select one execution target for all algorithms.

State is an optional bounded checkpoint with an encoding name, version,
input/result references, and bytes. The host owns persistence and retry. Tree
nodes, maps, prior resource sets, DNS/IP maps, and flow-evidence maps must fit the
declared checkpoint bound. Label combinations need an explicit combination
limit. File and HTTP trees need depth, segment, node, and byte limits. Limit
failure must not return a partial candidate as a complete result.

## Computation records

[Algorithm records](discovery-algorithm-inventory.md) identify both system
pipelines, both network pipelines, path and HTTP aggregation, incremental
candidates, summaries, insights, templates, and admission recommendations.
[Input and delegated computation records](discovery-input-inventory.md) identify
recorded-log normalization, converters, analyzer wrappers, inventory adapters,
common operations, database selection/count reduction, and export selection.
Each record states source symbols, variants, typed inputs/outputs, state, and
source tests. No delegate is covered only by its entry point.

## Required differences and qualification

These observations come from source bodies. They are not proof of reachable
production failures. Each later port must decide and test the specified
behavior. It must not copy a defect to claim source parity.

| Source observation | Required port behavior and example |
|---|---|
| The analyzer wrappers pass `nil` instead of the supplied log arrays. System response conversion uses `SysSpec` before it is initialized. | A recorded positive system/network event must reach its candidate output. Empty input must return a valid empty result. A response conversion must not panic. |
| Some label lookup helpers use pod name without namespace/cluster. Summary file grouping uses pod name plus source. System naming has both `clusterName` and `clustername` keys. | Use full qualified identity. Two namespaces with the same pod/source must keep separate labels, summaries, and candidates. A short FNV hash must not merge different identities. |
| Legacy all-pod checks have reversed membership loops. FQDN latest selection has nested equality checks. Active network merge tests only selected peer/port branches. | Test subset, superset, and disjoint cases for each variant. A different selector, peer, port, FQDN, or cluster must not acquire an unrelated allow rule. |
| The pod-to-pod converter assigns destination selectors/namespaces to egress and source selectors/namespaces to ingress, against its stated source-to-destination intent. | Test a flow from pod A in namespace A to pod B in namespace B. Egress must govern A to B; ingress must govern B from A. Retain an explicit reference-output difference. |
| Map iteration affects DNS first-match selection, label ranking ties, and output order. `RandSeq` seeds from the process clock. | Declare stable tie/order rules and use host time/seed. Repeated input, revision, parameters, checkpoint, and seed must produce the same semantic output. |
| `GetSummaryData` builds egress from the ingress array. `GetCiliumSummaryData` does not apply all request filters. `validateSummaryRequest` does not check container name. | An ingress-only event must not appear in egress. A container or namespace filter must exclude a different identity. |
| Network insight aggregation modifies a range copy; selector labels are overwritten; entities are appended twice; ICMP is not carried into insights. | Preserve all rows and labels once. Include ICMP or emit an explicit unsupported-field result. Test two merged candidates and multiple selector labels. |
| `ShouldSATokenBeAutoMounted` uses the first pod and returns true on missing input/error. | Evaluate every selected workload/container or return incomplete coverage. A token read in a later pod must count as used. Missing logs must not prove unused. |
| The recommendation source has limited precondition handling and namespace/workload selection defects. `uniqueNsDeploy` can return an empty object for an existing workload. | Declare supported preconditions; reject an unsupported precondition. Test empty include filters, exclusions, owner references, duplicate workloads, and deletion. Never emit a recommendation for an empty workload identity. |
| Kubernetes network conversion discards richer peers, ICMP, HTTP, and extra ports. Cilium conversion does not preserve CIDR exceptions. Some system exports remove source constraints or add global/preconfigured access. | Emit a conversion-loss record or reject the target. Do not label a broader converted policy as equivalent. Test a two-port rule, CIDR exception, and source-restricted file access. |
| Database variants differ in selected fields, optional-zero filters, and network type/rule filters. Summary SQL contains `workpsace_id`. | A descriptor declares the selected schema/filter semantics. Use typed host selection. Test workspace filtering, false reply, zero numeric values, and SQLite/MySQL reference differences. |
| Count writers add totals on each upsert and can overwrite a newer time with an older time. Source counts use several narrow integer widths. | Use checked exact counts and an explicit time-reduction rule. A retry of the same input revision must not increase the count. Test out-of-order time, overflow, and replacement windows. |
| Template downloads use mutable release/cache state. Template contents are outside this pinned repository. | Pin template bytes and their index as a separate input digest. An unavailable template is an input block, not proof that the generator is implemented. |

Later qualification must cover all rows, including retained helper variants.
The existing multiubuntu, observability, and recommendation cases are source
references. They are not installed-package tests. Use focused Rust tests and
supported lightweight production APIs. Do not introduce long shell test files.
Use a physical case only after the paired lightweight case passes.

An example complete end scope for the later port is: an installed package reads
recorded TCP, DNS, file, and token-use inputs plus pinned workload/template data;
it emits named candidate, insight, recommendation, evidence, and conversion-loss
datasets; replay gives the same output; a missing pod revision gives incomplete
coverage; a Kubernetes export of an HTTP rule gives a declared loss. Control
must still approve and activate any resulting policy.

## Source-tree accounting

The file count comes from `git ls-files` at the recorded revision. These
disjoint groups account for all 412 tracked files.

| Tracked path group | Files | Treatment |
|---|---:|---|
| `src/` handwritten non-test Go | 56 | Each analysis owner and delegated computation is listed above. The remaining functions are infrastructure as specified below. |
| `src/` Go test files | 19 | Source test references above. Infrastructure-only tests do not prove an algorithm. |
| `src/protobuf/` Go files | 18 | Generated wire schemas. Inspect fields for conversion loss; do not port generated RPC servers as algorithms. |
| Other `src/` files | 27 | Configuration, protobuf source, build/container/module files, certificates, and package inputs. Parameter/schema requirements are mapped above. No separate analysis algorithm. |
| `pkg/` handwritten Go | 10 | API registration/schema, discovered-policy reconciliation, deployment, and watchers. These implement lifecycle and physical policy activation. They are excluded from package execution. Spec equality is DE05.6; decode/kind/namespace checks remain host export checks. |
| `pkg/` generated Go | 23 | Generated clientsets, informers, listers, and deepcopy. No independent analysis computation. |
| Other `pkg/` files | 35 | CRD, RBAC, webhook/deployment, build/module, and controller packaging files. Host/controller lifecycle only. |
| `tests/` Go | 5 | External scenario tests and K8s test utilities. Reference proof only. |
| Other `tests/` files | 137 | Scenario inputs/expected outputs and test drivers. Preserve reference cases. Drivers, cluster setup, and example workloads are not runtime algorithms. |
| `.github/`, `.gitignore`, `Jenkinsfile`, `README.md`, `STABLE-RELEASE` | 12 | CI, source metadata, and usage instructions. No runtime analysis. |
| `deployments/`, `getting-started/`, `k3s/`, `onboarding/` | 51 | Installation, examples, and cluster setup. No separate algorithm. |
| `policies/`, `resources/`, `scripts/` | 19 | Example/static policy resources and build/installation/database/qualification scripts. These are acquisition or reference artifacts. They are not new detector exports. |

All 56 handwritten `src/` Go files were classified. The semantic source owners
are `systempolicy`, `networkpolicy`, `common`, `observability`, `insight`,
`recommendpolicy`, `admissioncontrollerpolicy`, `plugin`, `analyzer`, and the
mapped portions of `libs`, `cluster`, `feedconsumer`, `config`, and `types`.

The remaining symbols in these files have the following explicit exclusions:

- `main.go`, `logging/*.go`, `license/*.go`: process startup, logging,
  license cryptography/claims/expiry, and license RPC. They do not infer a
  workload security candidate. Licensing remains host configuration.
- `server/grpcServer.go` and consumer registration/stream functions: RPC/TLS,
  start/stop/status, and transport. Their analysis delegates are DE01–08.
- Discovery `init`, configuration initializers, receiver/worker/cron start,
  stop, and main loops: lifecycle and acquisition. Any data transformation in
  these paths is listed in DE03.10, DE07.3, or DE08.2–6/15.
- `cluster` client/HTTP connections, list calls, secret/license/annotation
  writes, relay URL selection, and API-resource checks: host acquisition or
  effects. Resource normalization is DE08.11. `CreateDsp` and `UpdateExisting`
  are host policy effects. Their spec equality is DE05.6.
- `libs` database connection/mock/wait, table creation, insert/update/delete,
  and purge mechanics: host persistence. Data selection, count reduction,
  key/label/time construction, replacement, and serialization are mapped to
  DE05, DE06.10–11, and DE08.12–14. No unlisted merge is delegated to storage.
- `libs/common.go` command-line/configuration loading, pprof, environment,
  IP/interface detection, signal, command execution, directory checks, and
  file-write helpers: host infrastructure. Packages have no shell capability.
- `recommendpolicy/downloadTemplates.go` release HTTP, ZIP download/extract,
  cache/home paths, path sanitization, and cache deletion: host acquisition.
  Template decode/version selection is DE07.1. Logging of generated rules is
  a diagnostic effect, not another pattern algorithm.
- `feedconsumer` Kafka/Pulsar setup, polling/subscription, start/stop, buffering,
  and acknowledgements: host transport. Message decode is DE08.6.
- `ReplaceMultiubuntuPodName` in system/network code: fixture identity rewrite.
  It is excluded from runtime analysis and cannot replace real subject identity.
- `types/*.go`: declarations and constants. The eight network rule equality
  and accessor methods are included in DE03.5.

This accounting leaves no source directory as an unspecified later algorithm.
Source changes after the pinned revision require a new audit. The contract
owner must check the SDK descriptor examples against these dataset and bound
requirements before it freezes the ABI.
