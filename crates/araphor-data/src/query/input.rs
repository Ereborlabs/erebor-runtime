use std::mem::{size_of, take};
use std::sync::Arc;

use duckdb::core::LogicalTypeId::{self, *};
use duckdb::types::{TimeUnit, Value};
use duckdb::Connection;
use prost::Message as _;
use snafu::{IntoError as _, ResultExt as _};

use super::adapter::{InputColumn, InputTable};
use super::discovery::{BEHAVIORS, CONTEXT};
use super::QueryTemplate;
use crate::{
    AnalysisContextVersionV1, AnalysisExtractionV1, AnalysisGapV1, AnalysisInputV1,
    AnalysisRelationV1, AnalysisSourceSnapshotV1, CoverageCounters, CoverageInterval,
    CoverageReport, EvidenceIntakeIdentityV1, EvidenceRecord, Result, TraceRecipeManifestV1,
    TraceRecipeV1,
};

pub(super) struct InputField(
    pub(super) &'static str,
    pub(super) LogicalTypeId,
    pub(super) &'static str,
    pub(super) &'static str,
);

pub(super) struct InputSchema {
    pub(super) name: &'static str,
    pub(super) columns: &'static [InputField],
    pub(super) join_keys: &'static str,
    pub(super) owner: &'static str,
    pub(super) readiness: &'static str,
    pub(super) description: &'static str,
}

const SOURCE_KEY: &str = "tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch,cpu_id";
const CONTEXT_ABSENT: &str = "No decision context is present.";
const OBJECT_ABSENT: &str = "No exact file object is present.";
const INTERVAL_ABSENT: &str = "This row is not a report interval.";
const OPENING_ABSENT: &str = "No opening counter snapshot is present.";
const CLOSING_ABSENT: &str = "No closing counter snapshot is present.";

const EVENTS: InputSchema = InputSchema {
    name: "events",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("node_id", Varchar, "exact Node ID", ""),
        InputField("node_boot_id", Blob, "16-byte ID", ""),
        InputField("label_epoch", UBigint, "label epoch", ""),
        InputField("source_id", Blob, "16-byte ID", ""),
        InputField("source_epoch", UBigint, "source epoch", ""),
        InputField("cpu_id", UInteger, "CPU ID", ""),
        InputField("source_cursor", UBigint, "source cursor", ""),
        InputField("commit_revision", UBigint, "store revision", ""),
        InputField("ordinal", UInteger, "record index within commit", ""),
        InputField(
            "received_utc_ns",
            UBigint,
            "Control intake UTC nanoseconds",
            "",
        ),
        InputField(
            "received_at",
            Timestamp,
            "Control intake UTC microseconds; nanoseconds truncated",
            "",
        ),
        InputField(
            "observed_boottime_ns",
            UBigint,
            "Node boot-relative nanoseconds",
            "",
        ),
        InputField(
            "ingested_utc_ns",
            Bigint,
            "Node ingestion UTC nanoseconds",
            "",
        ),
        InputField("coverage_interval_id", Blob, "exact interval ID", ""),
        InputField(
            "profile_generation_ref_id",
            UBigint,
            "profile generation reference",
            "No profile reference is present.",
        ),
        InputField("task_cookie", UBigint, "boot-local task cookie", ""),
        InputField(
            "process_lineage_id",
            Blob,
            "ID bytes; empty means absent",
            "",
        ),
        InputField(
            "authority_domain_id",
            Blob,
            "ID bytes; empty means absent",
            "",
        ),
        InputField("execution_set_id", Blob, "ID bytes; empty means absent", ""),
        InputField("exact_object_id", Blob, "ID bytes; empty means absent", ""),
        InputField(
            "destination_id",
            UBigint,
            "destination ID; zero means absent",
            "",
        ),
        InputField(
            "policy_rule_id",
            UBigint,
            "policy rule ID; zero means absent",
            "",
        ),
        InputField(
            "reason",
            UInteger,
            "wire reason code; unknown values retained",
            "",
        ),
        InputField(
            "decision",
            UInteger,
            "wire decision code; unknown values retained",
            "",
        ),
        InputField(
            "effect_family",
            UInteger,
            "wire family code; unknown values retained",
            "",
        ),
        InputField(
            "operation",
            UInteger,
            "wire operation code; unknown values retained",
            "",
        ),
        InputField("configured_errno", Integer, "configured errno", ""),
        InputField("kernel_result", Integer, "kernel return value", ""),
        InputField(
            "temporal_coverage",
            Integer,
            "wire coverage enum; 0 unknown, 1 complete, 2 gapped; other values retained",
            "",
        ),
        InputField(
            "target_task_cookie",
            UBigint,
            "boot-local target task cookie",
            "No target task cookie is present.",
        ),
        InputField(
            "operation_argument",
            UInteger,
            "operation-specific argument",
            "No operation argument is present.",
        ),
        InputField(
            "context_schema_version",
            UInteger,
            "decision context version",
            CONTEXT_ABSENT,
        ),
        InputField(
            "kernel_sequence",
            UBigint,
            "original kernel sequence, not source cursor",
            CONTEXT_ABSENT,
        ),
        InputField(
            "process_instance_id",
            Blob,
            "ID bytes; empty means absent",
            CONTEXT_ABSENT,
        ),
        InputField(
            "entry_instance_id",
            Blob,
            "ID bytes; empty means absent",
            CONTEXT_ABSENT,
        ),
        InputField(
            "binding_id",
            Blob,
            "ID bytes; empty means absent",
            CONTEXT_ABSENT,
        ),
        InputField(
            "context_profile_generation_ref_id",
            UBigint,
            "context profile generation reference",
            CONTEXT_ABSENT,
        ),
        InputField("role_id", UInteger, "role ID", CONTEXT_ABSENT),
        InputField("state_id", UInteger, "state ID", CONTEXT_ABSENT),
        InputField("entry_rule_id", UInteger, "entry rule ID", CONTEXT_ABSENT),
        InputField(
            "exact_object_key_id",
            UBigint,
            "exact object handle",
            CONTEXT_ABSENT,
        ),
        InputField(
            "composite_atom_id",
            UBigint,
            "composite atom ID",
            CONTEXT_ABSENT,
        ),
        InputField(
            "catalog_json",
            Blob,
            "unchanged catalog bytes",
            CONTEXT_ABSENT,
        ),
        InputField(
            "catalog_state",
            Varchar,
            "unchanged catalog state",
            CONTEXT_ABSENT,
        ),
        InputField(
            "exact_profile_generation_ref_id",
            UBigint,
            "file object profile generation reference",
            OBJECT_ABSENT,
        ),
        InputField("mount_id_unique", UBigint, "unique mount ID", OBJECT_ABSENT),
        InputField("inode", UBigint, "inode number", OBJECT_ABSENT),
        InputField(
            "inode_generation",
            UBigint,
            "inode generation",
            OBJECT_ABSENT,
        ),
        InputField(
            "mount_namespace_inode",
            UInteger,
            "mount namespace inode",
            OBJECT_ABSENT,
        ),
        InputField(
            "filesystem_device",
            UInteger,
            "filesystem device",
            OBJECT_ABSENT,
        ),
    ],
    join_keys: "Event identity: tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch,cpu_id,source_cursor. Store order: commit_revision,ordinal within the result store UUID and recovery epoch. Coverage: full source identity plus coverage_interval_id=interval_id. Context requires an exact owner/entity/lifetime/revision key; names and time are not join keys.",
    owner: "araphor-data.AnalysisStore",
    readiness: "available",
    description: "Immutable evidence rows. Row counts are not physical-action counts. Coverage corrections do not change these rows. Source, intake, and store positions are distinct.",
};

const COVERAGE: InputSchema = InputSchema {
    name: "coverage",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("node_id", Varchar, "exact Node ID", ""),
        InputField("node_boot_id", Blob, "16-byte ID", ""),
        InputField("label_epoch", UBigint, "label epoch", ""),
        InputField("source_id", Blob, "16-byte ID", ""),
        InputField("source_epoch", UBigint, "receipt source epoch", ""),
        InputField("cpu_id", UInteger, "CPU ID", ""),
        InputField(
            "contiguous_cursor",
            UBigint,
            "durable contiguous ACK cursor",
            "",
        ),
        InputField(
            "coverage_revision",
            UBigint,
            "captured report revision; zero means no report",
            "",
        ),
        InputField(
            "retained_floor",
            UBigint,
            "retained source cursor floor",
            "",
        ),
        InputField(
            "kind",
            Varchar,
            "receipt, expired, recovery, pending, or interval",
            "",
        ),
        InputField(
            "state",
            Varchar,
            "unchanged interval state; receipt is reported or unknown",
            "",
        ),
        InputField(
            "first_cursor",
            UBigint,
            "inclusive source gap cursor",
            "This row is not a source gap.",
        ),
        InputField(
            "last_cursor",
            UBigint,
            "inclusive source gap cursor",
            "This row is not a source gap.",
        ),
        InputField(
            "commit_revision",
            UBigint,
            "source gap store revision",
            "This row is not a source gap.",
        ),
        InputField(
            "interval_id",
            Blob,
            "exact report interval ID",
            INTERVAL_ABSENT,
        ),
        InputField(
            "interval_source_epoch",
            UBigint,
            "report interval source epoch",
            INTERVAL_ABSENT,
        ),
        InputField(
            "interval_revision",
            UBigint,
            "report interval revision",
            INTERVAL_ABSENT,
        ),
        InputField(
            "first_sequence",
            UBigint,
            "first kernel sequence, not source cursor",
            INTERVAL_ABSENT,
        ),
        InputField(
            "last_sequence",
            UBigint,
            "last kernel sequence, not source cursor",
            "The interval is open or this row is not an interval.",
        ),
        InputField(
            "current",
            Boolean,
            "current report interval",
            INTERVAL_ABSENT,
        ),
        InputField(
            "gap_reasons",
            Varchar,
            "JSON array of unchanged reason strings",
            INTERVAL_ABSENT,
        ),
        InputField("opening_attempted", UBigint, "counter", OPENING_ABSENT),
        InputField("opening_suppressed", UBigint, "counter", OPENING_ABSENT),
        InputField("opening_requested", UBigint, "counter", OPENING_ABSENT),
        InputField("opening_emitted", UBigint, "counter", OPENING_ABSENT),
        InputField("opening_lost", UBigint, "counter", OPENING_ABSENT),
        InputField(
            "opening_classifier_miss_count",
            UBigint,
            "counter",
            OPENING_ABSENT,
        ),
        InputField("opening_unresolved", UBigint, "counter", OPENING_ABSENT),
        InputField(
            "opening_next_sequence",
            UBigint,
            "next kernel sequence",
            OPENING_ABSENT,
        ),
        InputField("closing_attempted", UBigint, "counter", CLOSING_ABSENT),
        InputField("closing_suppressed", UBigint, "counter", CLOSING_ABSENT),
        InputField("closing_requested", UBigint, "counter", CLOSING_ABSENT),
        InputField("closing_emitted", UBigint, "counter", CLOSING_ABSENT),
        InputField("closing_lost", UBigint, "counter", CLOSING_ABSENT),
        InputField(
            "closing_classifier_miss_count",
            UBigint,
            "counter",
            CLOSING_ABSENT,
        ),
        InputField("closing_unresolved", UBigint, "counter", CLOSING_ABSENT),
        InputField(
            "closing_next_sequence",
            UBigint,
            "next kernel sequence",
            CLOSING_ABSENT,
        ),
    ],
    join_keys: SOURCE_KEY,
    owner: "araphor-data.AnalysisStore",
    readiness: "available",
    description: "One captured source receipt plus explicit source gaps and report intervals. Reported does not mean healthy. Missing reports and absent counters are unknown. Counters are snapshots, not additive action counts.",
};

const CONTEXTS: InputSchema = InputSchema {
    name: "context_versions",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("owner_id", Varchar, "exact owner ID", ""),
        InputField("entity_key", Blob, "exact entity key", ""),
        InputField("lifetime_key", Blob, "exact lifetime key", ""),
        InputField(
            "owner_revision",
            UBigint,
            "owner revision, not store revision",
            "",
        ),
        InputField(
            "valid_from_utc_ns",
            UBigint,
            "inclusive UTC nanoseconds",
            "The owner did not provide time bounds.",
        ),
        InputField(
            "valid_until_utc_ns",
            UBigint,
            "exclusive UTC nanoseconds",
            "The owner did not provide an end time.",
        ),
        InputField(
            "sensitivity",
            Varchar,
            "public, tenant, or host_restricted",
            "",
        ),
        InputField("body", Blob, "unchanged owner body bytes", ""),
    ],
    join_keys: "tenant_id,owner_id,entity_key,lifetime_key,owner_revision",
    owner: "araphor-data.AnalysisStore",
    readiness: "available",
    description: "Exact immutable context versions selected by key. Missing selected versions remain in result metadata. This relation does not assert discovery readiness.",
};

const CATALOG: InputSchema = InputSchema {
    name: "catalog",
    columns: &[
        InputField("relation", Varchar, "relation name", ""),
        InputField("ordinal", UInteger, "zero-based column index", ""),
        InputField("column_name", Varchar, "column name", ""),
        InputField("data_type", Varchar, "DuckDB logical type", ""),
        InputField("units", Varchar, "field units and representation", ""),
        InputField("nullable", Boolean, "whether the column can be NULL", ""),
        InputField(
            "null_meaning",
            Varchar,
            "NULL meaning; empty for required fields",
            "",
        ),
        InputField("join_keys", Varchar, "exact keys and join restrictions", ""),
        InputField("owner", Varchar, "data owner", ""),
        InputField("readiness", Varchar, "available or unavailable", ""),
        InputField(
            "description",
            Varchar,
            "relation meaning and proof limits",
            "",
        ),
    ],
    join_keys: "relation,ordinal",
    owner: "araphor-data.QueryOwner",
    readiness: "available",
    description: "Code-owned schemas for this internal evaluator. An unavailable relation is not registered as an empty table. This catalog grants no client access.",
};

const TRACES: InputSchema = InputSchema {
    name: "traces",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("request_id", Blob, "16-byte ID", ""),
        InputField("target_index", UInteger, "accepted target index", ""),
        InputField("execution_id", Blob, "16-byte frozen execution ID", ""),
        InputField("node_id", Varchar, "exact Node ID", ""),
        InputField("node_boot_id", Blob, "16-byte original Node boot ID", ""),
        InputField("binding_id", Blob, "16-byte frozen runtime binding ID", ""),
        InputField("namespace_uid", Varchar, "exact namespace UID", ""),
        InputField("source", Blob, "unchanged accepted source bytes", ""),
        InputField(
            "source_sha256",
            Blob,
            "SHA-256 of accepted source; not a raw batch digest",
            "",
        ),
        InputField("trace_schema_version", UInteger, "trace schema version", ""),
        InputField(
            "request_revision",
            UBigint,
            "metadata revision for cancellation and read revocation",
            "",
        ),
        InputField("accepted_unix_ns", UBigint, "UTC nanoseconds", ""),
        InputField("deadline_unix_ns", UBigint, "UTC nanoseconds", ""),
        InputField("last_sequence", UBigint, "trace frame sequence", ""),
        InputField("output_bytes", UBigint, "bytes", ""),
        InputField(
            "retained_floor",
            UBigint,
            "expired diagnostic record cursor; terminal uses last_sequence plus one",
            "",
        ),
        InputField(
            "cancel_requested",
            Boolean,
            "request cancellation state",
            "",
        ),
        InputField("read_revoked", Boolean, "read authority state", ""),
        InputField(
            "terminal_reason",
            Varchar,
            "terminal reason",
            "No terminal result is present.",
        ),
        InputField(
            "output_incomplete",
            Boolean,
            "terminal output completeness",
            "No terminal result is present.",
        ),
        InputField(
            "kernel_lost_events",
            UBigint,
            "lost event count",
            "The loss count is unknown or no terminal result is present.",
        ),
        InputField(
            "ready_at_unix_ns",
            UBigint,
            "UTC nanoseconds",
            "Readiness was not observed.",
        ),
        InputField(
            "exit_code",
            Integer,
            "process exit code",
            "No exit code is present.",
        ),
        InputField(
            "forced_kill",
            Boolean,
            "terminal forced-kill state",
            "No terminal result is present.",
        ),
        InputField(
            "cleanup",
            Varchar,
            "terminal cleanup proof",
            "No terminal result is present.",
        ),
    ],
    join_keys: "tenant_id,request_id,execution_id. The target index selects the immutable accepted binding. Original Node boot and source digest must match; names do not identify a target lifetime.",
    owner: "araphor-data.AnalysisStore",
    readiness: "available",
    description: "One execution's retained intent, request state and output receipt. A closed stream is not a terminal result. Receipt counters do not prove raw output remains retained.",
};

const TRACE_OUTPUT: InputSchema = InputSchema {
    name: "trace_output",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("request_id", Blob, "16-byte request ID", ""),
        InputField("execution_id", Blob, "16-byte execution ID", ""),
        InputField("node_id", Varchar, "exact Node ID", ""),
        InputField("node_boot_id", Blob, "16-byte original Node boot ID", ""),
        InputField(
            "source_sha256",
            Blob,
            "SHA-256 of accepted source; not a raw batch digest",
            "",
        ),
        InputField("target_index", UInteger, "accepted target index", ""),
        InputField("sequence", UBigint, "trace frame sequence", ""),
        InputField("commit_revision", UBigint, "raw store revision", ""),
        InputField("ordinal", UInteger, "record index within raw commit", ""),
        InputField(
            "kind",
            Varchar,
            "metadata, data, diagnostic, or terminal",
            "",
        ),
        InputField("bytes", Blob, "unchanged raw output bytes", ""),
    ],
    join_keys: "tenant_id,request_id,execution_id,sequence. Store order: commit_revision,ordinal within the result store UUID and recovery epoch. Match original Node boot and source digest.",
    owner: "araphor-data.AnalysisStore",
    readiness: "available",
    description: "Retained raw output with exact shared segment positions. Terminal bytes are unchanged TraceTerminalV1 JSON at last_sequence plus one. Empty output does not prove absence of activity. Expired output is not an empty successful read.",
};

const TRACE_MEASUREMENTS: InputSchema = InputSchema {
    name: "trace_measurements",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("request_id", Blob, "16-byte request ID", ""),
        InputField(
            "execution_id",
            Blob,
            "16-byte execution ID; reset epoch",
            "",
        ),
        InputField("sequence", UBigint, "source trace frame sequence", ""),
        InputField("ordinal", UInteger, "measurement index within frame", ""),
        InputField(
            "syscall_id",
            UInteger,
            "syscall number",
            "The recipe has no exact syscall ID.",
        ),
        InputField("errno", Bigint, "negative errno", ""),
        InputField("count", UBigint, "recipe unit", ""),
        InputField("cumulative", Boolean, "cumulative or interval count", ""),
        InputField("atomic_snapshot", Boolean, "snapshot atomicity", ""),
        InputField("unit", Varchar, "reviewed recipe unit", ""),
    ],
    join_keys: "tenant_id,request_id,execution_id,sequence,ordinal. The sequence identifies the source trace_output frame; ordinal identifies a measurement within that frame, not a store ordinal.",
    owner: "araphor-data.TraceRecipeV1",
    readiness: "available",
    description: "Reviewed measurements decoded from retained raw frames. Do not sum cumulative snapshots. The execution ID separates reset epochs. Sampling and loss are not inferred from these rows.",
};

const TARGETS: InputSchema = InputSchema {
    name: "targets",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("entity_key", Blob, "exact retained context entity key", ""),
        InputField(
            "lifetime_key",
            Blob,
            "exact retained context lifetime key",
            "",
        ),
        InputField("owner_revision", UBigint, "immutable context version", ""),
        InputField("node_id", Varchar, "exact Node ID", ""),
        InputField(
            "node_boot_id",
            Blob,
            "16-byte original Node boot ID",
            "No Kubernetes identity is present.",
        ),
        InputField(
            "label_epoch",
            UBigint,
            "original label epoch",
            "No Kubernetes identity is present.",
        ),
        InputField(
            "binding_id",
            Blob,
            "16-byte exact runtime binding ID",
            "No Kubernetes identity is present.",
        ),
        InputField(
            "workload_binding_generation_digest",
            Varchar,
            "existing signed fact generation identity",
            "",
        ),
        InputField("execution_set_id", Varchar, "exact execution set ID", ""),
        InputField("cluster_uid", Varchar, "exact cluster UID", ""),
        InputField("namespace_uid", Varchar, "exact namespace UID", ""),
        InputField("controller_uid", Varchar, "exact controller UID", ""),
        InputField(
            "service_account_uid",
            Varchar,
            "exact service account UID",
            "",
        ),
        InputField("pod_uid", Varchar, "exact Pod UID", ""),
        InputField("container_id", Varchar, "exact runtime container ID", ""),
        InputField(
            "container_name",
            Varchar,
            "container name; not a lifetime key",
            "",
        ),
        InputField(
            "container_kind",
            Varchar,
            "INIT, SIDECAR, APPLICATION, or EPHEMERAL",
            "",
        ),
        InputField("image_digest", Varchar, "retained image identity", ""),
        InputField("pod_labels", Blob, "JSON object of retained labels", ""),
        InputField(
            "namespace_name",
            Varchar,
            "retained namespace name",
            "No Kubernetes identity is present.",
        ),
        InputField(
            "pod_name",
            Varchar,
            "retained Pod name; not a lifetime key",
            "No Kubernetes identity is present.",
        ),
        InputField(
            "profile_id",
            Varchar,
            "exact profile ID",
            "No Kubernetes identity is present.",
        ),
        InputField(
            "policy_source_revision_id",
            Varchar,
            "existing policy source identity",
            "No Kubernetes identity is present.",
        ),
        InputField(
            "protected_scope_id",
            Varchar,
            "exact protected scope ID",
            "No Kubernetes identity is present.",
        ),
        InputField(
            "workload_selector_id",
            Varchar,
            "exact workload selector ID",
            "No Kubernetes identity is present.",
        ),
        InputField(
            "kubernetes_node_name",
            Varchar,
            "retained Kubernetes Node name",
            "No Kubernetes identity is present.",
        ),
        InputField(
            "kubernetes_node_uid",
            Varchar,
            "exact Kubernetes Node UID",
            "No Kubernetes identity is present.",
        ),
    ],
    join_keys: "tenant_id,entity_key,lifetime_key,owner_revision. Join events or traces by tenant_id,node_id,node_boot_id,binding_id. Names do not identify a target lifetime.",
    owner: "mithril-control.ControlContextOwner",
    readiness: "available",
    description: "Retained policy target inventory from committed immutable snapshots. This relation is not complete live inventory and does not assert current attachment, policy readiness, or trace capability. Trace submission resolves the current exact lifetime.",
};

const TRACE_RECIPES: InputSchema = InputSchema {
    name: "trace_recipes",
    columns: &[
        InputField("recipe", Varchar, "exact public recipe selector", ""),
        InputField("version", UInteger, "reviewed recipe version", ""),
        InputField("source", Blob, "unchanged reviewed bpftrace source", ""),
        InputField("source_sha256", Blob, "SHA-256 of reviewed source", ""),
        InputField(
            "parameter",
            Varchar,
            "Node-owned parameter; not a client override",
            "",
        ),
        InputField("attribution", Varchar, "recipe attribution boundary", ""),
        InputField("sensitivity", Varchar, "output sensitivity", ""),
        InputField("hook", Varchar, "required kernel hook", ""),
        InputField(
            "measurement_keys",
            Blob,
            "JSON array of measurement keys",
            "",
        ),
        InputField("unit", Varchar, "measurement unit", ""),
        InputField("cumulative", Boolean, "cumulative or interval count", ""),
        InputField("atomic_snapshot", Boolean, "snapshot atomicity", ""),
        InputField("maximum_probes", UInteger, "probe limit", ""),
        InputField("maximum_map_keys", UInteger, "map key limit", ""),
        InputField(
            "return_code_semantics",
            Varchar,
            "kernel return code meaning",
            "",
        ),
        InputField(
            "capability_status",
            Varchar,
            "unknown; backend readiness was not checked",
            "",
        ),
        InputField(
            "example",
            Varchar,
            "CLI example; target names require current resolution",
            "",
        ),
    ],
    join_keys: "recipe,version. source_sha256 binds the exact reviewed source. A recipe row grants no execution authority.",
    owner: "araphor-data.TraceRecipeV1",
    readiness: "available",
    description: "Code-owned reviewed recipes, not stored copies. Capability status is unknown until the selected Node admits the request. This relation does not enable a backend or assert performance qualification.",
};

pub(super) const SCHEMAS: &[InputSchema] = &[
    EVENTS,
    COVERAGE,
    CONTEXTS,
    CATALOG,
    TRACES,
    TRACE_OUTPUT,
    TRACE_MEASUREMENTS,
    TARGETS,
    TRACE_RECIPES,
    BEHAVIORS,
    CONTEXT,
];

#[derive(Debug)]
pub(super) struct InputRow(pub(super) Vec<Value>);

impl TryFrom<AnalysisInputV1<'_>> for InputRow {
    type Error = crate::Error;

    fn try_from(input: AnalysisInputV1<'_>) -> Result<Self> {
        match input {
            AnalysisInputV1::Event {
                identity,
                cpu_id,
                received_utc_ns,
                record,
            } => {
                let decoded = EvidenceRecord::try_from(record.framed_record.as_slice())?;
                let mut row = Self(Vec::with_capacity(EVENTS.columns.len()));
                row.source(identity, cpu_id);
                row.0.extend([
                    Value::UBigInt(record.cursor),
                    Value::UBigInt(record.position.commit_revision),
                    Value::UInt(record.position.ordinal),
                    Value::UBigInt(received_utc_ns),
                    Value::Timestamp(TimeUnit::Microsecond, (received_utc_ns / 1_000) as i64),
                    Value::UBigInt(decoded.observed_boottime_ns),
                    Value::BigInt(decoded.ingested_utc_ns),
                    Value::Blob(decoded.coverage_interval_id.into()),
                    decoded
                        .profile_generation_ref_id
                        .map_or(Value::Null, Value::UBigInt),
                    Value::UBigInt(decoded.task_cookie),
                    Value::Blob(decoded.process_lineage_id.into()),
                    Value::Blob(decoded.authority_domain_id.into()),
                    Value::Blob(decoded.execution_set_id.into()),
                    Value::Blob(decoded.exact_object_id.into()),
                    Value::UBigInt(decoded.destination_id),
                    Value::UBigInt(decoded.policy_rule_id),
                    Value::UInt(decoded.reason),
                    Value::UInt(decoded.decision),
                    Value::UInt(decoded.effect_family),
                    Value::UInt(decoded.operation),
                    Value::Int(decoded.configured_errno),
                    Value::Int(decoded.kernel_result),
                    Value::Int(decoded.temporal_coverage),
                    decoded
                        .target_task_cookie
                        .map_or(Value::Null, Value::UBigInt),
                    decoded.operation_argument.map_or(Value::Null, Value::UInt),
                ]);
                if let Some(context) = decoded.decision_context {
                    row.0.extend([
                        Value::UInt(context.schema_version),
                        Value::UBigInt(context.original_kernel_sequence),
                        Value::Blob(context.process_instance_id),
                        Value::Blob(context.entry_instance_id),
                        Value::Blob(context.binding_id),
                        Value::UBigInt(context.profile_generation_ref_id),
                        Value::UInt(context.role_id),
                        Value::UInt(context.state_id),
                        Value::UInt(context.entry_rule_id),
                        Value::UBigInt(context.exact_object_key_id),
                        Value::UBigInt(context.composite_atom_id),
                        Value::Blob(context.catalog_json),
                        Value::Text(context.catalog_state),
                    ]);
                    if let Some(object) = context.exact_file_object {
                        row.0.extend([
                            Value::UBigInt(object.profile_generation_ref_id),
                            Value::UBigInt(object.mount_id_unique),
                            Value::UBigInt(object.inode),
                            Value::UBigInt(object.inode_generation),
                            Value::UInt(object.mount_namespace_inode),
                            Value::UInt(object.filesystem_device),
                        ]);
                    }
                }
                row.0.resize(EVENTS.columns.len(), Value::Null);
                Ok(row)
            }
            AnalysisInputV1::Context(context) => Ok(Self::from(context)),
            AnalysisInputV1::DiscoveryContext(context) => super::discovery::context_row(context),
            AnalysisInputV1::Behavior {
                profile,
                commit_revision,
                atom,
                discovery_enabled,
            } => super::discovery::behavior_row(profile, commit_revision, atom, discovery_enabled),
            AnalysisInputV1::Target { context, fact } => {
                let entity = fact
                    .kubernetes
                    .as_ref()
                    .map_or(fact.execution_set_id.as_str(), |identity| {
                        identity.binding_id.as_str()
                    });
                if context.key.owner_id != "mithril-control/target"
                    || context.key.entity_key != entity.as_bytes()
                    || context.key.lifetime_key
                        != fact.workload_binding_generation_digest.as_bytes()
                    || context.key.owner_revision != 1
                    || !crate::node_id_is_valid(&fact.node_id)
                {
                    return crate::QueryInvalidSnafu {
                        field: "target context",
                    }
                    .fail();
                }
                let identity = fact.kubernetes.as_ref();
                let id = |value: &str| {
                    uuid::Uuid::parse_str(value)
                        .ok()
                        .filter(|id| !id.is_nil())
                        .map(|id| Value::Blob(id.as_bytes().to_vec()))
                        .ok_or_else(|| {
                            crate::QueryInvalidSnafu {
                                field: "target identity",
                            }
                            .build()
                        })
                };
                let kind = match fact.container_kind {
                    crate::ContainerKindV1::Init => "INIT",
                    crate::ContainerKindV1::Sidecar => "SIDECAR",
                    crate::ContainerKindV1::Application => "APPLICATION",
                    crate::ContainerKindV1::Ephemeral => "EPHEMERAL",
                };
                let labels = serde_json::to_vec(&fact.pod_labels)
                    .map_err(|source| crate::QueryEncodingSnafu.into_error(source))?;
                let mut row = Self(vec![
                    Value::Blob(context.key.tenant_id.to_vec()),
                    Value::Blob(context.key.entity_key.clone()),
                    Value::Blob(context.key.lifetime_key.clone()),
                    Value::UBigInt(context.key.owner_revision),
                    Value::Text(fact.node_id.clone()),
                    identity
                        .map(|identity| id(&identity.node_boot_id))
                        .transpose()?
                        .unwrap_or(Value::Null),
                    identity.map_or(Value::Null, |identity| Value::UBigInt(identity.label_epoch)),
                    identity
                        .map(|identity| id(&identity.binding_id))
                        .transpose()?
                        .unwrap_or(Value::Null),
                    Value::Text(fact.workload_binding_generation_digest.clone()),
                    Value::Text(fact.execution_set_id.clone()),
                    Value::Text(fact.cluster_uid.clone()),
                    Value::Text(fact.namespace_uid.clone()),
                    Value::Text(fact.controller_uid.clone()),
                    Value::Text(fact.service_account_uid.clone()),
                    Value::Text(fact.pod_uid.clone()),
                    Value::Text(fact.container_id.clone()),
                    Value::Text(fact.container_name.clone()),
                    Value::Text(kind.into()),
                    Value::Text(fact.image_digest.clone()),
                    Value::Blob(labels),
                ]);
                if let Some(identity) = identity {
                    row.0.extend([
                        Value::Text(identity.namespace_name.clone()),
                        Value::Text(identity.pod_name.clone()),
                        Value::Text(identity.profile_id.clone()),
                        Value::Text(identity.policy_source_revision_id.clone()),
                        Value::Text(identity.protected_scope_id.clone()),
                        Value::Text(identity.workload_selector_id.clone()),
                        Value::Text(identity.kubernetes_node_name.clone()),
                        Value::Text(identity.kubernetes_node_uid.clone()),
                    ]);
                }
                row.0.resize(TARGETS.columns.len(), Value::Null);
                Ok(row)
            }
            AnalysisInputV1::Trace {
                state,
                intent,
                target_index,
                receipt,
            } => {
                let binding = intent.bindings.get(target_index as usize).ok_or_else(|| {
                    crate::QueryInvalidSnafu {
                        field: "trace target index",
                    }
                    .build()
                })?;
                let identity = &binding.identity;
                let terminal = receipt.terminal.as_ref();
                Ok(Self(vec![
                    Value::Blob(intent.tenant_id.to_vec()),
                    Value::Blob(intent.request_id.to_vec()),
                    Value::UInt(target_index),
                    Value::Blob(identity.execution_id.to_vec()),
                    Value::Text(identity.node_id.clone()),
                    Value::Blob(identity.node_boot_id.to_vec()),
                    Value::Blob(binding.binding_id.to_vec()),
                    Value::Text(binding.namespace_uid.clone()),
                    Value::Blob(intent.source.bytes.clone()),
                    Value::Blob(intent.source.sha256.to_vec()),
                    Value::UInt(1),
                    Value::UBigInt(state.revision),
                    Value::UBigInt(intent.accepted_unix_ns),
                    Value::UBigInt(intent.deadline_unix_ns),
                    Value::UBigInt(receipt.last_sequence),
                    Value::UBigInt(receipt.output_bytes),
                    Value::UBigInt(receipt.retained_floor),
                    Value::Boolean(state.cancel_requested),
                    Value::Boolean(state.read_revoked),
                    terminal.map_or(Value::Null, |value| {
                        Value::Text(format!("{:?}", value.reason))
                    }),
                    terminal.map_or(Value::Null, |value| Value::Boolean(value.output_incomplete)),
                    terminal
                        .and_then(|value| value.kernel_lost_events)
                        .map_or(Value::Null, Value::UBigInt),
                    terminal
                        .and_then(|value| value.ready_at_unix_ns)
                        .map_or(Value::Null, Value::UBigInt),
                    terminal
                        .and_then(|value| value.exit_code)
                        .map_or(Value::Null, Value::Int),
                    terminal.map_or(Value::Null, |value| Value::Boolean(value.forced_kill)),
                    terminal.map_or(Value::Null, |value| {
                        Value::Text(format!("{:?}", value.cleanup))
                    }),
                ]))
            }
            AnalysisInputV1::TraceOutput {
                identity,
                target_index,
                sequence,
                position,
                kind,
                bytes,
            } => Ok(Self(vec![
                Value::Blob(identity.tenant_id.to_vec()),
                Value::Blob(identity.request_id.to_vec()),
                Value::Blob(identity.execution_id.to_vec()),
                Value::Text(identity.node_id.clone()),
                Value::Blob(identity.node_boot_id.to_vec()),
                Value::Blob(identity.source_sha256.to_vec()),
                Value::UInt(target_index),
                Value::UBigInt(sequence),
                Value::UBigInt(position.commit_revision),
                Value::UInt(position.ordinal),
                Value::Text(kind.into()),
                Value::Blob(bytes.to_vec()),
            ])),
            AnalysisInputV1::TraceMeasurement {
                identity,
                measurement,
            } => Ok(Self(vec![
                Value::Blob(identity.tenant_id.to_vec()),
                Value::Blob(identity.request_id.to_vec()),
                Value::Blob(identity.execution_id.to_vec()),
                Value::UBigInt(measurement.sequence),
                Value::UInt(u32::from(measurement.ordinal)),
                measurement.syscall_id.map_or(Value::Null, Value::UInt),
                Value::BigInt(measurement.errno),
                Value::UBigInt(measurement.count),
                Value::Boolean(measurement.cumulative),
                Value::Boolean(measurement.atomic_snapshot),
                Value::Text(measurement.unit.clone()),
            ])),
            AnalysisInputV1::Result { .. } => crate::QueryUnsupportedSnafu {
                relation: "results",
            }
            .fail(),
        }
    }
}

impl From<&AnalysisContextVersionV1> for InputRow {
    fn from(context: &AnalysisContextVersionV1) -> Self {
        Self(vec![
            Value::Blob(context.key.tenant_id.to_vec()),
            Value::Text(context.key.owner_id.clone()),
            Value::Blob(context.key.entity_key.clone()),
            Value::Blob(context.key.lifetime_key.clone()),
            Value::UBigInt(context.key.owner_revision),
            context
                .valid_from_utc_ns
                .map_or(Value::Null, Value::UBigInt),
            context
                .valid_until_utc_ns
                .map_or(Value::Null, Value::UBigInt),
            Value::Text(<&str>::from(context.sensitivity).into()),
            Value::Blob(context.body.clone()),
        ])
    }
}

impl TryFrom<TraceRecipeManifestV1> for InputRow {
    type Error = crate::Error;

    fn try_from(recipe: TraceRecipeManifestV1) -> Result<Self> {
        let name = match recipe.recipe {
            TraceRecipeV1::SyscallErrors => "syscall-errors@1",
            TraceRecipeV1::FailedOpens => "failed-opens@1",
        };
        let keys = serde_json::to_vec(&recipe.measurement_keys)
            .map_err(|source| crate::QueryEncodingSnafu.into_error(source))?;
        Ok(Self(vec![
            Value::Text(name.into()),
            Value::UInt(recipe.version),
            Value::Blob(recipe.source.bytes),
            Value::Blob(recipe.source.sha256.into()),
            Value::Text(recipe.parameter),
            Value::Text(recipe.attribution),
            Value::Text(recipe.sensitivity),
            Value::Text(recipe.hook),
            Value::Blob(keys),
            Value::Text(recipe.unit),
            Value::Boolean(recipe.cumulative),
            Value::Boolean(recipe.atomic_snapshot),
            Value::UInt(u32::from(recipe.maximum_probes)),
            Value::UInt(recipe.maximum_map_keys),
            Value::Text(recipe.return_code_semantics),
            Value::Text("unknown".into()),
            Value::Text(format!(
                "araphor trace --target pod/default/workload --recipe {name} --duration 30s"
            )),
        ]))
    }
}

impl InputRow {
    pub(super) fn allocation_bytes(&self) -> Result<usize> {
        let mut bytes = self.0.capacity().checked_mul(size_of::<Value>());
        for value in &self.0 {
            let owned = match value {
                Value::Text(value) => value.capacity(),
                Value::Blob(value) => value.capacity(),
                Value::Null
                | Value::Boolean(_)
                | Value::UInt(_)
                | Value::UBigInt(_)
                | Value::Int(_)
                | Value::BigInt(_)
                | Value::Timestamp(TimeUnit::Microsecond, _) => 0,
                _ => {
                    return crate::QueryInvalidSnafu {
                        field: "input row value",
                    }
                    .fail();
                }
            };
            bytes = bytes.and_then(|bytes| bytes.checked_add(owned));
        }
        bytes.ok_or_else(|| {
            crate::QueryLimitSnafu {
                resource: "query input bytes",
                limit: usize::MAX,
            }
            .build()
        })
    }

    fn source(&mut self, identity: &EvidenceIntakeIdentityV1, cpu_id: u32) {
        self.0.extend([
            Value::Blob(identity.tenant_id.to_vec()),
            Value::Text(identity.node_id.clone()),
            Value::Blob(identity.node_boot_id.to_vec()),
            Value::UBigInt(identity.label_epoch),
            Value::Blob(identity.source_id.to_vec()),
            Value::UBigInt(identity.source_epoch),
            Value::UInt(cpu_id),
        ]);
    }

    fn coverage(
        source: &AnalysisSourceSnapshotV1,
        kind: &'static str,
        state: String,
        gap: Option<&AnalysisGapV1>,
        interval: Option<CoverageInterval>,
    ) -> Result<Self> {
        let receipt = &source.receipt;
        let mut row = Self(Vec::with_capacity(COVERAGE.columns.len()));
        row.source(&receipt.identity, receipt.cpu_id);
        row.0.extend([
            Value::UBigInt(receipt.contiguous_cursor),
            Value::UBigInt(receipt.coverage_revision),
            Value::UBigInt(receipt.retained_floor),
            Value::Text(kind.into()),
            Value::Text(state),
            gap.map_or(Value::Null, |gap| Value::UBigInt(gap.first_cursor)),
            gap.map_or(Value::Null, |gap| Value::UBigInt(gap.last_cursor)),
            gap.map_or(Value::Null, |gap| Value::UBigInt(gap.commit_revision)),
        ]);
        if let Some(interval) = interval {
            let reasons = serde_json::to_string(&interval.gap_reasons)
                .map_err(|source| crate::QueryEncodingSnafu.into_error(source))?;
            row.0.extend([
                Value::Blob(interval.interval_id),
                Value::UBigInt(interval.source_epoch),
                Value::UBigInt(interval.revision),
                Value::UBigInt(interval.first_sequence),
                interval.last_sequence.map_or(Value::Null, Value::UBigInt),
                Value::Boolean(interval.current),
                Value::Text(reasons),
            ]);
            row.counters(interval.opening_counters);
            row.counters(interval.closing_counters);
        }
        row.0.resize(COVERAGE.columns.len(), Value::Null);
        Ok(row)
    }

    fn counters(&mut self, counters: Option<CoverageCounters>) {
        if let Some(counters) = counters {
            self.0.extend(
                [
                    counters.attempted,
                    counters.suppressed,
                    counters.requested,
                    counters.emitted,
                    counters.lost,
                    counters.classifier_miss_count,
                    counters.unresolved,
                    counters.next_sequence,
                ]
                .map(Value::UBigInt),
            );
        } else {
            self.0.resize(self.0.len() + 8, Value::Null);
        }
    }
}

pub(super) struct InputRelations {
    tables: Vec<Arc<InputTable>>,
    schemas: Vec<&'static InputSchema>,
    bytes: usize,
}

impl InputRelations {
    pub(super) fn new(
        extraction: &mut AnalysisExtractionV1<InputRow>,
        limit: usize,
        template: &QueryTemplate,
    ) -> Result<Self> {
        let mut bytes = extraction.input_bytes;
        Self::charge(&mut bytes, 0, limit)?;
        let mut counts = [0_usize; 11];
        if !extraction.missing_results.is_empty() {
            return crate::QueryUnsupportedSnafu {
                relation: "results",
            }
            .fail();
        }
        for page in &extraction.pages {
            let index = match page.relation {
                AnalysisRelationV1::Events => 0,
                AnalysisRelationV1::Context => 2,
                AnalysisRelationV1::Behaviors => 9,
                AnalysisRelationV1::DiscoveryContext => 10,
                AnalysisRelationV1::Traces => 4,
                AnalysisRelationV1::TraceOutput => 5,
                AnalysisRelationV1::TraceMeasurements => 6,
                AnalysisRelationV1::Targets => 7,
                AnalysisRelationV1::Results => {
                    return crate::QueryUnsupportedSnafu {
                        relation: "results",
                    }
                    .fail();
                }
            };
            counts[index] = counts[index].checked_add(page.rows.len()).ok_or_else(|| {
                crate::QueryLimitSnafu {
                    resource: "query input bytes",
                    limit,
                }
                .build()
            })?;
        }
        let mut tables = [
            Self::table(&EVENTS, counts[0], &mut bytes, limit)?,
            Self::table(&COVERAGE, 0, &mut bytes, limit)?,
            Self::table(&CONTEXTS, counts[2], &mut bytes, limit)?,
            Self::table(&CATALOG, 0, &mut bytes, limit)?,
            Self::table(&TRACES, counts[4], &mut bytes, limit)?,
            Self::table(&TRACE_OUTPUT, counts[5], &mut bytes, limit)?,
            Self::table(&TRACE_MEASUREMENTS, counts[6], &mut bytes, limit)?,
            Self::table(&TARGETS, counts[7], &mut bytes, limit)?,
            Self::table(&TRACE_RECIPES, 0, &mut bytes, limit)?,
            Self::table(&BEHAVIORS, counts[9], &mut bytes, limit)?,
            Self::table(&CONTEXT, counts[10], &mut bytes, limit)?,
        ];
        Self::charge(&mut bytes, size_of::<Self>(), limit)?;
        for page in &mut extraction.pages {
            let index = match page.relation {
                AnalysisRelationV1::Events => 0,
                AnalysisRelationV1::Context => 2,
                AnalysisRelationV1::Behaviors => 9,
                AnalysisRelationV1::DiscoveryContext => 10,
                AnalysisRelationV1::Traces => 4,
                AnalysisRelationV1::TraceOutput => 5,
                AnalysisRelationV1::TraceMeasurements => 6,
                AnalysisRelationV1::Targets => 7,
                AnalysisRelationV1::Results => {
                    return crate::QueryUnsupportedSnafu {
                        relation: "results",
                    }
                    .fail();
                }
            };
            for row in take(&mut page.rows) {
                tables[index].rows.push(row.0);
            }
        }
        if matches!(template, QueryTemplate::Coverage)
            || matches!(template, QueryTemplate::Client(sql) if sql.dependencies().contains("coverage"))
        {
            for source in &extraction.sources {
                let report = Self::report(source)?;
                Self::push(
                    &mut tables[1],
                    InputRow::coverage(
                        source,
                        "receipt",
                        if report.is_some() {
                            "reported"
                        } else {
                            "unknown"
                        }
                        .into(),
                        None,
                        None,
                    )?,
                    &mut bytes,
                    limit,
                )?;
                for (kind, gaps) in [
                    ("expired", &source.expired),
                    ("recovery", &source.recovery),
                    ("pending", &source.pending),
                ] {
                    for gap in gaps {
                        Self::push(
                            &mut tables[1],
                            InputRow::coverage(source, kind, kind.into(), Some(gap), None)?,
                            &mut bytes,
                            limit,
                        )?;
                    }
                }
                if let Some(report) = report {
                    for mut interval in report.intervals {
                        let state = take(&mut interval.state);
                        Self::push(
                            &mut tables[1],
                            InputRow::coverage(source, "interval", state, None, Some(interval))?,
                            &mut bytes,
                            limit,
                        )?;
                    }
                }
            }
        }
        if matches!(template, QueryTemplate::Catalog)
            || matches!(template, QueryTemplate::Client(sql) if sql.dependencies().contains("catalog"))
        {
            for schema in SCHEMAS {
                for (ordinal, field) in schema.columns.iter().enumerate() {
                    Self::push(
                        &mut tables[3],
                        InputRow(vec![
                            Value::Text(schema.name.into()),
                            Value::UInt(ordinal as u32),
                            Value::Text(field.0.into()),
                            Value::Text(format!("{:?}", field.1)),
                            Value::Text(field.2.into()),
                            Value::Boolean(!field.3.is_empty()),
                            Value::Text(field.3.into()),
                            Value::Text(schema.join_keys.into()),
                            Value::Text(schema.owner.into()),
                            Value::Text(
                                if schema.name == "behaviors" {
                                    if extraction.discovery_enabled {
                                        "enabled"
                                    } else {
                                        "disabled"
                                    }
                                } else {
                                    schema.readiness
                                }
                                .into(),
                            ),
                            Value::Text(schema.description.into()),
                        ]),
                        &mut bytes,
                        limit,
                    )?;
                }
            }
        }
        if matches!(template, QueryTemplate::Client(sql) if sql.dependencies().contains("trace_recipes"))
        {
            for recipe in [TraceRecipeV1::SyscallErrors, TraceRecipeV1::FailedOpens] {
                Self::push(
                    &mut tables[8],
                    InputRow::try_from(recipe.manifest()?)?,
                    &mut bytes,
                    limit,
                )?;
            }
        }
        extraction.input_bytes = bytes;
        Ok(Self {
            tables: tables.into_iter().map(Arc::new).collect(),
            schemas: SCHEMAS.iter().collect(),
            bytes,
        })
    }

    pub(super) fn append_positions(mut self, limit: usize) -> Result<Self> {
        Self::charge(&mut self.bytes, 0, limit)?;
        for (table, schema) in self.tables.iter_mut().zip(&self.schemas) {
            if !matches!(schema.name, "events" | "trace_output") {
                continue;
            }
            let invalid = || {
                crate::QueryInvalidSnafu {
                    field: "append input",
                }
                .build()
            };
            let table = Arc::get_mut(table).ok_or_else(invalid)?;
            if table.columns.len() != schema.columns.len()
                || table
                    .columns
                    .iter()
                    .zip(schema.columns)
                    .any(|(column, field)| column.0 != field.0 || column.1 != field.1)
            {
                return Err(invalid());
            }
            let revision = table
                .columns
                .iter()
                .position(|column| column.0 == "commit_revision")
                .ok_or_else(invalid)?;
            let ordinal = table
                .columns
                .iter()
                .position(|column| column.0 == "ordinal")
                .ok_or_else(invalid)?;
            let width = table.columns.len();
            let needed =
                (width + 2).saturating_sub(table.columns.capacity()) * size_of::<InputColumn>();
            Self::charge(&mut self.bytes, needed, limit)?;
            let previous = table.columns.capacity();
            table.columns.try_reserve_exact(2).map_err(|_| {
                crate::QueryLimitSnafu {
                    resource: "query input bytes",
                    limit,
                }
                .build()
            })?;
            Self::charge(
                &mut self.bytes,
                (table.columns.capacity() - previous) * size_of::<InputColumn>() - needed,
                limit,
            )?;
            table.columns.extend([
                InputColumn("__araphor_commit_revision", UBigint),
                InputColumn("__araphor_ordinal", UInteger),
            ]);
            for row in &mut table.rows {
                if row.len() != width {
                    return Err(invalid());
                }
                let (Value::UBigInt(revision), Value::UInt(ordinal)) =
                    (&row[revision], &row[ordinal])
                else {
                    return Err(invalid());
                };
                let positions = [Value::UBigInt(*revision), Value::UInt(*ordinal)];
                let needed = (width + 2).saturating_sub(row.capacity()) * size_of::<Value>();
                Self::charge(&mut self.bytes, needed, limit)?;
                let previous = row.capacity();
                row.try_reserve_exact(2).map_err(|_| {
                    crate::QueryLimitSnafu {
                        resource: "query input bytes",
                        limit,
                    }
                    .build()
                })?;
                Self::charge(
                    &mut self.bytes,
                    (row.capacity() - previous) * size_of::<Value>() - needed,
                    limit,
                )?;
                row.extend(positions);
            }
        }
        Ok(self)
    }

    pub(super) fn allocation_bytes(&self) -> usize {
        self.bytes
    }

    pub(super) fn register(&self, connection: &Connection) -> Result<()> {
        for (table, schema) in self.tables.iter().zip(&self.schemas) {
            let function = match schema.name {
                "events" => "_query_events",
                "coverage" => "_query_coverage",
                "context_versions" => "_query_contexts",
                "catalog" => "_query_catalog",
                "traces" => "_query_traces",
                "trace_output" => "_query_trace_output",
                "trace_measurements" => "_query_trace_measurements",
                "targets" => "_query_targets",
                "trace_recipes" => "_query_trace_recipes",
                "behaviors" => "_query_behaviors",
                "context" => "_query_discovery_context",
                _ => {
                    return crate::QueryInvalidSnafu {
                        field: "query relation",
                    }
                    .fail();
                }
            };
            table.register(connection, function, schema.name)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn references(&self) -> impl Iterator<Item = std::sync::Weak<InputTable>> + '_ {
        self.tables.iter().map(Arc::downgrade)
    }

    #[cfg(test)]
    pub(super) fn set_scan_gate(&self, gate: Option<super::adapter::ScanGate>) -> Result<()> {
        *self.tables[0].scan_gate.lock().map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "test scan gate",
            }
            .build()
        })? = gate;
        Ok(())
    }

    fn table(
        schema: &InputSchema,
        rows: usize,
        bytes: &mut usize,
        limit: usize,
    ) -> Result<InputTable> {
        let columns: Vec<_> = schema
            .columns
            .iter()
            .map(|field| InputColumn(field.0, field.1))
            .collect();
        Self::charge(
            bytes,
            columns.capacity() * size_of::<InputColumn>()
                + size_of::<InputTable>()
                + 2 * size_of::<usize>(),
            limit,
        )?;
        Self::charge(bytes, rows.saturating_mul(size_of::<Vec<Value>>()), limit)?;
        let rows = Vec::with_capacity(rows);
        // Source and destination row descriptors coexist during transfer.
        Ok(InputTable {
            columns,
            rows,
            #[cfg(test)]
            scan_gate: Default::default(),
        })
    }

    fn push(table: &mut InputTable, row: InputRow, bytes: &mut usize, limit: usize) -> Result<()> {
        Self::charge(bytes, row.allocation_bytes()?, limit)?;
        let previous = table.rows.capacity();
        table.rows.try_reserve_exact(1).map_err(|_| {
            crate::QueryLimitSnafu {
                resource: "query input bytes",
                limit,
            }
            .build()
        })?;
        Self::charge(
            bytes,
            (table.rows.capacity() - previous) * size_of::<Vec<Value>>(),
            limit,
        )?;
        table.rows.push(row.0);
        Ok(())
    }

    fn charge(bytes: &mut usize, added: usize, limit: usize) -> Result<()> {
        *bytes = bytes
            .checked_add(added)
            .filter(|total| *total <= limit)
            .ok_or_else(|| {
                crate::QueryLimitSnafu {
                    resource: "query input bytes",
                    limit,
                }
                .build()
            })?;
        Ok(())
    }

    fn report(source: &AnalysisSourceSnapshotV1) -> Result<Option<CoverageReport>> {
        let Some(bytes) = &source.coverage_report else {
            if source.receipt.coverage_revision != 0 {
                return crate::QueryInvalidSnafu {
                    field: "coverage snapshot report",
                }
                .fail();
            }
            return Ok(None);
        };
        if bytes.is_empty() || bytes.len() > crate::MAX_EVIDENCE_GRPC_MESSAGE_BYTES {
            return crate::QueryInvalidSnafu {
                field: "coverage snapshot size",
            }
            .fail();
        }
        let report =
            CoverageReport::decode(bytes.as_slice()).context(crate::EvidenceDecodeSnafu {
                frame_bytes: bytes.len(),
            })?;
        let receipt = &source.receipt;
        if report.source_id != receipt.identity.source_id
            || report.source_epoch != receipt.identity.source_epoch
            || report.cpu_id != receipt.cpu_id
            || report.revision != receipt.coverage_revision
            || report.revision == 0
        {
            return crate::QueryInvalidSnafu {
                field: "coverage snapshot coordinates",
            }
            .fail();
        }
        Ok(Some(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisContextKeyV1, AnalysisInputPageV1, AnalysisRecordV1, AnalysisSourceReceiptV1,
        AnalysisStoreMetaV1, ContextSensitivityV1, EvidenceDecisionContext,
        EvidenceExactFileObject, StorePositionV1,
    };

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn query_input_append_positions() -> TestResult {
        let mut extraction = empty_input();
        let mut row = event(&EvidenceRecord {
            operation: 7,
            ..Default::default()
        })?;
        row.0[43] = Value::Blob(vec![42; 8192]);
        add_page(&mut extraction, AnalysisRelationV1::Events, row)?;
        let input = InputRelations::new(
            &mut extraction,
            1_000_000,
            &QueryTemplate::Events { operation: None },
        )?;
        let before = input.allocation_bytes();
        let columns: Vec<_> = input
            .tables
            .iter()
            .map(|table| table.columns.capacity())
            .collect();
        let capacity = input.tables[0].rows[0].capacity();
        let Value::Blob(blob) = &input.tables[0].rows[0][43] else {
            return Err("catalog bytes are absent".into());
        };
        let address = blob.as_ptr();
        let input = input.append_positions(1_000_000)?;
        let bound = input.allocation_bytes();
        assert_eq!(
            bound - before,
            input
                .tables
                .iter()
                .zip(columns)
                .map(|(table, before)| (table.columns.capacity() - before)
                    * size_of::<InputColumn>())
                .sum::<usize>()
                + (input.tables[0].rows[0].capacity() - capacity) * size_of::<Value>()
        );
        let Value::Blob(blob) = &input.tables[0].rows[0][43] else {
            return Err("catalog bytes are absent".into());
        };
        assert_eq!(blob.as_ptr(), address);
        assert_eq!(blob, &vec![42; 8192]);
        assert_eq!(input.tables[0].rows[0].len(), EVENTS.columns.len() + 2);
        let connection = Connection::open_in_memory()?;
        input.register(&connection)?;
        let values = connection.query_row(
            "SELECT operation, __araphor_commit_revision, __araphor_ordinal FROM events",
            [],
            |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u32>(2)?,
                ))
            },
        )?;
        assert_eq!(values, (7, 8, 9));
        drop(connection);
        drop(input);
        for limit in [bound, bound - 1] {
            let mut extraction = empty_input();
            let mut row = event(&EvidenceRecord {
                operation: 7,
                ..Default::default()
            })?;
            row.0[43] = Value::Blob(vec![42; 8192]);
            add_page(&mut extraction, AnalysisRelationV1::Events, row)?;
            let input = InputRelations::new(
                &mut extraction,
                limit,
                &QueryTemplate::Events { operation: None },
            )?;
            let result = input.append_positions(limit);
            if limit == bound {
                assert_eq!(result?.allocation_bytes(), bound);
            } else {
                assert!(
                    matches!(result, Err(crate::Error::QueryLimit { limit: found, .. }) if found == limit)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn query_input_append_rejects() -> TestResult {
        for mode in 0..5 {
            let mut extraction = empty_input();
            add_page(
                &mut extraction,
                AnalysisRelationV1::Events,
                event(&EvidenceRecord::default())?,
            )?;
            let mut input = InputRelations::new(
                &mut extraction,
                1_000_000,
                &QueryTemplate::Events { operation: None },
            )?;
            let table = Arc::get_mut(&mut input.tables[0]).ok_or("input is shared")?;
            match mode {
                0 => {
                    table.rows[0].pop();
                }
                1 => table.rows[0][8] = Value::Null,
                2 => table.rows[0][9] = Value::UBigInt(9),
                3 => table.columns[8].0 = "changed",
                _ => {
                    input = input.append_positions(1_000_000)?;
                }
            }
            assert!(matches!(
                input.append_positions(1_000_000),
                Err(crate::Error::QueryInvalid { .. })
            ));
        }
        Ok(())
    }

    fn identity() -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 3,
            source_id: [4; 16],
            source_epoch: 5,
        }
    }

    fn framed(record: &EvidenceRecord) -> AnalysisRecordV1 {
        let mut payload = record.encode_to_vec();
        payload.extend([0xa0, 0x06, 0x07]);
        let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
        bytes.extend(payload);
        bytes.extend(crc32c::crc32c(&bytes).to_be_bytes());
        AnalysisRecordV1 {
            cursor: 7,
            framed_record: bytes,
            position: StorePositionV1 {
                commit_revision: 8,
                ordinal: 9,
            },
        }
    }

    fn event(record: &EvidenceRecord) -> Result<InputRow> {
        InputRow::try_from(AnalysisInputV1::Event {
            identity: &identity(),
            cpu_id: 6,
            received_utc_ns: u64::MAX,
            record: &framed(record),
        })
    }

    fn value<'a>(schema: &InputSchema, row: &'a [Value], name: &str) -> TestResult<&'a Value> {
        let index = schema
            .columns
            .iter()
            .position(|field| field.0 == name)
            .ok_or("column absent")?;
        row.get(index).ok_or_else(|| "row value absent".into())
    }

    fn empty_input() -> AnalysisExtractionV1<InputRow> {
        AnalysisExtractionV1 {
            discovery_enabled: false,
            meta: AnalysisStoreMetaV1 {
                store_uuid: uuid::Uuid::from_u128(1),
                schema_version: 1,
                recovery_epoch: 2,
                commit_revision: 8,
            },
            replay_floor: None,
            sources: Vec::new(),
            missing_contexts: Vec::new(),
            missing_results: Vec::new(),
            pages: Vec::new(),
            scanned_bytes: 0,
            projected_bytes: 0,
            input_bytes: size_of::<AnalysisExtractionV1<InputRow>>(),
            trace_reads: Vec::new(),
            limits: Default::default(),
        }
    }

    fn add_page(
        extraction: &mut AnalysisExtractionV1<InputRow>,
        relation: AnalysisRelationV1,
        row: InputRow,
    ) -> Result<()> {
        let bytes = row.allocation_bytes()? + size_of::<InputRow>();
        extraction.input_bytes += bytes + size_of::<AnalysisInputPageV1<InputRow>>();
        extraction.projected_bytes += row.allocation_bytes()?;
        extraction.pages.push(AnalysisInputPageV1 {
            relation,
            rows: vec![row],
            input_bytes: bytes,
        });
        Ok(())
    }

    fn context() -> AnalysisContextVersionV1 {
        AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "policy".into(),
                entity_key: vec![0, 255],
                lifetime_key: vec![1, 0],
                owner_revision: u64::MAX,
            },
            valid_from_utc_ns: Some(1),
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::HostRestricted,
            body: vec![0, 128, 255],
        }
    }

    fn snapshot() -> AnalysisSourceSnapshotV1 {
        AnalysisSourceSnapshotV1 {
            receipt: AnalysisSourceReceiptV1 {
                identity: identity(),
                cpu_id: 6,
                contiguous_cursor: 0,
                coverage_revision: 0,
                retained_floor: 1,
            },
            expired: Vec::new(),
            recovery: Vec::new(),
            pending: Vec::new(),
            coverage_report: None,
        }
    }

    #[test]
    fn query_input_record_mapping() -> TestResult {
        let record = EvidenceRecord {
            observed_boottime_ns: u64::MAX,
            ingested_utc_ns: i64::MIN,
            coverage_interval_id: vec![0, 255, 128, 0].into(),
            profile_generation_ref_id: Some(0),
            task_cookie: u64::MAX - 1,
            process_lineage_id: Vec::new().into(),
            authority_domain_id: vec![1, 0, 2].into(),
            execution_set_id: vec![3, 0, 4].into(),
            exact_object_id: vec![5, 0, 6].into(),
            destination_id: 60,
            policy_rule_id: 61,
            reason: u32::MAX,
            decision: 42,
            effect_family: 101,
            operation: 303,
            configured_errno: i32::MIN,
            kernel_result: i32::MAX,
            temporal_coverage: -17,
            target_task_cookie: Some(0),
            operation_argument: Some(0),
            decision_context: Some(EvidenceDecisionContext {
                schema_version: u32::MAX,
                original_kernel_sequence: u64::MAX,
                process_instance_id: vec![7, 0, 8],
                entry_instance_id: vec![9, 0, 10],
                binding_id: vec![11, 0, 12],
                profile_generation_ref_id: 199,
                role_id: 200,
                state_id: 201,
                entry_rule_id: 202,
                exact_file_object: Some(EvidenceExactFileObject {
                    profile_generation_ref_id: 602,
                    mount_id_unique: 603,
                    inode: u64::MAX,
                    inode_generation: 605,
                    mount_namespace_inode: u32::MAX,
                    filesystem_device: 607,
                }),
                exact_object_key_id: 900,
                composite_atom_id: 901,
                catalog_json: b"{\0}".to_vec(),
                catalog_state: "FUTURE\0STATE".into(),
            }),
        };
        let mapped = event(&record)?;
        assert_eq!(
            mapped.0,
            vec![
                Value::Blob(vec![1; 16]),
                Value::Text("node-a".into()),
                Value::Blob(vec![2; 16]),
                Value::UBigInt(3),
                Value::Blob(vec![4; 16]),
                Value::UBigInt(5),
                Value::UInt(6),
                Value::UBigInt(7),
                Value::UBigInt(8),
                Value::UInt(9),
                Value::UBigInt(u64::MAX),
                Value::Timestamp(TimeUnit::Microsecond, (u64::MAX / 1_000) as i64),
                Value::UBigInt(u64::MAX),
                Value::BigInt(i64::MIN),
                Value::Blob(vec![0, 255, 128, 0]),
                Value::UBigInt(0),
                Value::UBigInt(u64::MAX - 1),
                Value::Blob(Vec::new()),
                Value::Blob(vec![1, 0, 2]),
                Value::Blob(vec![3, 0, 4]),
                Value::Blob(vec![5, 0, 6]),
                Value::UBigInt(60),
                Value::UBigInt(61),
                Value::UInt(u32::MAX),
                Value::UInt(42),
                Value::UInt(101),
                Value::UInt(303),
                Value::Int(i32::MIN),
                Value::Int(i32::MAX),
                Value::Int(-17),
                Value::UBigInt(0),
                Value::UInt(0),
                Value::UInt(u32::MAX),
                Value::UBigInt(u64::MAX),
                Value::Blob(vec![7, 0, 8]),
                Value::Blob(vec![9, 0, 10]),
                Value::Blob(vec![11, 0, 12]),
                Value::UBigInt(199),
                Value::UInt(200),
                Value::UInt(201),
                Value::UInt(202),
                Value::UBigInt(900),
                Value::UBigInt(901),
                Value::Blob(b"{\0}".to_vec()),
                Value::Text("FUTURE\0STATE".into()),
                Value::UBigInt(602),
                Value::UBigInt(603),
                Value::UBigInt(u64::MAX),
                Value::UBigInt(605),
                Value::UInt(u32::MAX),
                Value::UInt(607),
            ]
        );
        assert_eq!(mapped.0.len(), EVENTS.columns.len());
        let expected = mapped.0.clone();
        let mut extraction = empty_input();
        add_page(&mut extraction, AnalysisRelationV1::Events, mapped)?;
        let input = InputRelations::new(
            &mut extraction,
            1_000_000,
            &QueryTemplate::Events { operation: None },
        )?;
        let connection = Connection::open_in_memory()?;
        input.register(&connection)?;
        let mut query = connection.prepare("SELECT * FROM events")?;
        let result = query.query_row([], |row| {
            (0..row.as_ref().column_count())
                .map(|index| row.get::<_, Value>(index))
                .collect::<duckdb::Result<Vec<_>>>()
        })?;
        assert_eq!(result, expected);
        assert!(extraction.pages.iter().all(|page| page.rows.is_empty()));
        assert_eq!(extraction.meta.commit_revision, 8);
        Ok(())
    }

    #[test]
    fn query_input_invalid_values() -> TestResult {
        let mut record = EvidenceRecord::default();
        let absent = event(&record)?;
        for name in [
            "profile_generation_ref_id",
            "target_task_cookie",
            "operation_argument",
            "context_schema_version",
            "kernel_sequence",
            "inode",
        ] {
            assert_eq!(value(&EVENTS, &absent.0, name)?, &Value::Null);
        }
        assert_eq!(
            value(&EVENTS, &absent.0, "process_lineage_id")?,
            &Value::Blob(Vec::new())
        );
        record.decision_context = Some(EvidenceDecisionContext::default());
        let present = event(&record)?;
        assert_eq!(
            value(&EVENTS, &present.0, "context_schema_version")?,
            &Value::UInt(0)
        );
        assert_eq!(
            value(&EVENTS, &present.0, "kernel_sequence")?,
            &Value::UBigInt(0)
        );
        assert_eq!(value(&EVENTS, &present.0, "inode")?, &Value::Null);
        let mut corrupt = framed(&record);
        corrupt.framed_record[4] ^= 1;
        assert!(matches!(
            InputRow::try_from(AnalysisInputV1::Event {
                identity: &identity(),
                cpu_id: 6,
                received_utc_ns: 1,
                record: &corrupt,
            }),
            Err(crate::Error::EvidenceFrame { .. })
        ));
        assert!(matches!(
            InputRow::try_from(AnalysisInputV1::Result {
                result_id: "result",
                body: b"body",
            }),
            Err(crate::Error::QueryUnsupported { .. })
        ));
        Ok(())
    }

    #[test]
    fn query_input_context_pages() -> TestResult {
        let context = context();
        let mapped = InputRow::try_from(AnalysisInputV1::Context(&context))?;
        assert_eq!(CONTEXTS.columns.len(), 9);
        assert!(!CONTEXTS
            .columns
            .iter()
            .any(|field| field.0 == "content_sha256"));
        assert_eq!(
            mapped.0,
            vec![
                Value::Blob(vec![1; 16]),
                Value::Text("policy".into()),
                Value::Blob(vec![0, 255]),
                Value::Blob(vec![1, 0]),
                Value::UBigInt(u64::MAX),
                Value::UBigInt(1),
                Value::Null,
                Value::Text("host_restricted".into()),
                Value::Blob(vec![0, 128, 255]),
            ]
        );
        let expected = mapped.0.clone();
        let mut extraction = empty_input();
        extraction.missing_contexts.push(context.key.clone());
        add_page(
            &mut extraction,
            AnalysisRelationV1::Events,
            event(&EvidenceRecord::default())?,
        )?;
        add_page(&mut extraction, AnalysisRelationV1::Context, mapped)?;
        add_page(
            &mut extraction,
            AnalysisRelationV1::Events,
            event(&EvidenceRecord {
                operation: 42,
                ..EvidenceRecord::default()
            })?,
        )?;
        let input =
            InputRelations::new(&mut extraction, 1_000_000, &QueryTemplate::ContextVersions)?;
        assert_eq!(input.tables[0].rows.len(), 2);
        assert_eq!(
            value(&EVENTS, &input.tables[0].rows[1], "operation")?,
            &Value::UInt(42)
        );
        assert_eq!(input.tables[2].rows, vec![expected]);
        assert_eq!(extraction.missing_contexts, vec![context.key]);
        let mut unsupported = empty_input();
        add_page(
            &mut unsupported,
            AnalysisRelationV1::Results,
            InputRow(Vec::new()),
        )?;
        assert!(matches!(
            InputRelations::new(&mut unsupported, 1_000_000, &QueryTemplate::ContextVersions),
            Err(crate::Error::QueryUnsupported { .. })
        ));
        assert_eq!(unsupported.pages[0].rows.len(), 1);
        Ok(())
    }

    #[test]
    fn query_input_coverage_states() -> TestResult {
        let mut source = snapshot();
        source.receipt.coverage_revision = 10;
        source.expired.push(AnalysisGapV1 {
            first_cursor: 2,
            last_cursor: 3,
            commit_revision: 7,
        });
        source.recovery.push(AnalysisGapV1 {
            first_cursor: 4,
            last_cursor: 5,
            commit_revision: 8,
        });
        source.pending.push(AnalysisGapV1 {
            first_cursor: 1,
            last_cursor: 10,
            commit_revision: 9,
        });
        let report = CoverageReport {
            source_id: source.receipt.identity.source_id.to_vec(),
            cpu_id: 6,
            source_epoch: 5,
            revision: 10,
            intervals: vec![CoverageInterval {
                interval_id: vec![0, 255],
                source_epoch: 4,
                revision: 11,
                state: "FUTURE_STATE".into(),
                first_sequence: 100,
                last_sequence: None,
                opening_counters: Some(CoverageCounters {
                    attempted: u64::MAX,
                    suppressed: 2,
                    requested: 3,
                    emitted: 4,
                    lost: 5,
                    classifier_miss_count: 6,
                    unresolved: 7,
                    next_sequence: 8,
                }),
                closing_counters: None,
                gap_reasons: vec!["future\"reason".into(), "lost\0reason".into()],
                current: false,
            }],
        };
        let mut encoded = report.encode_to_vec();
        encoded.extend([0xa0, 0x06, 0x07]);
        source.coverage_report = Some(encoded);
        let mut extraction = empty_input();
        extraction.sources = vec![source, snapshot()];
        let input = InputRelations::new(&mut extraction, 1_000_000, &QueryTemplate::Coverage)?;
        let rows = &input.tables[1].rows;
        assert_eq!(rows.len(), 6);
        let kinds: Vec<_> = rows
            .iter()
            .map(|row| value(&COVERAGE, row, "kind").cloned())
            .collect::<TestResult<_>>()?;
        assert_eq!(
            kinds,
            ["receipt", "expired", "recovery", "pending", "interval", "receipt"]
                .map(|kind| Value::Text(kind.into()))
        );
        assert_eq!(
            value(&COVERAGE, &rows[0], "state")?,
            &Value::Text("reported".into())
        );
        assert_eq!(
            value(&COVERAGE, &rows[5], "state")?,
            &Value::Text("unknown".into())
        );
        assert_eq!(
            value(&COVERAGE, &rows[3], "contiguous_cursor")?,
            &Value::UBigInt(0)
        );
        assert_eq!(
            value(&COVERAGE, &rows[3], "first_cursor")?,
            &Value::UBigInt(1)
        );
        assert_eq!(
            value(&COVERAGE, &rows[3], "last_cursor")?,
            &Value::UBigInt(10)
        );
        assert_eq!(
            value(&COVERAGE, &rows[3], "commit_revision")?,
            &Value::UBigInt(9)
        );
        assert_eq!(value(&COVERAGE, &rows[3], "first_sequence")?, &Value::Null);
        let interval = &rows[4];
        assert_eq!(
            value(&COVERAGE, interval, "state")?,
            &Value::Text("FUTURE_STATE".into())
        );
        assert_eq!(
            value(&COVERAGE, interval, "source_epoch")?,
            &Value::UBigInt(5)
        );
        assert_eq!(
            value(&COVERAGE, interval, "interval_source_epoch")?,
            &Value::UBigInt(4)
        );
        assert_eq!(
            value(&COVERAGE, interval, "first_sequence")?,
            &Value::UBigInt(100)
        );
        assert_eq!(value(&COVERAGE, interval, "last_sequence")?, &Value::Null);
        assert_eq!(value(&COVERAGE, interval, "first_cursor")?, &Value::Null);
        assert_eq!(
            value(&COVERAGE, interval, "current")?,
            &Value::Boolean(false)
        );
        assert_eq!(
            value(&COVERAGE, interval, "opening_attempted")?,
            &Value::UBigInt(u64::MAX)
        );
        assert_eq!(
            value(&COVERAGE, interval, "opening_next_sequence")?,
            &Value::UBigInt(8)
        );
        assert_eq!(
            value(&COVERAGE, interval, "closing_attempted")?,
            &Value::Null
        );
        assert_eq!(
            value(&COVERAGE, interval, "gap_reasons")?,
            &Value::Text(serde_json::to_string(&report.intervals[0].gap_reasons)?)
        );
        assert_eq!(extraction.sources[0].receipt.coverage_revision, 10);
        Ok(())
    }

    #[test]
    fn query_input_coverage_rejects() -> TestResult {
        let mut source = snapshot();
        source.receipt.coverage_revision = 1;
        assert!(InputRelations::report(&source).is_err());
        source.coverage_report = Some(vec![255]);
        assert!(matches!(
            InputRelations::report(&source),
            Err(crate::Error::EvidenceDecode { .. })
        ));
        let mut report = CoverageReport {
            source_id: source.receipt.identity.source_id.to_vec(),
            cpu_id: source.receipt.cpu_id,
            source_epoch: source.receipt.identity.source_epoch,
            revision: 2,
            intervals: Vec::new(),
        };
        source.coverage_report = Some(report.encode_to_vec());
        assert!(InputRelations::report(&source).is_err());
        report.revision = 1;
        report.cpu_id += 1;
        source.coverage_report = Some(report.encode_to_vec());
        assert!(InputRelations::report(&source).is_err());
        report.cpu_id -= 1;
        report.source_id[0] ^= 1;
        source.coverage_report = Some(report.encode_to_vec());
        assert!(InputRelations::report(&source).is_err());
        Ok(())
    }

    #[test]
    fn query_input_selected_relations() -> TestResult {
        let mut events = empty_input();
        events.sources.push(snapshot());
        add_page(
            &mut events,
            AnalysisRelationV1::Events,
            event(&EvidenceRecord::default())?,
        )?;
        let input = InputRelations::new(
            &mut events,
            64 * 1024,
            &QueryTemplate::Events { operation: None },
        )?;
        assert_eq!(input.tables[0].rows.len(), 1);
        assert!(input.tables[1].rows.is_empty());
        assert!(input.tables[3].rows.is_empty());
        assert!(events.input_bytes < 64 * 1024);

        let mut coverage = empty_input();
        coverage.sources.push(snapshot());
        let input = InputRelations::new(&mut coverage, 64 * 1024, &QueryTemplate::Coverage)?;
        assert_eq!(input.tables[1].rows.len(), 1);
        assert!(input.tables[3].rows.is_empty());

        let mut catalog = empty_input();
        catalog.sources.push(snapshot());
        let input = InputRelations::new(&mut catalog, 1_000_000, &QueryTemplate::Catalog)?;
        assert!(input.tables[1].rows.is_empty());
        assert_eq!(
            input.tables[3].rows.len(),
            SCHEMAS
                .iter()
                .map(|schema| schema.columns.len())
                .sum::<usize>()
        );
        Ok(())
    }

    #[test]
    fn query_client_catalog_keys() -> TestResult {
        let template = QueryTemplate::Client(super::super::QuerySql::admit(
            "SELECT relation, column_name, join_keys FROM catalog",
            Vec::new(),
            false,
        )?);
        let mut extraction = empty_input();
        let input = InputRelations::new(&mut extraction, 1_000_000, &template)?;
        let mut extraction = empty_input();
        let trusted = InputRelations::new(&mut extraction, 1_000_000, &QueryTemplate::Catalog)?;
        assert_eq!(input.tables[3].rows, trusted.tables[3].rows);
        assert!(input.tables[3].rows.iter().any(|row| {
            matches!(value(&CATALOG, row, "join_keys"), Ok(Value::Text(keys)) if !keys.is_empty())
        }));
        Ok(())
    }

    #[test]
    fn query_input_catalog_bounds() -> TestResult {
        let mut text = String::with_capacity(257);
        text.push('a');
        let mut blob = Vec::with_capacity(19);
        blob.extend([0, 1, 255]);
        let expected = text.capacity() + blob.capacity() + 7 * size_of::<Value>();
        let mut values = Vec::with_capacity(7);
        values.extend([Value::Text(text), Value::Blob(blob)]);
        assert_eq!(InputRow(values).allocation_bytes()?, expected);
        assert!(InputRow(vec![Value::List(Vec::new())])
            .allocation_bytes()
            .is_err());
        let mut maximum = usize::MAX;
        assert!(InputRelations::charge(&mut maximum, 1, usize::MAX).is_err());
        let mut baseline = empty_input();
        let base = baseline.input_bytes;
        let input = InputRelations::new(&mut baseline, 1_000_000, &QueryTemplate::Catalog)?;
        let bound = baseline.input_bytes;
        assert!(bound > base);
        let mut at_bound = empty_input();
        InputRelations::new(&mut at_bound, bound, &QueryTemplate::Catalog)?;
        assert_eq!(at_bound.input_bytes, bound);
        let mut over_bound = empty_input();
        assert!(
            matches!(InputRelations::new(&mut over_bound, bound - 1, &QueryTemplate::Catalog), Err(crate::Error::QueryLimit { limit, .. }) if limit == bound - 1)
        );
        let mut populated = empty_input();
        add_page(
            &mut populated,
            AnalysisRelationV1::Events,
            event(&EvidenceRecord::default())?,
        )?;
        let charged = populated.input_bytes;
        let populated_bound = charged + bound - base + size_of::<Vec<Value>>();
        InputRelations::new(&mut populated, populated_bound, &QueryTemplate::Catalog)?;
        assert_eq!(populated.input_bytes, populated_bound);
        let mut over_populated = empty_input();
        add_page(
            &mut over_populated,
            AnalysisRelationV1::Events,
            event(&EvidenceRecord::default())?,
        )?;
        assert!(matches!(
            InputRelations::new(&mut over_populated, populated_bound - 1, &QueryTemplate::Catalog),
            Err(crate::Error::QueryLimit { limit, .. }) if limit == populated_bound - 1
        ));
        let rows = &input.tables[3].rows;
        assert_eq!(
            rows.len(),
            SCHEMAS
                .iter()
                .map(|schema| schema.columns.len())
                .sum::<usize>()
        );
        for relation in ["traces", "trace_output", "trace_measurements"] {
            let mut found = false;
            for row in rows {
                if value(&CATALOG, row, "relation")? == &Value::Text(relation.into()) {
                    found = true;
                    assert_eq!(
                        value(&CATALOG, row, "readiness")?,
                        &Value::Text("available".into())
                    );
                }
            }
            assert!(found);
        }
        for schema in [&TRACES, &TRACE_OUTPUT, &TRACE_MEASUREMENTS] {
            for name in ["tenant_id", "request_id", "execution_id"] {
                assert!(schema.columns.iter().any(|field| field.0 == name));
            }
        }
        for name in ["source_sha256", "commit_revision", "ordinal"] {
            assert!(TRACE_OUTPUT.columns.iter().any(|field| field.0 == name));
        }
        let connection = Connection::open_in_memory()?;
        input.register(&connection)?;
        assert_eq!(
            connection.query_row("SELECT count(*) FROM trace_output", [], |row| row
                .get::<_, u64>(0))?,
            0
        );
        assert_eq!(
            connection.query_row("SELECT count(*) FROM catalog", [], |row| row
                .get::<_, u64>(0))?,
            rows.len() as u64
        );
        Ok(())
    }

    #[test]
    fn query_recipe_input_bounds() -> TestResult {
        let template = QueryTemplate::Client(super::super::QuerySql::admit(
            "SELECT * FROM trace_recipes",
            Vec::new(),
            false,
        )?);
        let mut extraction = empty_input();
        let input = InputRelations::new(&mut extraction, 1_000_000, &template)?;
        assert!(input.tables[7].rows.is_empty());
        assert_eq!(input.tables[8].rows.len(), 2);
        let bound = extraction.input_bytes;
        drop(input);
        let mut exact = empty_input();
        InputRelations::new(&mut exact, bound, &template)?;
        assert_eq!(exact.input_bytes, bound);
        let mut limited = empty_input();
        assert!(
            matches!(InputRelations::new(&mut limited, bound - 1, &template), Err(crate::Error::QueryLimit { limit, .. }) if limit == bound - 1)
        );
        Ok(())
    }
}
