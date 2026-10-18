use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock};

use araphor_analysis_sdk::{Field, Schema};

use super::Capture;

type SchemaRef = Arc<Schema>;

impl Capture<'_> {
    pub(in crate::analysis::extraction) fn schemas() -> &'static BTreeMap<String, SchemaRef> {
        static SCHEMAS: LazyLock<BTreeMap<String, SchemaRef>> =
            LazyLock::new(Capture::build_table_schemas);
        &SCHEMAS
    }

    fn build_table_schemas() -> BTreeMap<String, SchemaRef> {
        let mut schemas = BTreeMap::new();
        let mut insert = |name: &str, fields: Vec<Field>| {
            let (join_keys, description) = match name {
                "events" => (
                    "tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch,cpu_id,source_cursor",
                    "Immutable evidence record. Source cursors, kernel sequences, and store positions are distinct.",
                ),
                "coverage" => (
                    "tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch,cpu_id",
                    "Captured source receipt, coverage interval, or retained gap. Silence does not prove complete coverage.",
                ),
                "context" | "context_versions" => (
                    "tenant_id,owner_id,entity_key,lifetime_key,owner_revision",
                    "Immutable context version. Names and time do not establish a subject join.",
                ),
                "targets" => (
                    "tenant_id,entity_key,lifetime_key,owner_revision",
                    "Recorded workload target and its exact retained context revision.",
                ),
                "compiled_policies" => (
                    "tenant_id,entity_key,lifetime_key,owner_revision",
                    "Recorded compiled policy proof and its exact retained context revision.",
                ),
                "discovery_state" => (
                    "tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch,method_version",
                    "Captured source receipt, discovery processor head, and typed retained profile state.",
                ),
                "behaviors" => (
                    "tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch,profile_id,profile_revision",
                    "Retained discovery profile summary or behavior atom. An open profile can change.",
                ),
                "traces" => (
                    "tenant_id,request_id,execution_id,target_index",
                    "Frozen trace target, request state, and captured output receipt.",
                ),
                "trace_output" => (
                    "tenant_id,request_id,execution_id,sequence",
                    "Retained diagnostic frame in durable store order.",
                ),
                "trace_measurements" => (
                    "tenant_id,request_id,execution_id,sequence,ordinal",
                    "Recipe measurement from one retained trace frame. A negative kernel return code is not a final userspace result.",
                ),
                "trace_recipes" => (
                    "recipe,version,source_sha256",
                    "Exact recipe source and its measurement contract. Node capability must be checked before execution.",
                ),
                "catalog" => (
                    "relation,ordinal",
                    "Native Arrow source schema and its field metadata.",
                ),
                "notifications" => (
                    "tenant_id,notification_id,notification_revision",
                    "Retained notification obligation. Overdue uses the captured query time.",
                ),
                _ => (
                    "tenant_id,graph_result_id",
                    "Retained graph version. Evidence and coverage limits remain part of its result.",
                ),
            };
            let fields = fields
                .into_iter()
                .map(|field| {
                    let units = if field.name() == "received_at" {
                        "microseconds since Unix epoch"
                    } else if field.name().ends_with("_ns") {
                        "nanoseconds"
                    } else if field.name().ends_with("_bytes")
                        || matches!(field.name().as_str(), "input_bytes" | "framed_record")
                    {
                        "bytes"
                    } else {
                        ""
                    };
                    let null_meaning = if field.is_nullable() {
                        "No value is recorded for this row."
                    } else {
                        ""
                    };
                    let description = if field.name() == "framed_record" {
                        "Original length-prefixed evidence bytes with CRC32C."
                    } else {
                        description
                    };
                    field.with_metadata(HashMap::from([
                        (
                            "araphor.owner".into(),
                            if name == "catalog" {
                                "araphor-query.native-schema"
                            } else if name == "trace_recipes" {
                                "araphor-data.TraceRecipeV1"
                            } else {
                                "araphor-data.AnalysisStore"
                            }
                            .into(),
                        ),
                        ("araphor.units".into(), units.into()),
                        ("araphor.null_meaning".into(), null_meaning.into()),
                        ("araphor.join_keys".into(), join_keys.into()),
                        ("araphor.readiness".into(), "available".into()),
                        ("araphor.description".into(), description.into()),
                    ]))
                })
                .collect::<Vec<_>>();
            schemas.insert(name.to_owned(), Arc::new(Schema::new(fields)));
        };
        insert("events", Self::event_fields());
        insert("coverage", Self::coverage_fields());
        insert("context_versions", Self::version_fields());
        insert("context", Self::context_fields());
        insert("catalog", Self::catalog_fields());
        insert("traces", Self::trace_fields());
        insert("trace_output", Self::frame_fields());
        insert("trace_measurements", Self::measurement_fields());
        insert("trace_recipes", Self::recipe_fields());
        insert("targets", Self::target_fields());
        insert("compiled_policies", Self::compiled_fields());
        insert("behaviors", Self::behavior_fields());
        insert("discovery_state", Self::discovery_state_fields());
        insert("findings", Self::finding_fields());
        insert("relationships", Self::relationship_fields());
        insert("graph_subjects", Self::subject_fields());
        insert("graph_branches", Self::branch_fields());
        insert("correlation_packages", Self::package_fields());
        insert("policy_observations", Self::observation_fields());
        insert("graph_manifest", Self::graph_fields());
        insert("notifications", Self::notification_fields());
        schemas
    }
}
