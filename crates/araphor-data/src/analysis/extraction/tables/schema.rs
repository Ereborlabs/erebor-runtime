use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock};

use araphor_analysis_sdk::{DataType::*, Field, Schema, TimeUnit};

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
                    } else if field.name().ends_with("_bytes") || field.name() == "input_bytes" {
                        "bytes"
                    } else {
                        ""
                    };
                    let null_meaning = if field.is_nullable() {
                        "No value is recorded for this row."
                    } else {
                        ""
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
        insert(
            "events",
            vec![
                Field::new("tenant_id", Binary, false),
                Field::new("node_id", Utf8, false),
                Field::new("node_boot_id", Binary, false),
                Field::new("label_epoch", UInt64, false),
                Field::new("source_id", Binary, false),
                Field::new("source_epoch", UInt64, false),
                Field::new("cpu_id", UInt32, false),
                Field::new("source_cursor", UInt64, false),
                Field::new("commit_revision", UInt64, false),
                Field::new("ordinal", UInt32, false),
                Field::new("received_utc_ns", UInt64, false),
                Field::new("received_at", Timestamp(TimeUnit::Microsecond, None), false),
                Field::new("observed_boottime_ns", UInt64, false),
                Field::new("ingested_utc_ns", Int64, false),
                Field::new("coverage_interval_id", Binary, false),
                Field::new("profile_generation_ref_id", UInt64, true),
                Field::new("task_cookie", UInt64, false),
                Field::new("process_lineage_id", Binary, false),
                Field::new("authority_domain_id", Binary, false),
                Field::new("execution_set_id", Binary, false),
                Field::new("exact_object_id", Binary, false),
                Field::new("destination_id", UInt64, false),
                Field::new("policy_rule_id", UInt64, false),
                Field::new("reason", UInt32, false),
                Field::new("decision", UInt32, false),
                Field::new("effect_family", UInt32, false),
                Field::new("operation", UInt32, false),
                Field::new("configured_errno", Int32, false),
                Field::new("kernel_result", Int32, false),
                Field::new("temporal_coverage", Int32, false),
                Field::new("target_task_cookie", UInt64, true),
                Field::new("operation_argument", UInt32, true),
                Field::new("context_schema_version", UInt32, true),
                Field::new("kernel_sequence", UInt64, true),
                Field::new("process_instance_id", Binary, true),
                Field::new("entry_instance_id", Binary, true),
                Field::new("binding_id", Binary, true),
                Field::new("context_profile_generation_ref_id", UInt64, true),
                Field::new("role_id", UInt32, true),
                Field::new("state_id", UInt32, true),
                Field::new("entry_rule_id", UInt32, true),
                Field::new("exact_object_key_id", UInt64, true),
                Field::new("composite_atom_id", UInt64, true),
                Field::new("catalog_json", Binary, true),
                Field::new("catalog_state", Utf8, true),
                Field::new("exact_profile_generation_ref_id", UInt64, true),
                Field::new("mount_id_unique", UInt64, true),
                Field::new("inode", UInt64, true),
                Field::new("inode_generation", UInt64, true),
                Field::new("mount_namespace_inode", UInt32, true),
                Field::new("filesystem_device", UInt32, true),
            ],
        );
        insert(
            "coverage",
            vec![
                Field::new("tenant_id", Binary, false),
                Field::new("node_id", Utf8, false),
                Field::new("node_boot_id", Binary, false),
                Field::new("label_epoch", UInt64, false),
                Field::new("source_id", Binary, false),
                Field::new("source_epoch", UInt64, false),
                Field::new("cpu_id", UInt32, false),
                Field::new("contiguous_cursor", UInt64, false),
                Field::new("coverage_revision", UInt64, false),
                Field::new("retained_floor", UInt64, false),
                Field::new("kind", Utf8, false),
                Field::new("state", Utf8, false),
                Field::new("first_cursor", UInt64, true),
                Field::new("last_cursor", UInt64, true),
                Field::new("commit_revision", UInt64, true),
                Field::new("interval_id", Binary, true),
                Field::new("interval_source_epoch", UInt64, true),
                Field::new("interval_revision", UInt64, true),
                Field::new("first_sequence", UInt64, true),
                Field::new("last_sequence", UInt64, true),
                Field::new("current", Boolean, true),
                Field::new("gap_reasons", Utf8, true),
                Field::new("opening_attempted", UInt64, true),
                Field::new("opening_suppressed", UInt64, true),
                Field::new("opening_requested", UInt64, true),
                Field::new("opening_emitted", UInt64, true),
                Field::new("opening_lost", UInt64, true),
                Field::new("opening_classifier_miss_count", UInt64, true),
                Field::new("opening_unresolved", UInt64, true),
                Field::new("opening_next_sequence", UInt64, true),
                Field::new("closing_attempted", UInt64, true),
                Field::new("closing_suppressed", UInt64, true),
                Field::new("closing_requested", UInt64, true),
                Field::new("closing_emitted", UInt64, true),
                Field::new("closing_lost", UInt64, true),
                Field::new("closing_classifier_miss_count", UInt64, true),
                Field::new("closing_unresolved", UInt64, true),
                Field::new("closing_next_sequence", UInt64, true),
            ],
        );
        let context = vec![
            Field::new("tenant_id", Binary, false),
            Field::new("owner_id", Utf8, false),
            Field::new("entity_key", Binary, false),
            Field::new("lifetime_key", Binary, false),
            Field::new("owner_revision", UInt64, false),
            Field::new("valid_from_utc_ns", UInt64, true),
            Field::new("valid_until_utc_ns", UInt64, true),
            Field::new("sensitivity", Utf8, false),
            Field::new("body", Binary, false),
        ];
        insert("context_versions", context.clone());
        let mut documents = context;
        documents.extend([
            Field::new("kind", Utf8, true),
            Field::new("subject_owner_id", Utf8, true),
            Field::new("subject_entity_key", Binary, true),
            Field::new("subject_lifetime_key", Binary, true),
            Field::new("subject_revision", UInt64, true),
            Field::new("method_id", Utf8, true),
            Field::new("method_revision", UInt64, true),
            Field::new("origin", Utf8, true),
            Field::new("trust", Utf8, true),
            Field::new("imported_utc_ns", UInt64, true),
            Field::new("approver", Utf8, true),
            Field::new("text", Utf8, true),
        ]);
        insert("context", documents);
        insert(
            "catalog",
            vec![
                Field::new("relation", Utf8, false),
                Field::new("ordinal", UInt32, false),
                Field::new("column_name", Utf8, false),
                Field::new("data_type", Utf8, false),
                Field::new("units", Utf8, false),
                Field::new("nullable", Boolean, false),
                Field::new("null_meaning", Utf8, false),
                Field::new("join_keys", Utf8, false),
                Field::new("owner", Utf8, false),
                Field::new("readiness", Utf8, false),
                Field::new("description", Utf8, false),
            ],
        );
        insert(
            "traces",
            vec![
                Field::new("tenant_id", Binary, false),
                Field::new("request_id", Binary, false),
                Field::new("target_index", UInt32, false),
                Field::new("execution_id", Binary, false),
                Field::new("node_id", Utf8, false),
                Field::new("node_boot_id", Binary, false),
                Field::new("binding_id", Binary, false),
                Field::new("namespace_uid", Utf8, false),
                Field::new("source", Binary, false),
                Field::new("source_sha256", Binary, false),
                Field::new("trace_schema_version", UInt32, false),
                Field::new("request_revision", UInt64, false),
                Field::new("accepted_unix_ns", UInt64, false),
                Field::new("deadline_unix_ns", UInt64, false),
                Field::new("last_sequence", UInt64, false),
                Field::new("output_bytes", UInt64, false),
                Field::new("retained_floor", UInt64, false),
                Field::new("cancel_requested", Boolean, false),
                Field::new("read_revoked", Boolean, false),
                Field::new("terminal_reason", Utf8, true),
                Field::new("output_incomplete", Boolean, true),
                Field::new("kernel_lost_events", UInt64, true),
                Field::new("ready_at_unix_ns", UInt64, true),
                Field::new("exit_code", Int32, true),
                Field::new("forced_kill", Boolean, true),
                Field::new("cleanup", Utf8, true),
            ],
        );
        insert(
            "trace_output",
            vec![
                Field::new("tenant_id", Binary, false),
                Field::new("request_id", Binary, false),
                Field::new("execution_id", Binary, false),
                Field::new("node_id", Utf8, false),
                Field::new("node_boot_id", Binary, false),
                Field::new("source_sha256", Binary, false),
                Field::new("target_index", UInt32, false),
                Field::new("sequence", UInt64, false),
                Field::new("commit_revision", UInt64, false),
                Field::new("ordinal", UInt32, false),
                Field::new("kind", Utf8, false),
                Field::new("bytes", Binary, false),
            ],
        );
        insert(
            "trace_measurements",
            vec![
                Field::new("tenant_id", Binary, false),
                Field::new("request_id", Binary, false),
                Field::new("execution_id", Binary, false),
                Field::new("sequence", UInt64, false),
                Field::new("ordinal", UInt32, false),
                Field::new("syscall_id", UInt32, true),
                Field::new("errno", Int64, false),
                Field::new("count", UInt64, false),
                Field::new("cumulative", Boolean, false),
                Field::new("atomic_snapshot", Boolean, false),
                Field::new("unit", Utf8, false),
            ],
        );
        insert(
            "trace_recipes",
            vec![
                Field::new("recipe", Utf8, false),
                Field::new("version", UInt32, false),
                Field::new("source", Binary, false),
                Field::new("source_sha256", Binary, false),
                Field::new("parameter", Utf8, false),
                Field::new("attribution", Utf8, false),
                Field::new("sensitivity", Utf8, false),
                Field::new("hook", Utf8, false),
                Field::new("measurement_keys", Binary, false),
                Field::new("unit", Utf8, false),
                Field::new("cumulative", Boolean, false),
                Field::new("atomic_snapshot", Boolean, false),
                Field::new("maximum_probes", UInt32, false),
                Field::new("maximum_map_keys", UInt32, false),
                Field::new("return_code_semantics", Utf8, false),
                Field::new("capability_status", Utf8, false),
                Field::new("example", Utf8, false),
            ],
        );
        insert(
            "targets",
            vec![
                Field::new("tenant_id", Binary, false),
                Field::new("entity_key", Binary, false),
                Field::new("lifetime_key", Binary, false),
                Field::new("owner_revision", UInt64, false),
                Field::new("node_id", Utf8, false),
                Field::new("node_boot_id", Binary, true),
                Field::new("label_epoch", UInt64, true),
                Field::new("binding_id", Binary, true),
                Field::new("workload_binding_generation_digest", Utf8, false),
                Field::new("execution_set_id", Utf8, false),
                Field::new("cluster_uid", Utf8, false),
                Field::new("namespace_uid", Utf8, false),
                Field::new("controller_uid", Utf8, false),
                Field::new("service_account_uid", Utf8, false),
                Field::new("pod_uid", Utf8, false),
                Field::new("container_id", Utf8, false),
                Field::new("container_name", Utf8, false),
                Field::new("container_kind", Utf8, false),
                Field::new("image_digest", Utf8, false),
                Field::new("pod_labels", Binary, false),
                Field::new("namespace_name", Utf8, true),
                Field::new("pod_name", Utf8, true),
                Field::new("profile_id", Utf8, true),
                Field::new("policy_source_revision_id", Utf8, true),
                Field::new("protected_scope_id", Utf8, true),
                Field::new("workload_selector_id", Utf8, true),
                Field::new("kubernetes_node_name", Utf8, true),
                Field::new("kubernetes_node_uid", Utf8, true),
            ],
        );
        insert(
            "behaviors",
            vec![
                Field::new("tenant_id", Binary, false),
                Field::new("node_id", Utf8, false),
                Field::new("node_boot_id", Binary, false),
                Field::new("label_epoch", UInt64, false),
                Field::new("source_id", Binary, false),
                Field::new("source_epoch", UInt64, false),
                Field::new("cpu_id", UInt32, true),
                Field::new("profile_id", Utf8, false),
                Field::new("interval_id", Utf8, false),
                Field::new("profile_revision", UInt64, false),
                Field::new("facts_revision", UInt64, false),
                Field::new("coverage_revision", UInt64, false),
                Field::new("method_version", UInt64, false),
                Field::new("commit_revision", UInt64, false),
                Field::new("profile_state", Utf8, false),
                Field::new("created_utc_ns", UInt64, false),
                Field::new("updated_utc_ns", UInt64, false),
                Field::new("input_bytes", UInt64, false),
                Field::new("incomplete", Boolean, false),
                Field::new("kind", Utf8, false),
                Field::new("source_revision", Utf8, false),
                Field::new("proof_kind", Utf8, false),
                Field::new("accepted_records", UInt64, true),
                Field::new("included_records", UInt64, true),
                Field::new("unresolved_records", UInt64, true),
                Field::new("excluded_records", UInt64, true),
                Field::new("atom_key", Binary, true),
                Field::new("subject_revision", Utf8, true),
                Field::new("image_digest", Utf8, true),
                Field::new("configuration_digest", Utf8, true),
                Field::new("process_instance_id", Binary, true),
                Field::new("entry_instance_id", Binary, true),
                Field::new("binding_id", Binary, true),
                Field::new("role_id", UInt32, true),
                Field::new("state_id", UInt32, true),
                Field::new("entry_rule_id", UInt32, true),
                Field::new("catalog_revision", UInt64, true),
                Field::new("generation", UInt64, true),
                Field::new("coverage_interval_id", Binary, true),
                Field::new("temporal_coverage", Int32, true),
                Field::new("operation_id", Utf8, true),
                Field::new("static_key", Binary, true),
                Field::new("policy_revision", Binary, true),
                Field::new("effect", Binary, true),
                Field::new("source_reason", UInt32, true),
                Field::new("source_decision", UInt32, true),
                Field::new("kernel_result", Int32, true),
                Field::new("physical_result", Utf8, true),
                Field::new("record_count", UInt64, false),
                Field::new("first_cursor", UInt64, true),
                Field::new("last_cursor", UInt64, true),
                Field::new("evidence_sample", Binary, true),
                Field::new("coverage", Binary, false),
                Field::new("lifecycle", Binary, true),
                Field::new("gaps", Binary, true),
                Field::new("context_refs", Binary, true),
                Field::new("effect_family", UInt32, true),
                Field::new("operation", UInt32, true),
                Field::new("operation_argument", UInt32, true),
                Field::new("configured_errno", Int32, true),
                Field::new("exact_object_id", Binary, true),
                Field::new("task_cookie", UInt64, true),
                Field::new("target_task_cookie", UInt64, true),
                Field::new("unresolved", Binary, true),
                Field::new("excluded", Binary, true),
                Field::new("discovery_enabled", Boolean, false),
            ],
        );
        let graph = vec![
            Field::new("tenant_id", Binary, false),
            Field::new("source_key", Binary, false),
            Field::new("graph_result_id", Utf8, false),
            Field::new("commit_revision", UInt64, false),
            Field::new("graph_revision", Binary, false),
            Field::new("graph_sensitivity", Utf8, false),
        ];
        for (name, fields) in [
            (
                "findings",
                vec![
                    Field::new("finding_id", Utf8, false),
                    Field::new("finding_revision", Binary, false),
                    Field::new("package_id", Utf8, false),
                    Field::new("package_version", UInt64, false),
                    Field::new("subject_id", Binary, false),
                    Field::new("state", Utf8, false),
                    Field::new("window_start_utc_ns", Int64, false),
                    Field::new("window_end_utc_ns", Int64, false),
                    Field::new("evidence", Binary, false),
                    Field::new("required_coverage_interval_ids", Binary, false),
                    Field::new("policy_provenance", Binary, false),
                    Field::new("effects", Binary, false),
                    Field::new("reason", Utf8, false),
                    Field::new("severity", Utf8, false),
                    Field::new("sensitivity", Utf8, false),
                    Field::new("required_action", Utf8, true),
                    Field::new("limits", Binary, false),
                ],
            ),
            (
                "relationships",
                vec![
                    Field::new("relationship_key", Binary, false),
                    Field::new("from_subject_id", Binary, false),
                    Field::new("to_subject_id", Binary, false),
                    Field::new("edge_type", Utf8, false),
                    Field::new("package_id", Utf8, false),
                    Field::new("cause", Utf8, false),
                    Field::new("evidence", Binary, false),
                    Field::new("proof_quality", Binary, false),
                    Field::new("required_coverage_interval_ids", Binary, false),
                    Field::new("first_boottime_ns", UInt64, false),
                    Field::new("last_boottime_ns", UInt64, false),
                ],
            ),
            (
                "graph_subjects",
                vec![
                    Field::new("subject_id", Binary, false),
                    Field::new("subject_kind", Utf8, false),
                    Field::new("authority", Binary, false),
                    Field::new("identity", Binary, false),
                    Field::new("traversal_depth", UInt32, true),
                ],
            ),
            (
                "graph_branches",
                vec![
                    Field::new("package_id", Utf8, false),
                    Field::new("seed_subject_id", Binary, false),
                    Field::new("evidence", Binary, false),
                    Field::new("state", Utf8, false),
                    Field::new("missing_fields", Binary, false),
                ],
            ),
            (
                "correlation_packages",
                vec![
                    Field::new("package_id", Utf8, false),
                    Field::new("package_version", UInt64, false),
                    Field::new("required_inputs", Binary, false),
                    Field::new("state", Utf8, false),
                    Field::new("maximum_lateness_ns", UInt64, false),
                    Field::new("retention_ttl_ns", UInt64, false),
                    Field::new("clock_uncertainty_ns", UInt64, true),
                    Field::new("late_action", Utf8, false),
                    Field::new("window_ns", UInt64, false),
                    Field::new("window_records", UInt64, false),
                    Field::new("window_bytes", UInt64, false),
                    Field::new("coverage_predicate", Utf8, false),
                    Field::new("replay_contract_id", Utf8, false),
                    Field::new("result_states", Binary, false),
                    Field::new("accepted_cursor_watermark", UInt64, false),
                    Field::new("observed_boottime_watermark_ns", UInt64, false),
                ],
            ),
            (
                "policy_observations",
                vec![
                    Field::new("finding_id", Utf8, false),
                    Field::new("profile_generation_ref_id", UInt64, false),
                    Field::new("observations", Binary, false),
                    Field::new("policy_source_revision_id", Utf8, true),
                    Field::new("candidate_content_id", Utf8, true),
                    Field::new("target_snapshot_digest", Utf8, true),
                    Field::new("node_bound_generation_digest", Utf8, true),
                    Field::new("activation_acknowledgement", Binary, true),
                    Field::new("state", Utf8, false),
                    Field::new("limits", Binary, false),
                ],
            ),
            (
                "graph_manifest",
                vec![
                    Field::new("first_cursor", UInt64, false),
                    Field::new("last_cursor", UInt64, false),
                    Field::new("previous_result_id", Utf8, true),
                    Field::new("subject_count", UInt64, false),
                    Field::new("relationship_count", UInt64, false),
                    Field::new("max_hops", UInt32, false),
                    Field::new("hop_boundary", Boolean, false),
                ],
            ),
        ] {
            let mut common = graph.clone();
            common.extend(fields);
            insert(name, common);
        }
        insert(
            "notifications",
            vec![
                Field::new("tenant_id", Binary, false),
                Field::new("notification_id", Binary, false),
                Field::new("notification_revision", UInt64, false),
                Field::new("kind", Utf8, false),
                Field::new("finding_id", Utf8, true),
                Field::new("finding_result_id", Utf8, true),
                Field::new("finding_revision", Binary, true),
                Field::new("finding_available", Boolean, false),
                Field::new("package_id", Utf8, false),
                Field::new("required_action", Utf8, true),
                Field::new("route_id", Utf8, true),
                Field::new("route_revision", UInt64, true),
                Field::new("priority", Utf8, false),
                Field::new("source_priority", Utf8, false),
                Field::new("minimum_priority", Utf8, false),
                Field::new("first_seen_utc_ns", UInt64, false),
                Field::new("deadline_utc_ns", UInt64, true),
                Field::new("overdue", Boolean, false),
                Field::new("overdue_since_utc_ns", UInt64, true),
                Field::new("sink_health", Utf8, false),
                Field::new("failure", Utf8, true),
                Field::new("human_acknowledgement", Binary, true),
                Field::new("agent_receipt", Binary, true),
                Field::new("advisory", Binary, true),
                Field::new("unconfirmed_concern", Binary, true),
                Field::new("delivery_attempts", Binary, false),
                Field::new("sensitivity", Utf8, false),
                Field::new("commit_revision", UInt64, false),
            ],
        );
        schemas
    }
}
