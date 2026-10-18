use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::sync::{Arc, LazyLock};

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisStore, DiscoverySnapshotRowV1, DiscoveryStateRowV1, PackageArtifactV1, PackageBundleV1,
    PackageErrorCodeV1, PackageImplementationV1, SqlModelV1,
};

use datafusion::sql::sqlparser::ast::{
    Ident, ObjectName, TableAlias, TableFactor, VisitMut, VisitorMut,
};

use crate::ObservedEffects;

struct Bindings<'a>(&'a [(&'a str, &'a str)]);

impl VisitorMut for Bindings<'_> {
    type Break = ();

    fn post_visit_table_factor(&mut self, factor: &mut TableFactor) -> ControlFlow<()> {
        let TableFactor::Table { name, alias, .. } = factor else {
            return ControlFlow::Continue(());
        };
        let original = name.to_string();
        if let Some((_, target)) = self.0.iter().find(|(port, _)| *port == original) {
            *name = ObjectName::from(vec![Ident::new(*target)]);
            alias.get_or_insert_with(|| TableAlias {
                explicit: true,
                name: Ident::new(original),
                columns: Vec::new(),
            });
        }
        ControlFlow::Continue(())
    }
}

const INPUTS: &[(&str, &[&str])] = &[
    (
        "events",
        &[
            "tenant_id",
            "node_id",
            "node_boot_id",
            "label_epoch",
            "source_id",
            "source_epoch",
            "cpu_id",
            "source_cursor",
            "framed_record",
            "coverage_interval_id",
            "profile_generation_ref_id",
            "temporal_coverage",
            "task_cookie",
            "target_task_cookie",
            "process_lineage_id",
            "authority_domain_id",
            "execution_set_id",
            "exact_object_id",
            "destination_id",
            "policy_rule_id",
            "reason",
            "decision",
            "effect_family",
            "operation",
            "operation_argument",
            "configured_errno",
            "kernel_result",
            "context_schema_version",
            "kernel_sequence",
            "process_instance_id",
            "entry_instance_id",
            "binding_id",
            "role_id",
            "state_id",
            "entry_rule_id",
            "exact_profile_generation_ref_id",
            "mount_id_unique",
            "inode",
            "inode_generation",
            "mount_namespace_inode",
            "filesystem_device",
            "catalog_profile_id",
            "catalog_profile_version",
            "catalog_policy_document_digest",
            "catalog_key_workload_selector_id",
            "catalog_key_protected_scope_id",
            "catalog_key_execution_set_id",
            "catalog_key_entry_kind",
            "catalog_key_role_id",
            "catalog_key_process_state_id",
            "catalog_key_effect_family",
            "catalog_key_operation_id",
            "catalog_key_operation",
            "catalog_key_operation_argument",
            "catalog_key_argument_wildcard",
            "catalog_key_object_selector",
            "catalog_key_binding_lifecycle",
        ],
    ),
    (
        "targets",
        &[
            "tenant_id",
            "node_id",
            "node_boot_id_text",
            "label_epoch",
            "binding_id_text",
            "workload_binding_generation_digest",
            "workload_digest_valid",
            "execution_set_id",
            "cluster_uid",
            "namespace_uid",
            "controller_uid",
            "service_account_uid",
            "pod_uid",
            "container_id",
            "container_name",
            "container_kind",
            "image_digest",
            "pod_labels",
            "namespace_name",
            "pod_name",
            "profile_id",
            "policy_source_revision_id",
            "source_revision_id",
            "signed_profile_digest",
            "protected_scope_id",
            "workload_selector_id",
            "kubernetes_node_name",
            "kubernetes_node_uid",
        ],
    ),
    (
        "compiled_policies",
        &[
            "tenant_id",
            "lifetime_key",
            "commit_revision",
            "source_revision_id",
            "signed_profile_digest",
            "profile_id",
            "profile_version",
            "policy_document_digest",
            "execution_set_ids",
            "compiled_keys",
        ],
    ),
    (
        "coverage",
        &[
            "tenant_id",
            "node_id",
            "node_boot_id",
            "label_epoch",
            "source_id",
            "source_epoch",
            "cpu_id",
            "kind",
            "coverage_revision",
            "interval_id",
            "interval_source_epoch",
            "state",
            "gap_reasons",
            "first_sequence",
            "last_sequence",
            "opening_attempted",
            "opening_suppressed",
            "opening_requested",
            "opening_emitted",
            "opening_lost",
            "opening_classifier_miss_count",
            "opening_unresolved",
            "opening_next_sequence",
            "closing_attempted",
            "closing_suppressed",
            "closing_requested",
            "closing_emitted",
            "closing_lost",
            "closing_classifier_miss_count",
            "closing_unresolved",
            "closing_next_sequence",
        ],
    ),
    (
        "discovery_state",
        &[
            "tenant_id",
            "node_id",
            "node_boot_id",
            "label_epoch",
            "source_id",
            "source_epoch",
            "cpu_id",
            "contiguous_cursor",
            "retained_floor",
            "source_coverage_revision",
            "processor_present",
            "consumed_cursor",
            "resume_floor",
            "retired",
            "current_result_id",
            "result_commit_revision",
            "interval_id",
            "profile_revision",
            "facts_revision",
            "coverage_revision",
            "created_utc_ns",
            "updated_utc_ns",
            "sealed",
            "input_bytes",
            "incomplete",
            "gaps",
            "context_refs",
            "snapshot",
        ],
    ),
];

#[expect(
    clippy::expect_used,
    reason = "The fixed native SQL fragments are qualified by package execution tests."
)]
static LIVE_BODY: LazyLock<String> = LazyLock::new(|| {
    let fragments = [
        (
            "@@CONTEXT_SQL@@",
            ObservedEffects::CONTEXT_BINDINGS_SQL,
            vec![("records", "__live_candidates")],
        ),
        (
            "@@DELTA_COVERAGE_SQL@@",
            include_str!("coverage_ranges.sql"),
            vec![("records", "__live_selected")],
        ),
        (
            "@@APPEND_COVERAGE_SQL@@",
            include_str!("coverage_ranges.sql"),
            vec![("records", "__live_append")],
        ),
        (
            "@@REFRESH_COVERAGE_SQL@@",
            include_str!("coverage_ranges.sql"),
            vec![("records", "__live_refresh_records")],
        ),
        (
            "@@RECORDED_SQL@@",
            ObservedEffects::RECORDED_SNAPSHOT_SQL,
            vec![
                ("records", "__live_selected"),
                ("contexts", "__live_bindings"),
                ("ranges", "__live_ranges"),
                ("exclusions", "__live_exclusions"),
                ("lifecycle", "__live_empty_lifecycle"),
            ],
        ),
        (
            "@@APPEND_QUALIFY_SQL@@",
            include_str!("qualify_ranges.sql"),
            vec![
                ("records", "__live_append"),
                ("ranges", "__live_append_ranges"),
            ],
        ),
        (
            "@@REFRESH_QUALIFY_SQL@@",
            include_str!("qualify_ranges.sql"),
            vec![
                ("records", "__live_refresh_records"),
                ("ranges", "__live_refresh_ranges"),
            ],
        ),
        (
            "@@MERGE_SQL@@",
            ObservedEffects::MERGE_SQL,
            vec![
                ("left_snapshot", "__live_left"),
                ("right_snapshot", "__live_right"),
            ],
        ),
    ];
    let mut body = include_str!("live.sql").to_owned();
    for (marker, sql, bindings) in fragments {
        let mut statement =
            ObservedEffects::query(sql).expect("the fixed Discovery SQL is a native query");
        let _flow = statement.visit(&mut Bindings(&bindings));
        body = body.replace(marker, &statement.to_string());
    }
    body
});

static LIVE_QUERY: LazyLock<String> = LazyLock::new(|| {
    let inputs = INPUTS
        .iter()
        .zip(["records", "targets", "policies", "reports", "state"])
        .map(|((table, columns), alias)| {
            format!("{alias} AS (SELECT {} FROM {table})", columns.join(", "))
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "WITH {inputs}, \
            exclusions AS (SELECT named_struct('stream', named_struct(\
                'tenant_id', tenant_id, 'node_id', node_id, 'node_boot_id', node_boot_id, \
                'label_epoch', label_epoch, 'source_id', source_id, 'source_epoch', source_epoch), \
                'cpu_id', cpu_id, 'durable_cursor', source_cursor) AS record_id, \
                arrow_cast(NULL, 'Utf8') AS reason FROM records WHERE FALSE), \
            lifecycle AS (SELECT arrow_cast(NULL, 'Utf8') AS \"case\", \
                arrow_cast(NULL, 'Utf8') AS state, [record_id] AS records, reason \
                FROM exclusions WHERE FALSE), \
            metadata AS (SELECT tenant_id, \
                CASE WHEN snapshot IS NULL OR COALESCE(sealed, FALSE) THEN 'native-live-v1' \
                    ELSE COALESCE(snapshot['source_revision'], 'native-live-v1') END AS source_revision, \
                arrow_cast('OBSERVED_RUNTIME', 'Utf8') AS proof_kind FROM state) \
        SELECT * FROM ({}) AS live",
        LIVE_BODY.as_str()
    )
});

impl ObservedEffects {
    pub const LIVE_SQL: &'static LazyLock<String> = &LIVE_QUERY;
    pub(crate) const LIVE_BODY: &'static LazyLock<String> = &LIVE_BODY;
    pub const MERGE_SQL: &'static str = include_str!("merge_snapshot.sql");

    pub fn live_bundle() -> araphor_data::Result<PackageBundleV1> {
        let tables = AnalysisStore::table_schemas();
        let inputs = INPUTS
            .iter()
            .map(|(name, columns)| {
                let schema = tables
                    .get(*name)
                    .ok_or_else(|| PackageErrorCodeV1::Invalid.error("native Discovery table"))?;
                let fields = columns
                    .iter()
                    .map(|column| {
                        schema.field_with_name(column).cloned().map_err(|_| {
                            PackageErrorCodeV1::Invalid.error("native Discovery input field")
                        })
                    })
                    .collect::<araphor_data::Result<Vec<_>>>()?;
                Ok(sdk::Port::new(*name, sdk::Schema::new(fields)))
            })
            .collect::<araphor_data::Result<Vec<_>>>()?;
        let state = DiscoveryStateRowV1::schema();
        let field = |name: &str| {
            state
                .field_with_name(name)
                .map(|field| Arc::new(field.clone()))
                .map_err(|_| PackageErrorCodeV1::Invalid.error("native Discovery state field"))
        };
        let source = [
            "tenant_id",
            "node_id",
            "node_boot_id",
            "label_epoch",
            "source_id",
            "source_epoch",
        ]
        .into_iter()
        .map(field)
        .collect::<araphor_data::Result<Vec<_>>>()?;
        let mut output = vec![
            Arc::new(sdk::Field::new(
                "source",
                sdk::DataType::Struct(source.into()),
                false,
            )),
            field("cpu_id")?,
            field("processor_present")?,
            field("retired")?,
            field("resume_floor")?,
            field("retained_floor")?,
            Arc::new(sdk::Field::new(
                "expected_cursor",
                sdk::DataType::UInt64,
                false,
            )),
            Arc::new(sdk::Field::new(
                "consumed_cursor",
                sdk::DataType::UInt64,
                false,
            )),
            field("current_result_id")?,
            field("result_commit_revision")?,
            Arc::new(sdk::Field::new(
                "coverage_revision",
                sdk::DataType::UInt64,
                false,
            )),
        ];
        for name in [
            "interval_id",
            "profile_revision",
            "facts_revision",
            "created_utc_ns",
            "updated_utc_ns",
            "sealed",
            "input_bytes",
            "incomplete",
            "gaps",
            "context_refs",
        ] {
            output.push(if name == "facts_revision" || name == "input_bytes" {
                Arc::new(sdk::Field::new(name, sdk::DataType::UInt64, false))
            } else if name == "incomplete" {
                Arc::new(sdk::Field::new(name, sdk::DataType::Boolean, false))
            } else {
                field(name)?
            });
        }
        output.push(Arc::new(sdk::Field::new(
            "snapshot",
            sdk::DataType::Struct(DiscoverySnapshotRowV1::schema().fields().clone()),
            false,
        )));
        let mut model = sdk::Model::new(
            "live",
            inputs,
            vec![sdk::Port::new("snapshot", sdk::Schema::new(output))],
        );
        model.input_mode = sdk::InputMode::Resolved;
        let artifact = PackageArtifactV1 {
            descriptor: sdk::Package::new("discovery-effects-live", "1", vec![model]),
            implementations: vec![PackageImplementationV1::Sql {
                export: "live".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([(
                        "snapshot".into(),
                        Self::LIVE_SQL.as_str().to_owned(),
                    )]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        };
        Ok(PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        })
    }
}
