use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisStore, DiscoverySnapshotRowV1, DiscoveryStateRowV1, PackageArtifactV1, PackageBundleV1,
    PackageErrorCodeV1, PackageImplementationV1, SqlModelV1,
};

use araphor_analysis_builtins::discovery::sql::{CONTEXT_BINDINGS_SQL, COVERAGE_RANGES_SQL};
use datafusion::common::{DataFusionError, Result};
use datafusion::sql::parser::{DFParserBuilder, Statement};
use datafusion::sql::sqlparser::ast::Statement as SqlStatement;

pub(crate) fn query(sql: &str) -> Result<SqlStatement> {
    let mut statements = DFParserBuilder::new(sql)
        .with_recursion_limit(usize::MAX)
        .build()?
        .parse_statements()?;
    if statements.len() != 1 {
        return datafusion::common::internal_err!("Discovery SQL requires one statement");
    }
    let Some(Statement::Statement(statement)) = statements.pop_front() else {
        return datafusion::common::internal_err!("Discovery SQL is absent");
    };
    match *statement {
        SqlStatement::Query(query) => Ok(SqlStatement::Query(query)),
        SqlStatement::CreateView(view) => Ok(SqlStatement::Query(view.query)),
        _ => Err(DataFusionError::Internal(
            "Discovery SQL is not a query or view".into(),
        )),
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
    araphor_analysis_builtins::discovery::Discovery::live_program(
        &query(CONTEXT_BINDINGS_SQL)
            .expect("the context view is native SQL")
            .to_string(),
        &query(COVERAGE_RANGES_SQL)
            .expect("the coverage view is native SQL")
            .to_string(),
    )
});

pub(crate) static LIVE_SQL: LazyLock<String> = LazyLock::new(|| {
    let inputs = INPUTS
        .iter()
        .zip([
            "__live_input_records",
            "targets",
            "policies",
            "reports",
            "state",
        ])
        .map(|((table, columns), alias)| {
            format!("{alias} AS (SELECT {} FROM {table})", columns.join(", "))
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "WITH {inputs}, \
            __live_input_exclusions AS (SELECT named_struct('stream', named_struct(\
                'tenant_id', tenant_id, 'node_id', node_id, 'node_boot_id', node_boot_id, \
                'label_epoch', label_epoch, 'source_id', source_id, 'source_epoch', source_epoch), \
                'cpu_id', cpu_id, 'durable_cursor', source_cursor) AS record_id, \
                arrow_cast(NULL, 'Utf8') AS reason FROM __live_input_records WHERE FALSE), \
            __live_input_lifecycle AS (SELECT arrow_cast(NULL, 'Utf8') AS \"case\", \
                arrow_cast(NULL, 'Utf8') AS state, [record_id] AS records, reason \
                FROM __live_input_exclusions WHERE FALSE), \
            metadata AS (SELECT tenant_id, \
                CASE WHEN snapshot IS NULL OR COALESCE(sealed, FALSE) THEN 'native-live-v1' \
                    ELSE COALESCE(snapshot['source_revision'], 'native-live-v1') END AS source_revision, \
                arrow_cast('OBSERVED_RUNTIME', 'Utf8') AS proof_kind FROM state) \
        SELECT * FROM ({}) AS live",
        LIVE_BODY.as_str()
    )
});

impl super::Package {
    pub fn discovery_bundle() -> araphor_data::Result<PackageBundleV1> {
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
                    outputs: BTreeMap::from([("snapshot".into(), LIVE_SQL.as_str().to_owned())]),
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
