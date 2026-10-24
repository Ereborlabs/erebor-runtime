use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisStore, DiscoverySnapshotRowV1, DiscoveryStateRowV1, PackageArtifactV1, PackageBundleV1,
    PackageErrorCodeV1, PackageImplementationV1, SqlModelV1,
};

use araphor_analysis_builtins::discovery::sql::{CONTEXT_BINDINGS_SQL, COVERAGE_RANGES_SQL};
use datafusion::common::{DataFusionError, Result};
use datafusion::sql::parser::Statement;
use datafusion::sql::sqlparser::ast::Statement as SqlStatement;

pub(crate) fn query(sql: &str) -> Result<SqlStatement> {
    let statement = araphor_query::parser::Parser::default()
        .parse(sql)
        .map_err(|error| DataFusionError::External(Box::new(error)))?;
    let Statement::Statement(statement) = statement else {
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
            "commit_revision",
            "node_id",
            "node_boot_id",
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
            "first_cursor",
            "last_cursor",
            "commit_revision",
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
            "input_unbounded",
            "retained_floor",
            "source_coverage_revision",
            "processor_present",
            "consumed_cursor",
            "resume_floor",
            "retired",
            "current_result_id",
            "result_commit_revision",
            "current_compatible",
            "notice_facts_revision",
            "notice_coverage_revision",
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
            "history",
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

static LIVE_STATE_SQL: LazyLock<String> = LazyLock::new(|| {
    let columns = INPUTS
        .iter()
        .filter(|(table, _)| *table == "discovery_state")
        .flat_map(|(_, columns)| columns.iter())
        .map(|column| {
            if *column == "contiguous_cursor" {
                "GREATEST(COALESCE(consumed_cursor, CAST(0 AS BIGINT UNSIGNED)), \
                COALESCE(resume_floor, CAST(0 AS BIGINT UNSIGNED)), \
                COALESCE((SELECT MAX(source_cursor) FROM events), CAST(0 AS BIGINT UNSIGNED)), \
                COALESCE(CASE WHEN input_unbounded THEN \
                        (SELECT MAX(last_cursor) FROM coverage AS expiry \
                         WHERE expiry.kind = 'expired' \
                            AND expiry.tenant_id = discovery_state.tenant_id \
                            AND expiry.node_id = discovery_state.node_id \
                            AND expiry.node_boot_id = discovery_state.node_boot_id \
                            AND expiry.label_epoch = discovery_state.label_epoch \
                            AND expiry.source_id = discovery_state.source_id \
                            AND expiry.source_epoch = discovery_state.source_epoch \
                            AND expiry.cpu_id = discovery_state.cpu_id) \
                        ELSE CAST(0 AS BIGINT UNSIGNED) END, \
                    CAST(0 AS BIGINT UNSIGNED))) AS contiguous_cursor"
                    .to_owned()
            } else {
                (*column).to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"WITH captured_state AS (SELECT {columns} FROM discovery_state),
        policies AS (SELECT * FROM compiled_policies),
        facts AS (
            SELECT GREATEST(COALESCE(MAX(policy.commit_revision), CAST(0 AS BIGINT UNSIGNED)),
                COALESCE(MAX(target.commit_revision), CAST(0 AS BIGINT UNSIGNED)),
                COALESCE(MAX(state.facts_revision), CAST(0 AS BIGINT UNSIGNED))) AS revision
            FROM captured_state AS state LEFT JOIN targets AS target
                ON target.tenant_id = state.tenant_id AND target.node_id = state.node_id
                AND target.node_boot_id = state.node_boot_id
                AND target.label_epoch = state.label_epoch
            LEFT JOIN policies AS policy ON policy.tenant_id = target.tenant_id
                AND policy.source_revision_id = target.source_revision_id
                AND policy.signed_profile_digest = target.signed_profile_digest
                AND policy.profile_id = target.profile_id),
        history AS (SELECT UNNEST(history) AS prior FROM captured_state),
        candidate AS (
            SELECT prior FROM history CROSS JOIN facts CROSS JOIN captured_state AS state
            WHERE state.current_result_id IS NOT NULL
                AND (prior['notice_facts_revision'] < facts.revision
                    OR prior['notice_coverage_revision'] < state.source_coverage_revision)
            ORDER BY prior['interval_id'] LIMIT 1),
        current_work AS (
            SELECT state.*, facts.revision AS required_facts,
                GREATEST(COALESCE(consumed_cursor, CAST(0 AS BIGINT UNSIGNED)),
                    COALESCE(resume_floor, CAST(0 AS BIGINT UNSIGNED))) AS frontier,
                facts.revision > COALESCE(notice_facts_revision, CAST(0 AS BIGINT UNSIGNED))
                    OR source_coverage_revision > COALESCE(notice_coverage_revision,
                        CAST(0 AS BIGINT UNSIGNED)) AS pending
            FROM captured_state AS state CROSS JOIN facts),
        chosen AS (
            SELECT current_work.*, candidate.prior,
                prior IS NOT NULL AND processor_present AND current_result_id IS NOT NULL
                    AND retained_floor <= frontier AND contiguous_cursor = frontier
                    AND NOT COALESCE(resume_floor > COALESCE(consumed_cursor, 0), FALSE)
                    AND (COALESCE(sealed, FALSE) OR NOT pending) AS repair
            FROM current_work LEFT JOIN candidate ON TRUE),
        selected_ranges AS (
            SELECT UNNEST(prior['snapshot']['coverage']) AS range FROM chosen WHERE repair),
        missing_ranges AS (
                SELECT 1 FROM selected_ranges LEFT JOIN events AS record
                    ON record.tenant_id = range['stream']['tenant_id']
                    AND record.node_id = range['stream']['node_id']
                    AND record.node_boot_id = range['stream']['node_boot_id']
                    AND record.label_epoch = range['stream']['label_epoch']
                    AND record.source_id = range['stream']['source_id']
                    AND record.source_epoch = range['stream']['source_epoch']
                    AND record.cpu_id = range['cpu_id']
                    AND record.source_cursor BETWEEN range['first_cursor'] AND range['last_cursor']
                GROUP BY range['stream']['tenant_id'], range['stream']['node_id'],
                    range['stream']['node_boot_id'], range['stream']['label_epoch'],
                    range['stream']['source_id'], range['stream']['source_epoch'],
                    range['cpu_id'], range['first_cursor'], range['last_cursor'],
                    range['expected_records']
                HAVING COUNT(DISTINCT record.source_cursor) <> range['expected_records']),
        availability AS (SELECT COUNT(*) = 0 AS complete FROM missing_ranges),
        selected AS (
            SELECT chosen.* EXCLUDE (frontier),
                NOT repair OR (prior['compatible'] AND complete) AS available
            FROM chosen CROSS JOIN availability)
        SELECT * FROM selected"#,
    )
});

pub(crate) static LIVE_SQL: LazyLock<String> = LazyLock::new(|| {
    let inputs = INPUTS
        .iter()
        .zip(["captured_records", "targets", "policies", "reports", "work"])
        .map(|((table, columns), alias)| {
            if *table == "discovery_state" {
                format!(
                    "{alias} AS (SELECT *, GREATEST(\
                    COALESCE(consumed_cursor, CAST(0 AS BIGINT UNSIGNED)), \
                    COALESCE(resume_floor, CAST(0 AS BIGINT UNSIGNED))) AS frontier FROM {table})"
                )
            } else {
                format!("{alias} AS (SELECT {} FROM {table})", columns.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"WITH {inputs},
        selected_ranges AS (
            SELECT UNNEST(prior['snapshot']['coverage']) AS range FROM work WHERE repair),
        selected_records AS (
            SELECT record.* FROM captured_records AS record WHERE EXISTS (
                SELECT 1 FROM selected_ranges WHERE record.tenant_id = range['stream']['tenant_id']
                    AND record.node_id = range['stream']['node_id']
                    AND record.node_boot_id = range['stream']['node_boot_id']
                    AND record.label_epoch = range['stream']['label_epoch']
                    AND record.source_id = range['stream']['source_id']
                    AND record.source_epoch = range['stream']['source_epoch']
                    AND record.cpu_id = range['cpu_id']
                    AND record.source_cursor BETWEEN range['first_cursor'] AND range['last_cursor'])),
        state AS (
            SELECT * EXCLUDE (history, prior, required_facts, frontier, pending, repair, available)
            REPLACE (
                CASE WHEN repair THEN frontier ELSE contiguous_cursor END AS contiguous_cursor,
                CASE WHEN repair THEN prior['result_id'] ELSE current_result_id END AS current_result_id,
                CASE WHEN repair THEN prior['commit_revision'] ELSE result_commit_revision END AS result_commit_revision,
                CASE WHEN repair THEN prior['interval_id'] ELSE interval_id END AS interval_id,
                CASE WHEN repair THEN prior['profile_revision'] ELSE profile_revision END AS profile_revision,
                CASE WHEN repair THEN prior['facts_revision'] ELSE facts_revision END AS facts_revision,
                CASE WHEN repair THEN prior['coverage_revision'] ELSE coverage_revision END AS coverage_revision,
                CASE WHEN repair THEN prior['created_utc_ns'] ELSE created_utc_ns END AS created_utc_ns,
                CASE WHEN repair THEN prior['updated_utc_ns'] ELSE updated_utc_ns END AS updated_utc_ns,
                CASE WHEN repair THEN FALSE ELSE sealed END AS sealed,
                CASE WHEN repair THEN prior['input_bytes'] ELSE input_bytes END AS input_bytes,
                CASE WHEN repair THEN prior['incomplete'] ELSE incomplete END AS incomplete,
                CASE WHEN repair THEN prior['gaps'] ELSE gaps END AS gaps,
                CASE WHEN repair THEN prior['context_refs'] ELSE context_refs END AS context_refs,
                CASE WHEN repair THEN prior['snapshot'] ELSE snapshot END AS snapshot)
            FROM work),
        __live_input_records AS (
            SELECT record.* FROM captured_records AS record CROSS JOIN work WHERE NOT repair
            UNION ALL SELECT record.* FROM selected_records AS record CROSS JOIN work WHERE repair AND available),
        __live_input_exclusions AS (
            SELECT named_struct('stream', named_struct('tenant_id', tenant_id, 'node_id', node_id,
                'node_boot_id', node_boot_id, 'label_epoch', label_epoch, 'source_id', source_id,
                'source_epoch', source_epoch), 'cpu_id', cpu_id, 'durable_cursor', source_cursor) AS record_id,
                arrow_cast(NULL, 'Utf8') AS reason FROM captured_records WHERE FALSE),
        __live_input_lifecycle AS (
            SELECT arrow_cast(NULL, 'Utf8') AS "case", arrow_cast(NULL, 'Utf8') AS state,
                [record_id] AS records, reason FROM __live_input_exclusions WHERE FALSE),
        metadata AS (
            SELECT tenant_id,
                CASE WHEN snapshot IS NULL OR COALESCE(sealed, FALSE) THEN 'native-live-v1'
                    ELSE COALESCE(snapshot['source_revision'], 'native-live-v1') END AS source_revision,
                arrow_cast('OBSERVED_RUNTIME', 'Utf8') AS proof_kind FROM state),
        publication AS (
            SELECT live.*, work.available AND live.source IS NOT NULL AS changed,
                work.repair, work.pending, work.required_facts
            FROM ({body}) AS live RIGHT JOIN work ON TRUE)
        SELECT
            CASE WHEN changed THEN publication.source ELSE named_struct('tenant_id', state.tenant_id,
                'node_id', state.node_id, 'node_boot_id', state.node_boot_id, 'label_epoch', state.label_epoch,
                'source_id', state.source_id, 'source_epoch', state.source_epoch) END AS source,
            state.cpu_id, state.processor_present, state.retired, state.resume_floor, state.retained_floor,
            CASE WHEN changed THEN publication.expected_cursor ELSE GREATEST(
                COALESCE(state.consumed_cursor, CAST(0 AS BIGINT UNSIGNED)),
                COALESCE(state.resume_floor, CAST(0 AS BIGINT UNSIGNED))) END AS expected_cursor,
            CASE WHEN changed THEN publication.consumed_cursor ELSE GREATEST(
                COALESCE(state.consumed_cursor, CAST(0 AS BIGINT UNSIGNED)),
                COALESCE(state.resume_floor, CAST(0 AS BIGINT UNSIGNED))) END AS consumed_cursor,
            state.current_result_id, state.result_commit_revision,
            CASE WHEN changed THEN publication.coverage_revision
                ELSE COALESCE(state.coverage_revision, CAST(0 AS BIGINT UNSIGNED)) END AS coverage_revision,
            state.interval_id, state.profile_revision,
            CASE WHEN changed THEN publication.facts_revision ELSE state.facts_revision END AS facts_revision,
            state.created_utc_ns, state.updated_utc_ns,
            CASE WHEN publication.repair THEN TRUE ELSE state.sealed END AS sealed,
            CASE WHEN changed THEN publication.input_bytes ELSE state.input_bytes END AS input_bytes,
            CASE WHEN changed THEN publication.incomplete ELSE state.incomplete END AS incomplete,
            CASE WHEN changed THEN publication.gaps ELSE arrow_cast(state.gaps,
                'List(Struct("first_cursor": UInt64, "last_cursor": UInt64, "commit_revision": UInt64))') END AS gaps,
            state.context_refs,
            CASE WHEN changed THEN publication.snapshot ELSE state.snapshot END AS snapshot,
            publication.repair, NOT changed AS notice_only,
            publication.required_facts AS notice_facts_revision,
            state.source_coverage_revision AS notice_coverage_revision
        FROM publication CROSS JOIN state
        WHERE changed OR publication.repair OR (publication.pending
            AND NOT COALESCE(state.sealed, FALSE) AND state.current_result_id IS NOT NULL)"#,
        body = LIVE_BODY.as_str(),
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
                let mut fields = columns
                    .iter()
                    .map(|column| {
                        schema.field_with_name(column).cloned().map_err(|_| {
                            PackageErrorCodeV1::Invalid.error("native Discovery input field")
                        })
                    })
                    .collect::<araphor_data::Result<Vec<_>>>()?;
                let source = if *name == "discovery_state" {
                    let history = schema.field_with_name("history").map_err(|_| {
                        PackageErrorCodeV1::Invalid.error("native Discovery history field")
                    })?;
                    let sdk::DataType::List(prior) = history.data_type() else {
                        return Err(
                            PackageErrorCodeV1::Invalid.error("native Discovery history type")
                        );
                    };
                    fields.extend([
                        sdk::Field::new("required_facts", sdk::DataType::UInt64, false),
                        sdk::Field::new("pending", sdk::DataType::Boolean, false),
                        sdk::Field::new("prior", prior.data_type().clone(), true),
                        sdk::Field::new("repair", sdk::DataType::Boolean, false),
                        sdk::Field::new("available", sdk::DataType::Boolean, false),
                    ]);
                    sdk::InputSource::Query(LIVE_STATE_SQL.as_str().to_owned())
                } else {
                    sdk::InputSource::Table(sdk::TableRef::Named((*name).into()))
                };
                Ok(sdk::InputPort {
                    port: sdk::Port::new(*name, sdk::Schema::new(fields)),
                    source,
                })
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
        for name in ["repair", "notice_only"] {
            output.push(Arc::new(sdk::Field::new(
                name,
                sdk::DataType::Boolean,
                false,
            )));
        }
        for name in ["notice_facts_revision", "notice_coverage_revision"] {
            output.push(Arc::new(sdk::Field::new(
                name,
                sdk::DataType::UInt64,
                false,
            )));
        }
        let mut model = sdk::Model::new(
            "live",
            Vec::new(),
            vec![sdk::Port::new("snapshot", sdk::Schema::new(output))],
        );
        model.inputs = inputs;
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
