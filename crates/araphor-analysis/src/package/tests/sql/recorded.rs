use std::borrow::Cow;

use araphor_analysis_builtins::{discovery as builtin, Rows};
use araphor_analysis_sdk as sdk;
use builtin::{
    BehaviorAtomKeyV1, BehaviorAtomV1, Discovery, DiscoveryContextBindingV1 as Binding,
    DiscoveryCoverageStateV1 as CoverageState, DiscoveryCoverageV1 as Coverage,
    DiscoveryLifecycleCaseV1 as Case, DiscoveryLifecycleEntryV1 as Lifecycle,
    DiscoveryLifecycleStateV1 as State, DiscoveryPhysicalResultV1, DiscoveryPolicyKeyV1,
    DiscoveryPolicyRevisionV1, DiscoveryProofKindV1 as Proof, DiscoveryRecordIdV1 as RecordId,
    DiscoveryUnresolvedV1 as Disposition, EvidenceIntakeIdentityV1, Record,
};
use datafusion::arrow::datatypes::{Field, FieldRef};
use serde::{Deserialize, Serialize};
use serde_arrow::schema::{SchemaLike as _, TracingOptions};

use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn native_statement(sql: &str) -> TestResult<datafusion::sql::parser::Statement> {
    let mut statements = datafusion::sql::parser::DFParserBuilder::new(sql)
        .with_recursion_limit(usize::MAX)
        .build()?
        .parse_statements()?;
    assert_eq!(statements.len(), 1);
    statements
        .pop_front()
        .ok_or_else(|| "native statement absent".into())
}

async fn native_frame(
    context: &SessionContext,
    sql: &str,
) -> TestResult<datafusion::dataframe::DataFrame> {
    let state = context.state();
    let statement = native_statement(sql)?;
    let plan = state.statement_to_plan(statement).await?;
    Ok(datafusion::dataframe::DataFrame::new(state, plan))
}

#[test]
fn templates_use_native_parser() -> TestResult {
    for sql in [MERGE_SQL, LIVE_SQL.as_str()] {
        assert!(matches!(
            native_statement(sql)?,
            datafusion::sql::parser::Statement::Statement(_)
        ));
    }
    Ok(())
}

const EVENT_FIELDS: &[&str] = &[
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
];

use araphor_data::DiscoveryLifecycleRowV1 as FlatLifecycle;

mod live;
mod merge;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u32,
    tenant_id: [u8; 16],
    source_revision: String,
    proof_kind: Proof,
    accepted_records: u64,
    included_records: u64,
    unresolved_records: u64,
    excluded_records: u64,
    duplicate_deliveries: u64,
    atoms: Vec<BehaviorAtomV1>,
    coverage: Vec<Coverage>,
    unresolved: Vec<Disposition>,
    excluded: Vec<Disposition>,
    lifecycle: Vec<FlatLifecycle>,
}

impl Snapshot {
    fn assert_batch(&self, batch: RecordBatch) -> TestResult {
        for name in [
            "accepted_records",
            "included_records",
            "unresolved_records",
            "excluded_records",
            "duplicate_deliveries",
        ] {
            assert_eq!(
                batch.schema().field_with_name(name)?.data_type(),
                &DataType::UInt64
            );
        }
        let expected = serde_arrow::to_record_batch(batch.schema().fields(), &[self])?;
        assert_eq!(batch, expected);
        Ok(())
    }
}

#[derive(Serialize)]
struct Metadata {
    tenant_id: [u8; 16],
    source_revision: &'static str,
    proof_kind: Proof,
}

struct Recorded {
    records: Vec<Record<'static>>,
    contexts: Vec<Binding>,
    coverage: Vec<Coverage>,
    exclusions: Vec<Disposition>,
    lifecycle: Vec<Lifecycle>,
    metadata: Vec<Metadata>,
}

impl Recorded {
    fn new(count: u64) -> Self {
        let stream = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let records: Vec<_> = (1..=count)
            .map(|cursor| Record {
                id: RecordId {
                    stream: stream.clone(),
                    cpu_id: 3,
                    durable_cursor: cursor,
                },
                bytes: Cow::Owned(format!("exact-frame-{cursor}").into_bytes()),
                temporal: 1,
                effect: builtin::DiscoveryEffectKeyV1 {
                    task_cookie: 7,
                    target_task_cookie: None,
                    process_lineage_id: Vec::new(),
                    authority_domain_id: Vec::new(),
                    execution_set_id: Vec::new(),
                    exact_object_id: vec![7; 16],
                    destination_id: 0,
                    policy_rule_id: 1,
                    reason: 0,
                    decision: 1,
                    effect_family: 1,
                    operation: 1,
                    operation_argument: Some(0),
                    configured_errno: -13,
                    kernel_result: -13,
                    exact_file_object: None,
                },
                generation: Some(9_007_199_254_740_999),
                original_sequence: Some(cursor + 100),
                source: None,
            })
            .collect();
        let contexts = records
            .iter()
            .map(|record| Binding {
                record_id: record.id.clone(),
                subject_revision: "subject".into(),
                image_digest: "image".into(),
                configuration_digest: "config".into(),
                process_instance_id: [1; 16],
                entry_instance_id: [2; 16],
                binding_id: [3; 16],
                role_id: 1,
                state_id: 1,
                entry_rule_id: 1,
                catalog_revision: 1,
                static_key: DiscoveryPolicyKeyV1 {
                    workload_selector_id: "workload".into(),
                    protected_scope_id: "scope".into(),
                    execution_set_id: "execution".into(),
                    entry_kind: "entry".into(),
                    role_id: "role".into(),
                    process_state_id: "state".into(),
                    effect_family: 1,
                    operation_id: "operation".into(),
                    operation: 1,
                    operation_argument: 0,
                    argument_wildcard: false,
                    object_selector: "object".into(),
                    binding_lifecycle: "lifecycle".into(),
                },
                policy_revision: DiscoveryPolicyRevisionV1 {
                    profile_id: "profile".into(),
                    profile_version: 1,
                    source_revision_id: "source".into(),
                    signed_profile_digest: "digest".into(),
                },
            })
            .collect();
        let coverage = (count > 0)
            .then_some(Coverage {
                stream,
                cpu_id: 3,
                first_cursor: 1,
                last_cursor: count,
                expected_records: count,
                coverage_revision: 9_007_199_254_740_999,
                coverage_interval_id: [4; 16],
                state: CoverageState::Healthy,
                gap_reasons: Vec::new(),
            })
            .into_iter()
            .collect();
        Self {
            records,
            contexts,
            coverage,
            exclusions: Vec::new(),
            lifecycle: Vec::new(),
            metadata: vec![Metadata {
                tenant_id: [1; 16],
                source_revision: "recorded-test",
                proof_kind: Proof::RecordedInput,
            }],
        }
    }

    fn key(&self, record: &Record<'_>, binding: &Binding) -> BehaviorAtomKeyV1 {
        BehaviorAtomKeyV1 {
            stream: record.id.stream.clone(),
            cpu_id: record.id.cpu_id,
            subject_revision: binding.subject_revision.clone(),
            image_digest: binding.image_digest.clone(),
            configuration_digest: binding.configuration_digest.clone(),
            process_instance_id: binding.process_instance_id,
            entry_instance_id: binding.entry_instance_id,
            binding_id: binding.binding_id,
            role_id: binding.role_id,
            state_id: binding.state_id,
            entry_rule_id: binding.entry_rule_id,
            catalog_revision: binding.catalog_revision,
            static_key: binding.static_key.clone(),
            policy_revision: binding.policy_revision.clone(),
            generation: record.generation.unwrap_or_default(),
            coverage_interval_id: [4; 16],
            temporal_coverage: record.temporal,
            effect: record.effect.clone(),
            physical_result: DiscoveryPhysicalResultV1::Unknown,
            proof_kind: self.metadata[0].proof_kind,
        }
    }

    fn oracle(&self) -> TestResult<Snapshot> {
        let contexts: Vec<_> = self
            .contexts
            .iter()
            .map(|binding| builtin::Context {
                record_id: binding.record_id.clone(),
                atom_key: self
                    .records
                    .iter()
                    .find(|record| record.id == binding.record_id)
                    .map(|record| self.key(record, binding)),
            })
            .collect();
        let datasets = vec![
            Record::encode(&self.records)?,
            Rows::encode(&Discovery::port::<builtin::Context>("contexts"), &contexts)?,
            Rows::encode(&Discovery::port::<Coverage>("coverage"), &self.coverage)?,
            Rows::encode(
                &Discovery::port::<Disposition>("exclusions"),
                &self.exclusions,
            )?,
            Rows::encode(&Discovery::port::<Lifecycle>("lifecycle"), &self.lifecycle)?,
            Rows::encode(
                &Discovery::port::<bool>("observed"),
                &[self.metadata[0].proof_kind == Proof::ObservedRuntime],
            )?,
        ];
        let output = Discovery::evaluate(&sdk::Evaluation {
            previous_outputs: Vec::new(),
            export: "atoms".into(),
            inputs: datasets
                .into_iter()
                .map(|data| sdk::Input {
                    data,
                    revision: sdk::Revision {
                        owner: "fixture".into(),
                        id: "1".into(),
                        window: None,
                    },
                    coverage: sdk::Coverage {
                        state: sdk::CoverageState::Unknown,
                        limits: Vec::new(),
                    },
                })
                .collect(),
            parameters: None,
            checkpoint: None,
            context: sdk::EvaluationContext {
                id: "fixture".into(),
                time_utc_ns: 100,
                seed: None,
            },
        })?;
        macro_rules! rows {
            ($ty:ty, $name:literal) => {
                Rows::decode::<$ty>(
                    &Discovery::port::<$ty>($name),
                    output
                        .datasets
                        .iter()
                        .find(|data| data.name == $name)
                        .ok_or("oracle dataset absent")?,
                )?
            };
        }
        let counts = rows!(builtin::Counts, "counts")
            .pop()
            .ok_or("oracle counts absent")?;
        Ok(Snapshot {
            schema_version: araphor_data::DISCOVERY_SCHEMA_VERSION,
            tenant_id: self.metadata[0].tenant_id,
            source_revision: self.metadata[0].source_revision.into(),
            proof_kind: self.metadata[0].proof_kind,
            accepted_records: counts.accepted,
            included_records: counts.included,
            unresolved_records: counts.unresolved,
            excluded_records: counts.excluded,
            duplicate_deliveries: counts.duplicates,
            atoms: rows!(BehaviorAtomV1, "atoms"),
            coverage: rows!(Coverage, "coverage"),
            unresolved: rows!(Disposition, "unresolved"),
            excluded: rows!(Disposition, "excluded"),
            lifecycle: rows!(Lifecycle, "lifecycle")
                .iter()
                .map(FlatLifecycle::from)
                .collect(),
        })
    }

    fn event(record: &Record<'_>) -> TestResult<serde_json::Value> {
        use serde_json::{json, Value};
        let mut value = serde_json::to_value(&record.effect)?
            .as_object()
            .ok_or("effect object")?
            .clone();
        value.remove("exact_file_object");
        value.extend(
            serde_json::to_value(&record.id.stream)?
                .as_object()
                .ok_or("stream object")?
                .clone(),
        );
        for (name, field) in [
            ("cpu_id", json!(record.id.cpu_id)),
            ("source_cursor", json!(record.id.durable_cursor)),
            ("framed_record", json!(record.bytes.as_ref())),
            ("coverage_interval_id", json!(vec![4u8; 16])),
            ("profile_generation_ref_id", json!(record.generation)),
            ("temporal_coverage", json!(record.temporal)),
            (
                "context_schema_version",
                json!(record.source.as_ref().map(|_| 1u32)),
            ),
            ("kernel_sequence", json!(record.original_sequence)),
            (
                "process_instance_id",
                json!(record.source.as_ref().map(|source| &source.process)),
            ),
            (
                "entry_instance_id",
                json!(record.source.as_ref().map(|source| &source.entry)),
            ),
            (
                "binding_id",
                json!(record.source.as_ref().map(|source| &source.binding)),
            ),
            (
                "role_id",
                json!(record.source.as_ref().map(|source| source.role)),
            ),
            (
                "state_id",
                json!(record.source.as_ref().map(|source| source.state)),
            ),
            (
                "entry_rule_id",
                json!(record.source.as_ref().map(|source| source.rule)),
            ),
        ] {
            value.insert(name.into(), field);
        }
        let exact = record.effect.exact_file_object.as_ref();
        for (name, field) in [
            (
                "exact_profile_generation_ref_id",
                json!(exact.map(|file| file.profile_generation_ref_id)),
            ),
            (
                "mount_id_unique",
                json!(exact.map(|file| file.mount_id_unique)),
            ),
            ("inode", json!(exact.map(|file| file.inode))),
            (
                "inode_generation",
                json!(exact.map(|file| file.inode_generation)),
            ),
            (
                "mount_namespace_inode",
                json!(exact.map(|file| file.mount_namespace_inode)),
            ),
            (
                "filesystem_device",
                json!(exact.map(|file| file.filesystem_device)),
            ),
        ] {
            value.insert(name.into(), field);
        }
        Ok(Value::Object(value))
    }

    fn table(
        fixture: &Fixture,
        name: &str,
        fields: Vec<FieldRef>,
        rows: &impl Serialize,
        split: bool,
    ) -> TestResult {
        let schema = Arc::new(Schema::new(fields));
        let batch = serde_arrow::to_record_batch(schema.fields(), rows)?;
        let partitions = if split && batch.num_rows() > 1 {
            let cut = batch.num_rows() / 2;
            vec![
                vec![batch.slice(cut, batch.num_rows() - cut)],
                vec![batch.slice(0, cut)],
            ]
        } else {
            vec![vec![batch]]
        };
        fixture
            .context
            .register_table(name, Arc::new(MemTable::try_new(schema, partitions)?))?;
        Ok(())
    }

    async fn query(&self, split: bool) -> TestResult<RecordBatch> {
        self.query_scope(
            split,
            "",
            "SELECT * FROM input_events",
            "SELECT * FROM input_contexts",
        )
        .await
    }

    fn fixture(&self, split: bool) -> TestResult<Fixture> {
        let fixture = Fixture::new()?;
        let canonical = &araphor_data::AnalysisStore::table_schemas()["events"];
        let events = self
            .records
            .iter()
            .map(Self::event)
            .collect::<TestResult<Vec<_>>>()?;
        Self::table(
            &fixture,
            "input_events",
            EVENT_FIELDS
                .iter()
                .map(|name| canonical.field_with_name(name).cloned().map(Arc::new))
                .collect::<std::result::Result<_, _>>()?,
            &events,
            split,
        )?;
        let id = Record::port().schema.field(0).data_type().clone();
        let mut bindings = Vec::<FieldRef>::from_samples(
            &Recorded::new(1).contexts,
            TracingOptions::default().strings_as_large_utf8(false),
        )?;
        for field in &mut bindings {
            let datatype = match field.name().as_str() {
                "record_id" => Some(id.clone()),
                "process_instance_id" | "entry_instance_id" | "binding_id" => {
                    Some(DataType::Binary)
                }
                _ => None,
            };
            if let Some(datatype) = datatype {
                *field = Arc::new(Field::new(field.name(), datatype, false));
            }
        }
        Self::table(&fixture, "input_contexts", bindings, &self.contexts, split)?;
        let mut ranges = Vec::new();
        for range in &self.coverage {
            let mut row = serde_json::to_value(range)?
                .as_object()
                .ok_or("range object")?
                .clone();
            let stream = row.remove("stream").ok_or("range stream")?;
            row.extend(stream.as_object().ok_or("range stream object")?.clone());
            ranges.push(row);
        }
        let mut fields: Vec<FieldRef> = [
            "tenant_id",
            "node_id",
            "node_boot_id",
            "label_epoch",
            "source_id",
            "source_epoch",
            "cpu_id",
        ]
        .iter()
        .map(|name| canonical.field_with_name(name).cloned().map(Arc::new))
        .collect::<std::result::Result<_, _>>()?;
        fields.extend(
            [
                "first_cursor",
                "last_cursor",
                "expected_records",
                "coverage_revision",
            ]
            .iter()
            .map(|name| Arc::new(Field::new(*name, DataType::UInt64, false))),
        );
        fields.extend([
            Arc::new(Field::new("coverage_interval_id", DataType::Binary, false)),
            Arc::new(Field::new("state", DataType::Utf8, false)),
            Arc::new(Field::new(
                "gap_reasons",
                DataType::List(Arc::new(Field::new("item", DataType::Utf8, false))),
                false,
            )),
        ]);
        Self::table(&fixture, "input_ranges", fields, &ranges, split)?;
        Self::table(
            &fixture,
            "input_exclusions",
            vec![
                Arc::new(Field::new("record_id", id.clone(), false)),
                Arc::new(Field::new("reason", DataType::Utf8, false)),
            ],
            &self.exclusions,
            split,
        )?;
        let lifecycle: Vec<_> = self.lifecycle.iter().map(FlatLifecycle::from).collect();
        Self::table(
            &fixture,
            "input_lifecycle",
            vec![
                Arc::new(Field::new("case", DataType::Utf8, false)),
                Arc::new(Field::new("state", DataType::Utf8, false)),
                Arc::new(Field::new(
                    "records",
                    DataType::List(Arc::new(Field::new("item", id, false))),
                    false,
                )),
                Arc::new(Field::new("reason", DataType::Utf8, true)),
            ],
            &lifecycle,
            split,
        )?;
        Self::table(
            &fixture,
            "input_metadata",
            vec![
                Arc::new(Field::new("tenant_id", DataType::Binary, false)),
                Arc::new(Field::new("source_revision", DataType::Utf8, false)),
                Arc::new(Field::new("proof_kind", DataType::Utf8, false)),
            ],
            &self.metadata,
            false,
        )?;
        Ok(fixture)
    }

    async fn query_scope(
        &self,
        split: bool,
        outer: &str,
        records: &str,
        contexts: &str,
    ) -> TestResult<RecordBatch> {
        let fixture = self.fixture(split)?;
        let records = native_frame(
            &fixture.context,
            &format!("{outer} SELECT * FROM ({records}) AS input_records"),
        )
        .await?;
        let contexts = native_frame(
            &fixture.context,
            &format!("{outer} SELECT * FROM ({contexts}) AS input_contexts"),
        )
        .await?;
        fixture
            .context
            .register_table("records", records.into_view())?;
        fixture
            .context
            .register_table("contexts", contexts.into_view())?;
        for (name, source) in [
            ("ranges", "input_ranges"),
            ("exclusions", "input_exclusions"),
            ("lifecycle", "input_lifecycle"),
            ("metadata", "input_metadata"),
        ] {
            let frame = native_frame(&fixture.context, &format!("SELECT * FROM {source}")).await?;
            fixture.context.register_table(name, frame.into_view())?;
        }
        let dataframe = native_frame(&fixture.context, RECORDED_SNAPSHOT_SQL).await?;
        dataframe.logical_plan().apply(|plan| {
            assert!(!matches!(plan, LogicalPlan::Extension(_)));
            Ok(TreeNodeRecursion::Continue)
        })?;
        let schema = Arc::new(dataframe.schema().as_arrow().clone());
        let physical = dataframe.create_physical_plan().await?;
        let (mut nodes, mut aggregates) = (0, 0);
        physical.apply(|plan| {
            nodes += 1;
            aggregates += usize::from(plan.name() == "AggregateExec");
            assert!(!plan.name().contains("Discovery") && !plan.name().contains("Package"));
            Ok(TreeNodeRecursion::Continue)
        })?;
        assert!(aggregates > 0);
        eprintln!("recorded_snapshot physical plan: {nodes} nodes, {aggregates} aggregates");
        let batches =
            datafusion::physical_plan::collect(physical, fixture.context.task_ctx()).await?;
        let batch = concat_batches(&schema, &batches)?;
        assert_eq!(batch.num_rows(), 1);
        Ok(batch)
    }
}

#[tokio::test]
async fn recorded_oci_is_native() -> TestResult {
    use std::collections::BTreeMap;

    use araphor_data::{PackageArtifactV1, PackageBundleV1, PackageImplementationV1, SqlModelV1};

    for count in [0, 2] {
        let fixture = Recorded::new(count);
        let tables = fixture.fixture(true)?;
        let native = SessionContext::new();
        let mut ports = Vec::new();
        for name in [
            "events",
            "contexts",
            "ranges",
            "exclusions",
            "lifecycle",
            "metadata",
        ] {
            let name = format!("input_{name}");
            let table = tables.context.table_provider(&name).await?;
            ports.push(sdk::Port::new(&name, table.schema().as_ref().clone()));
            native.register_table(name, table)?;
        }
        let sql = format!(
            "WITH records AS (SELECT * FROM input_events), \
                contexts AS (SELECT * FROM input_contexts), \
                ranges AS (SELECT * FROM input_ranges), \
                exclusions AS (SELECT * FROM input_exclusions), \
                lifecycle AS (SELECT * FROM input_lifecycle), \
                metadata AS (SELECT * FROM input_metadata) \
            SELECT * FROM ({}) AS snapshot",
            RECORDED_SNAPSHOT_SQL
        );
        let frame = native.sql(&sql).await?;
        let schema = Arc::new(frame.schema().as_arrow().clone());
        let artifact = PackageArtifactV1 {
            descriptor: sdk::Package::new(
                "discovery-effects",
                "1",
                vec![sdk::Model::new(
                    "recorded_snapshot",
                    ports,
                    vec![sdk::Port::new("snapshot", schema.as_ref().clone())],
                )],
            ),
            implementations: vec![PackageImplementationV1::Sql {
                export: "recorded_snapshot".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([("snapshot".into(), sql.clone())]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        };
        let bundle = PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        };
        bundle.validate()?;
        let mut restored = PackageBundleV1::from_bytes(&bundle.encode()?)?;
        restored.validate()?;
        assert!(restored.artifacts[0].prepared("recorded_snapshot"));
        let digest = restored.digest()?;
        let PackageImplementationV1::Sql { program, .. } =
            &mut restored.artifacts[0].implementations[0]
        else {
            return Err("SQL artifact absent".into());
        };
        assert_eq!(program.outputs["snapshot"], sql);
        let batches = native
            .sql(&program.outputs["snapshot"])
            .await?
            .collect()
            .await?;
        fixture
            .oracle()?
            .assert_batch(concat_batches(&schema, &batches)?)?;
        program
            .outputs
            .get_mut("snapshot")
            .ok_or("SQL output absent")?
            .push('\n');
        assert_ne!(restored.digest()?, digest);

        let previous = native
            .deregister_table("input_metadata")?
            .ok_or("metadata absent")?;
        native.register_table(
            "input_metadata",
            Arc::new(MemTable::try_new(
                previous.schema(),
                vec![vec![RecordBatch::new_empty(previous.schema())]],
            )?),
        )?;
        let error = native.sql(&sql).await?.collect().await.unwrap_err();
        assert!(
            error
                .to_string()
                .to_ascii_lowercase()
                .contains("discovery recorded input: metadata"),
            "{error}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn recorded_snapshot_matches_oracle() -> TestResult {
    let mut fixture = Recorded::new(12);
    fixture
        .contexts
        .retain(|context| context.record_id.durable_cursor != 11);
    fixture.exclusions.push(Disposition {
        record_id: fixture.records[11].id.clone(),
        reason: "OPERATOR_EXCLUDED".into(),
    });
    fixture.records.push(fixture.records[0].clone());
    fixture.contexts.push(fixture.contexts[0].clone());
    fixture.lifecycle = vec![
        Lifecycle {
            case: Case::Startup,
            state: State::Recorded {
                records: vec![fixture.records[1].id.clone(), fixture.records[0].id.clone()],
            },
        },
        Lifecycle {
            case: Case::Startup,
            state: State::Recorded {
                records: vec![fixture.records[0].id.clone()],
            },
        },
        Lifecycle {
            case: Case::Probes,
            state: State::Declared {
                reason: "DECLARED_PROBE".into(),
            },
        },
        Lifecycle {
            case: Case::Restart,
            state: State::NotApplicable {
                reason: "NO_RESTART".into(),
            },
        },
        Lifecycle {
            case: Case::Rollout,
            state: State::Unsupported {
                reason: "NO_ROLLOUT_SOURCE".into(),
            },
        },
    ];
    fixture.records.reverse();
    let expected = fixture.oracle()?;
    assert_eq!(
        (
            expected.accepted_records,
            expected.included_records,
            expected.unresolved_records,
            expected.excluded_records,
            expected.duplicate_deliveries
        ),
        (12, 10, 1, 1, 1)
    );
    assert_eq!(
        expected.atoms[0]
            .evidence_sample
            .iter()
            .map(|id| id.durable_cursor)
            .collect::<Vec<_>>(),
        (1..=8).collect::<Vec<_>>()
    );
    expected.assert_batch(fixture.query(false).await?)?;
    expected.assert_batch(fixture.query(true).await?)?;
    Ok(())
}

#[tokio::test]
async fn recorded_empty_and_coverage() -> TestResult {
    let empty = Recorded::new(0);
    empty.oracle()?.assert_batch(empty.query(true).await?)?;
    for temporal in [0, 1, 2] {
        let mut fixture = Recorded::new(2);
        fixture.records[0].temporal = temporal;
        fixture.coverage[0].expected_records = 3;
        fixture.coverage[0].last_cursor = 3;
        let expected = fixture.oracle()?;
        assert_eq!(expected.coverage[0].state, CoverageState::Gapped);
        assert!(expected.coverage[0]
            .gap_reasons
            .iter()
            .any(|reason| reason == "INPUT_RANGE_INCOMPLETE"));
        expected.assert_batch(fixture.query(true).await?)?;
    }
    Ok(())
}

#[tokio::test]
async fn recorded_sources_and_file_objects() -> TestResult {
    let mut fixture = Recorded::new(2);
    fixture.metadata[0].proof_kind = Proof::ObservedRuntime;
    for record in &mut fixture.records {
        record.source = Some(builtin::Lifetime {
            process: vec![1; 16],
            entry: vec![2; 16],
            binding: vec![3; 16],
            role: 1,
            state: 1,
            rule: 1,
            sequence: record.original_sequence.ok_or("sequence absent")?,
        });
        record.effect.exact_file_object = Some(builtin::DiscoveryFileObjectV1 {
            profile_generation_ref_id: record.generation.ok_or("generation absent")?,
            mount_id_unique: 9_007_199_254_740_999,
            inode: 3,
            inode_generation: 4,
            mount_namespace_inode: 5,
            filesystem_device: 6,
        });
    }
    let mut foreign = fixture.records[0].clone();
    foreign.id.stream.source_id = [8; 16];
    foreign.id.cpu_id = 0;
    foreign.effect.decision = 0;
    foreign.effect.kernel_result = 0;
    let mut binding = fixture.contexts[0].clone();
    binding.record_id = foreign.id.clone();
    let mut range = fixture.coverage[0].clone();
    range.stream = foreign.id.stream.clone();
    range.cpu_id = 0;
    range.last_cursor = 1;
    range.expected_records = 1;
    fixture.records.push(foreign);
    fixture.contexts.push(binding);
    fixture.coverage.push(range);
    let expected = fixture.oracle()?;
    assert_eq!(expected.atoms.len(), 2);
    expected.assert_batch(fixture.query(true).await?)?;
    Ok(())
}

#[tokio::test]
async fn recorded_coverage_boundaries() -> TestResult {
    for state in [
        CoverageState::Closed,
        CoverageState::Unknown,
        CoverageState::Gapped,
    ] {
        let mut fixture = Recorded::new(4);
        fixture.coverage[0].last_cursor = 2;
        fixture.coverage[0].expected_records = 2;
        let mut range = fixture.coverage[0].clone();
        range.first_cursor = 3;
        range.last_cursor = 4;
        range.state = state;
        range.gap_reasons = vec!["SECOND_RANGE".into()];
        fixture.coverage.push(range);
        let expected = fixture.oracle()?;
        assert_eq!(expected.coverage.len(), 1);
        assert_eq!(expected.coverage[0].state, state);
        assert_eq!(expected.coverage[0].expected_records, 4);
        expected.assert_batch(fixture.query(true).await?)?;
    }
    let mut fixture = Recorded::new(2);
    for (index, record) in fixture.records.iter_mut().enumerate() {
        record.id.durable_cursor = u64::MAX - 1 + index as u64;
        fixture.contexts[index].record_id = record.id.clone();
    }
    fixture.coverage[0].first_cursor = u64::MAX - 1;
    fixture.coverage[0].last_cursor = u64::MAX;
    fixture.oracle()?.assert_batch(fixture.query(true).await?)?;
    Ok(())
}

#[tokio::test]
async fn recorded_preserves_caller_ctes() -> TestResult {
    let fixture = Recorded::new(1);
    let expected = fixture.oracle()?;
    for (outer, records) in [
        (
            "WITH __discovery_cte_records AS (SELECT * FROM input_events)",
            "SELECT * FROM __discovery_cte_records",
        ),
        (
            "WITH __discovery_cte_records AS (SELECT 42 AS unused)",
            "SELECT * FROM input_events",
        ),
        (
            "WITH records AS (SELECT * FROM input_events)",
            "WITH __discovery_cte_records AS (SELECT * FROM records) \
                SELECT caller.* FROM __discovery_cte_records AS caller",
        ),
    ] {
        expected.assert_batch(
            fixture
                .query_scope(false, outer, records, "SELECT * FROM input_contexts")
                .await?,
        )?;
    }
    Ok(())
}

#[tokio::test]
async fn recorded_rejects_null_keys() -> TestResult {
    let fixture = Recorded::new(1);
    for (records, contexts) in [
        (
            "SELECT * REPLACE(arrow_cast(NULL, 'Binary') AS exact_object_id) FROM input_events",
            "SELECT * FROM input_contexts",
        ),
        (
            "SELECT * FROM input_events",
            "SELECT * REPLACE(arrow_cast(NULL, 'UInt32') AS role_id) FROM input_contexts",
        ),
    ] {
        let error = fixture
            .query_scope(false, "", records, contexts)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .to_ascii_lowercase()
                .contains("discovery recorded input"),
            "{error}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn recorded_metadata_is_single() -> TestResult {
    for count in [0, 2] {
        let mut fixture = Recorded::new(1);
        fixture.metadata.resize_with(count, || Metadata {
            tenant_id: [1; 16],
            source_revision: "recorded-test",
            proof_kind: Proof::RecordedInput,
        });
        let error = fixture.query(false).await.unwrap_err();
        assert!(error.to_string().contains("metadata"), "{error}");
    }
    Ok(())
}

#[tokio::test]
async fn recorded_unresolved_precedence() -> TestResult {
    for case in [
        "missing context",
        "generation",
        "object",
        "operation",
        "argument",
        "decision",
        "lifetime",
        "contradictory",
    ] {
        let mut fixture = Recorded::new(1);
        fixture.metadata[0].proof_kind = Proof::ObservedRuntime;
        fixture.records[0].source = Some(builtin::Lifetime {
            process: vec![1; 16],
            entry: vec![2; 16],
            binding: vec![3; 16],
            role: 1,
            state: 1,
            rule: 1,
            sequence: 101,
        });
        match case {
            "missing context" => fixture.contexts.clear(),
            "generation" => fixture.records[0].generation = None,
            "object" => fixture.records[0].effect.exact_object_id.clear(),
            "operation" => fixture.records[0].effect.operation = 2,
            "argument" => fixture.records[0].effect.operation_argument = Some(7),
            "decision" => fixture.records[0].source = None,
            "lifetime" => fixture.records[0]
                .source
                .as_mut()
                .ok_or("lifetime absent")?
                .process
                .clear(),
            "contradictory" => {
                fixture.records[0]
                    .source
                    .as_mut()
                    .ok_or("lifetime absent")?
                    .binding = vec![9; 16]
            }
            _ => unreachable!("unresolved fixture"),
        }
        let expected = fixture.oracle()?;
        assert_eq!(expected.unresolved_records, 1, "{case}");
        expected.assert_batch(fixture.query(false).await?)?;
    }
    Ok(())
}

#[tokio::test]
async fn recorded_rejects_relational_conflicts() -> TestResult {
    for case in [
        "bytes",
        "context",
        "orphan context",
        "exclusion",
        "orphan exclusion",
        "range",
        "overlap",
        "lifecycle",
    ] {
        let mut fixture = Recorded::new(1);
        match case {
            "bytes" => {
                let mut record = fixture.records[0].clone();
                record.bytes.to_mut().push(0);
                fixture.records.push(record);
            }
            "context" => {
                let mut context = fixture.contexts[0].clone();
                context.image_digest.push_str("-changed");
                fixture.contexts.push(context);
            }
            "orphan context" => fixture.contexts[0].record_id.durable_cursor = 99,
            "exclusion" => {
                fixture.exclusions = ["FIRST", "SECOND"]
                    .into_iter()
                    .map(|reason| Disposition {
                        record_id: fixture.records[0].id.clone(),
                        reason: reason.into(),
                    })
                    .collect()
            }
            "orphan exclusion" => {
                let mut id = fixture.records[0].id.clone();
                id.durable_cursor = 99;
                fixture.exclusions.push(Disposition {
                    record_id: id,
                    reason: "ORPHAN".into(),
                });
            }
            "range" => fixture.coverage.clear(),
            "overlap" => fixture.coverage.push(fixture.coverage[0].clone()),
            "lifecycle" => {
                fixture.lifecycle = ["FIRST", "SECOND"]
                    .into_iter()
                    .map(|reason| Lifecycle {
                        case: Case::Startup,
                        state: State::Declared {
                            reason: reason.into(),
                        },
                    })
                    .collect()
            }
            _ => unreachable!("conflict fixture"),
        }
        assert!(fixture.oracle().is_err(), "oracle {case}");
        assert!(fixture.query(true).await.is_err(), "native {case}");
    }
    let mut fixture = Recorded::new(0);
    fixture.metadata.clear();
    assert!(fixture.query(false).await.is_err());
    Ok(())
}

#[tokio::test]
async fn recorded_sparse_counts_survive() -> TestResult {
    for count in [0, 1, 2, 3, 10_000] {
        let mut fixture = Recorded::new(2);
        fixture.records[1].id.durable_cursor = 10_000;
        fixture.contexts[1].record_id = fixture.records[1].id.clone();
        fixture.coverage[0].last_cursor = 10_000;
        fixture.coverage[0].expected_records = count;
        fixture.coverage[0].state = CoverageState::Unknown;
        fixture.coverage[0].gap_reasons = vec!["RECORDED_UNKNOWN".into()];
        let expected = fixture.oracle()?;
        assert_eq!(expected.accepted_records, 2);
        assert_eq!(expected.coverage.len(), 1);
        let range = &expected.coverage[0];
        assert_eq!(range.stream, fixture.coverage[0].stream);
        assert_eq!(range.cpu_id, fixture.coverage[0].cpu_id);
        assert_eq!((range.first_cursor, range.last_cursor), (1, 10_000));
        assert_eq!(range.expected_records, count);
        assert_eq!(
            range.coverage_revision,
            fixture.coverage[0].coverage_revision
        );
        assert_eq!(
            range.coverage_interval_id,
            fixture.coverage[0].coverage_interval_id
        );
        assert_eq!(
            range.state,
            if count == 2 {
                CoverageState::Unknown
            } else {
                CoverageState::Gapped
            }
        );
        assert!(range.gap_reasons.contains(&"RECORDED_UNKNOWN".into()));
        assert_eq!(
            range.gap_reasons.contains(&"INPUT_RANGE_INCOMPLETE".into()),
            count != 2
        );
        expected.assert_batch(fixture.query(true).await?)?;
    }
    Ok(())
}

#[tokio::test]
async fn recorded_preserves_empty_ranges() -> TestResult {
    let mut fixture = Recorded::new(2);
    fixture.records[0].id.durable_cursor = 2;
    fixture.records[1].id.durable_cursor = 4;
    fixture.records[1].id.stream.node_id = "zz-other-node".into();
    for (record, context) in fixture.records.iter().zip(&mut fixture.contexts) {
        context.record_id = record.id.clone();
    }
    fixture.coverage[0].last_cursor = 2;
    fixture.coverage[0].expected_records = 1;
    let mut other = fixture.coverage[0].clone();
    other.stream = fixture.records[1].id.stream.clone();
    other.last_cursor = 4;
    let mut empty = fixture.coverage[0].clone();
    empty.cpu_id += 1;
    empty.last_cursor = 8;
    empty.expected_records = 3;
    empty.state = CoverageState::Closed;
    fixture.coverage.extend([other, empty.clone()]);
    fixture.records.reverse();
    fixture.contexts.reverse();
    fixture.coverage.reverse();
    let expected = fixture.oracle()?;
    assert_eq!(expected.accepted_records, 2);
    assert_eq!(expected.coverage.len(), 3);
    let mut qualified = empty.clone();
    qualified.state = CoverageState::Gapped;
    qualified.gap_reasons.push("INPUT_RANGE_INCOMPLETE".into());
    assert_eq!(
        expected
            .coverage
            .iter()
            .filter(|range| **range == qualified)
            .count(),
        1
    );
    for original in fixture.coverage.iter().filter(|range| **range != empty) {
        assert!(expected.coverage.contains(original));
    }
    expected.assert_batch(fixture.query(true).await?)?;
    fixture.records.clear();
    fixture.contexts.clear();
    let empty = fixture.oracle()?;
    assert_eq!(empty.accepted_records, 0);
    assert_eq!(empty.coverage.len(), 3);
    for original in &fixture.coverage {
        let mut qualified = original.clone();
        qualified.state = CoverageState::Gapped;
        qualified.gap_reasons.push("INPUT_RANGE_INCOMPLETE".into());
        assert_eq!(
            empty
                .coverage
                .iter()
                .filter(|range| **range == qualified)
                .count(),
            1
        );
    }
    empty.assert_batch(fixture.query(true).await?)?;
    Ok(())
}
