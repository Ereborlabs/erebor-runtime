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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FlatLifecycle {
    case: Case,
    state: String,
    records: Vec<RecordId>,
    reason: Option<String>,
}

impl From<&Lifecycle> for FlatLifecycle {
    fn from(value: &Lifecycle) -> Self {
        let (state, records, reason) = match &value.state {
            State::Recorded { records } => ("RECORDED", records.clone(), None),
            State::Declared { reason } => ("DECLARED", Vec::new(), Some(reason.clone())),
            State::Missing => ("MISSING", Vec::new(), None),
            State::NotApplicable { reason } => ("NOT_APPLICABLE", Vec::new(), Some(reason.clone())),
            State::Unsupported { reason } => ("UNSUPPORTED", Vec::new(), Some(reason.clone())),
        };
        Self {
            case: value.case,
            state: state.into(),
            records,
            reason,
        }
    }
}

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
        let limits = Discovery::limits();
        let datasets = vec![
            Record::encode(&self.records)?,
            Rows::encode(
                &Discovery::port::<builtin::Context>("contexts"),
                &contexts,
                limits,
            )?,
            Rows::encode(
                &Discovery::port::<Coverage>("coverage"),
                &self.coverage,
                limits,
            )?,
            Rows::encode(
                &Discovery::port::<Disposition>("exclusions"),
                &self.exclusions,
                limits,
            )?,
            Rows::encode(
                &Discovery::port::<Lifecycle>("lifecycle"),
                &self.lifecycle,
                limits,
            )?,
            Rows::encode(
                &Discovery::port::<bool>("observed"),
                &[self.metadata[0].proof_kind == Proof::ObservedRuntime],
                limits,
            )?,
        ];
        let output = Discovery::evaluate(&sdk::Evaluation {
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
                limits,
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
                    limits,
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

    async fn query_scope(
        &self,
        split: bool,
        outer: &str,
        records: &str,
        contexts: &str,
    ) -> TestResult<RecordBatch> {
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
        let mut bindings =
            Vec::<FieldRef>::from_samples(&Recorded::new(1).contexts, TracingOptions::default())?;
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
        let dataframe = fixture.context.sql(&format!("{outer} SELECT * FROM discovery.recorded_snapshot(
            ({records}), ({contexts}), (SELECT * FROM input_ranges),
            (SELECT * FROM input_exclusions), (SELECT * FROM input_lifecycle), (SELECT * FROM input_metadata))")).await?;
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
            error.to_string().contains("Discovery recorded input"),
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
