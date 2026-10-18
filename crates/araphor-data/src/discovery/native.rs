use std::sync::{Arc, LazyLock};

use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use serde_arrow::schema::{SchemaLike as _, TracingOptions};

use super::*;
use crate::{DiscoveryInvalidSnafu, EvidenceIntakeIdentityV1, Result};

// serde_arrow uses "element" for list items. Use Arrow's default name for native SQL.
fn native_field(field: &sdk::Field) -> sdk::Field {
    let data_type = match field.data_type() {
        sdk::DataType::List(item) => sdk::DataType::List(Arc::new(
            native_field(item).with_name(sdk::Field::LIST_FIELD_DEFAULT_NAME),
        )),
        sdk::DataType::Struct(fields) => sdk::DataType::Struct(
            fields
                .iter()
                .map(|child| Arc::new(native_field(child)))
                .collect(),
        ),
        data_type => data_type.clone(),
    };
    field.clone().with_data_type(data_type)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryLifecycleRowV1 {
    pub case: DiscoveryLifecycleCaseV1,
    pub state: String,
    pub records: Vec<DiscoveryRecordIdV1>,
    pub reason: Option<String>,
}

impl From<DiscoveryLifecycleEntryV1> for DiscoveryLifecycleRowV1 {
    fn from(value: DiscoveryLifecycleEntryV1) -> Self {
        let (state, records, reason) = match value.state {
            DiscoveryLifecycleStateV1::Recorded { records } => ("RECORDED", records, None),
            DiscoveryLifecycleStateV1::Declared { reason } => {
                ("DECLARED", Vec::new(), Some(reason))
            }
            DiscoveryLifecycleStateV1::Missing => ("MISSING", Vec::new(), None),
            DiscoveryLifecycleStateV1::NotApplicable { reason } => {
                ("NOT_APPLICABLE", Vec::new(), Some(reason))
            }
            DiscoveryLifecycleStateV1::Unsupported { reason } => {
                ("UNSUPPORTED", Vec::new(), Some(reason))
            }
        };
        Self {
            case: value.case,
            state: state.into(),
            records,
            reason,
        }
    }
}

impl From<&DiscoveryLifecycleEntryV1> for DiscoveryLifecycleRowV1 {
    fn from(value: &DiscoveryLifecycleEntryV1) -> Self {
        value.clone().into()
    }
}

impl TryFrom<DiscoveryLifecycleRowV1> for DiscoveryLifecycleEntryV1 {
    type Error = crate::Error;

    fn try_from(value: DiscoveryLifecycleRowV1) -> Result<Self> {
        let state = match (value.state.as_str(), value.records.is_empty(), value.reason) {
            ("RECORDED", false, None) => DiscoveryLifecycleStateV1::Recorded {
                records: value.records,
            },
            ("DECLARED", true, Some(reason)) => DiscoveryLifecycleStateV1::Declared { reason },
            ("MISSING", true, None) => DiscoveryLifecycleStateV1::Missing,
            ("NOT_APPLICABLE", true, Some(reason)) => {
                DiscoveryLifecycleStateV1::NotApplicable { reason }
            }
            ("UNSUPPORTED", true, Some(reason)) => {
                DiscoveryLifecycleStateV1::Unsupported { reason }
            }
            _ => {
                return DiscoveryInvalidSnafu {
                    field: "native lifecycle state",
                }
                .fail()
            }
        };
        Ok(Self {
            case: value.case,
            state,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySnapshotRowV1 {
    pub schema_version: u32,
    #[serde(with = "serde_bytes")]
    pub tenant_id: [u8; 16],
    pub source_revision: String,
    pub proof_kind: DiscoveryProofKindV1,
    pub accepted_records: u64,
    pub included_records: u64,
    pub unresolved_records: u64,
    pub excluded_records: u64,
    pub atoms: Vec<BehaviorAtomV1>,
    pub coverage: Vec<DiscoveryCoverageV1>,
    pub unresolved: Vec<DiscoveryUnresolvedV1>,
    pub excluded: Vec<DiscoveryUnresolvedV1>,
    pub lifecycle: Vec<DiscoveryLifecycleRowV1>,
}

impl DiscoverySnapshotRowV1 {
    pub fn schema() -> &'static sdk::Schema {
        #[expect(
            clippy::expect_used,
            reason = "The native schema comes from one complete internal typed sample."
        )]
        static SCHEMA: LazyLock<sdk::Schema> = LazyLock::new(|| {
            let mut options = TracingOptions::default()
                .strings_as_large_utf8(false)
                .sequence_as_large_list(false)
                .bytes_as_large_binary(false)
                .enums_without_data_as_strings(true);
            for path in [
                "proof_kind",
                "atoms.element.key.proof_kind",
                "atoms.element.key.physical_result",
                "coverage.element.state",
                "lifecycle.element.case",
            ] {
                options = options
                    .overwrite(
                        path,
                        sdk::Field::new(
                            path.rsplit('.').next().unwrap_or(path),
                            sdk::DataType::Utf8,
                            false,
                        ),
                    )
                    .expect("the discovery enum field has a native Utf8 schema");
            }
            sdk::Schema::new(
                Vec::<std::sync::Arc<sdk::Field>>::from_samples(
                    [DiscoverySnapshotRowV1::schema_sample()],
                    options,
                )
                .expect("the discovery snapshot has a native Arrow schema")
                .into_iter()
                .map(|field| native_field(&field))
                .collect::<Vec<_>>(),
            )
        });
        &SCHEMA
    }

    // Type tracing supplies empty bytes, which fixed IDs reject. Populate each nested type once.
    fn schema_sample() -> Self {
        let stream = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: String::new(),
            node_boot_id: [2; 16],
            label_epoch: 0,
            source_id: [3; 16],
            source_epoch: 0,
        };
        let record = DiscoveryRecordIdV1 {
            stream: stream.clone(),
            cpu_id: 0,
            durable_cursor: 0,
        };
        let unresolved = DiscoveryUnresolvedV1 {
            record_id: record.clone(),
            reason: String::new(),
        };
        Self {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            tenant_id: stream.tenant_id,
            source_revision: String::new(),
            proof_kind: DiscoveryProofKindV1::ObservedRuntime,
            accepted_records: 0,
            included_records: 0,
            unresolved_records: 0,
            excluded_records: 0,
            atoms: vec![BehaviorAtomV1 {
                key: BehaviorAtomKeyV1 {
                    stream: stream.clone(),
                    cpu_id: 0,
                    subject_revision: String::new(),
                    image_digest: String::new(),
                    configuration_digest: String::new(),
                    process_instance_id: [4; 16],
                    entry_instance_id: [5; 16],
                    binding_id: [6; 16],
                    role_id: 0,
                    state_id: 0,
                    entry_rule_id: 0,
                    catalog_revision: 0,
                    static_key: DiscoveryPolicyKeyV1 {
                        workload_selector_id: String::new(),
                        protected_scope_id: String::new(),
                        execution_set_id: String::new(),
                        entry_kind: String::new(),
                        role_id: String::new(),
                        process_state_id: String::new(),
                        effect_family: 0,
                        operation_id: String::new(),
                        operation: 0,
                        operation_argument: 0,
                        argument_wildcard: false,
                        object_selector: String::new(),
                        binding_lifecycle: String::new(),
                    },
                    policy_revision: DiscoveryPolicyRevisionV1 {
                        profile_id: String::new(),
                        profile_version: 0,
                        source_revision_id: String::new(),
                        signed_profile_digest: String::new(),
                    },
                    generation: 0,
                    coverage_interval_id: [7; 16],
                    temporal_coverage: 0,
                    effect: DiscoveryEffectKeyV1 {
                        task_cookie: 0,
                        target_task_cookie: Some(0),
                        process_lineage_id: Vec::new(),
                        authority_domain_id: Vec::new(),
                        execution_set_id: Vec::new(),
                        exact_object_id: Vec::new(),
                        destination_id: 0,
                        policy_rule_id: 0,
                        reason: 0,
                        decision: 0,
                        effect_family: 0,
                        operation: 0,
                        operation_argument: Some(0),
                        configured_errno: 0,
                        kernel_result: 0,
                        exact_file_object: Some(DiscoveryFileObjectV1 {
                            profile_generation_ref_id: 0,
                            mount_id_unique: 0,
                            inode: 0,
                            inode_generation: 0,
                            mount_namespace_inode: 0,
                            filesystem_device: 0,
                        }),
                    },
                    physical_result: DiscoveryPhysicalResultV1::Prevented,
                    proof_kind: DiscoveryProofKindV1::ObservedRuntime,
                },
                count: 0,
                first_cursor: 0,
                last_cursor: 0,
                evidence_sample: vec![record.clone()],
            }],
            coverage: vec![DiscoveryCoverageV1 {
                stream,
                cpu_id: 0,
                first_cursor: 0,
                last_cursor: 0,
                expected_records: 0,
                coverage_revision: 0,
                coverage_interval_id: [8; 16],
                state: DiscoveryCoverageStateV1::Healthy,
                gap_reasons: vec![String::new()],
            }],
            unresolved: vec![unresolved.clone()],
            excluded: vec![unresolved],
            lifecycle: vec![DiscoveryLifecycleRowV1 {
                case: DiscoveryLifecycleCaseV1::Startup,
                state: String::new(),
                records: vec![record],
                reason: Some(String::new()),
            }],
        }
    }

    pub fn from_snapshot(snapshot: BehaviorSnapshotV1) -> Result<Self> {
        snapshot.validate()?;
        Ok(Self {
            schema_version: snapshot.schema_version,
            tenant_id: snapshot.tenant_id,
            source_revision: snapshot.source_revision,
            proof_kind: snapshot.proof_kind,
            accepted_records: snapshot.accepted_records,
            included_records: snapshot.included_records,
            unresolved_records: snapshot.unresolved_records,
            excluded_records: snapshot.excluded_records,
            atoms: snapshot.atoms,
            coverage: snapshot.coverage,
            unresolved: snapshot.unresolved,
            excluded: snapshot.excluded,
            lifecycle: snapshot.lifecycle.into_iter().map(Into::into).collect(),
        })
    }

    pub fn into_snapshot(self) -> Result<BehaviorSnapshotV1> {
        let snapshot = BehaviorSnapshotV1 {
            schema_version: self.schema_version,
            tenant_id: self.tenant_id,
            source_revision: self.source_revision,
            proof_kind: self.proof_kind,
            accepted_records: self.accepted_records,
            included_records: self.included_records,
            unresolved_records: self.unresolved_records,
            excluded_records: self.excluded_records,
            atoms: self.atoms,
            coverage: self.coverage,
            unresolved: self.unresolved,
            excluded: self.excluded,
            lifecycle: self
                .lifecycle
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryStateRowV1 {
    #[serde(with = "serde_bytes")]
    pub tenant_id: [u8; 16],
    pub node_id: String,
    #[serde(with = "serde_bytes")]
    pub node_boot_id: [u8; 16],
    pub label_epoch: u64,
    #[serde(with = "serde_bytes")]
    pub source_id: [u8; 16],
    pub source_epoch: u64,
    pub cpu_id: u32,
    pub contiguous_cursor: u64,
    pub retained_floor: u64,
    pub source_coverage_revision: u64,
    pub method_version: u64,
    pub processor_present: bool,
    pub processor_class: Option<String>,
    pub start_cursor: Option<u64>,
    pub consumed_cursor: Option<u64>,
    pub resume_floor: Option<u64>,
    pub context_revision: Option<u64>,
    pub retired: Option<bool>,
    pub current_result_id: Option<String>,
    pub result_commit_revision: Option<u64>,
    pub interval_id: Option<String>,
    pub profile_revision: Option<u64>,
    pub facts_revision: Option<u64>,
    pub coverage_revision: Option<u64>,
    pub created_utc_ns: Option<u64>,
    pub updated_utc_ns: Option<u64>,
    pub sealed: Option<bool>,
    pub input_bytes: Option<u64>,
    pub incomplete: Option<bool>,
    pub gaps: Option<Vec<crate::AnalysisGapV1>>,
    pub context_refs: Option<Vec<crate::AnalysisContextRefV1>>,
    pub snapshot: Option<DiscoverySnapshotRowV1>,
}

impl DiscoveryStateRowV1 {
    pub fn schema() -> &'static sdk::Schema {
        #[expect(
            clippy::expect_used,
            reason = "The native schema comes from one complete internal typed sample."
        )]
        static SCHEMA: LazyLock<sdk::Schema> = LazyLock::new(|| {
            sdk::Schema::new(
                Vec::<std::sync::Arc<sdk::Field>>::from_samples(
                    [DiscoveryStateRowV1::schema_sample()],
                    TracingOptions::default()
                        .strings_as_large_utf8(false)
                        .sequence_as_large_list(false)
                        .bytes_as_large_binary(false)
                        .enums_without_data_as_strings(true)
                        .overwrite(
                            "snapshot",
                            sdk::Field::new(
                                "snapshot",
                                sdk::DataType::Struct(
                                    DiscoverySnapshotRowV1::schema().fields().clone(),
                                ),
                                true,
                            ),
                        )
                        .expect("the state snapshot uses its nullable native schema"),
                )
                .expect("the discovery state read row has a native Arrow schema")
                .into_iter()
                .map(|field| native_field(&field))
                .collect::<Vec<_>>(),
            )
        });
        &SCHEMA
    }

    fn schema_sample() -> Self {
        Self {
            tenant_id: [1; 16],
            node_id: String::new(),
            node_boot_id: [2; 16],
            label_epoch: 0,
            source_id: [3; 16],
            source_epoch: 0,
            cpu_id: 0,
            contiguous_cursor: 0,
            retained_floor: 0,
            source_coverage_revision: 0,
            method_version: 0,
            processor_present: false,
            processor_class: Some(String::new()),
            start_cursor: Some(0),
            consumed_cursor: Some(0),
            resume_floor: Some(0),
            context_revision: Some(0),
            retired: Some(false),
            current_result_id: Some(String::new()),
            result_commit_revision: Some(0),
            interval_id: Some(String::new()),
            profile_revision: Some(0),
            facts_revision: Some(0),
            coverage_revision: Some(0),
            created_utc_ns: Some(0),
            updated_utc_ns: Some(0),
            sealed: Some(false),
            input_bytes: Some(0),
            incomplete: Some(false),
            gaps: Some(vec![crate::AnalysisGapV1 {
                first_cursor: 0,
                last_cursor: 0,
                commit_revision: 0,
            }]),
            context_refs: Some(vec![crate::AnalysisContextRefV1 {
                key: crate::AnalysisContextKeyV1 {
                    tenant_id: [1; 16],
                    owner_id: String::new(),
                    entity_key: Vec::new(),
                    lifetime_key: Vec::new(),
                    owner_revision: 0,
                },
                commit_revision: 0,
            }]),
            snapshot: Some(DiscoverySnapshotRowV1::schema_sample()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn native_discovery_schema_roundtrip() -> TestResult {
        let row = DiscoveryStateRowV1::schema_sample();
        let schema = DiscoveryStateRowV1::schema();
        let batch = serde_arrow::to_record_batch(schema.fields(), &[&row])?;
        let decoded = serde_arrow::from_record_batch::<Vec<DiscoveryStateRowV1>>(&batch)?;
        assert_eq!(decoded, [row]);
        let snapshot = schema.field_with_name("snapshot")?;
        assert!(snapshot.is_nullable());
        let sdk::DataType::Struct(fields) = snapshot.data_type() else {
            return Err("the native snapshot is not a struct".into());
        };
        assert_eq!(fields, DiscoverySnapshotRowV1::schema().fields());
        for name in ["tenant_id", "node_boot_id", "source_id"] {
            assert_eq!(
                schema.field_with_name(name)?.data_type(),
                &sdk::DataType::Binary
            );
        }
        for field in schema.flattened_fields() {
            if let sdk::DataType::List(item) = field.data_type() {
                assert_eq!(item.name(), sdk::Field::LIST_FIELD_DEFAULT_NAME);
            }
        }
        sdk::Package::new(
            "native-schema",
            "1",
            vec![sdk::Model::new(
                "state",
                Vec::new(),
                vec![
                    sdk::Port::new("snapshot", DiscoverySnapshotRowV1::schema().clone()),
                    sdk::Port::new("state", schema.clone()),
                ],
            )],
        )
        .validate()?;
        Ok(())
    }

    #[test]
    fn native_discovery_schema_nullable() -> TestResult {
        let mut row = DiscoveryStateRowV1::schema_sample();
        row.processor_class = None;
        row.current_result_id = None;
        row.snapshot = None;
        row.context_refs = Some(Vec::new());
        row.gaps = Some(Vec::new());
        let batch = serde_arrow::to_record_batch(DiscoveryStateRowV1::schema().fields(), &[&row])?;
        let decoded = serde_arrow::from_record_batch::<Vec<DiscoveryStateRowV1>>(&batch)?;
        assert_eq!(decoded, [row]);
        Ok(())
    }
}
