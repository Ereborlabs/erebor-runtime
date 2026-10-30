use super::*;

#[test]
fn native_ports_use_fields() -> sdk::Result<()> {
    let ports = [
        Observation::port(),
        Fact::port(),
        Manifest::port(),
        Metadata::port(),
        Subject::port(),
        Relationship::port(),
        Finding::port(),
        SubjectChange::port(),
        SubjectRemoval::port(),
        RelationshipChange::port(),
        RelationshipRemoval::port(),
        FindingChange::port(),
    ];
    assert_eq!(
        Fact::port()
            .schema
            .field_with_name("sensitivity")?
            .data_type(),
        &sdk::DataType::Utf8
    );
    let metadata = Metadata::port();
    assert!(matches!(
        metadata.schema.field_with_name("facts")?.data_type(),
        sdk::DataType::List(child)
            if matches!(child.data_type(), sdk::DataType::Struct(fields)
                if fields.iter().any(|field| field.name() == "sensitivity"
                    && field.data_type() == &sdk::DataType::Utf8))
    ));
    assert!(matches!(
        metadata.schema.field_with_name("package")?.data_type(),
        sdk::DataType::Struct(fields)
            if fields.iter().any(|field| field.name() == "result_states"
                && matches!(field.data_type(), sdk::DataType::List(child)
                    if child.data_type() == &sdk::DataType::Utf8))
    ));
    for port in ports {
        assert!(
            !(port.schema.fields().len() == 1
                && port.schema.field(0).name() == "value"
                && port.schema.field(0).data_type() == &sdk::DataType::Binary)
        );
        sdk::Package::new(
            "native-graph",
            "1",
            vec![sdk::Model::new("read", Vec::new(), vec![port])],
        )
        .validate()?;
    }
    assert!(Observation::decode(&Observation::encode(&[])?)?.is_empty());
    assert!(Fact::decode(&Fact::encode(&[])?)?.is_empty());
    assert!(Manifest::decode(&Manifest::encode(&[])?)?.is_empty());
    assert!(Metadata::decode(&Metadata::encode(&[])?)?.is_empty());
    assert!(Subject::decode(&Subject::encode(&[])?)?.is_empty());
    assert!(Relationship::decode(&Relationship::encode(&[])?)?.is_empty());
    assert!(Finding::decode(&Finding::encode(&[])?)?.is_empty());
    Ok(())
}

#[test]
fn stable_contribution_rows_roundtrip() -> sdk::Result<()> {
    let records = vec![record(7, 11)];
    let facts = facts();
    let anchor = Anchor::from_positions(0, Some(0), &records, &facts)?;
    let subject = SubjectChange {
        anchor: anchor.clone(),
        key: native_subject(),
    };
    assert_eq!(
        SubjectChange::decode(&SubjectChange::encode(std::slice::from_ref(&subject))?)?,
        vec![subject.clone()]
    );
    let subject_removal = SubjectRemoval {
        key: subject.key.clone(),
    };
    assert_eq!(
        SubjectRemoval::decode(&SubjectRemoval::encode(std::slice::from_ref(
            &subject_removal,
        ))?)?,
        vec![subject_removal]
    );
    let key = RelationshipIdentity {
        from: subject.key.clone(),
        to: subject.key,
        edge_type: GraphEdgeTypeV1::TaskInProcess,
        package_id: "HF-PROC-001".into(),
        evidence: records,
        cause: GraphCauseV1::Direct,
    };
    let relationship = RelationshipChange {
        anchor,
        key: key.clone(),
        proof_quality: proof(),
        required_coverage_interval_ids: vec![[3; 16]],
        first_boottime_ns: 1,
        last_boottime_ns: 2,
    };
    assert_eq!(
        RelationshipChange::decode(&RelationshipChange::encode(std::slice::from_ref(
            &relationship,
        ))?)?,
        vec![relationship]
    );
    let removal = RelationshipRemoval { key };
    assert_eq!(
        RelationshipRemoval::decode(&RelationshipRemoval::encode(std::slice::from_ref(
            &removal
        ))?)?,
        vec![removal]
    );
    Ok(())
}

use crate::discovery::{
    DiscoveryEffectKeyV1, DiscoveryFileObjectV1, DiscoveryRecordIdV1, EvidenceIntakeIdentityV1,
};

fn source() -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node".into(),
        node_boot_id: [2; 16],
        label_epoch: 3,
        source_id: [4; 16],
        source_epoch: 5,
    }
}
fn record(cpu: u32, cursor: u64) -> DiscoveryRecordIdV1 {
    DiscoveryRecordIdV1 {
        stream: source(),
        cpu_id: cpu,
        durable_cursor: cursor,
    }
}
fn key() -> AnalysisContextKeyV1 {
    AnalysisContextKeyV1 {
        tenant_id: [1; 16],
        owner_id: "owner".into(),
        entity_key: vec![6],
        lifetime_key: vec![7],
        owner_revision: 8,
    }
}
fn proof() -> ProofQualityV1 {
    ProofQualityV1::kernel_decision(TemporalCoverageV1::Complete)
}
fn subject(authority: GraphSubjectAuthorityV1) -> GraphSubjectKeyV1 {
    GraphSubjectKeyV1 {
        tenant_id: [1; 16],
        authority,
        kind: GraphSubjectKindV1::Process,
        identity: vec![0, 255, 17],
    }
}
fn native_subject() -> GraphSubjectKeyV1 {
    subject(GraphSubjectAuthorityV1::Native {
        node_id: "node".into(),
        node_boot_id: [2; 16],
        label_epoch: 3,
    })
}
fn policy() -> PolicyObservationProvenanceV1 {
    PolicyObservationProvenanceV1 {
        source: source(),
        profile_generation_ref_id: 9,
        observations: vec![record(7, 11)],
        policy_source_revision_id: Some("revision".into()),
        candidate_content_id: Some("candidate".into()),
        target_snapshot_digest: Some("target".into()),
        node_bound_generation_digest: Some("generation".into()),
        activation_acknowledgement: Some(key()),
        state: PolicyProvenanceStateV1::Exact,
        limits: vec!["bound".into()],
    }
}
fn facts() -> Vec<Fact> {
    let proof = proof();
    let values = vec![
        GraphFactValueV1::Policy(policy()),
        GraphFactValueV1::Activation(GraphPolicyActivationV1 {
            tenant_id: "tenant".into(),
            node_id: "node".into(),
            node_boot_id: vec![2; 16],
            label_epoch: 3,
            candidate_content_id: "candidate".into(),
            policy_source_revision_id: "revision".into(),
            target_snapshot_digest: "target".into(),
            state: "ACTIVE".into(),
            node_bound_generation_digest: Some("generation".into()),
            profile_generation_ref_id: Some(9),
            readback_digest: Some("readback".into()),
            probe_result_digest: Some("probe".into()),
            reason_code: Some("ready".into()),
            observed_utc_ns: -10,
        }),
        GraphFactValueV1::Context {
            subject: native_subject(),
            action_id: "action".into(),
            classification: GraphContextActionV1::OutsideAuthority,
            proof_quality: proof,
        },
        GraphFactValueV1::Credential {
            object_id: [12; 16],
            expected_access: true,
            reviewed_policy_revision: "review".into(),
            completion: Some(GraphReadCompletionV1 {
                admission_record: record(7, 11),
                owner: "read-owner".into(),
                completion_id: "read".into(),
                task_cookie: 13,
                process_instance_id: [14; 16],
                object_id: [15; 16],
                file_description_id: "fd".into(),
                path: GraphReadPathV1::IoUring,
                result: -16,
                byte_count: 17,
                credential_lease_id: Some("lease".into()),
                principal_id: Some("principal".into()),
            }),
            proof_quality: proof,
            principal_id: Some("principal".into()),
        },
        GraphFactValueV1::Baseline {
            role_id: 18,
            state_id: 19,
            outside_reviewed_baseline: true,
            reviewed_policy_revision: "review".into(),
        },
        GraphFactValueV1::NativeParent {
            parent: native_subject(),
            child: subject(GraphSubjectAuthorityV1::External {
                authority_id: "external".into(),
            }),
            proof_quality: proof,
        },
        GraphFactValueV1::AuthorityUse {
            authority_id: "authority".into(),
            process_instance_id: Some([20; 16]),
            task_cookie: Some(21),
            credential_object_id: Some([22; 16]),
            socket_object_id: Some([23; 16]),
            request_id: Some("request".into()),
            credential_lease_id: Some("lease".into()),
            principal_id: "principal".into(),
            operation_id: "operation".into(),
            outside_reviewed_behavior: true,
            proof_quality: proof,
            workload_binding: Some(native_subject()),
        },
        GraphFactValueV1::Channel {
            task_cookie: 24,
            process_instance_id: [25; 16],
            socket_object_id: [26; 16],
            authority_id: "authority".into(),
            carried_request_id: "request".into(),
            credential_lease_id: "lease".into(),
            principal_id: "principal".into(),
            operation_id: "operation".into(),
            proof_quality: proof,
        },
        GraphFactValueV1::Kubernetes(KubernetesStageProofV1 {
            cluster_id: "cluster".into(),
            carried_request_id: Some("request".into()),
            audit_id: Some("audit".into()),
            object_uid: Some("object".into()),
            resource_version: Some("version".into()),
            owner_uid: Some("owner".into()),
            pod_uid: Some("pod".into()),
            node_id: Some("node".into()),
            full_container_id: Some("container".into()),
            remote_admission_id: Some("admission".into()),
            proof_quality: proof,
        }),
    ];
    values
        .into_iter()
        .enumerate()
        .map(|(at, value)| Fact {
            record: 0,
            key: AnalysisContextKeyV1 {
                owner_revision: at as u64 + 8,
                ..key()
            },
            sensitivity: if at == 1 {
                ContextSensitivityV1::HostRestricted
            } else {
                ContextSensitivityV1::Tenant
            },
            value,
        })
        .collect()
}
fn package() -> GraphPackageCheckpointV1 {
    GraphPackageCheckpointV1 {
        package_id: "HF-PROC-001".into(),
        package_version: 1,
        required_inputs: vec!["input".into()],
        state: GraphPackageStateV1::Waiting,
        maximum_lateness_ns: 27,
        retention_ttl_ns: 28,
        clock_uncertainty_ns: Some(29),
        late_action: "late".into(),
        window_ns: 30,
        coverage_predicate: "coverage".into(),
        replay_contract_id: "replay".into(),
        result_states: vec![FindingStateV1::Confirmed, FindingStateV1::Retracted],
        accepted_cursor_watermark: 31,
        observed_boottime_watermark_ns: 32,
    }
}

#[test]
fn qualified_variants_roundtrip() -> sdk::Result<()> {
    let raw = Observation {
        id: record(7, 11),
        position: Position {
            commit_revision: 1,
            ordinal: 0,
        },
        effect: DiscoveryEffectKeyV1 {
            task_cookie: 33,
            target_task_cookie: Some(34),
            process_lineage_id: vec![35; 16],
            authority_domain_id: vec![36; 16],
            execution_set_id: vec![37; 16],
            exact_object_id: vec![38; 16],
            destination_id: 39,
            policy_rule_id: 40,
            reason: 41,
            decision: 1,
            effect_family: 2,
            operation: 3,
            operation_argument: Some(42),
            configured_errno: -43,
            kernel_result: -44,
            exact_file_object: Some(DiscoveryFileObjectV1 {
                profile_generation_ref_id: 45,
                mount_id_unique: 46,
                inode: 47,
                inode_generation: 48,
                mount_namespace_inode: 49,
                filesystem_device: 50,
            }),
        },
        ingested_utc_ns: -51,
        observed_boottime_ns: 52,
        profile_generation_ref_id: Some(53),
        original_kernel_sequence: Some(54),
        coverage_interval_id: vec![55; 16],
        process_instance_id: Some([56; 16]),
        entry_instance_id: None,
        binding_id: Some([57; 16]),
        role_id: Some(0),
        state_id: None,
        entry_rule_id: Some(58),
        proof_quality: proof(),
    };
    let values = vec![
        raw.clone(),
        Observation {
            id: record(2, 101),
            ..raw
        },
    ];
    let mut encoded = Observation::encode(&values)?;
    let batch = encoded.batches.remove(0);
    encoded.batches = vec![batch.slice(0, 1), batch.slice(1, 1)];
    assert_eq!(Observation::decode(&encoded)?, values);
    let mut rows = facts();
    rows.push(rows[0].clone());
    assert_eq!(Fact::decode(&Fact::encode(&rows)?)?, rows);
    let metadata = Metadata {
        record_ids: values.iter().map(|row| row.id.clone()).collect(),
        facts: rows,
        package: package(),
    };
    assert_eq!(
        Metadata::decode(&Metadata::encode(std::slice::from_ref(&metadata))?)?,
        vec![metadata]
    );
    let authorities = vec![
        GraphSubjectAuthorityV1::Native {
            node_id: "node".into(),
            node_boot_id: [2; 16],
            label_epoch: 3,
        },
        GraphSubjectAuthorityV1::Provider {
            authority_id: "provider".into(),
        },
        GraphSubjectAuthorityV1::Kubernetes {
            cluster_id: "cluster".into(),
        },
        GraphSubjectAuthorityV1::External {
            authority_id: "external".into(),
        },
    ];
    let subjects = authorities
        .into_iter()
        .map(|authority| Subject {
            record: 0,
            context: Some(2),
            key: subject(authority),
        })
        .collect::<Vec<_>>();
    assert_eq!(Subject::decode(&Subject::encode(&subjects)?)?, subjects);
    let manifest = Manifest { window_ns: 59 };
    assert_eq!(
        Manifest::decode(&Manifest::encode(std::slice::from_ref(&manifest))?)?,
        vec![manifest]
    );
    Ok(())
}

#[test]
fn resolved_rows_roundtrip() -> sdk::Result<()> {
    let edge = Relationship {
        record: 0,
        fact: Some(3),
        edge: GraphEdgeV1 {
            key: GraphEdgeKeyV1 {
                from: 1,
                to: 3,
                edge_type: GraphEdgeTypeV1::NativeEffect,
                package_id: "HF-PROC-001".into(),
                evidence: vec![0, 1],
                cause: GraphCauseV1::Direct,
            },
            proof_quality: proof(),
            required_coverage_interval_ids: vec![[60; 16]],
            first_boottime_ns: 61,
            last_boottime_ns: 62,
        },
    };
    assert_eq!(
        Relationship::decode(&Relationship::encode(std::slice::from_ref(&edge))?)?,
        vec![edge]
    );
    let mut evidence = vec![record(7, 11), record(2, 101)];
    evidence.sort();
    let finding = FindingV1 {
        tenant_id: [1; 16],
        finding_id: "stable-finding".into(),
        package_id: "HF-PROC-001".into(),
        package_version: 1,
        subject_id: native_subject(),
        state: FindingStateV1::Confirmed,
        window_start_utc_ns: -63,
        window_end_utc_ns: 64,
        evidence: evidence.clone(),
        required_coverage_interval_ids: vec![[60; 16]],
        policy_provenance: vec![policy()],
        effects: vec![GraphEffectV1 {
            evidence: record(7, 11),
            process_instance_id: Some([65; 16]),
            entry_instance_id: None,
            binding_id: Some([66; 16]),
            role_id: Some(67),
            state_id: None,
            entry_rule_id: Some(68),
            profile_generation_ref_id: Some(69),
            original_kernel_sequence: Some(70),
            effect_family: 71,
            operation: 72,
            source_decision: 73,
            source_reason: 74,
            configured_errno: -75,
            kernel_result: -76,
            physical_result: GraphPhysicalResultV1::Prevented,
            proof_quality: proof(),
        }],
        reason: FindingReasonV1::UnexpectedEffect,
        severity: FindingSeverityV1::High,
        sensitivity: ContextSensitivityV1::HostRestricted,
        required_action: Some("act".into()),
        limits: vec!["limit".into()],
    };
    let row = Finding::from_finding(
        0,
        Some(1),
        finding.clone(),
        "HF-PROC-001.UNEXPECTED_EFFECT".into(),
    );
    let change = FindingChange::from_local(
        row.clone(),
        Anchor::from_positions(0, Some(1), &evidence, &facts())?,
    );
    assert_eq!(
        FindingChange::decode(&FindingChange::encode(std::slice::from_ref(&change))?)?,
        vec![change.clone()]
    );
    let mut first = std::collections::HashMap::new();
    first.insert("z".into(), "last".into());
    first.insert("a".into(), "first".into());
    let mut reordered = std::collections::HashMap::new();
    reordered.insert("a".into(), "first".into());
    reordered.insert("z".into(), "last".into());
    let code = change.reason_code.clone();
    let declared = |field, schema| {
        FindingReasonV1::Declared(DeclaredFindingReasonV1 {
            code: code.clone(),
            schema: sdk::Schema::new(vec![sdk::Field::new(
                "detail",
                sdk::DataType::UInt64,
                false,
            )
            .with_metadata(field)])
            .with_metadata(schema),
            ipc: vec![1, 2, 3],
        })
    };
    let mut one = change.clone();
    one.prior_reason = Some(declared(first.clone(), reordered.clone()));
    let mut two = change;
    two.prior_reason = Some(declared(reordered, first));
    assert_eq!(one, two);
    assert_eq!(
        FindingChange::encode(&[one.clone()])?.batches,
        FindingChange::encode(&[two])?.batches,
    );
    assert_eq!(
        FindingChange::decode(&FindingChange::encode(&[one.clone()])?)?,
        [one]
    );
    let decoded = Finding::decode(&Finding::encode(std::slice::from_ref(&row))?)?.remove(0);
    assert_eq!(decoded, row);
    assert_eq!(
        decoded.into_finding(FindingReasonV1::UnexpectedEffect),
        finding
    );
    for (at, state) in [
        FindingStateV1::Provisional,
        FindingStateV1::Confirmed,
        FindingStateV1::Superseded,
        FindingStateV1::Retracted,
        FindingStateV1::CoverageInsufficient,
    ]
    .into_iter()
    .enumerate()
    {
        let mut value = finding.clone();
        value.state = state;
        value.severity = [
            FindingSeverityV1::Info,
            FindingSeverityV1::Warning,
            FindingSeverityV1::High,
            FindingSeverityV1::Critical,
        ][at % 4];
        value.sensitivity = [
            ContextSensitivityV1::Public,
            ContextSensitivityV1::Tenant,
            ContextSensitivityV1::HostRestricted,
        ][at % 3];
        value.effects[0].physical_result = [
            GraphPhysicalResultV1::Prevented,
            GraphPhysicalResultV1::PacketDropped,
            GraphPhysicalResultV1::TerminationQueued,
            GraphPhysicalResultV1::Unknown,
        ][at % 4];
        let row = Finding::from_finding(0, None, value, "HF-PROC-001.UNEXPECTED_EFFECT".into());
        assert_eq!(
            Finding::decode(&Finding::encode(std::slice::from_ref(&row))?)?,
            vec![row]
        );
    }
    for state in [
        GraphPackageStateV1::Waiting,
        GraphPackageStateV1::NativeEffect,
        GraphPackageStateV1::CredentialObserved,
        GraphPackageStateV1::AuthorityChannel,
        GraphPackageStateV1::DirectPivot,
        GraphPackageStateV1::ContextualPivot,
        GraphPackageStateV1::Contradicted,
        GraphPackageStateV1::CoverageInsufficient,
        GraphPackageStateV1::KubernetesProofMissing,
        GraphPackageStateV1::KubernetesRequest,
        GraphPackageStateV1::KubernetesAudit,
        GraphPackageStateV1::KubernetesObject,
        GraphPackageStateV1::KubernetesScheduled,
        GraphPackageStateV1::RemoteAdmission,
        GraphPackageStateV1::Declared("WAITING".into()),
        GraphPackageStateV1::Declared("custom".into()),
    ] {
        let decoded = GraphPackageStateV1::decode(&GraphPackageStateV1::encode(
            std::slice::from_ref(&state),
        )?)?;
        assert_eq!(decoded.as_slice(), std::slice::from_ref(&state));
        let metadata = Metadata {
            record_ids: vec![],
            facts: vec![],
            package: GraphPackageCheckpointV1 { state, ..package() },
        };
        assert_eq!(
            Metadata::decode(&Metadata::encode(std::slice::from_ref(&metadata))?)?,
            vec![metadata]
        );
    }
    Ok(())
}

#[test]
fn native_state_rejects_invalid_rows() -> Result<(), Box<dyn std::error::Error>> {
    for (tag, declared) in [
        ("UNKNOWN", None),
        ("DECLARED", None),
        ("WAITING", Some("custom")),
        ("NATIVE_EFFECT", Some("custom")),
    ] {
        let batch = serde_arrow::to_record_batch(
            GraphPackageStateV1::port().schema.fields(),
            &[views::StateRow {
                tag: tag.into(),
                declared: declared.map(str::to_owned),
            }],
        )?;
        assert!(GraphPackageStateV1::decode(&sdk::Dataset {
            name: "state".into(),
            batches: vec![batch],
        })
        .is_err());
    }
    Ok(())
}

#[test]
fn native_tags_require_payload() -> Result<(), Box<dyn std::error::Error>> {
    let row = Subject {
        record: 0,
        context: None,
        key: native_subject(),
    };
    for invalid in 0..3 {
        let mut value = serde_json::to_value(views::SubjectRow::from(&row))?;
        match invalid {
            0 => value["key"]["authority"]["tag"] = serde_json::json!("UNKNOWN"),
            1 => {
                value["key"]["authority"]["provider"] = serde_json::json!({"authority_id":"extra"})
            }
            _ => value["key"]["authority"]["native"] = serde_json::Value::Null,
        }
        let view: views::SubjectRow = serde_json::from_value(value)?;
        let batch = serde_arrow::to_record_batch(Subject::port().schema.fields(), &[view])?;
        assert!(Subject::decode(&sdk::Dataset {
            name: "subjects".into(),
            batches: vec![batch]
        })
        .is_err());
    }
    for invalid in 0..3 {
        let mut value = serde_json::to_value(views::FactRow::from(&facts()[2]))?;
        match invalid {
            0 => value["value"]["tag"] = serde_json::json!("UNKNOWN"),
            1 => {
                value["value"]["baseline"] = serde_json::json!({"role_id":1,"state_id":2,"outside_reviewed_baseline":false,"reviewed_policy_revision":"extra"})
            }
            _ => value["value"]["context"]["proof_quality"]["integrity"] = serde_json::json!(255),
        }
        let view: views::FactRow = serde_json::from_value(value)?;
        let batch = serde_arrow::to_record_batch(Fact::port().schema.fields(), &[view])?;
        assert!(Fact::decode(&sdk::Dataset {
            name: "facts".into(),
            batches: vec![batch]
        })
        .is_err());
    }
    Ok(())
}
