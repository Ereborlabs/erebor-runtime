use super::*;

mod targets;

use sdk::arrow_array::{BinaryArray, StringArray, UInt64Array};

#[tokio::test]
async fn native_rows_preserve_metadata() -> TestResult {
    let expected: DiscoveryRecordedResultV1 = serde_json::from_value(
        serde_json::from_slice::<serde_json::Value>(include_bytes!(
            "../../../../../araphor-data/src/discovery/validation/tests/fixtures/atoms.json"
        ))?["original"]
            .clone(),
    )?;
    let row = DiscoverySnapshotRowV1::from_snapshot(expected.snapshot.clone())?;
    let snapshot = serde_arrow::to_record_batch(DiscoverySnapshotRowV1::schema().fields(), &[row])?;
    let mut fields = snapshot
        .schema()
        .fields()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    fields.push(Arc::new(sdk::Field::new(
        "duplicate_deliveries",
        sdk::DataType::UInt64,
        false,
    )));
    let schema = sdk::Schema::new(fields);
    let mut columns = snapshot.columns().to_vec();
    columns.push(Arc::new(UInt64Array::from(vec![
        expected.duplicate_deliveries,
    ])));
    let batch = sdk::RecordBatch::try_new(Arc::new(schema.clone()), columns)?;
    let projection = schema
        .fields()
        .iter()
        .map(|field| format!("\"{}\"", field.name()))
        .collect::<Vec<_>>()
        .join(",");
    let model = sdk::Model::new(
        "snapshot",
        vec![sdk::Port::new("payload", schema.clone())],
        vec![sdk::Port::new("snapshot", schema)],
    );
    let descriptor = sdk::Package::new("typed-result", "1", vec![model]);
    let fixture = Fixture::installed(
        PackageBundleV1 {
            schema_version: 1,
            root: PackageRefV1 {
                package_id: descriptor.id.clone(),
                revision: descriptor.revision.clone(),
            },
            artifacts: vec![PackageArtifactV1 {
                descriptor,
                implementations: vec![PackageImplementationV1::Sql {
                    export: "snapshot".into(),
                    program: araphor_package::SqlModelV1 {
                        outputs: BTreeMap::from([(
                            "snapshot".into(),
                            format!("SELECT {projection} FROM payload"),
                        )]),
                        ..Default::default()
                    },
                }],
                fixtures: Vec::new(),
            }],
        },
        Limits::default(),
    )?;
    let (call, result) = fixture
        .call(
            "snapshot",
            vec![sdk::Dataset {
                name: "payload".into(),
                batches: vec![batch],
            }],
        )
        .await?;
    let input = Fixture::input()?;
    assert_eq!(
        DiscoveryOwner::recorded_result(&input, &call, &result)?,
        expected
    );
    let original = result.output().datasets[0].batches[0].clone();
    assert_eq!(
        expected.snapshot.proof_kind,
        DiscoveryProofKindV1::Synthetic
    );
    for name in ["tenant_id", "source_revision", "proof_kind"] {
        let mut columns = original.columns().to_vec();
        let index = original.schema().index_of(name)?;
        columns[index] = match name {
            "tenant_id" => Arc::new(BinaryArray::from_iter_values([&[99; 16][..]])),
            "source_revision" => Arc::new(StringArray::from(vec!["forged-revision"])),
            _ => Arc::new(StringArray::from(vec!["OBSERVED_RUNTIME"])),
        };
        let (call, result) = fixture
            .call(
                "snapshot",
                vec![sdk::Dataset {
                    name: "payload".into(),
                    batches: vec![sdk::RecordBatch::try_new(original.schema(), columns)?],
                }],
            )
            .await?;
        assert!(
            DiscoveryOwner::recorded_result(&input, &call, &result).is_err(),
            "{name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn durable_record_projection() -> TestResult {
    use futures_util::TryStreamExt as _;

    let fixture = Fixture::new()?;
    let input = Fixture::input()?;
    let mut records: BTreeMap<_, _> = input
        .records
        .iter()
        .map(|record| (record.id.clone(), record.clone()))
        .collect();
    for record in records.values_mut() {
        let mut wire = record.decode()?;
        if record.id.durable_cursor == 1 {
            wire.decision_context = Some(EvidenceDecisionContext {
                schema_version: 1,
                original_kernel_sequence: u64::MAX,
                profile_generation_ref_id: wire.profile_generation_ref_id.unwrap_or_default(),
                process_instance_id: vec![1; 16],
                entry_instance_id: vec![2; 16],
                binding_id: vec![3; 16],
                role_id: 1,
                state_id: 1,
                entry_rule_id: 1,
                exact_file_object: Some(EvidenceExactFileObject {
                    profile_generation_ref_id: wire.profile_generation_ref_id.unwrap_or_default(),
                    mount_id_unique: u64::MAX,
                    inode: 3,
                    inode_generation: 4,
                    mount_namespace_inode: 5,
                    filesystem_device: 6,
                }),
                ..Default::default()
            });
        }
        *record = DiscoveryRecordV1::try_from((
            record.id.clone(),
            Vec::<u8>::try_from(&wire)?.as_slice(),
        ))?;
    }
    for (id, record) in &records {
        fixture.query.store().accept_validated_batch(
            id.stream.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: id.cpu_id,
                first_cursor: id.durable_cursor,
                last_cursor: id.durable_cursor,
                intake_utc_ns: id.durable_cursor,
                frame_ends: vec![record.wire_record.len()],
                framed_records: record.wire_record.clone().into(),
            },
        )?;
    }
    let sql = r#"
        SELECT
            named_struct('stream', named_struct(
                'tenant_id', tenant_id, 'node_id', node_id, 'node_boot_id', node_boot_id,
                'label_epoch', label_epoch, 'source_id', source_id, 'source_epoch', source_epoch),
                'cpu_id', cpu_id, 'durable_cursor', source_cursor) AS id,
            framed_record AS bytes,
            temporal_coverage AS temporal,
            named_struct(
                'task_cookie', task_cookie, 'target_task_cookie', target_task_cookie,
                'process_lineage_id', process_lineage_id, 'authority_domain_id', authority_domain_id,
                'execution_set_id', execution_set_id, 'exact_object_id', exact_object_id,
                'destination_id', destination_id, 'policy_rule_id', policy_rule_id,
                'reason', reason, 'decision', decision, 'effect_family', effect_family,
                'operation', operation, 'operation_argument', operation_argument,
                'configured_errno', configured_errno, 'kernel_result', kernel_result,
                'exact_file_object', CASE WHEN exact_profile_generation_ref_id IS NULL THEN NULL
                    ELSE named_struct('profile_generation_ref_id', exact_profile_generation_ref_id,
                        'mount_id_unique', mount_id_unique, 'inode', inode,
                        'inode_generation', inode_generation,
                        'mount_namespace_inode', mount_namespace_inode,
                        'filesystem_device', filesystem_device) END) AS effect,
            profile_generation_ref_id AS generation,
            kernel_sequence AS original_sequence,
            CASE WHEN context_schema_version IS NULL THEN NULL ELSE named_struct(
                'process', process_instance_id, 'entry', entry_instance_id, 'binding', binding_id,
                'role', role_id, 'state', state_id, 'rule', entry_rule_id,
                'sequence', kernel_sequence) END AS source
        FROM events ORDER BY id
    "#;
    let (plan, sources) = fixture.query.prepare(sql, Vec::new()).await?;
    let session = fixture.query.session(
        AnalysisSelectionV1::tenant(input.tenant_id),
        &AnalysisReadControl::default(),
        0,
    )?;
    let mut subscription = session.subscribe(plan, sources, b"discovery-record-input", false)?;
    let update = subscription.try_next().await?.ok_or("query input absent")?;
    assert!(update.exhausted);
    let port = builtin::Record::port();
    let actual = sdk::Dataset {
        name: port.name.clone(),
        batches: update
            .batches
            .ok_or("query batches absent")?
            .into_iter()
            .map(|batch| sdk::Dataset::normalize_batch(batch, Arc::new(port.schema.clone())))
            .collect::<sdk::Result<_>>()?,
    };
    actual.validate(&port, builtin::Discovery::limits())?;
    let expected = records
        .values()
        .map(Fixture::record)
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(actual.batches, builtin::Record::encode(&expected)?.batches);
    assert!(subscription.try_next().await?.is_none());
    assert!(!update.snapshot.witnesses.is_empty());
    Ok(())
}

#[tokio::test]
async fn context_content_changes_revision() -> TestResult {
    let fixture = Fixture::new()?;
    let mut input = Fixture::input()?;
    let source = input.source_revision.clone();
    let meta = fixture.query.store().meta()?;
    let (_, first) = fixture.atoms(&input).await?;
    let contexts = first.evaluation().input("contexts")?.revision.clone();
    let records = first.evaluation().input("records")?.revision.clone();
    input.contexts[0].image_digest.push_str("-replacement");
    let (_, second) = fixture.atoms(&input).await?;
    assert_eq!(input.source_revision, source);
    assert_eq!(fixture.query.store().meta()?, meta);
    assert_ne!(second.evaluation().input("contexts")?.revision, contexts);
    assert_eq!(second.evaluation().input("records")?.revision, records);
    Ok(())
}
