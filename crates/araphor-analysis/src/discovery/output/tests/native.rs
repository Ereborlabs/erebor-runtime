use super::*;

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
    let fixture = Fixture::installed(PackageBundleV1 {
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
    })?;
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
