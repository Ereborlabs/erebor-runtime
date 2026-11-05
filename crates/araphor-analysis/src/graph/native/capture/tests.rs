use super::*;
use araphor_data::GraphFactV1;
use datafusion::arrow::array::{ArrayRef, UInt32Array};
use datafusion::arrow::buffer::NullBuffer;
use datafusion::arrow::compute::{concat, take};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn fixture() -> TestResult<(GraphReplayInputV1, sdk::RecordBatch)> {
    let mut input = crate::graph::tests::fixture::credential_input_from(1)?;
    let source = &input.source;
    let events = sdk::RecordBatch::try_from_iter(vec![
        (
            "tenant_id",
            Arc::new(BinaryArray::from_iter_values(std::iter::repeat_n(
                source.tenant_id.as_slice(),
                3,
            ))) as ArrayRef,
        ),
        (
            "node_id",
            Arc::new(StringArray::from_iter_values(std::iter::repeat_n(
                source.node_id.as_str(),
                3,
            ))),
        ),
        (
            "node_boot_id",
            Arc::new(BinaryArray::from_iter_values(std::iter::repeat_n(
                source.node_boot_id.as_slice(),
                3,
            ))),
        ),
        (
            "label_epoch",
            Arc::new(UInt64Array::from(vec![source.label_epoch; 3])),
        ),
        (
            "source_id",
            Arc::new(BinaryArray::from_iter_values(std::iter::repeat_n(
                source.source_id.as_slice(),
                3,
            ))),
        ),
        (
            "source_epoch",
            Arc::new(UInt64Array::from(vec![source.source_epoch; 3])),
        ),
        ("cpu_id", Arc::new(UInt32Array::from(vec![0; 3]))),
        ("source_cursor", Arc::new(UInt64Array::from(vec![1, 2, 3]))),
        (
            "commit_revision",
            Arc::new(UInt64Array::from(
                input
                    .input_positions
                    .iter()
                    .map(|(_, position)| position.commit_revision)
                    .collect::<Vec<_>>(),
            )),
        ),
        (
            "ordinal",
            Arc::new(UInt32Array::from(
                input
                    .input_positions
                    .iter()
                    .map(|(_, position)| position.ordinal)
                    .collect::<Vec<_>>(),
            )),
        ),
        (
            "framed_record",
            Arc::new(BinaryArray::from_iter_values(
                input
                    .records
                    .iter()
                    .map(|record| record.wire_record.as_slice()),
            )),
        ),
    ])?;
    let rows = input
        .records
        .iter()
        .map(|record| {
            let facts = input
                .facts
                .iter()
                .filter(|fact| GraphFactV1::try_from(*fact).unwrap().record_id == record.id)
                .cloned()
                .collect::<Vec<_>>();
            let proofs = facts
                .iter()
                .map(|fact| AnalysisContextRefV1 {
                    key: fact.key.clone(),
                    commit_revision: 17,
                })
                .collect();
            (record.id.clone(), facts, proofs)
        })
        .collect::<Vec<_>>();
    let resolved = GraphPublication::encode_resolved(&rows)?;
    let mut ids = input
        .records
        .iter()
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    ids.push(DiscoveryRecordIdV1 {
        durable_cursor: 4,
        ..ids[0].clone()
    });
    let keys = Unit::encode_affected(&ids)?;
    let indices = UInt32Array::from(vec![Some(0), Some(1), None, None, Some(2)]);
    let record_indices = UInt32Array::from(vec![Some(0), Some(1), None, Some(3), Some(2)]);
    let batch = sdk::RecordBatch::try_from_iter(vec![
        (
            "record",
            take(keys.batches[0].column(0).as_ref(), &record_indices, None)?,
        ),
        ("event", take(&StructArray::from(events), &indices, None)?),
        (
            "resolved",
            take(&StructArray::from(resolved), &indices, None)?,
        ),
        (
            "record_coverage_revision",
            Arc::new(UInt64Array::from(vec![11, 22, 33, 44, 55])) as ArrayRef,
        ),
        (
            "interval_revision",
            Arc::new(UInt64Array::from(vec![
                Some(1),
                Some(2),
                None,
                None,
                Some(3),
            ])),
        ),
        (
            "coverage_interval_id",
            Arc::new(BinaryArray::from_iter_values(std::iter::repeat_n(
                [4; 16].as_slice(),
                5,
            ))),
        ),
        (
            "coverage_state",
            Arc::new(StringArray::from(vec!["HEALTHY"; 5])),
        ),
        ("coverage_reasons", Arc::new(StringArray::from(vec![""; 5]))),
    ])?;
    input.coverage = input
        .records
        .iter()
        .zip([11, 22, 55])
        .map(|(record, revision)| DiscoveryCoverageV1 {
            stream: input.source.clone(),
            cpu_id: record.id.cpu_id,
            first_cursor: record.id.durable_cursor,
            last_cursor: record.id.durable_cursor,
            expected_records: 1,
            coverage_revision: revision,
            coverage_interval_id: [4; 16],
            state: DiscoveryCoverageStateV1::Healthy,
            gap_reasons: vec![],
        })
        .collect();
    input.coverage_keys = input
        .coverage
        .iter()
        .zip(1..=3)
        .map(|(range, revision)| GraphCoverageKeyV1 {
            source: input.source.clone(),
            cpu_id: range.cpu_id,
            report_revision: range.coverage_revision,
            interval_id: range.coverage_interval_id,
            interval_revision: revision,
            state: range.state,
            gap_reasons: vec![],
        })
        .collect();
    Ok((input, batch))
}

fn replace(batch: &sdk::RecordBatch, name: &str, value: ArrayRef) -> TestResult<sdk::RecordBatch> {
    let mut columns = batch.columns().to_vec();
    columns[batch.schema().index_of(name)?] = value;
    Ok(sdk::RecordBatch::try_new(batch.schema(), columns)?)
}

#[test]
fn decoder_keeps_mixed_runs() -> TestResult {
    let (expected, batch) = fixture()?;
    let (input, contexts, proofs, removed) = Projection::decode_rows(&[batch], &expected.source)?;
    assert_eq!(input.source, expected.source);
    assert_eq!(input.records, expected.records);
    assert_eq!(input.input_positions, expected.input_positions);
    assert_eq!(input.coverage, expected.coverage);
    assert_eq!(input.coverage_keys, expected.coverage_keys);
    assert!(input.facts.is_empty());
    assert!(input.missing_ranges.is_empty());
    let expected_contexts = expected
        .facts
        .iter()
        .map(|context| (context.key.clone(), context.clone()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        contexts,
        expected_contexts.into_values().collect::<Vec<_>>()
    );
    let expected_proofs = expected
        .facts
        .iter()
        .map(|context| {
            let record = GraphFactV1::try_from(context).unwrap().record_id;
            (
                (record, context.key.clone()),
                AnalysisContextRefV1 {
                    key: context.key.clone(),
                    commit_revision: 17,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        proofs,
        expected_proofs
            .into_iter()
            .map(|((record, _), proof)| (record, proof))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        removed,
        BTreeSet::from([DiscoveryRecordIdV1 {
            durable_cursor: 4,
            ..expected.records[0].id.clone()
        }])
    );
    Ok(())
}

#[test]
fn decoder_rejects_mixed_presence() -> TestResult {
    let (input, batch) = fixture()?;
    for (name, message) in [
        ("event", "Graph removed record"),
        ("resolved", "Graph resolved event"),
    ] {
        let values = Projection::column::<StructArray>(&batch, name)?;
        let values = StructArray::try_new(
            values.fields().clone(),
            values.columns().to_vec(),
            Some(NullBuffer::from(vec![false, true, false, false, true])),
        )?;
        let changed = replace(&batch, name, Arc::new(values))?;
        let error = Projection::decode_rows(&[changed], &input.source).unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
    }
    Ok(())
}

#[test]
fn decoder_checks_native_bindings() -> TestResult {
    let (input, batch) = fixture()?;
    let resolved = Projection::column::<StructArray>(&batch, "resolved")?;
    let first = sdk::RecordBatch::from(resolved.slice(0, 2));
    let facts = take(
        first.column_by_name("facts").unwrap().as_ref(),
        &UInt32Array::from(vec![1, 0]),
        None,
    )?;
    let tampered = replace(&first, "facts", facts)?;
    let error = GraphPublication::decode_resolved(&tampered).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("resolved graph facts differ from contexts"),
        "{error}"
    );
    let changed = concat(&[&StructArray::from(tampered), &resolved.slice(2, 3)])?;
    let error = Projection::decode_rows(&[replace(&batch, "resolved", changed)?], &input.source)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("resolved graph facts differ from contexts"),
        "{error}"
    );

    let mut rows = GraphPublication::decode_resolved(&first)?;
    rows[0] = rows[1].clone();
    let changed = GraphPublication::encode_resolved(&rows)?;
    let changed = concat(&[&StructArray::from(changed), &resolved.slice(2, 3)])?;
    let error = Projection::decode_rows(&[replace(&batch, "resolved", changed)?], &input.source)
        .unwrap_err();
    assert!(
        error.to_string().contains("Graph resolver record binding"),
        "{error}"
    );
    Ok(())
}
