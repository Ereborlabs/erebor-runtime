use std::collections::BTreeMap;

use araphor_analysis_sdk::arrow_array::{
    BinaryArray, BooleanArray, RecordBatch, StringArray, UInt32Array, UInt64Array,
};
use prost::Message as _;

use super::*;
use crate::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisReadModeV1, AnalysisSelectionV1,
    AnalysisTableRead, AnalysisWitnessV1, CoverageCounters, CoverageInterval, CoverageReport,
    DiscoveryInputManifestV1, Selection, ValidatedCoverageV1,
};

#[test]
fn profile_native_fields() -> TestResult {
    let baseline: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../../araphor-analysis_back/src/discovery/tests/baseline/atoms.json"
    ))?;
    let mut profile = profile();
    profile.snapshot = serde_json::from_value(baseline["original"]["snapshot"].clone())?;
    let manifest = DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?;
    profile.scope.identity = profile.snapshot.coverage[0].stream.clone();
    profile.coverage_revision = 1;
    profile.validate()?;
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    store.register_discovery_owner();
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    let records = manifest
        .records
        .iter()
        .map(|record| (record.id.durable_cursor, record))
        .collect::<BTreeMap<_, _>>();
    for (cursor, record) in &records {
        store.accept_validated_batch(
            profile.scope.identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: record.id.cpu_id,
                first_cursor: *cursor,
                last_cursor: *cursor,
                intake_utc_ns: *cursor,
                frame_ends: vec![record.wire_record.len()],
                framed_records: record.wire_record.clone().into(),
            },
        )?;
    }
    let covered = &profile.snapshot.coverage[0];
    store.accept_validated_coverage(ValidatedCoverageV1 {
        identity: profile.scope.identity.clone(),
        cpu_id: covered.cpu_id,
        revision: 1,
        encoded_report: CoverageReport {
            source_id: profile.scope.identity.source_id.to_vec(),
            source_epoch: profile.scope.identity.source_epoch,
            cpu_id: covered.cpu_id,
            revision: 1,
            intervals: vec![CoverageInterval {
                interval_id: covered.coverage_interval_id.to_vec(),
                source_epoch: profile.scope.identity.source_epoch,
                revision: 1,
                state: "HEALTHY".into(),
                first_sequence: 1,
                last_sequence: Some(3),
                opening_counters: Some(Default::default()),
                closing_counters: Some(CoverageCounters {
                    attempted: 3,
                    requested: 3,
                    emitted: 3,
                    next_sequence: 4,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        }
        .encode_to_vec(),
    })?;
    let mut input = commit(&profile);
    input.consumed_cursor = 3;
    input.witnesses = records
        .keys()
        .map(|cursor| AnalysisWitnessV1 {
            identity: profile.scope.identity.clone().into(),
            cursor: *cursor,
            expires_utc_ns: 1_000_000_000_000,
        })
        .collect();
    let receipt =
        store.commit_working_profile(input, PreparedProfile::new(profile.clone())?, None)?;
    let mut selection = AnalysisSelectionV1::new(
        profile.scope.identity.tenant_id,
        vec![profile.scope.identity.clone()],
    );
    selection.select_profiles(Selection::Exact(vec![profile.profile_id.clone()]))?;
    let schema = &AnalysisStore::table_schemas()["behaviors"];
    let columns = BTreeMap::from([(
        "behaviors".to_owned(),
        Some((0..schema.fields().len()).collect()),
    )]);
    let page = store.read_tables(
        &selection,
        AnalysisTableRead {
            requests: &columns,
            event_ranges: None,
            inputs: None,
            mode: AnalysisReadModeV1::Complete,
            now: 100,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    let batches = &page.tables["behaviors"];
    assert_eq!(
        batches.iter().map(RecordBatch::num_rows).sum::<usize>(),
        1 + profile.snapshot.atoms.len()
    );
    for batch in batches {
        assert_eq!(batch.schema(), *schema);
        for (field, array) in batch.schema_ref().fields().iter().zip(batch.columns()) {
            assert_eq!(array.data_type(), field.data_type());
            if !field.is_nullable() {
                assert_eq!(array.null_count(), 0);
            }
        }
    }
    let summary = batches[0].slice(0, 1);
    let kinds = summary
        .column_by_name("kind")
        .ok_or("native profile field: kind")?
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or("native profile type: StringArray")?;
    assert_eq!(kinds.value(0), "summary");
    let accepted = summary
        .column_by_name("accepted_records")
        .ok_or("native profile field: accepted_records")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("native profile type: UInt64Array")?;
    assert_eq!(accepted.value(0), 3);
    assert!(summary
        .column_by_name("atom_key")
        .ok_or("native profile field: atom_key")?
        .is_null(0));
    let atom = batches
        .iter()
        .find_map(|batch| {
            let kinds = batch
                .column_by_name("kind")?
                .as_any()
                .downcast_ref::<StringArray>()?;
            (0..batch.num_rows())
                .find(|row| kinds.value(*row) == "atom")
                .map(|row| batch.slice(row, 1))
        })
        .ok_or("native atom row")?;
    let expected = &profile.snapshot.atoms[0];
    let keys = atom
        .column_by_name("atom_key")
        .ok_or("native profile field: atom_key")?
        .as_any()
        .downcast_ref::<BinaryArray>()
        .ok_or("native profile type: BinaryArray")?;
    assert_eq!(keys.value(0), serde_json::to_vec(&expected.key)?);
    let effects = atom
        .column_by_name("effect")
        .ok_or("native profile field: effect")?
        .as_any()
        .downcast_ref::<BinaryArray>()
        .ok_or("native profile type: BinaryArray")?;
    assert_eq!(effects.value(0), serde_json::to_vec(&expected.key.effect)?);
    let operations = atom
        .column_by_name("operation")
        .ok_or("native profile field: operation")?
        .as_any()
        .downcast_ref::<UInt32Array>()
        .ok_or("native profile type: UInt32Array")?;
    assert_eq!(operations.value(0), expected.key.effect.operation);
    let counts = atom
        .column_by_name("record_count")
        .ok_or("native profile field: record_count")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("native profile type: UInt64Array")?;
    assert_eq!(counts.value(0), expected.count);
    let physical = atom
        .column_by_name("physical_result")
        .ok_or("native profile field: physical_result")?
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or("native profile type: StringArray")?;
    assert_eq!(physical.value(0), "prevented");
    assert!(atom
        .column_by_name("accepted_records")
        .ok_or("native profile field: accepted_records")?
        .is_null(0));
    assert!(atom
        .column_by_name("lifecycle")
        .ok_or("native profile field: lifecycle")?
        .is_null(0));
    let enabled = atom
        .column_by_name("discovery_enabled")
        .ok_or("native profile field: discovery_enabled")?
        .as_any()
        .downcast_ref::<BooleanArray>()
        .ok_or("native profile type: BooleanArray")?;
    assert!(enabled.value(0));
    assert!(page.mutable_discovery);
    assert_eq!(page.extraction.sources.len(), 1);
    assert_eq!(
        page.extraction.sources[0].receipt.identity,
        profile.scope.identity
    );
    assert_eq!(page.extraction.sources[0].receipt.contiguous_cursor, 3);
    assert!(page.extraction.references.iter().any(|reference| reference
        .result()
        .is_some_and(|reference| reference.result_id == profile.profile_id
            && reference.commit_revision == receipt.commit_revision)));
    assert_eq!(
        page.extraction.witnesses.len(),
        expected.evidence_sample.len()
    );
    for (actual, expected) in page
        .extraction
        .witnesses
        .iter()
        .zip(&expected.evidence_sample)
    {
        assert_eq!(actual.identity, expected.stream);
        assert_eq!(actual.cursor, expected.durable_cursor);
    }
    store.release_discovery_owner();
    Ok(())
}
