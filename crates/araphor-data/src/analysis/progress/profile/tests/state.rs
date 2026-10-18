use std::collections::BTreeMap;

use araphor_analysis_sdk::arrow_array::{RecordBatch, StringArray};

use super::*;
use crate::{
    AnalysisExtractLimits, AnalysisPositionPageV1, AnalysisReadControl, AnalysisReadModeV1,
    AnalysisSelectionV1, AnalysisTableRead, DiscoveryInputManifestV1, DiscoverySnapshotRowV1,
    DiscoveryStateRowV1, EvidenceRetentionOwner, RetentionLimitsV1,
};

fn read_state(
    store: &AnalysisStore,
    selection: &AnalysisSelectionV1,
    columns: Option<&[&str]>,
) -> std::result::Result<AnalysisPositionPageV1, Box<dyn std::error::Error>> {
    let schema = &AnalysisStore::table_schemas()["discovery_state"];
    let projected = match columns {
        Some(names) => names
            .iter()
            .map(|name| schema.index_of(name))
            .collect::<std::result::Result<_, _>>()?,
        None => (0..schema.fields().len()).collect(),
    };
    Ok(store.read_tables(
        selection,
        AnalysisTableRead {
            requests: &BTreeMap::from([("discovery_state".into(), Some(projected))]),
            event_ranges: None,
            inputs: None,
            mode: AnalysisReadModeV1::Complete,
            now: 100,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?)
}

fn state(
    page: &AnalysisPositionPageV1,
) -> std::result::Result<DiscoveryStateRowV1, Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for batch in &page.tables["discovery_state"] {
        rows.extend(serde_arrow::from_record_batch::<Vec<DiscoveryStateRowV1>>(
            batch,
        )?);
    }
    assert_eq!(rows.len(), 1);
    Ok(rows.remove(0))
}

#[test]
fn state_uses_current_head() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let mut profile = profile();
    for tenant in [profile.scope.identity.tenant_id, [9; 16]] {
        let mut source = profile.scope.identity.clone();
        source.tenant_id = tenant;
        store.accept_validated_batch(
            source,
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
    }
    let selection = AnalysisSelectionV1::tenant(profile.scope.identity.tenant_id);
    let bootstrap = read_state(&store, &selection, None)?;
    let row = state(&bootstrap)?;
    assert_eq!(row.tenant_id, profile.scope.identity.tenant_id);
    assert_eq!(row.contiguous_cursor, 1);
    assert!(!row.processor_present);
    assert_eq!(row.current_result_id, None);
    assert_eq!(row.consumed_cursor, None);
    assert_eq!(row.snapshot, None);
    assert!(bootstrap.extraction.references.is_empty());
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    let row = state(&read_state(&store, &selection, None)?)?;
    assert!(row.processor_present);
    assert_eq!(row.processor_class.as_deref(), Some("optional"));
    assert_eq!(row.start_cursor, Some(1));
    assert_eq!(row.consumed_cursor, Some(0));
    assert_eq!(row.resume_floor, Some(0));
    assert_eq!(row.snapshot, None);
    let context = store
        .commit_contexts(&[crate::AnalysisContextVersionV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: profile.scope.identity.tenant_id,
                owner_id: "native-state".into(),
                entity_key: vec![4; 16],
                lifetime_key: vec![5; 16],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant,
            body: b"recorded".to_vec(),
        }])?
        .pop()
        .ok_or("native context reference absent")?;
    profile.context_refs.push(context.clone());
    let mut input = commit(&profile);
    input.context_revision = context.commit_revision;
    let receipt =
        store.commit_working_profile(input, PreparedProfile::new(profile.clone())?, None)?;
    let mut history = profile.clone();
    history.profile_id = "newer-sealed-history".into();
    history.revision += 1;
    history.updated_utc_ns += 1;
    history.sealed = true;
    let mut historical_input = commit(&history);
    historical_input.context_revision = context.commit_revision;
    let historical =
        store.commit_sealed_profile(historical_input, PreparedProfile::new(history)?)?;
    assert!(historical.commit_revision > receipt.commit_revision);
    store.mark_notice(&profile, receipt.commit_revision, 7, 0)?;
    let captured = read_state(&store, &selection, None)?;
    let row = state(&captured)?;
    assert_eq!(
        row.current_result_id.as_deref(),
        Some(profile.profile_id.as_str())
    );
    assert_eq!(row.result_commit_revision, Some(receipt.commit_revision));
    assert_eq!(
        row.interval_id.as_deref(),
        Some(profile.interval_id.as_str())
    );
    assert_eq!(row.profile_revision, Some(profile.revision));
    assert_eq!(row.facts_revision, Some(profile.facts_revision));
    assert_eq!(row.context_refs, Some(vec![context]));
    assert_eq!(
        row.snapshot
            .clone()
            .ok_or("prior snapshot absent")?
            .into_snapshot()?,
        profile.snapshot
    );
    let refs = captured
        .extraction
        .references
        .iter()
        .filter_map(|value| value.result())
        .collect::<Vec<_>>();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].result_id, profile.profile_id);
    assert_eq!(refs[0].commit_revision, receipt.commit_revision);
    let body = serde_json::to_vec(&profile)?;
    store.writer()?.get_mut()?.execute(
        "UPDATE analysis_results SET body = ? WHERE result_id = ?",
        duckdb::params![b"not-json".as_slice(), profile.profile_id],
    )?;
    for columns in [
        &[][..],
        &["current_result_id", "consumed_cursor", "profile_revision"][..],
    ] {
        let page = read_state(&store, &selection, Some(columns))?;
        assert_eq!(
            page.tables["discovery_state"]
                .iter()
                .map(RecordBatch::num_rows)
                .sum::<usize>(),
            1
        );
        if !columns.is_empty() {
            let batch = &page.tables["discovery_state"][0];
            let ids = batch
                .column_by_name("current_result_id")
                .ok_or("head column absent")?
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or("head column type")?;
            assert_eq!(ids.value(0), profile.profile_id);
        }
    }
    assert!(read_state(&store, &selection, None).is_err());
    assert_eq!(state(&captured)?, row);
    store.writer()?.get_mut()?.execute(
        "UPDATE analysis_results SET body = ? WHERE result_id = ?",
        duckdb::params![body, profile.profile_id],
    )?;
    let mut narrowed = selection.clone();
    narrowed.binding_ids.push([4; 16]);
    let denied = read_state(&store, &narrowed, None)
        .err()
        .ok_or("partial source scope returned cumulative state")?;
    assert!(matches!(
        denied.downcast_ref::<crate::Error>(),
        Some(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Denied,
            ..
        })
    ));
    drop(store);
    let reopened = AnalysisStore::open(root)?;
    assert_eq!(state(&read_state(&reopened, &selection, None)?)?, row);
    Ok(())
}

#[test]
fn state_survives_raw_retention() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open_with_limits(
        directory.path().join("data"),
        RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
        Default::default(),
    )?;
    let baseline: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../../araphor-analysis_back/src/discovery/tests/baseline/atoms.json"
    ))?;
    let mut profile = profile();
    profile.snapshot = serde_json::from_value(baseline["original"]["snapshot"].clone())?;
    profile.scope.identity = profile.snapshot.coverage[0].stream.clone();
    profile.validate()?;
    let native = DiscoverySnapshotRowV1::from_snapshot(profile.snapshot.clone())?;
    let batch = serde_arrow::to_record_batch(DiscoverySnapshotRowV1::schema().fields(), &[native])?;
    let decoded = serde_arrow::from_record_batch::<Vec<DiscoverySnapshotRowV1>>(&batch)?;
    assert_eq!(
        decoded
            .into_iter()
            .next()
            .ok_or("native snapshot absent")?
            .into_snapshot()?,
        profile.snapshot
    );
    let manifest = DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?;
    let records = manifest
        .records
        .iter()
        .map(|record| (record.id.durable_cursor, record))
        .collect::<BTreeMap<_, _>>();
    for record in records.values() {
        store.accept_validated_batch(
            profile.scope.identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: record.id.cpu_id,
                first_cursor: record.id.durable_cursor,
                last_cursor: record.id.durable_cursor,
                intake_utc_ns: record.id.durable_cursor,
                frame_ends: vec![record.wire_record.len()],
                framed_records: record.wire_record.clone().into(),
            },
        )?;
    }
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    let mut input = commit(&profile);
    input.consumed_cursor = 3;
    let receipt =
        store.commit_working_profile(input, PreparedProfile::new(profile.clone())?, None)?;
    let selection = AnalysisSelectionV1::new(
        profile.scope.identity.tenant_id,
        vec![profile.scope.identity.clone()],
    );
    let before = state(&read_state(&store, &selection, None)?)?;
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .step(100)?
            .removed_records,
        3
    );
    let after = state(&read_state(&store, &selection, None)?)?;
    assert_eq!(after.retained_floor, 3);
    assert_eq!(after.consumed_cursor, Some(3));
    assert_eq!(after.result_commit_revision, Some(receipt.commit_revision));
    assert_eq!(after.snapshot, before.snapshot);
    assert_eq!(
        after
            .snapshot
            .ok_or("retained snapshot absent")?
            .into_snapshot()?,
        profile.snapshot
    );
    Ok(())
}

#[test]
fn state_keeps_bootstrap_gap() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open_with_limits(
        directory.path().join("data"),
        RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
        Default::default(),
    )?;
    let mut profile = profile();
    store.accept_validated_batch(
        profile.scope.identity.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        },
    )?;
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .step(100)?
            .removed_records,
        1
    );
    let gap = store
        .resume_optional(&profile.scope)?
        .ok_or("resume gap absent")?;
    let selection = AnalysisSelectionV1::new(
        profile.scope.identity.tenant_id,
        vec![profile.scope.identity.clone()],
    );
    let row = state(&read_state(&store, &selection, None)?)?;
    assert_eq!(row.snapshot, None);
    assert_eq!(row.current_result_id, None);
    assert_eq!(row.consumed_cursor, Some(0));
    assert_eq!(row.resume_floor, Some(1));
    assert_eq!(row.retained_floor, 1);
    assert_eq!(row.gaps, Some(vec![gap]));
    profile.incomplete = true;
    profile.gaps.push(gap);
    let mut input = commit(&profile);
    input.expected_cursor = 1;
    input.consumed_cursor = 1;
    store.commit_working_profile(input, PreparedProfile::new(profile)?, None)?;
    store.accept_validated_batch(
        selection.sources.as_slice()[0].clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 2,
            last_cursor: 2,
            intake_utc_ns: 2,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        },
    )?;
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .step(100)?
            .removed_records,
        1
    );
    let scope = ProcessorScopeV1 {
        processor_id: DISCOVERY_PROCESSOR.into(),
        method_version: DISCOVERY_SCHEMA_VERSION.into(),
        identity: selection.sources.as_slice()[0].clone(),
    };
    let next = store
        .resume_optional(&scope)?
        .ok_or("second resume gap absent")?;
    let row = state(&read_state(&store, &selection, None)?)?;
    assert!(row.snapshot.is_some());
    assert_eq!(row.consumed_cursor, Some(1));
    assert_eq!(row.resume_floor, Some(2));
    assert_eq!(row.gaps, Some(vec![gap, next]));
    Ok(())
}
