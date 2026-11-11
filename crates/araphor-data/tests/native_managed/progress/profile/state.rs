use super::*;
use araphor_data::{
    AnalysisPositionPageV1, AnalysisTableRead, DiscoverySnapshotRowV1, DiscoveryStateRowV1,
    EvidenceRetentionOwner, RetentionLimitsV1, ValidatedEvidenceBatchV1,
};

pub(super) fn read(
    store: &NativeStore,
    view: &araphor_data::analysis::native::DataView,
    selection: &AnalysisSelectionV1,
    columns: Option<&[&str]>,
) -> Result<AnalysisPositionPageV1, Box<dyn std::error::Error>> {
    let schema = &araphor_data::AnalysisStore::table_schemas()["discovery_state"];
    let columns = match columns {
        Some(names) => names
            .iter()
            .map(|name| schema.index_of(name))
            .collect::<Result<_, _>>()?,
        None => (0..schema.fields().len()).collect(),
    };
    let requests = BTreeMap::from([("discovery_state".into(), Some(columns))]);
    Ok(store.read_tables_at(
        view,
        &selection.project(&requests)?,
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: araphor_data::AnalysisReadModeV1::Complete,
            now: 1000,
        },
        Default::default(),
        &AnalysisReadControl::default(),
        None,
    )?)
}

pub(super) fn row(
    page: &AnalysisPositionPageV1,
) -> Result<DiscoveryStateRowV1, Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for batch in &page.tables["discovery_state"] {
        rows.extend(serde_arrow::from_record_batch::<Vec<DiscoveryStateRowV1>>(
            batch,
        )?);
    }
    assert_eq!(rows.len(), 1);
    Ok(rows.remove(0))
}

fn append(
    store: &NativeStore,
    source: &araphor_data::EvidenceIntakeIdentityV1,
    cursor: u64,
) -> TestResult {
    store.accept_validated_batch(
        source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: cursor,
            last_cursor: cursor,
            intake_utc_ns: cursor,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        },
    )?;
    Ok(())
}

#[test]
fn state_uses_current_head() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let profile = profile("profile-a");
    for tenant in [[1; 16], [9; 16]] {
        let mut source = profile.scope.identity.clone();
        source.tenant_id = tenant;
        append(&store, &source, 1)?;
    }
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let bootstrap = read(&store, store.view()?.as_ref(), &selection, None)?;
    let initial = row(&bootstrap)?;
    assert_eq!(initial.tenant_id, [1; 16]);
    assert_eq!(initial.contiguous_cursor, 1);
    assert!(!initial.processor_present);
    assert_eq!(initial.current_result_id, None);
    assert!(!initial.current_compatible);
    assert_eq!(initial.consumed_cursor, None);
    assert_eq!(initial.snapshot, None);
    assert!(bootstrap.extraction.references.is_empty());
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    let registered = row(&read(&store, store.view()?.as_ref(), &selection, None)?)?;
    assert!(registered.processor_present);
    assert_eq!(registered.processor_class.as_deref(), Some("optional"));
    assert_eq!(registered.start_cursor, Some(1));
    assert_eq!(registered.consumed_cursor, Some(0));
    assert_eq!(registered.resume_floor, Some(0));
    assert_eq!(registered.snapshot, None);
    let (_, model) = instance(&store)?;
    let mut prior = profile.clone();
    prior.profile_id = "old-sealed".into();
    prior.interval_id = "old-interval".into();
    prior.sealed = true;
    let (_, initial) = state_attempt(&store, &profile.scope.identity, "old-sealed")?;
    let (_, receipt) = publish(
        &store,
        &initial,
        &model,
        Some(packet(prior.clone(), None, None, 0, 0)?),
        false,
    )?;
    let prior_ref = PackageResultRefV1 {
        result_id: prior.profile_id.clone(),
        commit_revision: receipt.ok_or("prior")?.commit_revision,
    };
    let context = store
        .commit_contexts(&[araphor_data::AnalysisContextVersionV1 {
            key: araphor_data::AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "native-state".into(),
                entity_key: vec![4; 16],
                lifetime_key: vec![5; 16],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: araphor_data::ContextSensitivityV1::Tenant,
            body: b"recorded".to_vec(),
        }])?
        .pop()
        .ok_or("context")?;
    let mut profile = profile;
    profile.context_refs.push(context.clone());
    let (_, current) = state_attempt(&store, &profile.scope.identity, "current")?;
    let (_, receipt) = publish(
        &store,
        &current,
        &model,
        Some(packet(
            profile.clone(),
            Some(prior_ref.clone()),
            Some(prior_ref.clone()),
            0,
            0,
        )?),
        false,
    )?;
    let receipt = receipt.ok_or("current")?;
    let head = PackageResultRefV1 {
        result_id: profile.profile_id.clone(),
        commit_revision: receipt.commit_revision,
    };
    let mut history = prior;
    history.profile_id = "newer-sealed-history".into();
    history.revision += 1;
    history.updated_utc_ns += 1;
    let (_, repair) = state_attempt(&store, &profile.scope.identity, "history")?;
    let (_, historical) = publish(
        &store,
        &repair,
        &model,
        Some(packet(
            history.clone(),
            Some(prior_ref),
            Some(head.clone()),
            0,
            0,
        )?),
        false,
    )?;
    let historical = historical.ok_or("history")?;
    assert!(historical.commit_revision > receipt.commit_revision);
    let (_, notice) = state_attempt(&store, &profile.scope.identity, "notice")?;
    let mut input = packet(profile.clone(), Some(head.clone()), Some(head), 0, 0)?;
    input.notice = Some((7, 0));
    publish(&store, &notice, &model, Some(input), false)?;
    let captured = read(&store, store.view()?.as_ref(), &selection, None)?;
    let actual = row(&captured)?;
    assert_eq!(
        actual.current_result_id.as_deref(),
        Some(profile.profile_id.as_str())
    );
    assert_eq!(actual.result_commit_revision, Some(receipt.commit_revision));
    assert!(!actual.current_compatible);
    assert_eq!(actual.notice_facts_revision, Some(7));
    assert_eq!(actual.notice_coverage_revision, Some(0));
    assert_eq!(
        actual.interval_id.as_deref(),
        Some(profile.interval_id.as_str())
    );
    assert_eq!(actual.profile_revision, Some(profile.revision));
    assert_eq!(actual.facts_revision, Some(profile.facts_revision));
    assert_eq!(actual.context_refs, Some(vec![context]));
    assert_eq!(
        actual.snapshot.clone().ok_or("snapshot")?.into_snapshot()?,
        profile.snapshot
    );
    let references = captured
        .extraction
        .references
        .iter()
        .filter_map(|value| value.result())
        .collect::<Vec<_>>();
    assert_eq!(references.len(), 2);
    for (id, revision) in [
        (&profile.profile_id, receipt.commit_revision),
        (&history.profile_id, historical.commit_revision),
    ] {
        assert!(references
            .iter()
            .any(|reference| reference.result_id == *id && reference.commit_revision == revision));
    }
    assert_eq!(actual.history.len(), 1);
    assert_eq!(actual.history[0].result_id, history.profile_id);
    assert_eq!(
        actual.history[0].commit_revision,
        historical.commit_revision
    );
    assert_eq!(actual.history[0].interval_id, history.interval_id);
    assert_eq!(actual.history[0].profile_revision, history.revision);
    assert_eq!(
        actual.history[0].notice_facts_revision,
        history.facts_revision
    );
    assert_eq!(
        actual.history[0].notice_coverage_revision,
        history.coverage_revision
    );
    assert!(!actual.history[0].compatible);
    assert_eq!(
        actual.history[0].snapshot.clone().into_snapshot()?,
        history.snapshot
    );
    let view = store.view()?;
    #[derive(serde::Deserialize)]
    struct Header {
        request: AnalysisResultCommitV1,
    }
    let (key, _) = view
        .snapshot()
        .prefix(b"\0data/@progress/result/")
        .map(|entry| {
            let (key, bytes) = entry?;
            let header: Header = rmp_serde::from_slice(&bytes[1..])?;
            Ok::<_, Box<dyn std::error::Error>>((key, header))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|(_, header)| header.request.result_id == profile.profile_id)
        .ok_or("current header")?;
    let id = &key[b"\0data/@progress/result/".len()..];
    let body_key = [b"\0data/@progress/body/".as_slice(), id].concat();
    let body = view.snapshot().get(&body_key)?.ok_or("current body")?;
    let mut tx = store.write()?;
    tx.native().insert(&body_key, [0, b'x']);
    tx.commit([])?;
    for columns in [
        &[][..],
        &["current_result_id", "consumed_cursor", "profile_revision"][..],
    ] {
        let page = read(&store, store.view()?.as_ref(), &selection, Some(columns))?;
        assert_eq!(
            page.tables["discovery_state"]
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            1
        );
        if !columns.is_empty() {
            let ids = page.tables["discovery_state"][0]
                .column_by_name("current_result_id")
                .ok_or("head column")?
                .as_any()
                .downcast_ref::<sdk::arrow_array::StringArray>()
                .ok_or("head type")?;
            assert_eq!(ids.value(0), profile.profile_id);
        }
    }
    assert!(read(&store, store.view()?.as_ref(), &selection, None).is_err());
    assert_eq!(row(&captured)?, actual);
    let mut tx = store.write()?;
    tx.native().insert(body_key, body);
    tx.commit([])?;
    let mut narrowed = selection.clone();
    narrowed.binding_ids.push([4; 16]);
    let denied = read(&store, store.view()?.as_ref(), &narrowed, None)
        .err()
        .ok_or("partial source scope returned state")?;
    assert!(matches!(
        denied.downcast_ref::<Error>(),
        Some(Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    drop((view, initial, current, repair, notice, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        row(&read(&store, store.view()?.as_ref(), &selection, None)?)?,
        actual
    );
    Ok(())
}

#[test]
fn state_survives_raw_retention() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open_with_retention(
        &root,
        RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
    )?;
    let profile = native::sample()?;
    profile.validate()?;
    let native = DiscoverySnapshotRowV1::from_snapshot(profile.snapshot.clone())?;
    let batch = serde_arrow::to_record_batch(DiscoverySnapshotRowV1::schema().fields(), &[native])?;
    let decoded = serde_arrow::from_record_batch::<Vec<DiscoverySnapshotRowV1>>(&batch)?;
    assert_eq!(
        decoded
            .into_iter()
            .next()
            .ok_or("native snapshot")?
            .into_snapshot()?,
        profile.snapshot
    );
    native::append(&store, &profile)?;
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    let (_, model) = instance_for(&store, &profile.scope.identity)?;
    let (_, attempt) = state_attempt(&store, &profile.scope.identity, "retained-state")?;
    let (_, receipt) = publish(
        &store,
        &attempt,
        &model,
        Some(packet(profile.clone(), None, None, 0, 3)?),
        false,
    )?;
    let receipt = receipt.ok_or("profile")?;
    let selection = AnalysisSelectionV1::new(
        profile.scope.identity.tenant_id,
        vec![profile.scope.identity.clone()],
    );
    let before = row(&read(&store, store.view()?.as_ref(), &selection, None)?)?;
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .step(100)?
            .removed_records,
        3
    );
    let after = row(&read(&store, store.view()?.as_ref(), &selection, None)?)?;
    assert_eq!(after.retained_floor, 3);
    assert_eq!(after.consumed_cursor, Some(3));
    assert_eq!(after.result_commit_revision, Some(receipt.commit_revision));
    assert_eq!(after.snapshot, before.snapshot);
    assert_eq!(
        after
            .snapshot
            .clone()
            .ok_or("retained snapshot")?
            .into_snapshot()?,
        profile.snapshot
    );
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop((attempt, store));
    let store = NativeStore::open_with_retention(
        &root,
        RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
    )?;
    assert_eq!(
        row(&read(&store, store.view()?.as_ref(), &selection, None)?)?,
        after
    );
    Ok(())
}

#[test]
fn state_keeps_bootstrap_gap() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open_with_retention(
        &root,
        RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
    )?;
    let mut profile = profile("profile-a");
    append(&store, &profile.scope.identity, 1)?;
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .step(100)?
            .removed_records,
        1
    );
    let gap = store.resume_optional(&profile.scope)?.ok_or("resume gap")?;
    let selection = AnalysisSelectionV1::new([1; 16], vec![profile.scope.identity.clone()]);
    let initial = row(&read(&store, store.view()?.as_ref(), &selection, None)?)?;
    assert_eq!(initial.snapshot, None);
    assert_eq!(initial.current_result_id, None);
    assert_eq!(initial.consumed_cursor, Some(0));
    assert_eq!(initial.resume_floor, Some(1));
    assert_eq!(initial.retained_floor, 1);
    assert_eq!(initial.gaps, Some(vec![gap]));
    profile.incomplete = true;
    profile.gaps.push(gap);
    let (_, model) = instance(&store)?;
    let (_, attempt) = state_attempt(&store, &profile.scope.identity, "bootstrap-gap")?;
    publish(
        &store,
        &attempt,
        &model,
        Some(packet(profile.clone(), None, None, 1, 1)?),
        false,
    )?;
    append(&store, &profile.scope.identity, 2)?;
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .step(100)?
            .removed_records,
        1
    );
    let next = store
        .resume_optional(&profile.scope)?
        .ok_or("second resume gap")?;
    let actual = row(&read(&store, store.view()?.as_ref(), &selection, None)?)?;
    assert!(actual.snapshot.is_some());
    assert_eq!(actual.consumed_cursor, Some(1));
    assert_eq!(actual.resume_floor, Some(2));
    assert_eq!(actual.gaps, Some(vec![gap, next]));
    drop((attempt, store));
    let store = NativeStore::open_with_retention(
        &root,
        RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
    )?;
    assert_eq!(
        row(&read(&store, store.view()?.as_ref(), &selection, None)?)?,
        actual
    );
    Ok(())
}

#[test]
fn notice_keeps_frozen_profile() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model) = instance(&store)?;
    let mut profile = profile("profile-a");
    profile.sealed = true;
    append(&store, &profile.scope.identity, 1)?;
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    let (_, initial) = state_attempt(&store, &profile.scope.identity, "frozen")?;
    let (_, receipt) = publish(
        &store,
        &initial,
        &model,
        Some(packet(profile.clone(), None, None, 0, 0)?),
        false,
    )?;
    let receipt = receipt.ok_or("frozen profile")?;
    let head = PackageResultRefV1 {
        result_id: profile.profile_id.clone(),
        commit_revision: receipt.commit_revision,
    };
    let retained = store.view()?;
    let result = store.processor_result(&profile.scope)?;
    let mut health = store.processor_health(&profile.scope)?;
    let body = store.read_result([1; 16], &profile.profile_id)?;
    let selection = AnalysisSelectionV1::new([1; 16], vec![profile.scope.identity.clone()]);
    assert_eq!(notices::at(&retained, &profile)?, Some((0, 0)));
    let (captured, notice) = state_attempt(&store, &profile.scope.identity, "notice")?;
    let mut input = packet(
        profile.clone(),
        Some(head.clone()),
        Some(head.clone()),
        0,
        0,
    )?;
    input.notice = Some((2, 2));
    let (published, receipt) = publish(&store, &notice, &model, Some(input), false)?;
    assert!(receipt.is_none());
    let noticed = store.view()?;
    assert_eq!(notices::at(&noticed, &profile)?, Some((2, 2)));
    assert_eq!(notices::at(&retained, &profile)?, Some((0, 0)));
    let (_, noop) = state_attempt(&store, &profile.scope.identity, "notice-noop")?;
    let mut input = packet(
        profile.clone(),
        Some(head.clone()),
        Some(head.clone()),
        0,
        0,
    )?;
    input.notice = Some((1, 1));
    publish(&store, &noop, &model, Some(input), false)?;
    assert_eq!(
        notices::row(store.view()?.as_ref(), &profile)?,
        notices::row(&noticed, &profile)?
    );
    let (_, wrong) = state_attempt(&store, &profile.scope.identity, "wrong-revision")?;
    let before = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    let mut reference = head.clone();
    reference.commit_revision += 1;
    let mut input = packet(profile.clone(), Some(reference), Some(head), 0, 0)?;
    input.notice = Some((3, 3));
    assert!(publish(&store, &wrong, &model, Some(input), false).is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert_eq!(store.read_result([1; 16], &profile.profile_id)?, body);
    assert_eq!(store.processor_result(&profile.scope)?, result);
    health.as_mut().ok_or("health")?.read_revision = before.commit_revision;
    assert_eq!(store.processor_health(&profile.scope)?, health);
    let retry = store.register_managed_attempt(
        &captured,
        &super::super::super::attempts::request("notice", true),
        || Ok(()),
    )?;
    assert_eq!(retry.receipt(), Some(&published));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    store.finish_managed(
        &wrong,
        araphor_data::ManagedExit::Failed(Code::Invalid),
        || Ok(()),
    )?;
    let before = store.meta()?;
    health.as_mut().ok_or("health")?.read_revision = before.commit_revision;
    assert_eq!(store.processor_health(&profile.scope)?, health);
    let actual = row(&read(&store, store.view()?.as_ref(), &selection, None)?)?;
    assert_eq!(actual.history[0].notice_facts_revision, 2);
    assert_eq!(actual.history[0].notice_coverage_revision, 2);
    assert_eq!(
        actual.history[0].snapshot.clone().into_snapshot()?,
        profile.snapshot
    );
    drop((
        initial, retained, captured, notice, noticed, noop, wrong, retry, store,
    ));
    let store = NativeStore::open(&root)?;
    assert_eq!(store.read_result([1; 16], &profile.profile_id)?, body);
    assert_eq!(store.processor_result(&profile.scope)?, result);
    assert_eq!(store.processor_health(&profile.scope)?, health);
    assert_eq!(store.meta()?, before);
    assert_eq!(notices::at(store.view()?.as_ref(), &profile)?, Some((2, 2)));
    assert_eq!(
        row(&read(&store, store.view()?.as_ref(), &selection, None)?)?,
        actual
    );
    Ok(())
}
