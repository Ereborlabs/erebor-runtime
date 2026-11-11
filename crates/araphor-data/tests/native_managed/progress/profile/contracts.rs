use super::*;

#[cfg(feature = "test-fixtures")]
#[tokio::test]
async fn profile_guard_rolls_back() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model) = instance(&store)?;
    let mut profile = profile("profile-a");
    profile.interval_id = "interval-a".into();
    super::super::super::attempts::append(&store, 1)?;
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    let mut selection = AnalysisSelectionV1::new([1; 16], vec![profile.scope.identity.clone()]);
    selection.select_profiles(araphor_data::Selection::All)?;
    let demands = [("behaviors".into(), None)].into();
    let control = AnalysisReadControl::default();
    let budget = super::super::super::graph::Budget;
    let mut inputs = store.subscribe_inputs(&selection, &demands, None, &control, &budget)?;
    let mut previous = None;
    let mut changes = store.subscribe_revision();
    for revision in 1..=2 {
        profile.profile_id = format!("profile-{revision}");
        profile.revision = revision;
        profile.updated_utc_ns = 1000 + revision;
        let (captured, attempt) =
            state_attempt(&store, &profile.scope.identity, &profile.profile_id)?;
        changes.borrow_and_update();
        let before = store.meta()?;
        let journal = store.database().inner().journal_head()?;
        let head = store.processor_result(&profile.scope)?;
        let control = Arc::new(AnalysisReadControl::default());
        let cancelled = Arc::clone(&control);
        store.set_commit_hook(
            araphor_data::AnalysisCommitStage::BeforeResultCommit,
            move || cancelled.cancel(),
        )?;
        let error = publish_checked(
            &store,
            &attempt,
            &model,
            Some(packet(
                profile.clone(),
                previous.clone(),
                previous.clone(),
                0,
                0,
            )?),
            &control,
            || Ok(()),
        )
        .err()
        .ok_or("cancelled profile committed")?;
        assert!(matches!(
            error.downcast_ref::<Error>(),
            Some(Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.meta()?, before);
        assert_eq!(store.database().inner().journal_head()?, journal);
        assert_eq!(store.processor_result(&profile.scope)?, head);
        assert!(!changes.has_changed()?);
        let (published, receipt) = publish(
            &store,
            &attempt,
            &model,
            Some(packet(
                profile.clone(),
                previous.clone(),
                previous.clone(),
                0,
                0,
            )?),
            false,
        )?;
        let receipt = receipt.ok_or("profile receipt")?;
        assert_eq!(
            inputs.changed().await?.commit_revision,
            receipt.commit_revision
        );
        previous = Some(PackageResultRefV1 {
            result_id: profile.profile_id.clone(),
            commit_revision: receipt.commit_revision,
        });
        changes.borrow_and_update();
        let committed = store.meta()?;
        let journal = store.database().inner().journal_head()?;
        assert!(matches!(
            store.register_managed_attempt(
                &captured,
                &super::super::super::attempts::request(&profile.profile_id, true),
                || control.check()
            ),
            Err(Error::AnalysisReadCancelled { .. })
        ));
        let retry = store.register_managed_attempt(
            &captured,
            &super::super::super::attempts::request(&profile.profile_id, true),
            || Ok(()),
        )?;
        assert_eq!(retry.receipt(), Some(&published));
        assert_eq!(store.meta()?, committed);
        assert_eq!(store.database().inner().journal_head()?, journal);
        assert!(!changes.has_changed()?);
    }
    let head = store.processor_result(&profile.scope)?;
    drop((inputs, store));
    assert_eq!(
        NativeStore::open(&root)?.processor_result(&profile.scope)?,
        head
    );
    Ok(())
}

#[test]
fn profile_handoff_matches_bytes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model) = instance(&store)?;
    let mut profile = profile("profile-a");
    profile.interval_id = "interval-a".into();
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    super::super::super::attempts::append(&store, 1)?;
    let mut previous = None;
    let mut bodies = Vec::new();
    for step in 0..3 {
        profile.profile_id = format!("profile-{step}");
        profile.revision = step + 1;
        profile.updated_utc_ns = 1000 + step;
        profile.sealed = step == 2;
        if profile.sealed {
            profile.profile_id = "profile-history".into();
        }
        let (captured, attempt) =
            state_attempt(&store, &profile.scope.identity, &profile.profile_id)?;
        let mut input = packet(profile.clone(), previous.clone(), previous.clone(), 0, 0)?;
        let request = input.request.clone();
        input.profile = PreparedProfile::new(profile.clone())?;
        let (published, receipt) = publish(&store, &attempt, &model, Some(input), false)?;
        let receipt = receipt.ok_or("profile receipt")?;
        let bytes = serde_json::to_vec(&profile)?;
        assert_eq!(
            store.read_result([1; 16], &profile.profile_id)?,
            Some(bytes.clone())
        );
        #[derive(serde::Deserialize)]
        struct Saved {
            request: AnalysisResultCommitV1,
            revision: u64,
        }
        let records = store.view()?;
        let saved = records
            .snapshot()
            .prefix(b"\0data/@progress/result/")
            .map(|entry| {
                let (_, bytes) = entry?;
                Ok::<Saved, Box<dyn std::error::Error>>(rmp_serde::from_slice(&bytes[1..])?)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|saved| saved.request.result_id == profile.profile_id)
            .ok_or("saved profile header")?;
        let mut expected = request;
        expected.body.clear();
        assert_eq!(saved.request, expected);
        assert_eq!(saved.revision, receipt.commit_revision);
        let before = store.meta()?;
        let journal = store.database().inner().journal_head()?;
        let retry = store.register_managed_attempt(
            &captured,
            &super::super::super::attempts::request(&profile.profile_id, true),
            || Ok(()),
        )?;
        assert_eq!(retry.receipt(), Some(&published));
        assert_eq!(store.meta()?, before);
        assert_eq!(store.database().inner().journal_head()?, journal);
        previous = Some(PackageResultRefV1 {
            result_id: profile.profile_id.clone(),
            commit_revision: receipt.commit_revision,
        });
        bodies.push((profile.profile_id.clone(), bytes));
    }
    let head = store.processor_result(&profile.scope)?;
    assert_eq!(
        head.as_ref().map(|head| head.result_id.as_str()),
        Some("profile-history")
    );
    let meta = store.meta()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.meta()?, meta);
    assert_eq!(store.processor_result(&profile.scope)?, head);
    for (name, bytes) in bodies {
        assert_eq!(store.read_result([1; 16], &name)?, Some(bytes));
    }
    Ok(())
}

#[test]
fn profile_handoff_rejects_mismatches() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let (_, model) = instance(&store)?;
    let mut profile = profile("profile-a");
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    super::super::super::attempts::append(&store, 1)?;
    let (_, attempt) = state_attempt(&store, &profile.scope.identity, "mismatches")?;
    let before = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    for field in 0..5 {
        let mut input = packet(profile.clone(), None, None, 0, 0)?;
        match field {
            0 => input.request.scope.identity.tenant_id = [9; 16],
            1 => input.request.result_id.push('x'),
            2 => input.request.coverage_revision += 1,
            3 => input.request.body = b"independent".to_vec(),
            _ => input.request.scope.processor_id = "different".into(),
        }
        assert!(
            publish(&store, &attempt, &model, Some(input), false).is_err(),
            "field {field}"
        );
        assert_eq!(store.meta()?, before);
        assert_eq!(store.database().inner().journal_head()?, journal);
    }
    profile.snapshot.tenant_id = [9; 16];
    assert!(PreparedProfile::new(profile.clone()).is_err());
    profile.snapshot.tenant_id = [1; 16];
    profile.sealed = true;
    let (_, receipt) = publish(
        &store,
        &attempt,
        &model,
        Some(packet(profile.clone(), None, None, 0, 0)?),
        false,
    )?;
    let head = PackageResultRefV1 {
        result_id: profile.profile_id.clone(),
        commit_revision: receipt.ok_or("sealed profile")?.commit_revision,
    };
    let (_, next) = state_attempt(&store, &profile.scope.identity, "advancing-history")?;
    profile.profile_id = "history-next".into();
    profile.revision += 1;
    let before = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    assert!(publish(
        &store,
        &next,
        &model,
        Some(packet(
            profile.clone(),
            Some(head.clone()),
            Some(head.clone()),
            0,
            1
        )?),
        false
    )
    .is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    profile.sealed = false;
    assert!(publish(
        &store,
        &next,
        &model,
        Some(packet(profile, Some(head.clone()), Some(head), 0, 0)?),
        false
    )
    .is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    Ok(())
}

#[cfg(feature = "test-fixtures")]
#[test]
fn captured_profile_contexts_atomic() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model) = instance(&store)?;
    let profile = profile("profile-a");
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    super::super::super::attempts::append(&store, 1)?;
    let context = araphor_data::AnalysisContextVersionV1 {
        key: araphor_data::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "profile-input-test".into(),
            entity_key: b"immutable-input".to_vec(),
            lifetime_key: b"captured".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: araphor_data::ContextSensitivityV1::Tenant,
        body: b"exact-input".to_vec(),
    };
    let (captured, attempt) = state_attempt(&store, &profile.scope.identity, "contexts")?;
    let input = |context| -> araphor_data::Result<ProfileCommit> {
        let mut input = packet(profile.clone(), None, None, 0, 0)?;
        input.profile = PreparedProfile::captured(profile.clone(), vec![context])?;
        Ok(input)
    };
    let before = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    let mut changes = store.subscribe_revision();
    let control = Arc::new(AnalysisReadControl::default());
    let cancelled = Arc::clone(&control);
    store.set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeResultCommit,
        move || cancelled.cancel(),
    )?;
    let error = publish_checked(
        &store,
        &attempt,
        &model,
        Some(input(context.clone())?),
        &control,
        || Ok(()),
    )
    .err()
    .ok_or("cancelled context committed")?;
    assert!(matches!(
        error.downcast_ref::<Error>(),
        Some(Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert!(store.view()?.context(&context.key)?.is_none());
    assert!(store.processor_result(&profile.scope)?.is_none());
    assert!(!changes.has_changed()?);
    let (published, receipt) = publish(
        &store,
        &attempt,
        &model,
        Some(input(context.clone())?),
        false,
    )?;
    let receipt = receipt.ok_or("profile receipt")?;
    let retained = store.processor_result(&profile.scope)?.ok_or("profile")?;
    let saved = DiscoveryProfileV1::try_from(retained.body.as_slice())?;
    let (actual, revision) = store
        .view()?
        .context(&context.key)?
        .ok_or("captured context")?;
    assert_eq!(actual, context);
    assert_eq!(revision, receipt.commit_revision);
    assert_eq!(
        saved.context_refs,
        [araphor_data::AnalysisContextRefV1 {
            key: context.key.clone(),
            commit_revision: revision
        }]
    );
    #[derive(serde::Deserialize)]
    struct Saved {
        request: AnalysisResultCommitV1,
    }
    let (_, bytes) = store
        .view()?
        .snapshot()
        .prefix(b"\0data/@progress/result/")
        .next()
        .ok_or("result")??;
    let header: Saved = rmp_serde::from_slice(&bytes[1..])?;
    assert_eq!(header.request.context_refs, saved.context_refs);
    assert_eq!(header.request.context_revision, revision);
    changes.borrow_and_update();
    let committed = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    let retry = store.register_managed_attempt(
        &captured,
        &super::super::super::attempts::request("contexts", true),
        || Ok(()),
    )?;
    assert_eq!(retry.receipt(), Some(&published));
    assert_eq!(store.meta()?, committed);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert!(!changes.has_changed()?);
    let (_, next) = state_attempt(&store, &profile.scope.identity, "changed-context")?;
    changes.borrow_and_update();
    let before = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    let mut changed = context.clone();
    changed.body.push(1);
    let mut successor = profile.clone();
    successor.profile_id = "profile-next".into();
    successor.revision += 1;
    successor.updated_utc_ns += 1;
    let head = PackageResultRefV1 {
        result_id: profile.profile_id.clone(),
        commit_revision: receipt.commit_revision,
    };
    let successor_input = |context| -> araphor_data::Result<ProfileCommit> {
        let mut input = packet(
            successor.clone(),
            Some(head.clone()),
            Some(head.clone()),
            0,
            0,
        )?;
        input.profile = PreparedProfile::captured(successor.clone(), vec![context])?;
        Ok(input)
    };
    let error = publish(
        &store,
        &next,
        &model,
        Some(successor_input(changed)?),
        false,
    )
    .err()
    .ok_or("changed immutable context committed")?;
    assert!(matches!(
        error.downcast_ref::<Error>(),
        Some(Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert_eq!(
        store
            .view()?
            .context(&context.key)?
            .ok_or("unchanged context")?
            .0,
        context
    );
    assert!(!changes.has_changed()?);
    publish(
        &store,
        &next,
        &model,
        Some(successor_input(context.clone())?),
        false,
    )?;
    let current = store
        .processor_result(&profile.scope)?
        .ok_or("next profile")?;
    assert_eq!(current.result_id, successor.profile_id);
    assert_eq!(
        DiscoveryProfileV1::try_from(current.body.as_slice())?.context_refs,
        saved.context_refs
    );
    drop((next, captured, attempt, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(store.processor_result(&profile.scope)?, Some(current));
    assert_eq!(
        store.read_result([1; 16], &profile.profile_id)?,
        Some(retained.body)
    );
    Ok(())
}
