use super::*;
use araphor_data::{
    AnalysisGapV1, AnalysisWitnessV1, EvidenceRetentionOwner, ManagedAttempt, ManagedCapture,
    RetentionLimitsV1, ValidatedEvidenceBatchV1,
};

struct Fixture {
    store: NativeStore,
    model: sdk::Model,
    profile: DiscoveryProfileV1,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new(class: ProcessorClassV1) -> Result<Self, Box<dyn std::error::Error>> {
        let mut fixture = Self::raw()?;
        fixture.expire()?;
        fixture
            .store
            .register_processor(&fixture.profile.scope, class, 1)?;
        Ok(fixture)
    }

    fn raw() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open_with_retention(
            &directory.path().join("data"),
            RetentionLimitsV1 {
                raw_max_age_ns: Some(1),
                raw_max_bytes: None,
            },
        )?;
        let mut profile = profile("profile-a");
        profile.interval_id = "interval-a".into();
        profile.created_utc_ns = 10;
        profile.updated_utc_ns = 10;
        for (first, body) in [(1, b"a".as_slice()), (2, b"bc"), (4, b"d")] {
            store.accept_validated_batch(
                profile.scope.identity.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: first,
                    last_cursor: first + body.len() as u64 - 1,
                    intake_utc_ns: 1,
                    framed_records: body.to_vec().into(),
                    frame_ends: (1..=body.len()).collect(),
                },
            )?;
            if first != 4 {
                store.checkpoint()?;
            }
        }
        let mut pins = profile.scope.clone();
        pins.processor_id = "pin-live".into();
        store.register_processor(&pins, ProcessorClassV1::Optional, 1)?;
        store.commit_result(&AnalysisResultCommitV1 {
            scope: pins,
            expected_cursor: 0,
            consumed_cursor: 4,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "pin-live".into(),
            body: b"pins".to_vec(),
            created_utc_ns: 10,
            witnesses: [1, 4]
                .into_iter()
                .map(|cursor| AnalysisWitnessV1 {
                    identity: profile.scope.identity.clone().into(),
                    cursor,
                    expires_utc_ns: 10_000,
                })
                .collect(),
            context_refs: Vec::new(),
        })?;
        store.register_discovery_owner();
        let (_, model) = instance(&store)?;
        Ok(Self {
            store,
            model,
            profile,
            directory,
        })
    }

    fn expire(&mut self) -> TestResult {
        let expired =
            EvidenceRetentionOwner::new(&self.store).retain(&self.profile.scope.identity, 1000)?;
        assert_eq!(expired.removed_records, 2);
        assert_eq!(expired.retained_floor, 0);
        let gap = AnalysisGapV1 {
            first_cursor: 2,
            last_cursor: 3,
            commit_revision: self.store.meta()?.commit_revision,
        };
        self.profile.incomplete = true;
        self.profile.gaps.push(gap);
        Ok(())
    }

    fn attempt(
        &self,
        name: &str,
    ) -> Result<(ManagedCapture, ManagedAttempt), Box<dyn std::error::Error>> {
        let captured = capture(&self.store, &["discovery_state"], false)?;
        let attempt = self.store.register_managed_attempt(
            &captured,
            &super::super::super::attempts::request(name, true),
            || Ok(()),
        )?;
        Ok((captured, attempt))
    }
}

#[test]
fn profile_gaps_commit_atomically() -> TestResult {
    let fixture = Fixture::new(ProcessorClassV1::Optional)?;
    let store = &fixture.store;
    let (captured, attempt) = fixture.attempt("gaps")?;
    let before = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    let health = store.processor_health(&fixture.profile.scope)?;
    let mut changes = store.subscribe_revision();
    let control = AnalysisReadControl::default();
    let error = publish_checked(
        store,
        &attempt,
        &fixture.model,
        Some(packet(fixture.profile.clone(), None, None, 0, 4)?),
        &control,
        || {
            control.cancel()?;
            control.check()
        },
    )
    .err()
    .ok_or("cancelled profile committed")?;
    assert!(matches!(
        error.downcast_ref::<araphor_data::Error>(),
        Some(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert_eq!(store.processor_health(&fixture.profile.scope)?, health);
    assert!(store.processor_gaps(&fixture.profile.scope, 0)?.is_empty());
    assert!(store.processor_result(&fixture.profile.scope)?.is_none());
    assert!(!changes.has_changed()?);
    let (published, receipt) = publish(
        store,
        &attempt,
        &fixture.model,
        Some(packet(fixture.profile.clone(), None, None, 0, 4)?),
        false,
    )?;
    let receipt = receipt.ok_or("profile receipt")?;
    assert_eq!(published.commit_revision, receipt.commit_revision);
    assert_ne!(
        receipt.commit_revision,
        fixture.profile.gaps[0].commit_revision
    );
    assert!(store
        .read_at(before.commit_revision)?
        .snapshot()
        .prefix(b"\0data/@progress/gap/")
        .next()
        .is_none());
    assert!(store
        .read_at(before.commit_revision)?
        .processor_result(&fixture.profile.scope)?
        .is_none());
    assert_eq!(
        store.processor_gaps(&fixture.profile.scope, 0)?,
        [fixture.profile.gaps[0]]
    );
    let health = store
        .processor_health(&fixture.profile.scope)?
        .ok_or("profile health")?;
    assert_eq!((health.consumed_cursor, health.resume_floor), (4, 3));
    assert!(health.incomplete);
    assert!(changes.has_changed()?);
    changes.borrow_and_update();
    let after = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    let retry = store.register_managed_attempt(
        &captured,
        &super::super::super::attempts::request("gaps", true),
        || Ok(()),
    )?;
    assert_eq!(retry.receipt(), Some(&published));
    assert_eq!(store.meta()?, after);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert!(!changes.has_changed()?);
    let Fixture {
        store,
        profile,
        directory,
        ..
    } = fixture;
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&directory.path().join("data"))?;
    assert_eq!(store.meta()?, after);
    assert_eq!(store.processor_gaps(&profile.scope, 0)?, profile.gaps);
    assert_eq!(store.processor_health(&profile.scope)?, Some(health));
    assert_eq!(
        DiscoveryProfileV1::try_from(
            store
                .read_result([1; 16], &profile.profile_id)?
                .ok_or("profile body")?
                .as_slice()
        )?,
        profile
    );
    let retry = store.register_managed_attempt(
        &captured,
        &super::super::super::attempts::request("gaps", true),
        || Ok(()),
    )?;
    assert_eq!(retry.receipt(), Some(&published));
    assert_eq!(store.meta()?, after);
    Ok(())
}

#[test]
fn profile_rejects_gap_proof() -> TestResult {
    let fixture = Fixture::new(ProcessorClassV1::Optional)?;
    let store = &fixture.store;
    let (_, attempt) = fixture.attempt("forged")?;
    let before = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    let health = store.processor_health(&fixture.profile.scope)?;
    for change in 0..5 {
        let mut profile = fixture.profile.clone();
        match change {
            0 => profile.gaps.clear(),
            1 => profile.gaps[0].commit_revision += 1,
            2 => profile.gaps[0].first_cursor += 1,
            3 => profile.gaps[0].first_cursor -= 1,
            _ => profile.gaps[0].last_cursor += 1,
        }
        assert!(publish(
            store,
            &attempt,
            &fixture.model,
            Some(packet(profile, None, None, 0, 4)?),
            false
        )
        .is_err());
        assert_eq!(store.meta()?, before);
        assert_eq!(store.database().inner().journal_head()?, journal);
        assert_eq!(store.processor_health(&fixture.profile.scope)?, health);
        assert!(store.processor_gaps(&fixture.profile.scope, 0)?.is_empty());
    }
    let error = publish(
        store,
        &attempt,
        &fixture.model,
        Some(packet(fixture.profile.clone(), None, None, 1, 4)?),
        false,
    )
    .err()
    .ok_or("wrong frontier committed")?;
    assert!(matches!(
        error.downcast_ref::<araphor_data::Error>(),
        Some(araphor_data::Error::AnalysisConflict { .. })
    ));
    let wrong = PackageResultRefV1 {
        result_id: "stale-head".into(),
        commit_revision: before.commit_revision,
    };
    let error = publish(
        store,
        &attempt,
        &fixture.model,
        Some(packet(fixture.profile.clone(), None, Some(wrong), 0, 4)?),
        false,
    )
    .err()
    .ok_or("stale packet head committed")?;
    assert!(matches!(error.downcast_ref::<araphor_data::Error>(),
        Some(araphor_data::Error::Package { code: Code::Conflict, field, .. })
            if *field == "profile current head"));
    assert_eq!(store.meta()?, before);
    assert!(store.processor_gaps(&fixture.profile.scope, 0)?.is_empty());
    Ok(())
}

#[test]
fn required_profile_rejects_gap() -> TestResult {
    let fixture = Fixture::new(ProcessorClassV1::Required)?;
    let store = &fixture.store;
    let (_, attempt) = fixture.attempt("required")?;
    let before = store.meta()?;
    let health = store.processor_health(&fixture.profile.scope)?;
    let error = publish(
        store,
        &attempt,
        &fixture.model,
        Some(packet(fixture.profile.clone(), None, None, 0, 4)?),
        false,
    )
    .err()
    .ok_or("Required gap committed")?;
    assert!(
        matches!(error.downcast_ref::<araphor_data::Error>(), Some(araphor_data::Error::AnalysisState { reason, .. }) if *reason == "only optional Discovery can consume expired input")
    );
    assert_eq!(store.meta()?, before);
    assert_eq!(store.processor_health(&fixture.profile.scope)?, health);
    assert!(store.processor_gaps(&fixture.profile.scope, 0)?.is_empty());
    Ok(())
}

#[test]
fn profile_clips_expired_range() -> TestResult {
    let fixture = Fixture::new(ProcessorClassV1::Optional)?;
    let store = &fixture.store;
    let mut profile = fixture.profile.clone();
    profile.gaps[0].last_cursor = 2;
    let (_, first) = fixture.attempt("clip-first")?;
    let (_, receipt) = publish(
        store,
        &first,
        &fixture.model,
        Some(packet(profile.clone(), None, None, 0, 2)?),
        false,
    )?;
    let receipt = receipt.ok_or("clipped profile")?;
    let previous = PackageResultRefV1 {
        result_id: profile.profile_id.clone(),
        commit_revision: receipt.commit_revision,
    };
    let body = store.read_result([1; 16], &profile.profile_id)?;
    assert_eq!(store.processor_gaps(&profile.scope, 0)?, profile.gaps);
    profile.revision += 1;
    profile.profile_id = "profile-next".into();
    profile.updated_utc_ns += 1;
    profile.gaps.push(AnalysisGapV1 {
        first_cursor: 3,
        last_cursor: 3,
        ..fixture.profile.gaps[0]
    });
    let (_, second) = fixture.attempt("clip-second")?;
    publish(
        store,
        &second,
        &fixture.model,
        Some(packet(
            profile.clone(),
            Some(previous.clone()),
            Some(previous.clone()),
            2,
            4,
        )?),
        false,
    )?;
    assert_eq!(store.read_result([1; 16], &previous.result_id)?, body);
    assert_eq!(store.processor_gaps(&profile.scope, 0)?, profile.gaps);
    let health = store
        .processor_health(&profile.scope)?
        .ok_or("profile health")?;
    assert_eq!((health.consumed_cursor, health.resume_floor), (4, 3));
    assert!(health.incomplete);
    Ok(())
}

#[cfg(feature = "test-fixtures")]
#[test]
fn profile_cancel_at_commit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let (_, model) = instance(&store)?;
    let profile = profile("cancelled");
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    super::super::super::attempts::append(&store, 1)?;
    let attempt = attempt(&store, "cancelled")?;
    let before = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    let changes = store.subscribe_revision();
    let control = std::sync::Arc::new(AnalysisReadControl::default());
    let cancelled = std::sync::Arc::clone(&control);
    store.set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeResultCommit,
        move || cancelled.cancel(),
    )?;
    let error = publish_checked(
        &store,
        &attempt,
        &model,
        Some(packet(profile.clone(), None, None, 0, 1)?),
        &control,
        || Ok(()),
    )
    .err()
    .ok_or("cancelled profile committed")?;
    assert!(matches!(
        error.downcast_ref::<araphor_data::Error>(),
        Some(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert!(store.processor_result(&profile.scope)?.is_none());
    assert!(!changes.has_changed()?);
    publish(
        &store,
        &attempt,
        &model,
        Some(packet(profile, None, None, 0, 1)?),
        false,
    )?;
    Ok(())
}

#[test]
fn profile_gap_requires_capture() -> TestResult {
    let mut fixture = Fixture::raw()?;
    fixture
        .store
        .register_processor(&fixture.profile.scope, ProcessorClassV1::Optional, 1)?;
    let captured = capture(&fixture.store, &["discovery_state"], true)?;
    let attempt = fixture.store.register_managed_attempt(
        &captured,
        &super::super::super::attempts::request("before-expiry", true),
        || Ok(()),
    )?;
    let original = fixture.profile.clone();
    fixture.expire()?;
    let before = fixture.store.meta()?;
    let journal = fixture.store.database().inner().journal_head()?;
    let error = publish(
        &fixture.store,
        &attempt,
        &fixture.model,
        Some(packet(fixture.profile.clone(), None, None, 0, 4)?),
        false,
    )
    .err()
    .ok_or("future expiry authorized a captured gap")?;
    assert!(matches!(error.downcast_ref::<araphor_data::Error>(),
        Some(araphor_data::Error::AnalysisState { reason, .. })
            if reason == "the discovery gap differs from its captured expiry"));
    assert_eq!(fixture.store.meta()?, before);
    assert_eq!(fixture.store.database().inner().journal_head()?, journal);
    assert!(fixture.store.processor_gaps(&original.scope, 0)?.is_empty());
    publish(
        &fixture.store,
        &attempt,
        &fixture.model,
        Some(packet(original.clone(), None, None, 0, 4)?),
        false,
    )?;
    let health = fixture
        .store
        .processor_health(&original.scope)?
        .ok_or("captured health")?;
    assert_eq!((health.consumed_cursor, health.resume_floor), (4, 0));
    assert!(fixture.store.processor_gaps(&original.scope, 0)?.is_empty());
    let Fixture {
        store, directory, ..
    } = fixture;
    drop(store);
    let store = NativeStore::open(&directory.path().join("data"))?;
    assert_eq!(store.processor_health(&original.scope)?, Some(health));
    assert_eq!(
        DiscoveryProfileV1::try_from(
            store
                .read_result([1; 16], &original.profile_id)?
                .ok_or("captured profile")?
                .as_slice()
        )?,
        original
    );
    Ok(())
}

#[test]
fn profile_rejects_stale_head() -> TestResult {
    let fixture = Fixture::new(ProcessorClassV1::Optional)?;
    let store = &fixture.store;
    let (_, first) = fixture.attempt("head-first")?;
    let (_, receipt) = publish(
        store,
        &first,
        &fixture.model,
        Some(packet(fixture.profile.clone(), None, None, 0, 4)?),
        false,
    )?;
    let first = PackageResultRefV1 {
        result_id: fixture.profile.profile_id.clone(),
        commit_revision: receipt.ok_or("first head")?.commit_revision,
    };
    let mut next = fixture.profile.clone();
    next.profile_id = "next-head".into();
    next.revision += 1;
    next.updated_utc_ns += 1;
    let (_, second) = fixture.attempt("head-next")?;
    publish(
        store,
        &second,
        &fixture.model,
        Some(packet(
            next.clone(),
            Some(first.clone()),
            Some(first.clone()),
            4,
            4,
        )?),
        false,
    )?;
    let (_, stale) = fixture.attempt("head-stale")?;
    next.profile_id = "stale-change".into();
    let before = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    let head = store.processor_result(&next.scope)?;
    let error = publish(
        store,
        &stale,
        &fixture.model,
        Some(packet(next, Some(first.clone()), Some(first), 4, 4)?),
        false,
    )
    .err()
    .ok_or("stale progress head committed")?;
    assert!(matches!(
        error.downcast_ref::<araphor_data::Error>(),
        Some(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert_eq!(store.processor_result(&fixture.profile.scope)?, head);
    Ok(())
}

#[test]
fn profile_gap_rejects_damage() -> TestResult {
    for remove in [true, false] {
        let fixture = Fixture::new(ProcessorClassV1::Optional)?;
        let (_, attempt) = fixture.attempt("damaged")?;
        publish(
            &fixture.store,
            &attempt,
            &fixture.model,
            Some(packet(fixture.profile.clone(), None, None, 0, 4)?),
            false,
        )?;
        let view = fixture.store.view()?;
        let (key, _) = view
            .snapshot()
            .prefix(b"\0data/@progress/gap/")
            .next()
            .ok_or("accepted gap")??;
        let mut tx = fixture.store.write()?;
        if remove {
            tx.native().remove(key);
        } else {
            let mut gap = fixture.profile.gaps[0];
            gap.commit_revision += 1;
            let mut bytes = vec![0];
            bytes.extend(rmp_serde::to_vec_named(&gap)?);
            tx.native().insert(key, bytes);
        }
        tx.commit([])?;
        let Fixture {
            store, directory, ..
        } = fixture;
        drop((view, store));
        assert!(
            NativeStore::open(&directory.path().join("data")).is_err(),
            "accepted remove={remove}"
        );
    }
    Ok(())
}
