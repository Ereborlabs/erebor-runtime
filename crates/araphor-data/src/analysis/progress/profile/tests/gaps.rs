use super::*;
use crate::analysis::{progress::ResultHead, PackageResultRefV1};
use crate::{AnalysisGapV1, AnalysisReadControl, AnalysisWitnessV1, EvidenceRetentionOwner};

struct Fixture {
    store: AnalysisStore,
    profile: DiscoveryProfileV1,
    gap: AnalysisGapV1,
    _directory: tempfile::TempDir,
}

impl Fixture {
    
}

#[test]
fn profile_gaps_commit_atomically() -> TestResult {
    let fixture = Fixture::new(ProcessorClassV1::Optional)?;
    let store = &fixture.store;
    let profile = &fixture.profile;
    let before = store.meta()?;
    let health = store.processor_health(&profile.scope)?;
    let mut notices = store.subscribe_revision();
    let mut input = commit(profile);
    input.consumed_cursor = 4;
    let control = AnalysisReadControl::default();
    assert!(matches!(
        store.commit_working_profile_guarded(
            input.clone(),
            PreparedProfile::new(profile.clone())?,
            None,
            || {
                control.cancel()?;
                control.check()
            },
        ),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.processor_health(&profile.scope)?, health);
    assert!(store.processor_gaps(&profile.scope, 0)?.is_empty());
    assert!(store
        .read_result(profile.scope.identity.tenant_id, &profile.profile_id)?
        .is_none());
    assert!(!notices.has_changed()?);
    let receipt = store.commit_working_profile(
        input.clone(),
        PreparedProfile::new(profile.clone())?,
        None,
    )?;
    assert!(notices.has_changed()?);
    notices.borrow_and_update();
    assert_ne!(receipt.commit_revision, fixture.gap.commit_revision);
    assert_eq!(
        store.reader()?.get()?.query_row(
            "SELECT commit_revision, accepted_revision FROM processor_gaps
             WHERE processor_id = 'discovery'",
            [],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
        )?,
        (fixture.gap.commit_revision, receipt.commit_revision)
    );
    assert_eq!(
        store.reader()?.get()?.query_row(
            "SELECT count(*) FROM processor_gaps WHERE accepted_revision <= ?",
            params![before.commit_revision],
            |row| row.get::<_, u64>(0),
        )?,
        0
    );
    assert_eq!(store.processor_gaps(&profile.scope, 0)?, [fixture.gap]);
    let health = store
        .processor_health(&profile.scope)?
        .ok_or("profile health")?;
    assert_eq!((health.consumed_cursor, health.resume_floor), (4, 3));
    assert!(health.incomplete);
    let after = store.meta()?;
    assert_eq!(
        store.commit_working_profile(
            input.clone(),
            PreparedProfile::new(profile.clone())?,
            None,
        )?,
        receipt
    );
    assert_eq!(store.meta()?, after);
    assert!(!notices.has_changed()?);
    let Fixture {
        store,
        profile,
        gap,
        _directory: directory,
    } = fixture;
    drop(store);
    let store = AnalysisStore::open(directory.path().join("data"))?;
    assert_eq!(store.meta()?, after);
    assert_eq!(store.processor_gaps(&profile.scope, 0)?, [gap]);
    assert_eq!(store.processor_health(&profile.scope)?, Some(health));
    assert_eq!(
        DiscoveryProfileV1::try_from(
            store
                .read_result(profile.scope.identity.tenant_id, &profile.profile_id)?
                .ok_or("retained profile")?
                .as_slice(),
        )?,
        profile
    );
    assert_eq!(
        store.commit_working_profile(input, PreparedProfile::new(profile)?, None)?,
        receipt
    );
    assert_eq!(store.meta()?, after);
    Ok(())
}

#[test]
fn profile_rejects_gap_proof() -> TestResult {
    let fixture = Fixture::new(ProcessorClassV1::Optional)?;
    let store = &fixture.store;
    let before = store.meta()?;
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
        let mut input = commit(&profile);
        input.consumed_cursor = 4;
        assert!(store
            .commit_working_profile(input, PreparedProfile::new(profile)?, None)
            .is_err());
        assert_eq!(store.meta()?, before);
        assert_eq!(store.processor_health(&fixture.profile.scope)?, health);
        assert!(store.processor_gaps(&fixture.profile.scope, 0)?.is_empty());
    }
    let mut input = commit(&fixture.profile);
    input.expected_cursor = 1;
    input.consumed_cursor = 4;
    assert!(matches!(
        store.commit_working_profile(input, PreparedProfile::new(fixture.profile.clone())?, None),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    let mut writer = store.maintenance_writer()?;
    let transaction = writer.get_mut()?.transaction()?;
    let mut input = commit(&fixture.profile);
    input.consumed_cursor = 4;
    input.body = serde_json::to_vec(&fixture.profile)?;
    let wrong_head = PackageResultRefV1 {
        result_id: "stale-head".into(),
        commit_revision: before.commit_revision,
    };
    assert!(matches!(
        store.progress_rows(
            &transaction,
            &input,
            ResultHead::Current(Some(&wrong_head)),
            true,
            Some(&fixture.profile),
            &[],
        ),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    transaction.rollback()?;
    drop(writer);
    assert_eq!(store.meta()?, before);
    assert!(store.processor_gaps(&fixture.profile.scope, 0)?.is_empty());
    Ok(())
}

#[test]
fn required_profile_rejects_gap() -> TestResult {
    let fixture = Fixture::new(ProcessorClassV1::Required)?;
    let store = &fixture.store;
    let before = store.meta()?;
    let health = store.processor_health(&fixture.profile.scope)?;
    let mut input = commit(&fixture.profile);
    input.consumed_cursor = 4;
    assert!(matches!(
        store.commit_working_profile(input, PreparedProfile::new(fixture.profile.clone())?, None),
        Err(crate::Error::AnalysisState { reason, .. })
            if reason == "only optional Discovery can consume expired input"
    ));
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
    let mut input = commit(&profile);
    input.consumed_cursor = 2;
    let first =
        store.commit_working_profile(input, PreparedProfile::new(profile.clone())?, None)?;
    let previous = PackageResultRefV1 {
        result_id: profile.profile_id.clone(),
        commit_revision: first.commit_revision,
    };
    let first_body = store.read_result(profile.scope.identity.tenant_id, &profile.profile_id)?;
    assert_eq!(store.processor_gaps(&profile.scope, 0)?, profile.gaps);
    profile.revision += 1;
    profile.profile_id = "profile-next".into();
    profile.updated_utc_ns += 1;
    profile.gaps.push(AnalysisGapV1 {
        first_cursor: 3,
        last_cursor: 3,
        ..fixture.gap
    });
    let mut input = commit(&profile);
    input.expected_cursor = 2;
    input.consumed_cursor = 4;
    store.commit_working_profile(
        input,
        PreparedProfile::new(profile.clone())?,
        Some(previous.clone()),
    )?;
    assert_eq!(
        store.read_result(profile.scope.identity.tenant_id, &previous.result_id)?,
        first_body
    );
    assert_eq!(store.processor_gaps(&profile.scope, 0)?, profile.gaps);
    let health = store
        .processor_health(&profile.scope)?
        .ok_or("profile health")?;
    assert_eq!((health.consumed_cursor, health.resume_floor), (4, 3));
    assert!(health.incomplete);
    Ok(())
}
