use super::*;
use araphor_data::analysis::native::DataView;

#[derive(Debug, Eq, PartialEq, serde::Deserialize)]
pub(super) struct Notice {
    scope: ProcessorScopeV1,
    result: PackageResultRefV1,
    revision: u64,
    facts: u64,
    coverage: u64,
}

pub(super) fn row(
    view: &DataView,
    profile: &DiscoveryProfileV1,
) -> Result<Option<Notice>, Box<dyn std::error::Error>> {
    for entry in view.snapshot().prefix(b"\0data/@progress/notice/") {
        let (_, bytes) = entry?;
        let notice: Notice = rmp_serde::from_slice(&bytes[1..])?;
        if notice.result.result_id == profile.profile_id {
            assert_eq!(notice.scope, profile.scope);
            return Ok(Some(notice));
        }
    }
    Ok(None)
}

pub(super) fn at(
    view: &DataView,
    profile: &DiscoveryProfileV1,
) -> Result<Option<(u64, u64)>, Box<dyn std::error::Error>> {
    let Some(body) = view.read_result(profile.scope.identity.tenant_id, &profile.profile_id)?
    else {
        return Ok(None);
    };
    let retained = DiscoveryProfileV1::try_from(body.as_slice())?;
    Ok(Some(match row(view, profile)? {
        Some(notice) => (notice.facts, notice.coverage),
        None => (retained.facts_revision, retained.coverage_revision),
    }))
}

#[test]
fn notices_keep_each_interval() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model) = instance(&store)?;
    let mut first = profile("profile-a");
    first.interval_id = "interval-a".into();
    first.sealed = true;
    super::super::super::attempts::append(&store, 1)?;
    store.register_processor(&first.scope, ProcessorClassV1::Optional, 1)?;
    let (captured, initial) = state_attempt(&store, &first.scope.identity, "first")?;
    let (published, receipt) = publish(
        &store,
        &initial,
        &model,
        Some(packet(first.clone(), None, None, 0, 0)?),
        false,
    )?;
    let original = receipt.ok_or("first profile")?;
    let prior = PackageResultRefV1 {
        result_id: first.profile_id.clone(),
        commit_revision: original.commit_revision,
    };
    let mut second = first.clone();
    second.profile_id = "profile-b".into();
    second.interval_id = "interval-b".into();
    second.sealed = false;
    second.created_utc_ns = 1001;
    second.updated_utc_ns = 1001;
    let (_, next) = state_attempt(&store, &first.scope.identity, "second")?;
    let (_, receipt) = publish(
        &store,
        &next,
        &model,
        Some(packet(
            second.clone(),
            Some(prior.clone()),
            Some(prior.clone()),
            0,
            0,
        )?),
        false,
    )?;
    let current = receipt.ok_or("second profile")?;
    let head = PackageResultRefV1 {
        result_id: second.profile_id.clone(),
        commit_revision: current.commit_revision,
    };
    let frozen = [
        store.read_result([1; 16], &first.profile_id)?,
        store.read_result([1; 16], &second.profile_id)?,
    ];
    let result = store.processor_result(&first.scope)?;
    let mut health = store.processor_health(&first.scope)?;
    let (_, first_attempt) = state_attempt(&store, &first.scope.identity, "first-notice")?;
    let mut changes = store.subscribe_revision();
    let before = store.view()?.revision();
    let mut input = packet(first.clone(), Some(prior.clone()), Some(head.clone()), 0, 0)?;
    input.notice = Some((4, 3));
    publish(&store, &first_attempt, &model, Some(input), false)?;
    let first_notice = store.view()?.revision();
    assert_eq!(first_notice, before + 1);
    assert!(changes.has_changed()?);
    changes.borrow_and_update();
    let (_, second_attempt) = state_attempt(&store, &first.scope.identity, "second-notice")?;
    changes.borrow_and_update();
    let before = store.view()?.revision();
    let mut input = packet(second.clone(), Some(head.clone()), Some(head.clone()), 0, 0)?;
    input.notice = Some((9, 2));
    publish(&store, &second_attempt, &model, Some(input), false)?;
    let second_notice = store.view()?.revision();
    assert_eq!(second_notice, before + 1);
    assert!(changes.has_changed()?);
    let (_, noop) = state_attempt(&store, &first.scope.identity, "first-notice-noop")?;
    let noticed = row(store.view()?.as_ref(), &first)?;
    let mut input = packet(first.clone(), Some(prior.clone()), Some(head.clone()), 0, 0)?;
    input.notice = Some((2, 1));
    publish(&store, &noop, &model, Some(input), false)?;
    assert_eq!(row(store.view()?.as_ref(), &first)?, noticed);
    assert_eq!(
        at(&store.read_at(original.commit_revision)?, &first)?,
        Some((0, 0))
    );
    assert_eq!(
        at(&store.read_at(original.commit_revision)?, &second)?,
        None
    );
    assert_eq!(at(&store.read_at(first_notice)?, &first)?, Some((4, 3)));
    assert_eq!(at(&store.read_at(first_notice)?, &second)?, Some((0, 0)));
    assert_eq!(at(&store.read_at(second_notice)?, &first)?, Some((4, 3)));
    assert_eq!(at(&store.read_at(second_notice)?, &second)?, Some((9, 2)));
    let selection = AnalysisSelectionV1::new([1; 16], vec![first.scope.identity.clone()]);
    let state = state::row(&state::read(
        &store,
        store.view()?.as_ref(),
        &selection,
        None,
    )?)?;
    assert_eq!(
        (state.notice_facts_revision, state.notice_coverage_revision),
        (Some(9), Some(2))
    );
    assert_eq!(state.history.len(), 1);
    assert_eq!(
        (
            state.history[0].notice_facts_revision,
            state.history[0].notice_coverage_revision
        ),
        (4, 3)
    );
    assert_eq!(store.processor_result(&first.scope)?, result);
    for (profile, body) in [(&first, &frozen[0]), (&second, &frozen[1])] {
        assert_eq!(&store.read_result([1; 16], &profile.profile_id)?, body);
    }
    changes.borrow_and_update();
    let before = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    let retry = store.register_managed_attempt(
        &captured,
        &super::super::super::attempts::request("first", true),
        || Ok(()),
    )?;
    assert_eq!(retry.receipt(), Some(&published));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert!(!changes.has_changed()?);
    let mut third = second.clone();
    third.profile_id = "profile-c".into();
    third.revision += 1;
    third.updated_utc_ns += 1;
    let (_, invalid) = state_attempt(&store, &first.scope.identity, "invalid-profile")?;
    for mode in 0..3 {
        let before = store.meta()?;
        let journal = store.database().inner().journal_head()?;
        let input = match mode {
            0 => packet(
                third.clone(),
                Some(prior.clone()),
                Some(prior.clone()),
                0,
                0,
            )?,
            1 => packet(
                third.clone(),
                Some(PackageResultRefV1 {
                    result_id: second.profile_id.clone(),
                    commit_revision: first_notice,
                }),
                Some(head.clone()),
                0,
                0,
            )?,
            _ => {
                let mut rewritten = first.clone();
                rewritten.revision += 1;
                rewritten.updated_utc_ns += 1;
                packet(rewritten, Some(head.clone()), Some(head.clone()), 0, 0)?
            }
        };
        assert!(
            publish(&store, &invalid, &model, Some(input), false).is_err(),
            "mode {mode}"
        );
        assert_eq!(store.meta()?, before);
        assert_eq!(store.database().inner().journal_head()?, journal);
        assert!(store.read_result([1; 16], &third.profile_id)?.is_none());
    }
    store.finish_managed(
        &invalid,
        araphor_data::ManagedExit::Failed(Code::Invalid),
        || Ok(()),
    )?;
    let before = store.meta()?;
    health.as_mut().ok_or("health")?.read_revision = before.commit_revision;
    assert_eq!(store.processor_health(&first.scope)?, health);
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop((
        captured,
        initial,
        next,
        first_attempt,
        second_attempt,
        noop,
        retry,
        invalid,
        store,
    ));
    let store = NativeStore::open(&root)?;
    assert_eq!(store.meta()?, before);
    assert_eq!(store.processor_result(&first.scope)?, result);
    assert_eq!(store.processor_health(&first.scope)?, health);
    assert_eq!(at(&store.read_at(first_notice)?, &first)?, Some((4, 3)));
    assert_eq!(at(&store.read_at(first_notice)?, &second)?, Some((0, 0)));
    assert_eq!(at(&store.read_at(second_notice)?, &second)?, Some((9, 2)));
    assert_eq!(store.read_result([1; 16], &first.profile_id)?, frozen[0]);
    assert_eq!(store.read_result([1; 16], &second.profile_id)?, frozen[1]);
    Ok(())
}
