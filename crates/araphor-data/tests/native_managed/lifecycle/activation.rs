use super::*;
use std::time::Duration;

async fn next(
    notices: &mut araphor_data::analysis::native::ActivationSubscription,
    revision: u64,
) -> TestResult {
    tokio::time::timeout(Duration::from_secs(1), notices.changed()).await??;
    assert_eq!(notices.position(), revision);
    Ok(())
}

async fn silent(
    notices: &mut araphor_data::analysis::native::ActivationSubscription,
) -> TestResult {
    assert!(
        tokio::time::timeout(Duration::from_millis(25), notices.changed())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn activation_follows_original_logs() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = fixture(&store, "activation")?;
    let admitted = fixture.admit(&store)?;
    let original = store.view()?;
    let mut notices = store.subscribe_activations()?;
    assert_eq!(notices.position(), original.revision());
    super::super::attempts::append(&store, 1)?;
    store.commit_contexts(&[super::super::attempts::context(1)])?;
    silent(&mut notices).await?;
    let running =
        store.set_managed_running([1; 16], "activation", admitted.lifecycle, true, || Ok(()))?;
    let requests = AnalysisTableRequests::from([(
        "context_versions".into(),
        Some(std::collections::BTreeSet::from([0])),
    )]);
    let budget = super::super::graph::Budget;
    let control = AnalysisReadControl::default();
    let inputs =
        store.subscribe_inputs(&fixture.grant.selection, &requests, None, &control, &budget)?;
    next(&mut notices, running.lifecycle).await?;
    drop(inputs);
    let resume = store.managed_resume([1; 16], "activation", &control)?;
    store.fail_managed(&resume, Code::Invalid, || Ok(()))?;
    silent(&mut notices).await?;
    let mut candidate = running.spec.clone();
    candidate
        .manifest
        .calls
        .get_mut(&10)
        .ok_or("call")?
        .arguments
        .push("new".into());
    store.prepare_managed_version(&running, &candidate, || Ok(()))?;
    silent(&mut notices).await?;
    let page = capture(&store, &running, None)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::super::attempts::request("publication", false),
        || Ok(()),
    )?;
    publish(&store, &attempt, false)?;
    silent(&mut notices).await?;
    let current = store
        .managed_instance([1; 16], "activation", &control)?
        .ok_or("instance")?;
    assert!(store
        .stop_managed(&current, || Err(Code::Denied.error("stop guard")))
        .is_err());
    silent(&mut notices).await?;
    let stopped = store.stop_managed(&current, || Ok(()))?;
    let rewound = store.subscribe_inputs_at(
        &original,
        &fixture.grant.selection,
        &requests,
        None,
        &control,
        &budget,
    )?;
    next(&mut notices, stopped.lifecycle).await?;
    let position = notices.position();
    drop(rewound);
    let rewound = store.subscribe_inputs_at(
        &original,
        &fixture.grant.selection,
        &requests,
        None,
        &control,
        &budget,
    )?;
    silent(&mut notices).await?;
    assert_eq!(notices.position(), position);
    drop(rewound);
    let mut grant = stopped.grant.clone();
    grant.principal = "renewed".into();
    let renewed = store.renew_managed(&stopped, &grant, || Ok(()))?;
    next(&mut notices, renewed.lifecycle).await?;
    let removed = store.remove_managed(&renewed, || Ok(()))?;
    next(&mut notices, removed.lifecycle).await?;
    let recreated = store.recreate_managed(&removed, &fixture.spec, &fixture.grant, || Ok(()))?;
    next(&mut notices, recreated.lifecycle).await?;
    drop((original, page, attempt, notices, store));
    let store = NativeStore::open(&root)?;
    let mut notices = store.subscribe_activations()?;
    let (cut, members) = store.active_managed(&control)?;
    assert_eq!(notices.position(), cut);
    assert!(members.is_empty());
    silent(&mut notices).await?;
    let started =
        store.set_managed_running([1; 16], "activation", recreated.lifecycle, true, || Ok(()))?;
    next(&mut notices, started.lifecycle).await?;
    let suspended = store.suspend_managed(&started, || Ok(()))?;
    next(&mut notices, suspended.lifecycle).await?;
    Ok(())
}

#[tokio::test]
async fn recreation_retires_old_consumers() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = Arc::new(NativeStore::open(&root)?);
    let fixture = fixture(&store, "consumer")?;
    let admitted = fixture.admit(&store)?;
    let control = AnalysisReadControl::default();
    let budget = super::super::graph::Budget;
    let requests = AnalysisTableRequests::from([(
        "events".into(),
        Some(std::collections::BTreeSet::from([0])),
    )]);
    let mut inputs = store.subscribe_managed_inputs(
        &admitted,
        &fixture.grant.selection,
        &requests,
        None,
        &control,
        &budget,
    )?;
    let removed = store.remove_managed(&admitted, || Ok(()))?;
    assert!(matches!(
        inputs.changed().await,
        Err(Error::Package {
            code: Code::Conflict,
            ..
        })
    ));
    let recreated = store.recreate_managed(&removed, &fixture.spec, &fixture.grant, || Ok(()))?;
    let mut current = store.subscribe_managed_inputs(
        &recreated,
        &fixture.grant.selection,
        &requests,
        None,
        &control,
        &budget,
    )?;
    super::super::attempts::append(&store, 1)?;
    assert_eq!(
        current.changed().await?.commit_revision,
        store.view()?.revision()
    );
    assert!(current.needs_initial());
    drop((inputs, current, store));
    let store = Arc::new(NativeStore::open(&root)?);
    assert!(store
        .subscribe_managed_inputs(
            &admitted,
            &fixture.grant.selection,
            &requests,
            None,
            &control,
            &budget
        )
        .is_err());
    let mut restored = store.subscribe_managed_inputs(
        &recreated,
        &fixture.grant.selection,
        &requests,
        None,
        &control,
        &budget,
    )?;
    assert!(restored.needs_initial());
    assert!(restored.changed().await?.commit_revision > recreated.generation);
    Ok(())
}
