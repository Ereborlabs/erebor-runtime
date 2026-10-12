use super::*;

fn process_twice(owner: &GraphAndFindingOwner, now: u64) -> Result<usize> {
    Ok(owner.process(now)? + owner.process(now)?)
}

fn process_bundle(revision: &str) -> TestResult<PackageBundleV1> {
    let mut bundle = AnalysisPackageOwner::required_bundles()
        .into_iter()
        .find(|bundle| bundle.root.package_id == "HF-PROC-001")
        .ok_or("process bundle")?;
    bundle.root.revision = revision.into();
    bundle.artifacts[0].descriptor.revision = revision.into();
    Ok(bundle)
}

async fn execute(execution: &InstalledAnalysis, request: PackageRequestV1) -> Result<()> {
    execution
        .testing_owner()
        .execute(
            grant(),
            request,
            Arc::new(AnalysisReadControl::with_timeout(
                std::time::Duration::from_secs(30),
            )?),
        )
        .await?;
    Ok(())
}

#[tokio::test]
async fn cache_tracks_installed_changes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let execution = InstalledAnalysis::testing(Some(store.clone()), source().tenant_id)?;
    let owner = GraphAndFindingOwner::new(
        store.clone(),
        Arc::new(Inputs::default()),
        execution.clone(),
    )?;
    accept(
        &store,
        &[record(1, &wire(1, DeniedBeforeEffect, 2, 2, [20; 16]))?],
    )?;
    coverage(&store, 1, 1, "HEALTHY")?;
    super::super::window_expiry::process_to(&owner, &store, 1, 10)?;
    let original = store
        .processor_result(&GraphAndFindingOwner::scope(&source()))?
        .ok_or("original head")?;
    let saved = owner
        .snapshot_result(source().tenant_id, &original.result_id)?
        .ok_or("original graph")?;
    let finding = saved.findings.first().ok_or("original finding")?;
    let mut progress = store
        .processor_health(&saved.scope)?
        .ok_or("original progress")?;
    assert_eq!(process_twice(&owner, 11)?, 0);

    execute(
        &execution,
        PackageRequestV1::Update {
            scope_id: AnalysisPackageOwner::DOMAIN_SCOPE.into(),
            bundle: process_bundle("2")?,
        },
    )
    .await?;
    assert_eq!(process_twice(&owner, 12)?, 1);
    let (upgraded_id, _) = owner
        .current_finding(source().tenant_id, &finding.finding_id)?
        .ok_or("upgraded head")?;
    assert_ne!(upgraded_id, original.result_id);
    let upgraded = owner
        .snapshot_result(source().tenant_id, &upgraded_id)?
        .ok_or("upgraded graph")?;
    assert_eq!(upgraded.packages[0].replay_contract_id, "HF-PROC-001/v2");
    assert_eq!(
        upgraded.witness_deadline_utc_ns,
        saved.witness_deadline_utc_ns
    );
    assert_eq!(
        owner.snapshot_result(source().tenant_id, &original.result_id)?,
        Some(saved.clone())
    );

    let mut extra = AnalysisPackageOwner::required_bundles()
        .into_iter()
        .find(|bundle| bundle.root.package_id == "HF-DW-001")
        .ok_or("credential bundle")?;
    extra.root.package_id = "fixture-extra".into();
    extra.artifacts[0].descriptor.id = extra.root.package_id.clone();
    for reason in &mut extra.artifacts[0].descriptor.exports[0].reasons {
        reason.code = reason.code.replace("HF-DW-001.", "fixture-extra.");
    }
    execute(
        &execution,
        PackageRequestV1::Install {
            scope_id: AnalysisPackageOwner::DOMAIN_SCOPE.into(),
            bundle: extra,
            parameters: None,
        },
    )
    .await?;
    assert_eq!(process_twice(&owner, 13)?, 1);
    let (current_id, _) = owner
        .current_finding(source().tenant_id, &finding.finding_id)?
        .ok_or("current head")?;
    assert_ne!(current_id, upgraded_id);
    let snapshot = owner
        .snapshot_result(source().tenant_id, &current_id)?
        .ok_or("current graph")?;
    assert_eq!(snapshot.packages.len(), 4);
    assert!(snapshot
        .packages
        .iter()
        .any(|package| package.package_id == "fixture-extra"));
    assert_eq!(snapshot.findings, upgraded.findings);
    assert_eq!(
        snapshot.witness_deadline_utc_ns,
        saved.witness_deadline_utc_ns
    );
    assert_eq!(process_twice(&owner, 14)?, 0);
    assert_eq!(
        store.processor_result(&saved.scope)?,
        Some(original.clone())
    );
    progress.read_revision = store.meta()?.commit_revision;
    assert_eq!(store.processor_health(&saved.scope)?, Some(progress));

    execute(
        &execution,
        PackageRequestV1::Remove {
            scope_id: AnalysisPackageOwner::DOMAIN_SCOPE.into(),
            package_id: "HF-PROC-001".into(),
        },
    )
    .await?;
    assert!(matches!(
        process_twice(&owner, 15),
        Err(Error::GraphInvalid {
            field: "required installed graph package",
            ..
        })
    ));
    assert_eq!(
        store
            .processor_health(&GraphAndFindingOwner::scope(&source()))?
            .ok_or("processor health")?
            .state,
        ProcessorStateV1::ProcessingFailed
    );
    assert_eq!(
        owner.snapshot_result(source().tenant_id, &current_id)?,
        Some(snapshot)
    );
    assert_eq!(
        store.processor_result(&saved.scope)?,
        Some(original.clone())
    );
    assert_eq!(
        owner.snapshot_result(source().tenant_id, &original.result_id)?,
        Some(saved)
    );
    Ok(())
}

mod authority;
mod descriptors;
