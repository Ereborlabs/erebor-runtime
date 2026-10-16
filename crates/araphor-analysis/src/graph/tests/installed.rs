use super::*;

mod current;

fn grant() -> PackageGrantV1 {
    PackageGrantV1 {
        principal: "fixture".into(),
        revision: 1,
        selection: AnalysisSelectionV1::tenant(source().tenant_id),
        expires_utc_ns: None,
        authorization_id: None,
    }
}

#[tokio::test]
async fn installed_history_preserves_expiry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let input = credential_input()?;
    let (result_id, refs, expected) = {
        let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
        let execution = crate::InstalledAnalysis::testing(Some(store.clone()), source().tenant_id)?;
        let expected = GraphAndFindingOwner::derive(&input, &execution)?;
        let owner = GraphAndFindingOwner::new(
            store.clone(),
            Arc::new(Inputs(Mutex::new(input.facts.clone()))),
            execution.clone(),
        )?;
        accept(&store, &input.records)?;
        coverage(&store, 3, 1, "HEALTHY")?;
        super::window_expiry::process_to(&owner, &store, 3, 10)?;
        let result_id = store
            .processor_result(&GraphAndFindingOwner::scope(&source()))?
            .ok_or("graph head")?
            .result_id;
        let refs = owner
            .installed_refs(source().tenant_id, &result_id)?
            .ok_or("installed refs")?;
        assert_eq!(refs.len(), 3);
        let mut bundle = AnalysisPackageOwner::required_bundles()
            .into_iter()
            .find(|bundle| bundle.root.package_id == "HF-PROC-001")
            .ok_or("process bundle")?;
        bundle.root.revision = "2".into();
        bundle.artifacts[0].descriptor.revision = "2".into();
        execution
            .testing_owner()
            .execute(
                grant(),
                PackageRequestV1::Update {
                    scope_id: AnalysisPackageOwner::DOMAIN_SCOPE.into(),
                    bundle,
                },
                Arc::new(AnalysisReadControl::with_timeout(
                    std::time::Duration::from_secs(30),
                )?),
            )
            .await?;
        let current = GraphAndFindingOwner::derive(&input, &execution)?;
        assert_eq!(current.packages[0].replay_contract_id, "HF-PROC-001/v2");
        let historical = execution.pin_at(source().tenant_id, &refs)?;
        assert_eq!(GraphAndFindingOwner::derive(&input, &historical)?, expected);
        assert!(historical
            .authorize(source().tenant_id, &historical.revisions(), || Ok(()))
            .is_err());
        (result_id, refs, expected)
    };
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let execution = crate::InstalledAnalysis::testing(Some(store.clone()), source().tenant_id)?;
    let owner = GraphAndFindingOwner::new(
        store.clone(),
        Arc::new(Inputs::default()),
        execution.clone(),
    )?;
    assert_eq!(
        owner.installed_refs(source().tenant_id, &result_id)?,
        Some(refs.clone())
    );
    assert_eq!(
        GraphAndFindingOwner::derive(&input, &execution.pin_at(source().tenant_id, &refs)?)?,
        expected
    );
    execution
        .testing_owner()
        .execute(
            grant(),
            PackageRequestV1::Remove {
                scope_id: AnalysisPackageOwner::DOMAIN_SCOPE.into(),
                package_id: "HF-PROC-001".into(),
            },
            Arc::new(AnalysisReadControl::with_timeout(
                std::time::Duration::from_secs(30),
            )?),
        )
        .await?;
    assert!(execution.pin_at(source().tenant_id, &refs).is_err());
    let original = owner
        .snapshot_result(source().tenant_id, &result_id)?
        .ok_or("original graph")?;
    assert!(owner.refresh(&source(), original.witness_deadline_utc_ns + 1)?);
    let current = owner.current_findings(source().tenant_id)?;
    assert!(!current.is_empty());
    for (expired_id, finding) in current {
        assert_eq!(finding.state, FindingStateV1::CoverageInsufficient);
        let expired = owner
            .snapshot_result(source().tenant_id, &expired_id)?
            .ok_or("expired graph")?;
        assert!(expired
            .graph
            .edges
            .iter()
            .all(|edge| edge.key.cause == GraphCauseV1::Superseded));
        assert!(expired
            .packages
            .iter()
            .all(|package| package.state == GraphPackageStateV1::CoverageInsufficient));
        assert_eq!(
            owner.installed_refs(source().tenant_id, &expired_id)?,
            Some(refs.clone())
        );
    }
    drop(owner);
    drop(execution);
    drop(store);
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let execution = crate::InstalledAnalysis::testing(Some(store), source().tenant_id)?;
    assert!(execution
        .descriptors(source().tenant_id)?
        .iter()
        .all(|package| package.id != "HF-PROC-001"));
    assert!(GraphAndFindingOwner::derive(&input, &execution).is_err());
    Ok(())
}
