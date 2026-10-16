use super::*;

#[test]
fn reuse_checks_current_grants() -> TestResult {
    let fixture = RetainedFixture::new("echo")?;
    let previous = fixture.execution.snapshot([1; 16])?;
    let pins = Arc::downgrade(previous.snapshot.as_ref().ok_or("previous snapshot")?);
    let bundle = Arc::downgrade(&pins.upgrade().ok_or("previous pins")?.bundles[0]);
    let references = previous.refs()?;
    let current = fixture
        .execution
        .snapshot_reusing([1; 16], Some(previous))?;
    assert!(pins.upgrade().is_none());
    assert!(std::sync::Weak::ptr_eq(
        &bundle,
        &Arc::downgrade(&current.snapshot.as_ref().ok_or("current snapshot")?.bundles[0])
    ));
    assert_eq!(current.refs()?, references);
    assert_eq!(fixture.authority.admissions.load(Ordering::SeqCst), 4);
    assert_eq!(fixture.authority.checks.load(Ordering::SeqCst), 8);
    let result = current.evaluate(
        [1; 16],
        "runtime-fixture",
        &fixture.echo()?,
        &AnalysisReadControl::with_timeout(Duration::from_secs(60))?,
    )?;
    RetainedFixture::assert_value(&result, 17)?;
    drop(result);
    fixture.fixture.authority.set_revision(0);
    assert!(matches!(
        fixture.execution.snapshot_reusing([1; 16], Some(current)),
        Err(crate::Error::Package {
            code: Code::Denied,
            field: "fixture grant",
            ..
        })
    ));
    assert!(bundle.upgrade().is_none());
    drop(
        fixture
            .query
            .retain_analysis_input(QueryLimits::default().input_capacity)?,
    );
    Ok(())
}

#[test]
fn reuse_tracks_active_roots() -> TestResult {
    let fixture = RetainedFixture::new("echo")?;
    let execution = InstalledAnalysis::new(fixture.fixture.owner.clone(), "test")?;
    let previous = execution.snapshot([1; 16])?;
    let bundle = Arc::downgrade(
        &previous
            .snapshot
            .as_ref()
            .ok_or("previous snapshot")?
            .bundles[0],
    );
    let mut added = component();
    added.root.package_id = "other-fixture".into();
    added.artifacts[0].descriptor.id = added.root.package_id.clone();
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    fixture.fixture.owner.execute_sync(
        fixture.fixture.grant.clone(),
        PackageRequestV1::Install {
            scope_id: "test".into(),
            bundle: added,
            parameters: Some(serde_json::json!({
                "other-fixture": {"count-input": {"mode": "sum-input", "amount": 0}}
            })),
        },
        &control,
    )?;
    let current = execution.snapshot_reusing([1; 16], Some(previous))?;
    assert_eq!(current.pins().len(), 3);
    assert_eq!(
        current
            .snapshot
            .as_ref()
            .ok_or("current snapshot")?
            .bundles
            .len(),
        2
    );
    assert!(current
        .refs()?
        .iter()
        .any(|reference| reference.package_id == "other-fixture"));
    assert!(current
        .snapshot
        .as_ref()
        .ok_or("current snapshot")?
        .bundles
        .iter()
        .any(|entry| std::sync::Weak::ptr_eq(&bundle, &Arc::downgrade(entry))));
    fixture.fixture.owner.execute_sync(
        fixture.fixture.grant.clone(),
        PackageRequestV1::Remove {
            scope_id: "test".into(),
            package_id: "runtime-fixture".into(),
        },
        &control,
    )?;
    let current = execution.snapshot_reusing([1; 16], Some(current))?;
    assert!(bundle.upgrade().is_none());
    assert_eq!(current.pins().len(), 1);
    assert_eq!(current.refs()?[0].package_id, "other-fixture");
    assert_eq!(
        current
            .snapshot
            .as_ref()
            .ok_or("remaining snapshot")?
            .bundles
            .len(),
        1
    );
    let remaining = Arc::downgrade(
        &current
            .snapshot
            .as_ref()
            .ok_or("remaining snapshot")?
            .bundles[0],
    );
    fixture.fixture.owner.execute_sync(
        fixture.fixture.grant.clone(),
        PackageRequestV1::Remove {
            scope_id: "test".into(),
            package_id: "other-fixture".into(),
        },
        &control,
    )?;
    let empty = execution.snapshot_reusing([1; 16], Some(current))?;
    assert!(empty.pins().is_empty());
    assert!(empty
        .snapshot
        .as_ref()
        .ok_or("empty snapshot")?
        .bundles
        .is_empty());
    assert!(remaining.upgrade().is_none());
    drop(empty);
    drop(
        execution
            .owner
            .query
            .retain_analysis_input(QueryLimits::default().input_capacity)?,
    );
    Ok(())
}

#[test]
fn reuse_excludes_other_scope() -> TestResult {
    let fixture = RetainedFixture::new("echo")?;
    let previous = fixture.execution.snapshot([1; 16])?;
    let bundle = Arc::downgrade(
        &previous
            .snapshot
            .as_ref()
            .ok_or("previous snapshot")?
            .bundles[0],
    );
    let execution = InstalledAnalysis::new(fixture.fixture.owner.clone(), "test")?;
    let current = execution.snapshot_reusing([1; 16], Some(previous))?;
    assert!(bundle.upgrade().is_none());
    assert_eq!(current.pins().len(), 2);
    drop(
        fixture
            .query
            .retain_analysis_input(QueryLimits::default().input_capacity)?,
    );
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    fixture.fixture.owner.execute_sync(
        fixture.fixture.grant.clone(),
        PackageRequestV1::Install {
            scope_id: "other".into(),
            bundle: fixture.selected.clone(),
            parameters: Some(serde_json::json!({
                "runtime-fixture": {
                    "count-input": {"mode": "sum-input", "amount": 0},
                    "evaluate": {"mode": "echo", "amount": 17}
                }
            })),
        },
        &control,
    )?;
    let bundle = Arc::downgrade(&current.snapshot.as_ref().ok_or("current snapshot")?.bundles[0]);
    let execution = InstalledAnalysis::new(fixture.fixture.owner.clone(), "other")?;
    let current = execution.snapshot_reusing([1; 16], Some(current))?;
    assert!(bundle.upgrade().is_none());
    assert!(current.pins().iter().all(|pin| pin.key.scope_id == "other"));
    let mut grant = fixture.fixture.grant.clone();
    grant.selection = crate::AnalysisSelectionV1::tenant([2; 16]);
    fixture.fixture.owner.execute_sync(
        grant,
        PackageRequestV1::Install {
            scope_id: "other".into(),
            bundle: fixture.selected.clone(),
            parameters: Some(serde_json::json!({
                "runtime-fixture": {
                    "count-input": {"mode": "sum-input", "amount": 0},
                    "evaluate": {"mode": "echo", "amount": 17}
                }
            })),
        },
        &control,
    )?;
    let bundle = Arc::downgrade(&current.snapshot.as_ref().ok_or("current snapshot")?.bundles[0]);
    let current = execution.snapshot_reusing([2; 16], Some(current))?;
    assert!(bundle.upgrade().is_none());
    assert_eq!(current.tenant, Some([2; 16]));
    assert_eq!(current.pins().len(), 2);
    assert!(current
        .pins()
        .iter()
        .all(|pin| pin.key.tenant_id == [2; 16]));
    drop(current);
    drop(
        execution
            .owner
            .query
            .retain_analysis_input(QueryLimits::default().input_capacity)?,
    );
    Ok(())
}

#[test]
fn reuse_releases_before_loading() -> TestResult {
    let capacity = QueryLimits::default().input_capacity;
    let mut fixture = Fixture::new()?;
    let selected = component();
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    fixture.owner.execute_sync(
        fixture.grant.clone(),
        PackageRequestV1::Install {
            scope_id: "test".into(),
            bundle: selected.clone(),
            parameters: Some(serde_json::json!({
                "runtime-fixture": {"count-input": {"mode": "sum-input", "amount": 0}}
            })),
        },
        &control,
    )?;
    let execution = InstalledAnalysis::new(fixture.owner.clone(), "test")?;
    let previous = execution.snapshot([1; 16])?;
    let pins = Arc::downgrade(previous.snapshot.as_ref().ok_or("previous snapshot")?);
    let bundle = Arc::downgrade(&pins.upgrade().ok_or("previous pins")?.bundles[0]);
    let retained = fixture.owner.query.input_charge();
    let mut updated = selected;
    updated.root.revision = "2".into();
    updated.artifacts[0].descriptor.revision = "2".into();
    let transient = crate::package::installed::snapshot::InstalledBundle::new(
        &fixture.owner.query,
        updated.clone(),
    )?;
    let transient_bytes = fixture.owner.query.input_charge() - retained;
    drop(transient);
    let pressure = fixture.owner.query.retain_analysis_input(
        capacity
            .checked_sub(retained + transient_bytes)
            .ok_or("snapshot pressure capacity")?,
    )?;
    assert!(matches!(
        execution.snapshot([1; 16]),
        Err(crate::Error::AnalysisBusy {
            resource: "query input capacity",
            ..
        })
    ));
    fixture.renew();
    fixture.owner.execute_sync(
        fixture.grant.clone(),
        PackageRequestV1::Update {
            scope_id: "test".into(),
            bundle: updated.clone(),
        },
        &control,
    )?;
    let current = execution.snapshot_reusing([1; 16], Some(previous))?;
    assert!(pins.upgrade().is_none());
    assert!(bundle.upgrade().is_none());
    assert_eq!(current.pins()[0].revision, "2");
    assert_eq!(
        current.snapshot.as_ref().ok_or("current snapshot")?.bundles[0]
            .value
            .root,
        updated.root
    );
    let context: InstalledContext = AnalysisPackageOwner::decode(&current.pins()[0].metadata)?;
    assert_eq!(context.grant, fixture.grant);
    drop(current);
    drop(pressure);
    drop(fixture.owner.query.retain_analysis_input(capacity)?);
    Ok(())
}

#[test]
fn reuse_reloads_reinstalled_revision() -> TestResult {
    let fixture = Fixture::new()?;
    let selected = component();
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    let parameters = Some(serde_json::json!({
        "runtime-fixture": {"count-input": {"mode": "sum-input", "amount": 0}}
    }));
    fixture.owner.execute_sync(
        fixture.grant.clone(),
        PackageRequestV1::Install {
            scope_id: "test".into(),
            bundle: selected.clone(),
            parameters: parameters.clone(),
        },
        &control,
    )?;
    let execution = InstalledAnalysis::new(fixture.owner.clone(), "test")?;
    let previous = execution.snapshot([1; 16])?;
    let generation = previous.pins()[0].generation;
    let bundle = Arc::downgrade(
        &previous
            .snapshot
            .as_ref()
            .ok_or("previous snapshot")?
            .bundles[0],
    );
    fixture.owner.execute_sync(
        fixture.grant.clone(),
        PackageRequestV1::Remove {
            scope_id: "test".into(),
            package_id: selected.root.package_id.clone(),
        },
        &control,
    )?;
    assert!(fixture
        .store
        .package_revision([1; 16], "runtime-fixture", "1")?
        .is_none());
    assert!(fixture
        .store
        .package_revision([1; 16], "test.model", "1")?
        .is_some());
    let mut replacement = selected;
    let sdk::InputSource::Table(sdk::TableRef::Output(source)) =
        &mut replacement.artifacts[0].descriptor.exports[0].inputs[0].source
    else {
        return Err("dependency input absent".into());
    };
    source.revision = "2".into();
    let source = replacement
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.descriptor.id == "test.model")
        .ok_or("replacement dependency")?;
    source.descriptor.revision = "2".into();
    let Some(PackageImplementationV1::Sql { program, .. }) = source.implementations.first_mut()
    else {
        return Err("replacement SQL implementation".into());
    };
    program
        .outputs
        .insert("rows".into(), "SELECT 9::BIGINT UNSIGNED AS value".into());
    fixture.owner.execute_sync(
        fixture.grant.clone(),
        PackageRequestV1::Install {
            scope_id: "test".into(),
            bundle: replacement.clone(),
            parameters,
        },
        &control,
    )?;
    let current = execution.snapshot_reusing([1; 16], Some(previous))?;
    assert!(bundle.upgrade().is_none());
    assert!(current.pins()[0].generation > generation);
    let retained = current.snapshot.as_ref().ok_or("replacement snapshot")?;
    assert_eq!(retained.bundles[0].value.root, replacement.root);
    assert_eq!(retained.bundles[0].value.artifacts, replacement.artifacts);
    Ok(())
}
