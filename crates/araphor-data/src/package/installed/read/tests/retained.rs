use super::*;

struct RetainedFixture {
    fixture: Fixture,
    selected: PackageBundleV1,
    authority: Arc<SelectionAuthority>,
    query: Arc<QueryOwner>,
    execution: InstalledAnalysis,
}

impl RetainedFixture {
    fn new(mode: &str) -> TestResult<Self> {
        let fixture = Fixture::new()?;
        let mut selected = component();
        let artifact = &mut selected.artifacts[0];
        let mut echo = artifact.descriptor.exports[0].clone();
        echo.name = "evaluate".into();
        echo.inputs.clear();
        artifact.descriptor.exports.push(echo);
        if let PackageImplementationV1::Wasm { exports, .. } = &mut artifact.implementations[0] {
            exports.push("evaluate".into());
        }
        fixture.owner.execute_sync(
            fixture.grant.clone(),
            PackageRequestV1::Install {
                scope_id: "test".into(),
                bundle: selected.clone(),
                parameters: Some(serde_json::json!({
                    "runtime-fixture": {
                        "count-input": {"mode": "sum-input", "amount": 0},
                        "evaluate": {"mode": mode, "amount": 17}
                    }
                })),
            },
            &AnalysisReadControl::with_timeout(Duration::from_secs(60))?,
        )?;
        let authority = Arc::new(SelectionAuthority {
            base: fixture.authority.clone(),
            expected: selected.clone(),
            checks: AtomicUsize::new(0),
            admissions: AtomicUsize::new(0),
        });
        let query = Arc::new(QueryOwner::new(
            fixture.store.clone(),
            QueryLimits {
                evaluate_timeout: Duration::from_secs(30),
                ..Default::default()
            },
        )?);
        let mut owner =
            AnalysisPackageOwner::new(fixture.store.clone(), query.clone(), authority.clone())?;
        owner.prepare_test_code()?;
        let execution = InstalledAnalysis::new(Arc::new(owner), "test")?;
        Ok(Self {
            fixture,
            selected,
            authority,
            query,
            execution,
        })
    }

    fn echo(&self) -> sdk::Result<sdk::Evaluation> {
        let mut input = evaluation(&self.selected)?;
        input.export = "evaluate".into();
        input.inputs.clear();
        Ok(input)
    }

    fn assert_value(result: &crate::InstalledEvaluation, value: u64) -> TestResult {
        let values = result.output.datasets[0].batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("retained component output")?;
        assert_eq!(values.values().as_ref(), &[value]);
        Ok(())
    }
}

#[test]
fn snapshot_reuses_bundle() -> TestResult {
    let fixture = RetainedFixture::new("echo")?;
    let snapshot = fixture.execution.snapshot([1; 16])?;
    let pinned = snapshot.snapshot.as_ref().ok_or("retained snapshot")?;
    assert_eq!(pinned.pins.len(), 2);
    assert_eq!(pinned.bundles.len(), 1);
    assert_eq!(pinned.bundles[0].value.artifacts.len(), 2);
    let shared = snapshot.snapshot([1; 16])?;
    assert!(Arc::ptr_eq(
        pinned,
        shared.snapshot.as_ref().ok_or("shared snapshot")?
    ));
    assert!(snapshot.snapshot([2; 16]).is_err());
    let references = snapshot.refs()?;
    let historical = shared.pin_at([1; 16], &references)?;
    let retained = historical.snapshot.as_ref().ok_or("historical snapshot")?;
    assert_eq!(retained.bundles.len(), 1);
    assert_eq!(retained.bundles[0].value.root, pinned.bundles[0].value.root);
    let readers = (0..16)
        .map(|_| fixture.fixture.store.reserve_reader())
        .collect::<Result<Vec<_>>>()?;
    assert!(matches!(
        fixture.fixture.store.reserve_reader(),
        Err(crate::Error::AnalysisBusy {
            resource: "reader",
            ..
        })
    ));
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    let descriptors = shared.descriptors([1; 16])?;
    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].exports.len(), 2);
    let count = evaluation(&fixture.selected)?;
    let result = shared.evaluate([1; 16], "runtime-fixture", &count, &control)?;
    RetainedFixture::assert_value(&result, 7)?;
    drop(result);
    let echo = fixture.echo()?;
    let result = shared.evaluate([1; 16], "runtime-fixture", &echo, &control)?;
    RetainedFixture::assert_value(&result, 17)?;
    drop(result);
    assert_eq!(fixture.authority.admissions.load(Ordering::SeqCst), 10);
    assert_eq!(fixture.authority.checks.load(Ordering::SeqCst), 20);
    let result = historical.evaluate([1; 16], "runtime-fixture", &count, &control)?;
    RetainedFixture::assert_value(&result, 7)?;
    drop(result);
    assert!(historical
        .authorize([1; 16], &historical.revisions(), || Ok(()))
        .is_err());
    fixture.fixture.authority.set_revision(0);
    assert!(matches!(
        shared.evaluate([1; 16], "runtime-fixture", &count, &control),
        Err(crate::Error::Package {
            code: Code::Denied,
            field: "fixture grant",
            ..
        })
    ));
    drop(readers);
    Ok(())
}

#[test]
fn snapshot_leases_release() -> TestResult {
    let fixture = RetainedFixture::new("echo")?;
    let snapshot = fixture.execution.snapshot([1; 16])?;
    let weak = Arc::downgrade(snapshot.snapshot.as_ref().ok_or("retained snapshot")?);
    let retained = Arc::downgrade(
        &snapshot
            .snapshot
            .as_ref()
            .ok_or("retained snapshot")?
            .bundles[0],
    );
    let shared = snapshot.clone();
    let capacity = QueryLimits::default().input_capacity;
    assert!(fixture.query.retain_analysis_input(capacity).is_err());
    drop(snapshot);
    assert!(weak.upgrade().is_some());
    assert!(retained.upgrade().is_some());
    assert!(fixture.query.retain_analysis_input(capacity).is_err());
    drop(shared);
    assert!(weak.upgrade().is_none());
    assert!(retained.upgrade().is_none());
    drop(fixture.query.retain_analysis_input(capacity)?);
    Ok(())
}

#[test]
fn result_metadata_keeps_lease() -> TestResult {
    let fixture = RetainedFixture::new("echo")?;
    let snapshot = fixture.execution.snapshot([1; 16])?;
    let pinned = snapshot.snapshot.as_ref().ok_or("retained snapshot")?;
    let artifact = pinned.bundles[0]
        .value
        .artifacts
        .iter()
        .find(|artifact| artifact.descriptor.id == "runtime-fixture")
        .ok_or("retained artifact")?;
    let metadata = artifact.descriptor.allocated_bytes() + "1".len();
    let result = snapshot.evaluate(
        [1; 16],
        "runtime-fixture",
        &evaluation(&fixture.selected)?,
        &AnalysisReadControl::with_timeout(Duration::from_secs(60))?,
    )?;
    let retained = result.evaluation.allocated_bytes() + metadata;
    drop(snapshot);
    let capacity = QueryLimits::default().input_capacity;
    let rest = fixture.query.retain_analysis_input(capacity - retained)?;
    assert!(fixture.query.retain_analysis_input(1).is_err());
    drop(result);
    drop(fixture.query.retain_analysis_input(retained)?);
    drop(rest);
    drop(fixture.query.retain_analysis_input(capacity)?);
    Ok(())
}

#[test]
fn retained_trap_releases_capacity() -> TestResult {
    let fixture = RetainedFixture::new("trap")?;
    let snapshot = fixture.execution.snapshot([1; 16])?;
    assert!(matches!(
        snapshot.evaluate(
            [1; 16],
            "runtime-fixture",
            &fixture.echo()?,
            &AnalysisReadControl::with_timeout(Duration::from_secs(60))?,
        ),
        Err(crate::Error::PackageWasm {
            code: Code::Incomplete,
            ..
        })
    ));
    let cancelled = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    cancelled.cancel()?;
    assert!(matches!(
        snapshot.evaluate([1; 16], "runtime-fixture", &fixture.echo()?, &cancelled),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    drop(snapshot);
    drop(
        fixture
            .query
            .retain_analysis_input(QueryLimits::default().input_capacity)?,
    );
    Ok(())
}

#[test]
fn historical_snapshot_replaces_bundle() -> TestResult {
    let mut fixture = RetainedFixture::new("echo")?;
    let original =
        InstalledAnalysis::new(fixture.fixture.owner.clone(), "test")?.snapshot([1; 16])?;
    let references = original.refs()?;
    fixture
        .fixture
        .store
        .commit_context(&crate::AnalysisContextVersionV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "discovery-source-v1".into(),
                entity_key: b"retained-bundle".to_vec(),
                lifetime_key: b"fixture".to_vec(),
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant,
            body: serde_json::to_vec(&serde_json::json!({"installed_packages": references}))?,
        })?;
    let mut updated = fixture.selected.clone();
    updated.root.revision = "2".into();
    updated.artifacts[0].descriptor.revision = "2".into();
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    fixture.fixture.renew();
    fixture.fixture.owner.execute_sync(
        fixture.fixture.grant.clone(),
        PackageRequestV1::Update {
            scope_id: "test".into(),
            bundle: updated,
        },
        &control,
    )?;
    let current =
        InstalledAnalysis::new(fixture.fixture.owner.clone(), "test")?.snapshot([1; 16])?;
    let historical = current.pin_at([1; 16], &references)?;
    let repinned = original.pin_at([1; 16], &references)?;
    let renewed: InstalledContext = AnalysisPackageOwner::decode(&repinned.pins()[0].metadata)?;
    assert_eq!(renewed.grant.revision, fixture.fixture.grant.revision);
    assert_eq!(repinned.refs()?, references);
    assert_eq!(
        current.snapshot.as_ref().ok_or("current snapshot")?.bundles[0]
            .value
            .root
            .revision,
        "2"
    );
    let pinned = historical.snapshot.as_ref().ok_or("historical snapshot")?;
    assert_eq!(pinned.bundles.len(), 1);
    assert_eq!(pinned.bundles[0].value.root.revision, "1");
    assert_eq!(historical.refs()?, references);
    let readers = (0..16)
        .map(|_| fixture.fixture.store.reserve_reader())
        .collect::<Result<Vec<_>>>()?;
    let input = evaluation(&fixture.selected)?;
    let result = historical.evaluate([1; 16], "runtime-fixture", &input, &control)?;
    assert_eq!(result.revision, "1");
    RetainedFixture::assert_value(&result, 7)?;
    drop(result);
    let result = current.evaluate([1; 16], "runtime-fixture", &input, &control)?;
    assert_eq!(result.revision, "2");
    RetainedFixture::assert_value(&result, 7)?;
    drop(result);
    let result = repinned.evaluate([1; 16], "runtime-fixture", &input, &control)?;
    assert_eq!(result.revision, "1");
    RetainedFixture::assert_value(&result, 7)?;
    drop(result);
    drop(readers);
    let mut committed = false;
    assert!(matches!(
        original.authorize([1; 16], &original.revisions(), || {
            committed = true;
            Ok(())
        }),
        Err(crate::Error::Package {
            code: Code::Conflict,
            field: "installed commit revision",
            ..
        })
    ));
    assert!(!committed);
    fixture.fixture.owner.execute_sync(
        fixture.fixture.grant.clone(),
        PackageRequestV1::Remove {
            scope_id: "test".into(),
            package_id: "runtime-fixture".into(),
        },
        &control,
    )?;
    assert!(current
        .authorize([1; 16], &current.revisions(), || {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    assert!(original.pin_at([1; 16], &references).is_err());
    assert!(
        InstalledAnalysis::new(fixture.fixture.owner.clone(), "test")?
            .pin_at([1; 16], &references)
            .is_err()
    );
    Ok(())
}
