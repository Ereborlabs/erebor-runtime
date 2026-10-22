use super::*;
use crate::PackageErrorCodeV1 as Code;

#[test]
fn metadata_skips_prior_ipc() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let mut fixture = Fixture::admit(&store)?;
    let mut spec = fixture.instance.spec.clone();
    let mut grant = fixture.instance.grant.clone();
    spec.id = "metadata".into();
    grant.selection.contexts = crate::Selection::All;
    grant.selection.select_profiles(crate::Selection::All)?;
    fixture.instance = store.admit_managed(&spec, &grant, || Ok(()))?;
    let context = crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "metadata-fixture".into(),
            entity_key: vec![1],
            lifetime_key: vec![1],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: vec![1],
    };
    let changed = store.commit_context(&context)?;
    let requests = AnalysisTableRequests::new();
    let page = store.read_managed_tables(
        &fixture.instance.grant.selection,
        &ManagedRead {
            instance: fixture.instance.clone(),
            rebuild: false,
            completed: None,
        },
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            inputs: None,
            mode: AnalysisReadModeV1::Complete,
            now: 10,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(page.page.tables.is_empty());
    assert_eq!(page.page.extraction.references.len(), 1);
    let reference = page.page.extraction.references[0]
        .context()
        .ok_or("captured context")?;
    assert_eq!(reference.key, context.key);
    assert_eq!(reference.commit_revision, changed);
    let captured = page.state;
    let mut input = request("metadata");
    input.frontier = Some(ManagedFrontier {
        cursor: vec![1],
        next_change: None,
    });
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let receipt = fixture.publish(
        &store,
        &attempt,
        &evaluations,
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    let selected = ManagedRead {
        instance: fixture.current(&store)?,
        rebuild: false,
        completed: Some(receipt.commit_revision),
    };
    let mut selection = selected.instance.grant.selection.clone();
    selection.select_profiles(crate::Selection::Exact(Vec::new()))?;
    let tables = AnalysisTableRequests::from([("context_versions".into(), None)]);
    let before = store.meta()?;
    let stale = ManagedRead {
        instance: fixture.instance.clone(),
        rebuild: false,
        completed: Some(0),
    };
    assert!(matches!(
        store.managed_dependency_revision(
            &selection,
            &tables,
            &stale,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        ),
        Err(crate::Error::Package {
            code: Code::Conflict,
            field: "managed capture generation",
            ..
        })
    ));
    let metadata = store.managed_dependency_revision(
        &selection,
        &tables,
        &selected,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(metadata, (before.clone(), changed));
    assert!(metadata.1 <= captured.revision());
    assert!(receipt.commit_revision > captured.revision());
    assert!(matches!(
        store.managed_dependency_revision(
            &selection,
            &tables,
            &selected,
            AnalysisExtractLimits {
                keys: Some(0),
                ..Default::default()
            },
            &AnalysisReadControl::default(),
        ),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "selected input keys",
            ..
        })
    ));
    let dependent = store.managed_dependency_revision(
        &selected.instance.grant.selection,
        &tables,
        &selected,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(dependent.1, receipt.commit_revision);
    {
        let mut writer = store.writer()?;
        let count = writer.get_mut()?.execute(
            "UPDATE managed_arrow SET ipc = ? WHERE role = 'checkpoint'",
            params![vec![0_u8, 1, 2, 3]],
        )?;
        assert_eq!(count, 2);
    }
    assert_eq!(
        store.managed_dependency_revision(
            &selection,
            &tables,
            &selected,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?,
        metadata
    );
    assert!(store
        .read_managed_tables(
            &selection,
            &selected,
            AnalysisTableRead {
                requests: &tables,
                event_ranges: None,
                inputs: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )
        .is_err());
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn metadata_fences_managed_head() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let tables = AnalysisTableRequests::new();
    let control = AnalysisReadControl::default();
    let mut selected = ManagedRead {
        instance: fixture.instance.clone(),
        rebuild: false,
        completed: Some(0),
    };
    let read = |selected: &ManagedRead| {
        store.managed_dependency_revision(
            &selected.instance.grant.selection,
            &tables,
            selected,
            AnalysisExtractLimits::default(),
            &control,
        )
    };
    assert_eq!(read(&selected)?.1, 0);
    let active = store.set_managed_running(
        [1; 16],
        "counter",
        selected.instance.lifecycle,
        true,
        || Ok(()),
    )?;
    let before = store.meta()?;
    assert!(matches!(
        read(&selected),
        Err(crate::Error::Package {
            code: Code::Conflict,
            field: "managed capture generation",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    selected.instance = active;
    let captured = fixture.capture(&store, false)?;
    let attempt =
        store.register_managed_attempt(&captured, &request("metadata-pending"), || Ok(()))?;
    let before = store.meta()?;
    assert!(matches!(
        read(&selected),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    let terminal = store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    let before = store.meta()?;
    assert!(matches!(
        read(&selected),
        Err(crate::Error::Package {
            code: Code::Conflict,
            field: "managed capture completion",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    selected.completed = Some(terminal.revision);
    assert_eq!(read(&selected)?.1, 0);
    let mut foreign = selected.instance.grant.selection.clone();
    foreign.tenant_id = [2; 16];
    assert!(matches!(
        store.managed_dependency_revision(
            &foreign,
            &tables,
            &selected,
            AnalysisExtractLimits::default(),
            &control
        ),
        Err(crate::Error::Package {
            code: Code::Invalid,
            field: "managed capture scope",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    Ok(())
}
