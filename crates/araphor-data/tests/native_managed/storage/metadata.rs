#![cfg(feature = "test-fixtures")]

use super::*;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisExtractLimits,
    AnalysisPositionPageV1, AnalysisReadModeV1, AnalysisTableRead, AnalysisTableRequests,
    ContextSensitivityV1, ManagedExit, ManagedFrontier, ManagedPage, Selection, StorePositionV1,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn capture(
    store: &NativeStore,
    selection: &AnalysisSelectionV1,
    read: &ManagedRead,
    tables: &AnalysisTableRequests,
) -> araphor_data::Result<ManagedPage> {
    store.read_managed_tables_filtered(
        selection,
        read,
        AnalysisTableRead {
            requests: tables,
            event_ranges: None,
            mode: AnalysisReadModeV1::Metadata,
            now: 10,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )
}

fn context_metadata(
    store: &NativeStore,
    key: &AnalysisContextKeyV1,
    limits: AnalysisExtractLimits,
) -> araphor_data::Result<AnalysisPositionPageV1> {
    let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    selection.contexts = Selection::Exact(vec![key.clone()]);
    store.read_tables(
        &selection,
        AnalysisTableRead {
            requests: &AnalysisTableRequests::new(),
            event_ranges: None,
            mode: AnalysisReadModeV1::Metadata,
            now: 10,
        },
        limits,
        &AnalysisReadControl::default(),
    )
}

#[test]
fn metadata_skips_prior_ipc() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("store"))?;
    let mut fixture =
        StorageFixture::new(&store, "counter", "Retain independent call state.".into())?;
    let mut spec = fixture.instance.spec.clone();
    let mut grant = fixture.instance.grant.clone();
    spec.id = "metadata".into();
    grant.selection.contexts = Selection::All;
    grant.selection.select_profiles(Selection::All)?;
    fixture.instance = store.admit_managed(&spec, &grant, || Ok(()))?;
    let control = AnalysisReadControl::default();
    let tables = AnalysisTableRequests::from([("context_versions".into(), None)]);
    let selection = grant.selection.project(&tables)?;
    let base = store.view()?;
    let budget = super::super::graph::Budget;
    let inputs = store.subscribe_inputs_at(&base, &selection, &tables, None, &control, &budget)?;
    let context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "metadata-fixture".into(),
            entity_key: vec![1],
            lifetime_key: vec![1],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![1],
    };
    let changed = store.commit_context(&context)?;
    let reference = AnalysisContextRefV1 {
        key: context.key.clone(),
        commit_revision: changed,
    };
    let read = ManagedRead {
        source: None,
        execution: None,
        follow: false,
        expected: None,
        instance: fixture.instance.clone(),
        rebuild: false,
        completed: None,
    };
    let page = capture(&store, &selection, &read, &tables)?;
    assert!(page.page.tables.is_empty());
    assert_eq!(page.page.extraction.references.len(), 1);
    assert_eq!(
        page.page.extraction.references[0].context(),
        Some(&reference)
    );
    let captured = page.state;
    let mut input = super::request("metadata");
    input.frontier = Some(ManagedFrontier {
        pending: false,
        cursor: vec![1],
        next_change: None,
    });
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.continued(&input, 10, Some(&captured))?,
        fixture.continued(&input, 11, Some(&captured))?,
    ];
    let receipt = fixture.publish(
        &store,
        &attempt,
        &evaluations,
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    assert_eq!(receipt.frontier, input.frontier);
    for (call, value) in [(10, 2), (11, 3)] {
        assert_eq!(
            fixture
                .checkpoint(&store, &receipt.results[&call])?
                .datasets[0]
                .batches,
            fixture
                .output(value)?
                .checkpoint
                .ok_or("checkpoint")?
                .datasets[0]
                .batches
        );
    }
    let selected = ManagedRead {
        instance: fixture.current(&store)?,
        completed: Some(receipt.commit_revision),
        ..read.clone()
    };
    let stale = ManagedRead {
        completed: Some(0),
        ..read
    };
    let before = store.meta()?;
    assert!(matches!(
        capture(&store, &selection, &stale, &tables),
        Err(Error::Package {
            code: Code::Conflict,
            field: "managed capture generation",
            ..
        })
    ));
    assert!(changed <= captured.revision());
    assert!(receipt.commit_revision > captured.revision());
    let point = context_metadata(&store, &context.key, AnalysisExtractLimits::default())?;
    assert!(point.tables.is_empty());
    assert_eq!(point.extraction.references.len(), 1);
    assert_eq!(point.extraction.references[0].context(), Some(&reference));
    assert!(matches!(
        context_metadata(
            &store,
            &context.key,
            AnalysisExtractLimits {
                keys: Some(0),
                ..Default::default()
            }
        ),
        Err(Error::AnalysisInputTooLarge {
            resource: "selected input keys",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    let view = store.view()?;
    let headers = records(&view, b"\0data/X")?;
    let checkpoints = records(&view, b"\0data/U")?;
    assert_eq!(checkpoints.len(), 2);
    let mut write = store.write()?;
    for key in checkpoints.keys() {
        write.native().insert(key, vec![0u8, 1, 2, 3]);
    }
    write.commit([])?;
    let before = store.meta()?;
    assert_eq!(records(store.view()?.as_ref(), b"\0data/X")?, headers);
    let resume = store.managed_resume([1; 16], "metadata", &control)?;
    assert_eq!(resume.instance, selected.instance);
    assert_eq!(resume.completed, receipt.commit_revision);
    for scope in [&selection, &selected.instance.grant.selection] {
        let (_, metadata) = store.subscription_metadata(
            scope,
            &tables,
            10,
            AnalysisExtractLimits::default(),
            &control,
        )?;
        assert_eq!(metadata.extraction.meta, before);
        assert!(metadata.tables.is_empty());
        assert!(metadata.extraction.witnesses.is_empty());
    }
    let point = context_metadata(&store, &context.key, AnalysisExtractLimits::default())?;
    assert_eq!(point.extraction.meta, before);
    assert_eq!(point.extraction.references.len(), 1);
    assert_eq!(point.extraction.references[0].context(), Some(&reference));
    let replay = store.subscribe_inputs_at(&base, &selection, &tables, None, &control, &budget)?;
    let position = StorePositionV1 {
        commit_revision: changed,
        ordinal: u32::MAX,
    };
    assert_eq!(inputs.position(), position);
    assert_eq!(replay.position(), position);
    assert!(matches!(
        capture(&store, &selection, &selected, &tables),
        Err(Error::ManagedDecoding { .. })
    ));
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn metadata_fences_managed_head() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("store"))?;
    let fixture = StorageFixture::new(&store, "counter", "Retain independent call state.".into())?;
    let tables = AnalysisTableRequests::new();
    let control = AnalysisReadControl::default();
    let mut selected = ManagedRead {
        source: None,
        execution: None,
        follow: false,
        expected: None,
        instance: fixture.instance.clone(),
        rebuild: false,
        completed: Some(0),
    };
    let read = |selected: &ManagedRead| {
        capture(
            &store,
            &selected.instance.grant.selection,
            selected,
            &tables,
        )
    };
    let page = read(&selected)?;
    assert!(page.page.tables.is_empty());
    assert!(page.page.extraction.references.is_empty());
    assert_eq!(
        store
            .managed_resume([1; 16], "counter", &control)?
            .completed,
        0
    );
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
        Err(Error::Package {
            code: Code::Conflict,
            field: "managed capture generation",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    selected.instance = active;
    let captured = fixture.capture(&store)?;
    let attempt = store.register_managed_attempt(
        &captured,
        &super::request("metadata-pending"),
        || Ok(()),
    )?;
    let before = store.meta()?;
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &control),
        Err(Error::Package {
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
        Err(Error::Package {
            code: Code::Conflict,
            field: "managed capture completion",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    selected.completed = Some(terminal.revision);
    let page = read(&selected)?;
    assert!(page.page.tables.is_empty());
    assert!(page.page.extraction.references.is_empty());
    let mut foreign = selected.instance.grant.selection.clone();
    foreign.tenant_id = [2; 16];
    assert!(matches!(
        capture(&store, &foreign, &selected, &tables),
        Err(Error::Package {
            code: Code::Invalid,
            field: "managed capture scope",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    Ok(())
}
