use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn owner(limits: Limits) -> TestResult<(tempfile::TempDir, Arc<Engine>)> {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let engine = Engine::new(store, limits)?;
    Ok((directory, engine))
}

#[tokio::test]
async fn execution_defaults_disable_bounds() -> TestResult {
    use datafusion::arrow::array::StringArray;
    use datafusion::execution::memory_pool::MemoryLimit;

    let limits: Limits = serde_json::from_str("{}")?;
    assert_eq!(limits, Limits::default());
    assert_eq!(limits.scan_bytes, usize::MAX);
    assert_eq!(limits.input_bytes, usize::MAX);
    assert_eq!(limits.output_rows, usize::MAX);
    assert_eq!(limits.output_bytes, usize::MAX);
    assert_eq!(limits.extract_keys, None);
    assert_eq!(limits.global_evaluations, None);
    assert_eq!(limits.tenant_evaluations, None);
    limits.validate()?;
    for limits in [
        Limits {
            input_capacity: Some(0),
            ..Limits::default()
        },
        Limits {
            output_capacity: Some(0),
            ..Limits::default()
        },
    ] {
        assert!(limits.validate().is_err());
    }
    let (_directory, engine) = owner(limits)?;
    assert!(engine.evaluations.is_none());
    assert!(engine.tenant([1; 16])?.evaluations.is_none());
    assert!(matches!(
        engine.state.runtime_env().memory_pool.memory_limit(),
        MemoryLimit::Infinite
    ));
    assert_eq!(engine.memory().prepare_input(usize::MAX)?.size(), 0);
    assert_eq!(engine.memory().prepare_output(usize::MAX)?.size(), 0);
    let mut permits = Vec::new();
    for tenant in [[1; 16], [2; 16]] {
        for _ in 0..32 {
            let permit = engine.reserve_evaluation(tenant)?;
            assert!(permit._global.is_none() && permit._local.is_none());
            permits.push(permit);
        }
    }
    drop(permits);
    let mut session = engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &AnalysisReadControl::default(),
        1,
    )?;
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Utf8,
        false,
    )]));
    let data = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::new(StringArray::from_iter_values(
            (0..601).map(|row| format!("{row}:{}", "x".repeat(2048))),
        ))],
    )?;
    assert!(data.get_array_memory_size() > 1024 * 1024);
    session.register(
        "unbounded_rows",
        Arc::clone(&schema),
        std::slice::from_ref(&data),
    )?;
    let state = engine.catalog(BTreeMap::from([(
        "unbounded_rows".into(),
        crate::sources::SourceProvider::local("unbounded_rows", schema),
    )]))?;
    let plan = Planner::new(&state)
        .build(
            Parser::default().parse("SELECT value FROM unbounded_rows")?,
            vec![],
        )
        .await?;
    let batches = session
        .stream_local(&plan, Arc::new(engine.reserve_evaluation([1; 16])?))
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    assert_eq!(
        batches.iter().map(RecordBatch::num_rows).sum::<usize>(),
        601
    );
    assert!(
        batches
            .iter()
            .map(RecordBatch::get_array_memory_size)
            .sum::<usize>()
            > 1024 * 1024
    );
    let (plan, sources) = engine
        .prepare("SELECT source_cursor FROM events", vec![])
        .await?;
    let (snapshot, stream) = session.stream(&plan, &sources, Read::Snapshot).await?;
    assert!(snapshot.page.extraction.input_bytes > 0);
    assert_eq!(
        stream
            .try_collect::<Vec<_>>()
            .await?
            .iter()
            .map(RecordBatch::num_rows)
            .sum::<usize>(),
        0
    );
    Ok(())
}

#[tokio::test]
async fn optional_evaluation_ownership() -> TestResult {
    let (_directory, engine) = owner(Limits::default())?;
    let foreign = Engine::new(Arc::clone(engine.store()), Limits::default())?;
    let session = engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &AnalysisReadControl::default(),
        1,
    )?;
    let (plan, _) = engine.prepare("SELECT 7 AS value", vec![]).await?;
    for permit in [
        engine.reserve_stream([1; 16])?,
        engine.reserve_evaluation([2; 16])?,
        foreign.reserve_evaluation([1; 16])?,
    ] {
        assert!(matches!(
            session.stream_local(&plan, Arc::new(permit)).await,
            Err(Error::Invalid {
                field: "evaluation permit",
                ..
            })
        ));
    }
    let batches = session
        .stream_local(&plan, Arc::new(engine.reserve_evaluation([1; 16])?))
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    assert_eq!(value(&batches), 7);
    Ok(())
}

#[tokio::test]
async fn optional_evaluation_limits() -> TestResult {
    for (global, tenant) in [
        (Some(2), Some(1)),
        (Some(1), None),
        (None, Some(1)),
        (Some(2), None),
    ] {
        let limits = Limits {
            global_evaluations: global,
            tenant_evaluations: tenant,
            ..Limits::default()
        };
        let restored: Limits = serde_json::from_value(serde_json::to_value(&limits)?)?;
        assert_eq!(restored, limits);
        let (_directory, engine) = owner(limits)?;
        let first = engine.reserve_evaluation([1; 16])?;
        let second = engine.reserve_evaluation([1; 16]);
        if tenant == Some(1) || global == Some(1) {
            assert!(matches!(
                second,
                Err(Error::Busy {
                    resource: "evaluation",
                    ..
                })
            ));
        } else {
            let second = second?;
            assert!(engine.reserve_evaluation([2; 16]).is_err());
            drop(second);
        }
        let other = engine.reserve_evaluation([2; 16]);
        if global == Some(1) {
            assert!(other.is_err());
        } else {
            let other = other?;
            if global == Some(2) {
                assert!(engine.reserve_evaluation([3; 16]).is_err());
            } else {
                drop(engine.reserve_evaluation([3; 16])?);
            }
            drop(other);
        }
        let waiting = engine.acquire_evaluation([1; 16]);
        futures_util::pin_mut!(waiting);
        if tenant == Some(1) || global == Some(1) {
            assert!(futures_util::poll!(&mut waiting).is_pending());
        }
        drop(first);
        drop(waiting.await?);
        drop(engine.reserve_evaluation([1; 16])?);
    }
    for (global, tenant) in [
        (Some(0), None),
        (None, Some(0)),
        (Some(tokio::sync::Semaphore::MAX_PERMITS + 1), None),
        (None, Some(tokio::sync::Semaphore::MAX_PERMITS + 1)),
        (Some(1), Some(2)),
    ] {
        assert!(Limits {
            global_evaluations: global,
            tenant_evaluations: tenant,
            ..Limits::default()
        }
        .validate()
        .is_err());
    }
    Ok(())
}

#[tokio::test]
async fn unbounded_budgets_keep_capacity() -> TestResult {
    let capacity = 64 * 1024;
    let (_directory, engine) = owner(Limits {
        input_capacity: Some(capacity),
        output_capacity: Some(capacity),
        ..Limits::default()
    })?;
    let input = engine.memory().prepare_input(usize::MAX)?;
    assert_eq!(input.size(), capacity);
    assert!(engine.memory().reserve_input(1).is_err());
    drop(input);
    let output = engine.memory().prepare_output(usize::MAX)?;
    assert_eq!(output.size(), capacity);
    assert!(engine.memory().reserve_output(1).is_err());
    drop(output);
    let session = engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &AnalysisReadControl::default(),
        1,
    )?;
    let (plan, sources) = engine
        .prepare(
            "SELECT 7 AS value FROM (SELECT COUNT(*) FROM events)",
            vec![],
        )
        .await?;
    let (snapshot, stream) = session.stream(&plan, &sources, Read::Snapshot).await?;
    assert!(snapshot.page.extraction.input_bytes > 0);
    let batches = stream.try_collect::<Vec<_>>().await?;
    assert_eq!(value(&batches), 7);
    assert!(engine.memory().reserve_input(capacity).is_err());
    assert!(engine.memory().reserve_output(capacity).is_err());
    drop((snapshot, batches));
    drop(engine.memory().reserve_input(capacity)?);
    drop(engine.memory().reserve_output(capacity)?);
    Ok(())
}

#[tokio::test]
async fn optional_extraction_keys() -> TestResult {
    let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    selection.contexts = araphor_data::Selection::Exact(
        (0..=1024)
            .map(|revision| araphor_data::AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "policy".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: revision,
            })
            .collect(),
    );
    for extract_keys in [None, Some(1024)] {
        let limits = Limits {
            extract_keys,
            ..Limits::default()
        };
        let restored: Limits = serde_json::from_value(serde_json::to_value(&limits)?)?;
        assert_eq!(restored, limits);
        let (_directory, engine) = owner(limits)?;
        let session = engine.session(selection.clone(), &AnalysisReadControl::default(), 1)?;
        let (plan, sources) = engine
            .prepare("SELECT body FROM context_versions", vec![])
            .await?;
        let metadata = session.metadata(&sources).await;
        let captured = session.stream(&plan, &sources, Read::Snapshot).await;
        if extract_keys.is_none() {
            assert_eq!(metadata?.page.extraction.missing_contexts.len(), 1025);
            let (snapshot, stream) = captured?;
            assert_eq!(snapshot.page.extraction.missing_contexts.len(), 1025);
            assert_eq!(
                stream
                    .try_collect::<Vec<_>>()
                    .await?
                    .iter()
                    .map(RecordBatch::num_rows)
                    .sum::<usize>(),
                0
            );
        } else {
            for failed in [metadata.map(|_| ()), captured.map(|_| ())] {
                let error = failed.err().ok_or("the configured key limit was ignored")?;
                assert_eq!(crate::Failure::from(&error), crate::Failure::InputTooLarge);
            }
        }
    }
    Ok(())
}
