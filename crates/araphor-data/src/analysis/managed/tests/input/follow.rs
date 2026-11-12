use super::*;

struct FollowFixture {
    _directory: tempfile::TempDir,
    store: AnalysisStore,
    fixture: Fixture,
}

impl FollowFixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("store"))?;
        let source = crate::analysis::tests::identity();
        let mut fixture = Fixture::admit_scope(
            &store,
            false,
            AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]),
        )?;
        let mut spec = fixture.instance.spec.clone();
        spec.id = "graph-prefix".into();
        spec.destination = crate::ManagedDestination::Graph {
            source,
            calls: BTreeSet::from([10, 11]),
            operation: crate::ManagedGraphOperation::Evaluate,
            events_sql: "SELECT * FROM events".into(),
            control_sql: "SELECT * FROM graph_state".into(),
        };
        fixture.instance = store.admit_managed(&spec, &fixture.instance.grant, || Ok(()))?;
        fixture.instance = store.set_managed_running(
            [1; 16],
            &spec.id,
            fixture.instance.lifecycle,
            true,
            || Ok(()),
        )?;
        Saved::append(&store, 1)?;
        Ok(Self {
            _directory: directory,
            store,
            fixture,
        })
    }

    fn capture(&self) -> TestResult<ManagedCapture> {
        let cursor = AnalysisStore::table_schemas()["events"].index_of("source_cursor")?;
        let requests =
            AnalysisTableRequests::from([("events".into(), Some(BTreeSet::from([cursor])))]);
        let instance = self.fixture.current(&self.store)?;
        Ok(self
            .store
            .read_managed_tables_filtered(
                &instance.grant.selection.project(&requests)?,
                &ManagedRead {
                    instance,
                    expected: None,
                    rebuild: false,
                    follow: true,
                    completed: Some(0),
                    source: None,
                    execution: None,
                },
                AnalysisTableRead {
                    requests: &requests,
                    event_ranges: None,
                    mode: AnalysisReadModeV1::Complete,
                    now: 10,
                },
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                None,
            )?
            .state)
    }

    fn input() -> ManagedRequest {
        let mut input = request("graph-prefix");
        input.frontier = Some(ManagedFrontier {
            cursor: vec![1],
            next_change: None,
            pending: false,
        });
        input
    }

    fn append_foreign(&self) -> TestResult {
        let mut source = crate::analysis::tests::identity();
        source.source_id = [93; 16];
        let frame = Vec::<u8>::try_from(&crate::EvidenceRecord {
            observed_boottime_ns: 2,
            ..Default::default()
        })?;
        self.store.accept_validated_batch(
            source,
            crate::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 2,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        Ok(())
    }

    fn cut(
        &self,
    ) -> TestResult<(
        crate::AnalysisStoreMetaV1,
        BTreeMap<Vec<u8>, Vec<u8>>,
        Option<fjall::Cursor>,
    )> {
        let records = self
            .store
            .view()?
            .snapshot()
            .prefix(b"")
            .map(|entry| {
                let (key, bytes) = entry?;
                Ok((key.to_vec(), bytes.to_vec()))
            })
            .collect::<TestResult<BTreeMap<_, _>>>()?;
        Ok((
            self.store.meta()?,
            records,
            self.store.database().inner().journal_head()?,
        ))
    }
}

#[test]
fn missing_follow_is_finite() -> TestResult {
    let fixture = FollowFixture::new()?;
    let mut captured = fixture.capture()?;
    assert!(captured.follows_graph());
    let mut legacy = serde_json::to_value(&captured.contract)?;
    legacy
        .as_object_mut()
        .ok_or("capture object")?
        .remove("follow");
    captured.contract = serde_json::from_value(legacy)?;
    assert!(!captured.follows_graph());
    fixture.append_foreign()?;
    let before = fixture.cut()?;
    assert!(matches!(
        fixture
            .store
            .register_managed_attempt(&captured, &FollowFixture::input(), || Ok(())),
        Err(crate::Error::AnalysisSourceChanged { .. })
    ));
    assert_eq!(fixture.cut()?, before);
    Ok(())
}

#[test]
fn graph_follow_rejects_future() -> TestResult {
    let fixture = FollowFixture::new()?;
    let mut captured = fixture.capture()?;
    let original = captured.contract.sources.clone();
    captured
        .contract
        .sources
        .first_mut()
        .ok_or("source guard")?
        .1 = captured.revision() + 1;
    let before = fixture.cut()?;
    assert!(matches!(
        fixture
            .store
            .register_managed_attempt(&captured, &FollowFixture::input(), || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(fixture.cut()?, before);
    captured.contract.sources = original;
    fixture
        .store
        .register_managed_attempt(&captured, &FollowFixture::input(), || Ok(()))?;
    Ok(())
}
