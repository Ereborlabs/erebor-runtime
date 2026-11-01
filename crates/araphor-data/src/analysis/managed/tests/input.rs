use super::*;

mod current;
mod origins;
mod scope;

struct Saved {
    _directory: tempfile::TempDir,
    store: Arc<AnalysisStore>,
    fixture: Arc<Fixture>,
    context: crate::AnalysisContextRefV1,
    receipt: ManagedReceipt,
    requests: AnalysisTableRequests,
}

impl Saved {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open_with_limits(
            directory.path().join("store"),
            Default::default(),
            crate::StorageLimitsV1 {
                reader_admissions: Some(2),
                ..Default::default()
            },
        )?);
        Self::append(&store, 1)?;
        let context = crate::AnalysisContextVersionV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "saved-input".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant,
            body: b"{}".to_vec(),
        };
        let revision = store.commit_context(&context)?;
        let context = crate::AnalysisContextRefV1 {
            key: context.key,
            commit_revision: revision,
        };
        let fixture = Arc::new(Fixture::admit_scope(
            &store,
            false,
            AnalysisSelectionV1::tenant([1; 16]),
        )?);
        let cursor = AnalysisStore::table_schemas()["events"].index_of("source_cursor")?;
        let requests = AnalysisTableRequests::from([
            ("events".into(), Some(BTreeSet::from([cursor]))),
            ("context_versions".into(), Some(BTreeSet::new())),
            ("traces".into(), Some(BTreeSet::new())),
        ]);
        let capture = store
            .read_managed_tables_filtered(
                &fixture.instance.grant.selection.project(&requests)?,
                &ManagedRead {
                    source: None,
                    execution: None,
                    follow: false,
                    instance: fixture.instance.clone(),
                    expected: None,
                    rebuild: false,
                    completed: None,
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
            .state;
        let mut input = request("saved-first");
        input.witness_expiry = 100;
        let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&input, 10, None)?,
            fixture.evaluation(&input, 11, None)?,
        ];
        let outputs = [fixture.output(7)?, fixture.output(3)?];
        let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
        Ok(Self {
            _directory: directory,
            store,
            fixture,
            context,
            receipt,
            requests,
        })
    }

    fn append(store: &AnalysisStore, cursor: u64) -> crate::Result<()> {
        let record = crate::EvidenceRecord {
            observed_boottime_ns: cursor,
            ..Default::default()
        };
        let framed = Vec::<u8>::try_from(&record)?;
        store.accept_validated_batch(
            crate::analysis::tests::identity(),
            crate::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: cursor,
                frame_ends: vec![framed.len()],
                framed_records: framed.into(),
            },
        )?;
        Ok(())
    }

    fn capture(&self) -> TestResult<ManagedCapture> {
        let instance = self.fixture.current(&self.store)?;
        Ok(self
            .store
            .read_managed_tables_filtered(
                &instance.grant.selection.project(&self.requests)?,
                &ManagedRead {
                    source: None,
                    execution: None,
                    follow: false,
                    instance: instance.clone(),
                    expected: None,
                    rebuild: false,
                    completed: None,
                },
                AnalysisTableRead {
                    requests: &self.requests,
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

    fn permits(&self) -> TestResult {
        assert_eq!(
            self.store
                .read_slots
                .as_ref()
                .ok_or("reader admissions absent")?
                .available_permits(),
            2
        );
        Ok(())
    }
}
