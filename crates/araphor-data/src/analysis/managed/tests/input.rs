use super::*;

mod current;
mod origins;
mod reads;
mod scope;

struct Saved {
    _directory: tempfile::TempDir,
    store: Arc<AnalysisStore>,
    fixture: Arc<Fixture>,
    context: crate::AnalysisContextRefV1,
    receipt: ManagedReceipt,
    inputs: [(Arc<crate::ManagedInputRef>, Arc<sdk::Schema>); 1],
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
        let requests =
            AnalysisTableRequests::from([("events".into(), Some(BTreeSet::from([cursor])))]);
        let capture = store
            .read_managed_tables(
                &fixture.instance.grant.selection,
                &ManagedRead {
                    follow: false,
                    instance: fixture.instance.clone(),
                    expected: None,
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
        let (pin, port) = store.managed_input(
            &fixture.instance.grant.selection,
            &fixture.instance.spec.id,
            &receipt.results[&10],
            "rows",
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        Ok(Self {
            _directory: directory,
            store,
            fixture,
            context,
            receipt,
            inputs: [(Arc::new(pin), Arc::new(port.schema))],
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
            .read_managed_tables(
                &instance.grant.selection,
                &ManagedRead {
                    follow: false,
                    instance: instance.clone(),
                    expected: None,
                    rebuild: false,
                    completed: None,
                },
                AnalysisTableRead {
                    requests: &self.requests,
                    event_ranges: None,
                    inputs: None,
                    mode: AnalysisReadModeV1::Complete,
                    now: 10,
                },
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
            )?
            .state)
    }

    fn read(
        &self,
        selection: &AnalysisSelectionV1,
        authorized: &AnalysisSelectionV1,
        outputs: &[(Arc<crate::ManagedInputRef>, Arc<sdk::Schema>)],
        mode: AnalysisReadModeV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> crate::Result<crate::AnalysisPositionPageV1> {
        self.store.read_tables(
            selection,
            AnalysisTableRead {
                requests: &self.requests,
                event_ranges: None,
                inputs: Some(crate::AnalysisInputTables {
                    authorized,
                    outputs,
                }),
                mode,
                now: 10,
            },
            limits,
            control,
        )
    }
}

#[test]
fn retained_header_skips_ipc() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let capture = fixture.capture(&store, false)?;
    let request = request("header");
    let attempt = store.register_managed_attempt(&capture, &request, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&request, 10, None)?,
        fixture.evaluation(&request, 11, None)?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let reference = &receipt.results[&10];
    store
        .writer()?
        .get_mut()?
        .execute(
            "UPDATE managed_arrow SET ipc = ? WHERE result_id = ?",
            params![b"invalid IPC".as_slice(), reference.result_id],
        )
        .context(crate::AnalysisDatabaseSnafu {
            operation: "corrupt test managed payload",
        })?;
    let before = store.meta()?;
    let (pin, port) = store.managed_input(
        &fixture.instance.grant.selection,
        &fixture.instance.spec.id,
        reference,
        "rows",
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(pin.result(), reference);
    assert_eq!(pin.output().package, "managed-fixture");
    assert_eq!(port.schema, fixture.model.outputs[0].schema);
    let inputs = [(Arc::new(pin), Arc::new(port.schema))];
    let requests = AnalysisTableRequests::new();
    for mode in [AnalysisReadModeV1::Metadata, AnalysisReadModeV1::Complete] {
        let read = store.read_tables(
            &fixture.instance.grant.selection,
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                inputs: Some(crate::AnalysisInputTables {
                    authorized: &fixture.instance.grant.selection,
                    outputs: &inputs,
                }),
                mode,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        );
        if matches!(mode, AnalysisReadModeV1::Metadata) {
            let page = read?;
            assert!(page.packages.is_empty());
            assert_eq!(
                page.extraction
                    .references
                    .iter()
                    .filter_map(|entry| entry.result())
                    .collect::<Vec<_>>(),
                [reference]
            );
        } else {
            assert!(matches!(read, Err(crate::Error::AnalysisContract { .. })));
        }
    }
    assert_eq!(store.meta()?, before);
    Ok(())
}
