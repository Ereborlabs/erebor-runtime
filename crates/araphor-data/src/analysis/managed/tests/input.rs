use super::*;

mod current;
mod follow;
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
}
