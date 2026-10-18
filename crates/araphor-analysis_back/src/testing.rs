use std::sync::Arc;

use araphor_data::{
    AnalysisStore, EvidenceIntakeIdentityV1, EvidenceRecord, ValidatedEvidenceBatchV1,
};
use araphor_query::execution::{Engine, Limits};
use prost::Message as _;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) struct QueryFixture {
    pub store: Arc<AnalysisStore>,
    pub source: EvidenceIntakeIdentityV1,
    _directory: tempfile::TempDir,
}

impl QueryFixture {
    pub fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        Ok(Self {
            store: Arc::new(AnalysisStore::open(directory.path().join("analysis"))?),
            source: EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "query-node".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            _directory: directory,
        })
    }

    pub fn owner(&self, mut limits: Limits) -> araphor_query::Result<Arc<Engine>> {
        limits.input_capacity.get_or_insert(128 * 1024 * 1024);
        limits.output_capacity.get_or_insert(16 * 1024 * 1024);
        Engine::new(self.store.clone(), limits)
    }

    pub fn event(&self, cursor: u64, received: u64, operation: u32) -> TestResult {
        self.commit(
            cursor,
            received,
            EvidenceRecord {
                operation,
                ..Default::default()
            },
        )
    }

    pub fn commit(&self, cursor: u64, received: u64, record: EvidenceRecord) -> TestResult {
        self.commit_as(&self.source, 0, cursor, received, record)
    }

    pub fn commit_as(
        &self,
        source: &EvidenceIntakeIdentityV1,
        cpu: u32,
        cursor: u64,
        received: u64,
        record: EvidenceRecord,
    ) -> TestResult {
        let payload = record.encode_to_vec();
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
        self.store.accept_validated_batch(
            source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: cpu,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: received,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        Ok(())
    }
}
