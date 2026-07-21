use crate::{error::ProtocolSnafu, DaemonClient, Result};
use erebor_runtime_core::RunnerCapabilityDocument;
use erebor_runtime_ipc::v1::{
    RunnerCapabilityRecord, RunnerInspectRequest, RunnerListRequest, RunnerListResponse,
    KIND_RUNNER_CAPABILITY_RECORD, KIND_RUNNER_INSPECT_REQUEST, KIND_RUNNER_LIST_REQUEST,
    KIND_RUNNER_LIST_RESPONSE,
};

#[derive(Clone, Debug)]
pub struct RunnerCapability {
    pub document: RunnerCapabilityDocument,
    pub available: bool,
    pub unavailable_reason: Option<String>,
}

impl DaemonClient {
    pub async fn runner_list(&self) -> Result<Vec<RunnerCapability>> {
        let mut connection = self.connect().await?;
        let response: RunnerListResponse = connection
            .unary(
                KIND_RUNNER_LIST_REQUEST,
                &RunnerListRequest {},
                KIND_RUNNER_LIST_RESPONSE,
                Vec::new(),
            )
            .await?;
        response
            .runners
            .into_iter()
            .map(RunnerCapability::from_record)
            .collect()
    }

    pub async fn runner_inspect(&self, runner_id: impl Into<String>) -> Result<RunnerCapability> {
        let mut connection = self.connect().await?;
        let record: RunnerCapabilityRecord = connection
            .unary(
                KIND_RUNNER_INSPECT_REQUEST,
                &RunnerInspectRequest {
                    runner_id: runner_id.into(),
                },
                KIND_RUNNER_CAPABILITY_RECORD,
                Vec::new(),
            )
            .await?;
        RunnerCapability::from_record(record)
    }
}

impl RunnerCapability {
    fn from_record(record: RunnerCapabilityRecord) -> Result<Self> {
        let document = serde_json::from_slice(&record.document_json).map_err(|error| {
            ProtocolSnafu {
                reason: format!("daemon returned an invalid runner capability document: {error}"),
            }
            .build()
        })?;
        Ok(Self {
            document,
            available: record.available,
            unavailable_reason: (!record.unavailable_reason.is_empty())
                .then_some(record.unavailable_reason),
        })
    }
}
