use erebor_runtime_core::RunnerCapabilityDocument;
use erebor_runtime_ipc::{
    transport::MAX_GRPC_MESSAGE_BYTES,
    v1::{
        runner_service_client::RunnerServiceClient, RunnerCapabilityRecord, RunnerInspectRequest,
        RunnerListRequest,
    },
};
use tonic::Request;

use crate::{error::ProtocolSnafu, rpc, DaemonClient, Result};

#[derive(Clone, Debug)]
pub struct RunnerCapability {
    pub document: RunnerCapabilityDocument,
    pub available: bool,
    pub unavailable_reason: Option<String>,
}

impl DaemonClient {
    pub async fn runner_list(&self) -> Result<Vec<RunnerCapability>> {
        let mut client = self.runner_client().await?;
        let response = rpc(client.list(Request::new(RunnerListRequest {})).await)?;
        response
            .runners
            .into_iter()
            .map(RunnerCapability::from_record)
            .collect()
    }

    pub async fn runner_inspect(&self, runner_id: impl Into<String>) -> Result<RunnerCapability> {
        let mut client = self.runner_client().await?;
        let record = rpc(client
            .inspect(Request::new(RunnerInspectRequest {
                runner_id: runner_id.into(),
            }))
            .await)?;
        RunnerCapability::from_record(record)
    }

    async fn runner_client(&self) -> Result<RunnerServiceClient<tonic::transport::Channel>> {
        Ok(RunnerServiceClient::new(self.connect().await?)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES))
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
