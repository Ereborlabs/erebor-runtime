use erebor_runtime_ipc::{
    transport::MAX_GRPC_MESSAGE_BYTES,
    v1::{
        approval_service_client::ApprovalServiceClient, ApprovalApproveRequest,
        ApprovalDenyRequest, ApprovalInspectRequest, ApprovalListRequest,
    },
};
use tonic::Request;

use crate::{rpc, DaemonClient, Result};

pub use erebor_runtime_ipc::v1::ApprovalRecord;

#[derive(Clone, Debug)]
pub struct ApprovalPage {
    pub records: Vec<ApprovalRecord>,
}

impl DaemonClient {
    pub async fn approval_list(&self) -> Result<ApprovalPage> {
        let mut client = self.approval_client().await?;
        let response = rpc(client.list(Request::new(ApprovalListRequest {})).await)?;
        Ok(ApprovalPage {
            records: response.approvals,
        })
    }

    pub async fn approval_inspect(
        &self,
        approval_id: impl Into<String>,
        owner_uid: u32,
    ) -> Result<ApprovalRecord> {
        let mut client = self.approval_client().await?;
        rpc(client
            .inspect(Request::new(ApprovalInspectRequest {
                approval_id: approval_id.into(),
                owner_uid,
            }))
            .await)
    }

    pub async fn approval_approve(
        &self,
        approval_id: impl Into<String>,
        owner_uid: u32,
        idempotency_key: &str,
    ) -> Result<ApprovalRecord> {
        let mut client = self.approval_client().await?;
        rpc(client
            .approve(self.mutation_request(
                ApprovalApproveRequest {
                    approval_id: approval_id.into(),
                    owner_uid,
                },
                idempotency_key,
            )?)
            .await)
    }

    pub async fn approval_deny(
        &self,
        approval_id: impl Into<String>,
        owner_uid: u32,
        reason: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<ApprovalRecord> {
        let mut client = self.approval_client().await?;
        rpc(client
            .deny(self.mutation_request(
                ApprovalDenyRequest {
                    approval_id: approval_id.into(),
                    reason: reason.into(),
                    owner_uid,
                },
                idempotency_key,
            )?)
            .await)
    }

    async fn approval_client(&self) -> Result<ApprovalServiceClient<tonic::transport::Channel>> {
        Ok(ApprovalServiceClient::new(self.connect().await?)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES))
    }
}
