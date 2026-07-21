use crate::{DaemonClient, Result};
use erebor_runtime_ipc::v1::{
    ApprovalApproveRequest, ApprovalDenyRequest, ApprovalInspectRequest, ApprovalListRequest,
    ApprovalListResponse, Header, EREBOR_IDEMPOTENCY_KEY_HEADER, KIND_APPROVAL_APPROVE_REQUEST,
    KIND_APPROVAL_DENY_REQUEST, KIND_APPROVAL_INSPECT_REQUEST, KIND_APPROVAL_LIST_REQUEST,
    KIND_APPROVAL_LIST_RESPONSE, KIND_APPROVAL_RECORD,
};

pub use erebor_runtime_ipc::v1::ApprovalRecord;

#[derive(Clone, Debug)]
pub struct ApprovalPage {
    pub records: Vec<ApprovalRecord>,
}

impl DaemonClient {
    pub async fn approval_list(&self) -> Result<ApprovalPage> {
        let mut connection = self.connect().await?;
        let response: ApprovalListResponse = connection
            .unary(
                KIND_APPROVAL_LIST_REQUEST,
                &ApprovalListRequest {},
                KIND_APPROVAL_LIST_RESPONSE,
                Vec::new(),
            )
            .await?;
        Ok(ApprovalPage {
            records: response.approvals,
        })
    }

    pub async fn approval_inspect(
        &self,
        approval_id: impl Into<String>,
        owner_uid: u32,
    ) -> Result<ApprovalRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_APPROVAL_INSPECT_REQUEST,
                &ApprovalInspectRequest {
                    approval_id: approval_id.into(),
                    owner_uid,
                },
                KIND_APPROVAL_RECORD,
                Vec::new(),
            )
            .await
    }

    pub async fn approval_approve(
        &self,
        approval_id: impl Into<String>,
        owner_uid: u32,
        idempotency_key: &str,
    ) -> Result<ApprovalRecord> {
        self.approval_mutation(
            KIND_APPROVAL_APPROVE_REQUEST,
            &ApprovalApproveRequest {
                approval_id: approval_id.into(),
                owner_uid,
            },
            idempotency_key,
        )
        .await
    }

    pub async fn approval_deny(
        &self,
        approval_id: impl Into<String>,
        owner_uid: u32,
        reason: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<ApprovalRecord> {
        self.approval_mutation(
            KIND_APPROVAL_DENY_REQUEST,
            &ApprovalDenyRequest {
                approval_id: approval_id.into(),
                reason: reason.into(),
                owner_uid,
            },
            idempotency_key,
        )
        .await
    }

    async fn approval_mutation<T: prost::Message>(
        &self,
        kind: &str,
        request: &T,
        idempotency_key: &str,
    ) -> Result<ApprovalRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                kind,
                request,
                KIND_APPROVAL_RECORD,
                vec![Header {
                    key: EREBOR_IDEMPOTENCY_KEY_HEADER.to_string(),
                    value: idempotency_key.to_string(),
                }],
            )
            .await
    }
}
