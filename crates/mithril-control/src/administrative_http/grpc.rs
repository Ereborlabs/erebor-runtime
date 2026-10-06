use erebor_runtime_error::{ErrorExt as _, StatusCode};
use erebor_runtime_ipc::araphor::{
    self as wire, araphor_administrative_service_server::AraphorAdministrativeService,
};
use tonic::{Request, Response, Status};

use super::AdministrativeHttpOwner;
use crate::{Error, NodeDecommissionStateV1, NodeDecommissionStatusV1};

#[tonic::async_trait]
impl AraphorAdministrativeService for AdministrativeHttpOwner {
    async fn create_administrative_exec_request(
        &self,
        request: Request<wire::AdministrativeExecDraftRequest>,
    ) -> Result<Response<wire::AdministrativeExecDraft>, Status> {
        self.create_draft(request.into_inner())
            .await
            .map(Response::new)
            .map_err(Self::status)
    }

    async fn poll_administrative_exec_request(
        &self,
        request: Request<wire::AdministrativeExecPollRequest>,
    ) -> Result<Response<wire::AdministrativeExecPoll>, Status> {
        self.poll_draft(&request.into_inner().poll_token)
            .map(Response::new)
    }

    async fn get_administrative_exec_activation(
        &self,
        request: Request<wire::GetAdministrativeExecActivationRequest>,
    ) -> Result<Response<wire::AdministrativeExecActivation>, Status> {
        self.activation(
            &request.get_ref().activation_token,
            &request.metadata().clone().into_headers(),
        )
        .map(Response::new)
    }

    async fn approve_administrative_exec(
        &self,
        request: Request<wire::ApproveAdministrativeExecRequest>,
    ) -> Result<Response<wire::AdministrativeExecApproval>, Status> {
        self.approve_draft(
            &request.get_ref().activation_token,
            &request.metadata().clone().into_headers(),
        )?;
        Ok(Response::new(wire::AdministrativeExecApproval {
            approved: true,
        }))
    }

    async fn submit_node_decommission(
        &self,
        request: Request<wire::SubmitNodeDecommissionRequest>,
    ) -> Result<Response<wire::ClientDecommissionStatus>, Status> {
        self.decommission
            .submit(request.into_inner().artifact)
            .await
            .map(|value| Response::new(value.into()))
    }

    async fn get_node_decommission(
        &self,
        request: Request<wire::GetNodeDecommissionRequest>,
    ) -> Result<Response<wire::ClientDecommissionStatus>, Status> {
        self.decommission
            .status(&request.into_inner().artifact_sha256)
            .map(|value| Response::new(value.into()))
    }
}

impl AdministrativeHttpOwner {
    pub(super) fn status(error: Error) -> Status {
        match error.status_code() {
            StatusCode::PermissionDenied => Status::permission_denied(error.to_string()),
            StatusCode::Unavailable => Status::unavailable("administrative service is unavailable"),
            StatusCode::NotFound => Status::not_found(error.to_string()),
            StatusCode::InvalidArguments => Status::invalid_argument(error.to_string()),
            _ => Status::internal("administrative operation failed"),
        }
    }
}

impl From<NodeDecommissionStatusV1> for wire::ClientDecommissionStatus {
    fn from(value: NodeDecommissionStatusV1) -> Self {
        Self {
            artifact_sha256: value.artifact_sha256,
            state: match value.state {
                NodeDecommissionStateV1::Submitted => "SUBMITTED",
                NodeDecommissionStateV1::Accepted => "ACCEPTED",
                NodeDecommissionStateV1::Quarantined => "QUARANTINED",
                NodeDecommissionStateV1::Completed => "COMPLETED",
                NodeDecommissionStateV1::Rejected => "REJECTED",
            }
            .into(),
            reason_code: value.reason_code,
        }
    }
}
