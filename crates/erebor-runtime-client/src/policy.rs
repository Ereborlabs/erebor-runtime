use erebor_runtime_ipc::{
    transport::MAX_GRPC_MESSAGE_BYTES,
    v1::{
        policy_service_client::PolicyServiceClient, PolicyPackageApplyRequest,
        PolicyPackageInspectRequest, PolicyPackageListRequest, PolicyPackageListResponse,
        PolicyPackageRecord, PolicyPackageVerifyRequest, PolicySetCreateRequest,
        PolicySetInspectRequest, PolicySetListRequest, PolicySetListResponse, PolicySetRecord,
        PolicySetVerifyRequest, PolicyTestRequest, PolicyTestResponse,
    },
};
use tonic::Request;

use crate::{rpc, DaemonClient, Result};

impl DaemonClient {
    pub async fn policy_test(
        &self,
        policy_json: Vec<u8>,
        event_json: Vec<u8>,
    ) -> Result<PolicyTestResponse> {
        let mut client = self.policy_client().await?;
        rpc(client
            .test(Request::new(PolicyTestRequest {
                policy_json,
                event_json,
            }))
            .await)
    }

    pub async fn policy_package_apply(
        &self,
        path: impl Into<String>,
        name: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<PolicyPackageRecord> {
        let mut client = self.policy_client().await?;
        rpc(client
            .apply_package(self.mutation_request(
                PolicyPackageApplyRequest {
                    path: path.into(),
                    name: name.into(),
                },
                idempotency_key,
            )?)
            .await)
    }

    pub async fn policy_package_list(&self) -> Result<PolicyPackageListResponse> {
        let mut client = self.policy_client().await?;
        rpc(client
            .list_packages(Request::new(PolicyPackageListRequest {}))
            .await)
    }

    pub async fn policy_package_inspect(
        &self,
        name: impl Into<String>,
    ) -> Result<PolicyPackageRecord> {
        let mut client = self.policy_client().await?;
        rpc(client
            .inspect_package(Request::new(PolicyPackageInspectRequest {
                name: name.into(),
            }))
            .await)
    }

    pub async fn policy_package_verify(
        &self,
        name: impl Into<String>,
    ) -> Result<PolicyPackageRecord> {
        let mut client = self.policy_client().await?;
        rpc(client
            .verify_package(Request::new(PolicyPackageVerifyRequest {
                name: name.into(),
            }))
            .await)
    }

    pub async fn policy_set_create(
        &self,
        name: impl Into<String>,
        package_names: Vec<String>,
        idempotency_key: &str,
    ) -> Result<PolicySetRecord> {
        let mut client = self.policy_client().await?;
        rpc(client
            .create_set(self.mutation_request(
                PolicySetCreateRequest {
                    name: name.into(),
                    package_names,
                },
                idempotency_key,
            )?)
            .await)
    }

    pub async fn policy_set_list(&self) -> Result<PolicySetListResponse> {
        let mut client = self.policy_client().await?;
        rpc(client
            .list_sets(Request::new(PolicySetListRequest {}))
            .await)
    }

    pub async fn policy_set_inspect(&self, name: impl Into<String>) -> Result<PolicySetRecord> {
        let mut client = self.policy_client().await?;
        rpc(client
            .inspect_set(Request::new(PolicySetInspectRequest { name: name.into() }))
            .await)
    }

    pub async fn policy_set_verify(&self, name: impl Into<String>) -> Result<PolicySetRecord> {
        let mut client = self.policy_client().await?;
        rpc(client
            .verify_set(Request::new(PolicySetVerifyRequest { name: name.into() }))
            .await)
    }

    async fn policy_client(&self) -> Result<PolicyServiceClient<tonic::transport::Channel>> {
        Ok(PolicyServiceClient::new(self.connect().await?)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES))
    }
}
