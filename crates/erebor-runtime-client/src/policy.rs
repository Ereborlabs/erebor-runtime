use erebor_runtime_ipc::v1::{
    Header, PolicyPackageApplyRequest, PolicyPackageInspectRequest, PolicyPackageListRequest,
    PolicyPackageListResponse, PolicyPackageRecord, PolicyPackageVerifyRequest,
    PolicySetCreateRequest, PolicySetInspectRequest, PolicySetListRequest, PolicySetListResponse,
    PolicySetRecord, PolicySetVerifyRequest, PolicyTestRequest, PolicyTestResponse,
    EREBOR_IDEMPOTENCY_KEY_HEADER, KIND_POLICY_PACKAGE_APPLY_REQUEST,
    KIND_POLICY_PACKAGE_INSPECT_REQUEST, KIND_POLICY_PACKAGE_LIST_REQUEST,
    KIND_POLICY_PACKAGE_LIST_RESPONSE, KIND_POLICY_PACKAGE_RECORD,
    KIND_POLICY_PACKAGE_VERIFY_REQUEST, KIND_POLICY_SET_CREATE_REQUEST,
    KIND_POLICY_SET_INSPECT_REQUEST, KIND_POLICY_SET_LIST_REQUEST, KIND_POLICY_SET_LIST_RESPONSE,
    KIND_POLICY_SET_RECORD, KIND_POLICY_SET_VERIFY_REQUEST, KIND_POLICY_TEST_REQUEST,
    KIND_POLICY_TEST_RESPONSE,
};

use crate::{DaemonClient, Result};

impl DaemonClient {
    pub async fn policy_test(
        &self,
        policy_json: Vec<u8>,
        event_json: Vec<u8>,
    ) -> Result<PolicyTestResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_POLICY_TEST_REQUEST,
                &PolicyTestRequest {
                    policy_json,
                    event_json,
                },
                KIND_POLICY_TEST_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn policy_package_apply(
        &self,
        path: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<PolicyPackageRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_POLICY_PACKAGE_APPLY_REQUEST,
                &PolicyPackageApplyRequest { path: path.into() },
                KIND_POLICY_PACKAGE_RECORD,
                vec![Header {
                    key: EREBOR_IDEMPOTENCY_KEY_HEADER.to_owned(),
                    value: idempotency_key.to_owned(),
                }],
            )
            .await
    }

    pub async fn policy_package_list(&self) -> Result<PolicyPackageListResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_POLICY_PACKAGE_LIST_REQUEST,
                &PolicyPackageListRequest {},
                KIND_POLICY_PACKAGE_LIST_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn policy_package_inspect(
        &self,
        name: impl Into<String>,
    ) -> Result<PolicyPackageRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_POLICY_PACKAGE_INSPECT_REQUEST,
                &PolicyPackageInspectRequest { name: name.into() },
                KIND_POLICY_PACKAGE_RECORD,
                Vec::new(),
            )
            .await
    }

    pub async fn policy_package_verify(
        &self,
        name: impl Into<String>,
    ) -> Result<PolicyPackageRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_POLICY_PACKAGE_VERIFY_REQUEST,
                &PolicyPackageVerifyRequest { name: name.into() },
                KIND_POLICY_PACKAGE_RECORD,
                Vec::new(),
            )
            .await
    }

    pub async fn policy_set_create(
        &self,
        name: impl Into<String>,
        package_names: Vec<String>,
        idempotency_key: &str,
    ) -> Result<PolicySetRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_POLICY_SET_CREATE_REQUEST,
                &PolicySetCreateRequest {
                    name: name.into(),
                    package_names,
                },
                KIND_POLICY_SET_RECORD,
                vec![Header {
                    key: EREBOR_IDEMPOTENCY_KEY_HEADER.to_owned(),
                    value: idempotency_key.to_owned(),
                }],
            )
            .await
    }

    pub async fn policy_set_list(&self) -> Result<PolicySetListResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_POLICY_SET_LIST_REQUEST,
                &PolicySetListRequest {},
                KIND_POLICY_SET_LIST_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn policy_set_inspect(&self, name: impl Into<String>) -> Result<PolicySetRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_POLICY_SET_INSPECT_REQUEST,
                &PolicySetInspectRequest { name: name.into() },
                KIND_POLICY_SET_RECORD,
                Vec::new(),
            )
            .await
    }

    pub async fn policy_set_verify(&self, name: impl Into<String>) -> Result<PolicySetRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_POLICY_SET_VERIFY_REQUEST,
                &PolicySetVerifyRequest { name: name.into() },
                KIND_POLICY_SET_RECORD,
                Vec::new(),
            )
            .await
    }
}
