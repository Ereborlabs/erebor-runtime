use erebor_runtime_ipc::v1::{
    Header, PolicyPackageApplyRequest, PolicyPackageRecord, PolicySetCreateRequest,
    PolicySetRecord, PolicyTestRequest, PolicyTestResponse, EREBOR_IDEMPOTENCY_KEY_HEADER,
    KIND_POLICY_PACKAGE_APPLY_REQUEST, KIND_POLICY_PACKAGE_RECORD, KIND_POLICY_SET_CREATE_REQUEST,
    KIND_POLICY_SET_RECORD, KIND_POLICY_TEST_REQUEST, KIND_POLICY_TEST_RESPONSE,
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

    pub async fn policy_set_create(
        &self,
        root_minimum_digest: impl Into<String>,
        package_minimum_digests: Vec<String>,
        local_override_digest: Option<String>,
        idempotency_key: &str,
    ) -> Result<PolicySetRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_POLICY_SET_CREATE_REQUEST,
                &PolicySetCreateRequest {
                    root_minimum_digest: root_minimum_digest.into(),
                    package_minimum_digests,
                    local_override_digest: local_override_digest.unwrap_or_default(),
                },
                KIND_POLICY_SET_RECORD,
                vec![Header {
                    key: EREBOR_IDEMPOTENCY_KEY_HEADER.to_owned(),
                    value: idempotency_key.to_owned(),
                }],
            )
            .await
    }
}
