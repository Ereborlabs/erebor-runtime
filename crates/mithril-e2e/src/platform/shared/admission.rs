use std::{collections::HashMap, os::unix::ffi::OsStrExt as _, time::Duration};

use mithril_control::{lower_kubernetes_policy, PolicySourceRevisionV1, PolicySourceStateV1};
use mithril_node::{
    policy_delivery_status, RuntimeAdmissionClient, CONTAINER_NAME_ANNOTATION,
    IMAGE_NAME_ANNOTATION, POD_NAMESPACE_ANNOTATION, POD_UID_ANNOTATION,
    POLICY_SOURCE_REVISION_ANNOTATION, PROFILE_ID_ANNOTATION, SANDBOX_ID_ANNOTATION,
};

use super::{wait_for, Shared, CLUSTER_UID, NAMESPACE_UID, TENANT_ID};
use crate::platform::{test_lifecycle, Host, TestResult};

#[test]
#[ignore = "requires its physical test environment"]
fn signed_target_delay_is_closed() -> TestResult<()> {
    test_lifecycle::<Host, _>("signed-target-delay", || {
        let mut env = Shared::setup("signed-target-delay")?;
        env.start_control()?;
        let labels = env.install_policy("socket_pass_allowed_policy.json")?;
        env.start_node()?;
        let ready = env.ready.as_ref().ok_or("Node readiness is missing")?;
        wait_for(
            &env.admit_path,
            "Node admission readiness",
            super::READY_LIMIT,
            || Ok(ready.borrow().admits_new_work().then_some(())),
            || format!("last readiness: {:?}", ready.borrow()),
        )?;

        let (resource, _) = env.policies.get(&labels).ok_or("the policy is missing")?;
        let document = lower_kubernetes_policy(resource, TENANT_ID, CLUSTER_UID, NAMESPACE_UID)?;
        let source = PolicySourceRevisionV1::from_resource(
            resource,
            &document,
            TENANT_ID,
            CLUSTER_UID,
            NAMESPACE_UID,
            PolicySourceStateV1::Accepted,
        )?;
        let image = &document.workload_selectors[0].image_digests[0];
        let request = erebor_runtime_ipc::v1::RuntimeAdmissionStageRequest {
            container_id: env.actor_id()?,
            cgroup_path: env.cgroup().as_os_str().as_bytes().to_vec(),
            annotations: HashMap::from([
                (POD_NAMESPACE_ANNOTATION.to_owned(), "default".to_owned()),
                (POD_UID_ANNOTATION.to_owned(), env.pod_uid.clone()),
                (CONTAINER_NAME_ANNOTATION.to_owned(), env.actor.clone()),
                (IMAGE_NAME_ANNOTATION.to_owned(), format!("fixture@{image}")),
                (
                    SANDBOX_ID_ANNOTATION.to_owned(),
                    format!("{:064x}", uuid::Uuid::parse_str(&env.pod_uid)?.as_u128()),
                ),
                (
                    PROFILE_ID_ANNOTATION.to_owned(),
                    document.metadata.profile_id,
                ),
                (
                    POLICY_SOURCE_REVISION_ANNOTATION.to_owned(),
                    source.policy_source_revision_id,
                ),
            ]),
        };
        let deadline = Duration::from_secs(4);
        let client = RuntimeAdmissionClient::new(env.admit_path.clone(), deadline)?;
        let mut invalid = request.clone();
        invalid.cgroup_path.clear();
        let (denied, probe) = env.runtime.block_on(async {
            tokio::join!(client.stage_runtime_facts(request.clone()), async {
                // Check Node validation while the valid request waits for its target.
                tokio::time::sleep(deadline / 2).await;
                client.stage_runtime_facts(invalid).await
            })
        });
        let probe = probe?;
        assert!(!probe.allowed, "{probe:?}");
        assert_eq!(probe.reason_code, "RUNTIME_ADMISSION_REJECTED");
        let error = denied
            .err()
            .ok_or("a Pod without a signed target was admitted")?;
        let message = error.to_string().to_lowercase();
        assert!(message.contains("timeout"), "{error}");
        let pending = policy_delivery_status(&env.state_path)?;
        assert_eq!(pending.active_target_count, 0, "{pending:?}");
        assert_eq!(pending.scheduled_binding_count, 0, "{pending:?}");
        assert_eq!(pending.runtime_binding_count, 0, "{pending:?}");

        env.sync_policy()?;
        env.node_ready()?;
        assert_eq!(request, env.stage_request()?);
        let allowed = env.runtime.block_on(client.stage_runtime_facts(request))?;
        assert!(allowed.allowed, "{allowed:?}");
        assert_eq!(allowed.reason_code, "RUNTIME_FACTS_STAGING");
        let after = policy_delivery_status(&env.state_path)?;
        assert_eq!(after.active_target_count, 1, "{after:?}");
        assert_eq!(after.scheduled_binding_count, 1, "{after:?}");
        assert_eq!(after.runtime_binding_count, 0, "{after:?}");
        env.stop()
    })
}
