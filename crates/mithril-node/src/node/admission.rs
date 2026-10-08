use erebor_runtime_ipc::v1::RuntimeAdmissionPrepareRequest;
use snafu::OptionExt as _;

use super::NodeChassis;
use crate::error::IdentityStateSnafu;
use crate::policy_delivery::RuntimeBindingRollbackV1;
use crate::runtime_admission::RuntimeAdmissionCall;
use crate::{Result, WorkloadBindingConfig};

pub(super) struct RuntimePreparation<'a> {
    node: &'a mut NodeChassis,
    durable: RuntimeBindingRollbackV1,
    physical_started: bool,
}

pub(super) struct RuntimeAdmissionFailureV1 {
    pub(super) source: Box<crate::Error>,
    pub(super) fatal: bool,
}

impl RuntimeAdmissionFailureV1 {
    fn fatal(source: crate::Error) -> Self {
        Self {
            source: Box::new(source),
            fatal: true,
        }
    }

    pub(super) fn with_rollback(self, rollback: Result<()>) -> Self {
        match rollback {
            Ok(()) => self,
            Err(error) => Self::fatal(
                IdentityStateSnafu {
                    reason: format!(
                        "runtime admission failed: {}; rollback failed: {error}",
                        self.source
                    ),
                }
                .build(),
            ),
        }
    }
}

impl From<crate::Error> for RuntimeAdmissionFailureV1 {
    fn from(source: crate::Error) -> Self {
        Self {
            source: Box::new(source),
            fatal: false,
        }
    }
}

impl<'a> RuntimePreparation<'a> {
    pub(super) async fn begin(
        node: &'a mut NodeChassis,
        call: &RuntimeAdmissionCall,
        request: &RuntimeAdmissionPrepareRequest,
        configured: &[WorkloadBindingConfig],
    ) -> std::result::Result<Self, RuntimeAdmissionFailureV1> {
        call.ensure_active()?;
        snafu::ensure!(
            request.initial_pid > 0,
            IdentityStateSnafu {
                reason: "OCI runtime admission has no initial process"
            }
        );
        let readiness = *node.readiness.borrow();
        snafu::ensure!(
            readiness.admits_protected_runtime_start(node.policy.is_some()),
            IdentityStateSnafu {
                reason: "runtime admission has no healthy active prevention generation"
            }
        );
        let (scheduled, observation) = node
            .bindings
            .verify_runtime_preparation(configured, request)
            .await?;
        let durable = node
            .policy_delivery
            .prepare_runtime_binding(&scheduled.resolved, configured)?;
        let mut preparation = Self {
            node,
            durable,
            physical_started: false,
        };
        let result = (|| -> std::result::Result<(), RuntimeAdmissionFailureV1> {
            // Check cancellation after CRI verification and before native changes.
            call.ensure_active()?;
            let node = &mut preparation.node;
            let authority =
                node.policy.is_some() || node.policy_delivery.inventory_retirement().is_some();
            let host = node.host.as_mut().context(IdentityStateSnafu {
                reason: "runtime admission has no live kernel host",
            })?;
            if let Some(previous) = scheduled.previous_binding_id.as_deref() {
                preparation.physical_started = true;
                node.bindings
                    .retire_binding_id(host, previous)
                    .map_err(RuntimeAdmissionFailureV1::fatal)?;
            }
            call.ensure_active()?;
            preparation.physical_started = true;
            node.bindings
                .publish_held_activated_root(
                    host,
                    &scheduled.resolved,
                    request.initial_pid,
                    &observation,
                )
                .map_err(RuntimeAdmissionFailureV1::fatal)?;
            // Verify the held task before persistence and the allow response.
            node.identity
                .activate_prepared_runtime_roots(host, authority)
                .and_then(|_report| {
                    node.bindings.verify_prepared_initial_root(
                        host,
                        &scheduled.resolved.binding_id,
                        request.initial_pid,
                    )
                })
                .map_err(RuntimeAdmissionFailureV1::fatal)?;
            call.ensure_active()?;
            node.policy_delivery
                .record_runtime_binding(&preparation.durable)
                .map_err(RuntimeAdmissionFailureV1::fatal)?;
            call.ensure_active()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(preparation),
            Err(error) => Err(error.with_rollback(preparation.rollback())),
        }
    }

    pub(super) fn rollback(self) -> Result<()> {
        let node = self.node;
        let kernel = if self.physical_started {
            node.host
                .as_ref()
                .context(IdentityStateSnafu {
                    reason: "runtime admission rollback has no live kernel host",
                })
                .and_then(|host| {
                    node.bindings
                        .retire_binding_id(host, self.durable.binding_id())
                })
        } else {
            Ok(())
        };

        // Attempt durable cleanup even if kernel cleanup fails.
        let durable = node
            .policy_delivery
            .rollback_runtime_binding(self.durable, self.physical_started);
        match (kernel, durable) {
            (Ok(()), Ok(())) => {
                if self.physical_started {
                    node.reconcile_runtime_exact_bindings()
                } else {
                    Ok(())
                }
            }
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(kernel), Err(durable)) => IdentityStateSnafu {
                reason: format!(
                    "runtime admission rollback is incomplete: kernel={kernel:?}; durable={durable:?}"
                ),
            }.fail(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use snafu::ResultExt as _;

    use super::{RuntimeAdmissionFailureV1, RuntimePreparation};
    use crate::error::{IdentityStateSnafu, IoSnafu, JsonSnafu};
    use crate::node::tests::AdmissionFixture;
    use crate::runtime_admission::ScheduledRuntimeBindingV1;
    use crate::{ContainerKindV1, WorkloadBindingConfig};

    #[test]
    fn rollback_tracks_kernel_publication() -> crate::Result<()> {
        let mut fixture = AdmissionFixture::new()?;
        let authority_id = "22222222-2222-4222-8222-222222222222";
        let profile_id = "33333333-3333-4333-8333-333333333333";
        let digest = "a".repeat(64);
        let binding = WorkloadBindingConfig {
            binding_id: ScheduledRuntimeBindingV1::runtime_binding_id(authority_id, &digest),
            scheduled_binding_authority_id: Some(authority_id.to_owned()),
            scheduled_target_digest: Some(digest.clone()),
            execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            protected_scope_id: "55555555-5555-4555-8555-555555555555".to_owned(),
            workload_selector_id: "66666666-6666-4666-8666-666666666666".to_owned(),
            profile_id: profile_id.to_owned(),
            container_id: digest.clone(),
            namespace: "default".to_owned(),
            cluster_uid: String::new(),
            namespace_uid: String::new(),
            controller_uid: String::new(),
            service_account_uid: String::new(),
            pod_labels: BTreeMap::new(),
            pod_uid: "pod-a".to_owned(),
            sandbox_id: "sandbox-a".to_owned(),
            container_name: "worker".to_owned(),
            image_digest: digest.clone(),
            container_kind: ContainerKindV1::Application,
            container_generation: 1,
            root_cgroup_path: None,
            lifecycle_generation: 1,
            active_profile_generation_ref_id: 1,
            initial_role_id: 1,
            external_role_id: 2,
            arm_initial_root: false,
        };
        let state = serde_json::json!({
            "active_profiles": {
                (profile_id): {
                    "tenant_id": "11111111-1111-4111-8111-111111111111",
                    "candidate_content_id": digest,
                    "policy_source_revision_id": digest,
                    "target_snapshot_digest": digest,
                    "bundle_digest": digest,
                    "artifact_file": "artifact.json",
                    "public_key_file": "public-key.pem",
                    "profile_generation_ref_id": 1,
                    "bindings": {(authority_id): {"Scheduled": 0}},
                    "node_bound_generation_digest": digest,
                    "readback_digest": digest,
                    "probe_result_digest": digest,
                    "observed_utc_ns": 1
                }
            },
            "issuer_high_water": {},
            "distribution_high_water": {}
        });
        let path = fixture
            .node
            .config
            .state_directory
            .join("policy-delivery-v1/state.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&state).context(JsonSnafu { path: &path })?,
        )
        .context(IoSnafu { path: &path })?;
        fixture.node.policy_delivery = crate::policy_delivery::NodePolicyDeliveryOwner::load(
            &fixture.node.config.state_directory,
        )?;
        let durable = fixture
            .node
            .policy_delivery
            .prepare_runtime_binding(&binding, std::slice::from_ref(&binding))?;
        RuntimePreparation {
            node: &mut fixture.node,
            durable,
            physical_started: false,
        }
        .rollback()?;

        let durable = fixture
            .node
            .policy_delivery
            .prepare_runtime_binding(&binding, std::slice::from_ref(&binding))?;
        let prepared = RuntimePreparation {
            node: &mut fixture.node,
            durable,
            physical_started: true,
        };
        let error = prepared.rollback().err().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "published binding rollback succeeded without a kernel host",
            }
            .build()
        })?;
        assert!(error
            .to_string()
            .contains("rollback has no live kernel host"));
        assert!(fixture
            .node
            .policy_delivery
            .prepare_runtime_binding(&binding, std::slice::from_ref(&binding))
            .is_err());
        Ok(())
    }

    #[test]
    fn rollback_errors_remain_fatal() {
        assert!(
            std::mem::size_of::<RuntimeAdmissionFailureV1>() <= 2 * std::mem::size_of::<usize>()
        );
        for fatal in [false, true] {
            let failure = RuntimeAdmissionFailureV1 {
                source: IdentityStateSnafu {
                    reason: "preparation failed",
                }
                .build()
                .into(),
                fatal,
            };
            let unchanged = failure.with_rollback(Ok(()));
            assert_eq!(unchanged.fatal, fatal);
            let failure = unchanged.with_rollback(
                IdentityStateSnafu {
                    reason: "cleanup failed",
                }
                .fail(),
            );
            assert!(failure.fatal);
            let message = failure.source.to_string();
            assert!(message.contains("preparation failed"), "{message}");
            assert!(message.contains("cleanup failed"), "{message}");
        }
    }
}
