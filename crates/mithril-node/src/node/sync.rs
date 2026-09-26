use mithril_control::{PolicyActivationAcknowledgement, PolicyBundleV1};
use snafu::OptionExt as _;

use super::NodeChassis;
use crate::error::IdentityStateSnafu;
use crate::policy_delivery::PolicyTransferActionV1;
use crate::{ControlConnection, Result};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PolicyControlPhaseV1 {
    #[default]
    Transfer,
    Exception,
}

#[derive(Default)]
pub(super) struct PolicyControlWorkV1 {
    pub(super) pacing: PolicyControlPacingOwner,
    phase: PolicyControlPhaseV1,
    rejected_acknowledgement: Option<PolicyActivationAcknowledgement>,
    exception_observed: bool,
    rejected_candidate: Option<String>,
}

#[derive(Default)]
pub struct PolicyControlPacingOwner {
    pending: bool,
}

impl PolicyControlPacingOwner {
    pub fn mark_pending(&mut self) {
        self.pending = true;
    }

    pub fn mark_idle(&mut self) {
        self.pending = false;
    }

    pub async fn wait_until_ready(&self, poll: &mut tokio::time::Interval) {
        // A yield can be canceled forever while the Control stream always has evidence ACKs.
        if !self.pending {
            let _instant = poll.tick().await;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PolicyControlStepV1 {
    Continue,
    Idle,
    Activated,
    Reconnect,
}

impl PolicyControlWorkV1 {
    pub(super) async fn advance(
        &mut self,
        node: &mut NodeChassis,
        connection: &mut ControlConnection,
        evidence_healthy: bool,
    ) -> Result<PolicyControlStepV1> {
        self.pacing.mark_pending();
        let result = self.step(node, connection, evidence_healthy).await;
        self.finish(result, &node.config.node_id)
    }

    fn finish(
        &mut self,
        result: Result<PolicyControlStepV1>,
        node_id: &str,
    ) -> Result<PolicyControlStepV1> {
        let step = match result {
            Err(
                error @ (crate::Error::ControlRpc { .. } | crate::Error::ControlTransport { .. }),
            ) => {
                let reuse_session = error.control_rpc_can_reuse_session();
                erebor_telemetry::debug!(
                    "policy Control RPC failed",
                    node_id = %node_id,
                    error = %error,
                    retry = %if reuse_session { "same_session" } else { "reconnect" }
                );
                if reuse_session {
                    PolicyControlStepV1::Idle
                } else {
                    PolicyControlStepV1::Reconnect
                }
            }
            other => other?,
        };
        if step == PolicyControlStepV1::Idle {
            self.pacing.mark_idle();
        }
        Ok(step)
    }

    async fn step(
        &mut self,
        node: &mut NodeChassis,
        connection: &mut ControlConnection,
        evidence_healthy: bool,
    ) -> Result<PolicyControlStepV1> {
        if let Some(ack) = self.rejected_acknowledgement.take() {
            Self::acknowledge(node, connection, ack).await?;
            self.rejected_candidate = None;
            return Ok(PolicyControlStepV1::Continue);
        }
        match self.phase {
            PolicyControlPhaseV1::Transfer => {
                self.transfer(node, connection, evidence_healthy).await
            }
            PolicyControlPhaseV1::Exception => self.exceptions(node, connection).await,
        }
    }

    async fn acknowledge(
        node: &mut NodeChassis,
        connection: &mut ControlConnection,
        ack: PolicyActivationAcknowledgement,
    ) -> Result<()> {
        let accepted = node
            .await_control_rpc(connection.acknowledge_policy(ack.clone()))
            .await?;
        node.policy_delivery.acknowledge_control(&ack, &accepted)?;
        node.policy_delivery.begin_control_session();
        Ok(())
    }

    async fn transfer(
        &mut self,
        node: &mut NodeChassis,
        connection: &mut ControlConnection,
        evidence_healthy: bool,
    ) -> Result<PolicyControlStepV1> {
        if let Some(ack) = node.policy_delivery.pending_acknowledgement() {
            Self::acknowledge(node, connection, ack).await?;
            self.phase = PolicyControlPhaseV1::Exception;
            return Ok(PolicyControlStepV1::Continue);
        }

        match node.policy_delivery.next_transfer_action()? {
            PolicyTransferActionV1::Inventory {
                active_candidate_content_id,
                durable_bundle_digests,
            } => {
                let inventory = node
                    .await_control_rpc(connection.policy_inventory(
                        active_candidate_content_id.as_deref(),
                        durable_bundle_digests,
                    ))
                    .await?;
                if !node.policy_delivery.accept_inventory(inventory)? {
                    node.reconcile_inventory_policy_retirement()?;
                    self.phase = PolicyControlPhaseV1::Exception;
                }
                Ok(PolicyControlStepV1::Continue)
            }
            PolicyTransferActionV1::Fetch {
                candidate_content_id,
                bundle_digest,
                chunk_index,
            } => {
                let chunk = node
                    .await_control_rpc(connection.fetch_policy_chunk(
                        candidate_content_id,
                        bundle_digest,
                        chunk_index,
                    ))
                    .await?;
                node.policy_delivery.accept_chunk(chunk)?;
                Ok(PolicyControlStepV1::Continue)
            }
            PolicyTransferActionV1::Ready(bundle) => {
                if self.rejected_candidate.as_deref()
                    == Some(bundle.candidate.candidate_content_id.as_str())
                {
                    return Ok(PolicyControlStepV1::Idle);
                }
                let prepared = match node.prepare_control_policy(&bundle) {
                    Ok(prepared) => prepared,
                    Err(_error) => {
                        self.rejected_candidate =
                            Some(bundle.candidate.candidate_content_id.clone());
                        self.rejected_acknowledgement = Some(Self::reject(&bundle)?);
                        return Ok(PolicyControlStepV1::Continue);
                    }
                };
                // Complete local readback before a later step sends the ACTIVE ACK.
                node.activate_control_policy(&bundle, prepared, evidence_healthy)?;
                Ok(PolicyControlStepV1::Activated)
            }
        }
    }

    async fn exceptions(
        &mut self,
        node: &mut NodeChassis,
        connection: &mut ControlConnection,
    ) -> Result<PolicyControlStepV1> {
        if !self.exception_observed {
            // Observe live counters once before this exception delivery cycle.
            if let (Some(policy), Some(host)) = (node.policy.as_ref(), node.host.as_ref()) {
                for candidate in node
                    .policy_delivery
                    .acknowledged_active_exception_candidates()?
                {
                    let observation = policy.observe_exception_candidate(host, &candidate)?;
                    node.policy_delivery.observe_exception_result(
                        &candidate,
                        observation,
                        crate::policy::current_utc_ns()?,
                    )?;
                }
            }
            self.exception_observed = true;
        }
        if let Some(acknowledgement) = node.policy_delivery.pending_exception_acknowledgement()? {
            let candidate_content_id = acknowledgement.candidate_content_id.clone();
            node.await_control_rpc(connection.acknowledge_exception(acknowledgement))
                .await?;
            node.policy_delivery
                .acknowledge_exception_control(&candidate_content_id)?;
            self.phase = PolicyControlPhaseV1::Transfer;
            self.exception_observed = false;
            node.policy_delivery.begin_control_session();
            return Ok(PolicyControlStepV1::Continue);
        }
        let node_boot_id = node.node_boot_id.to_be_bytes();
        let host = node.host.as_ref().context(IdentityStateSnafu {
            reason: "exception delivery has no live kernel host",
        })?;
        if let Some(prepared) = node.policy_delivery.reconcile_exception_candidate(
            host,
            &node.trust,
            &node.config,
            &node_boot_id,
            node.label_epoch,
        )? {
            node.apply_control_exception(prepared)?;
            return Ok(PolicyControlStepV1::Continue);
        }
        let candidate_ids = node.policy_delivery.exception_inventory_candidate_ids();
        let inventory = node
            .await_control_rpc(connection.exception_inventory(candidate_ids))
            .await?;
        if let Some(prepared) = node.policy_delivery.accept_exception_inventory(
            inventory,
            &node.trust,
            &node.config,
            &node_boot_id,
            node.label_epoch,
        )? {
            node.apply_control_exception(prepared)?;
            return Ok(PolicyControlStepV1::Continue);
        }
        self.phase = PolicyControlPhaseV1::Transfer;
        self.exception_observed = false;
        Ok(PolicyControlStepV1::Idle)
    }

    fn reject(bundle: &PolicyBundleV1) -> Result<PolicyActivationAcknowledgement> {
        Ok(PolicyActivationAcknowledgement {
            tenant_id: bundle.candidate.tenant_id.clone(),
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
            target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
            state: "REJECTED".to_owned(),
            node_bound_generation_digest: String::new(),
            profile_generation_ref_id: 0,
            readback_digest: String::new(),
            probe_result_digest: String::new(),
            reason_code: "NODE_POLICY_REJECTED".to_owned(),
            observed_utc_ns: crate::policy::current_utc_ns()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{PolicyControlPhaseV1, PolicyControlStepV1, PolicyControlWorkV1};

    #[test]
    fn control_failure_preserves_progress() -> crate::Result<()> {
        for (status, expected) in [
            (
                tonic::Status::deadline_exceeded("Control did not answer"),
                PolicyControlStepV1::Reconnect,
            ),
            (
                tonic::Status::resource_exhausted("Control is applying backpressure"),
                PolicyControlStepV1::Idle,
            ),
        ] {
            let mut work = PolicyControlWorkV1 {
                phase: PolicyControlPhaseV1::Exception,
                exception_observed: true,
                rejected_candidate: Some("candidate".into()),
                ..Default::default()
            };
            work.pacing.mark_pending();
            let error = crate::Error::ControlRpc {
                source: Box::new(status),
                location: snafu::Location::default(),
            };
            assert_eq!(work.finish(Err(error), "node")?, expected);
            assert_eq!(work.pacing.pending, expected != PolicyControlStepV1::Idle);
            assert_eq!(work.phase, PolicyControlPhaseV1::Exception);
            assert!(work.exception_observed);
            assert_eq!(work.rejected_candidate.as_deref(), Some("candidate"));
        }
        Ok(())
    }

    #[test]
    fn local_failure_is_not_retried() {
        let mut work = PolicyControlWorkV1::default();
        let error = crate::error::IdentityStateSnafu {
            reason: "exception delivery has no live kernel host",
        }
        .build();
        assert!(matches!(
            work.finish(Err(error), "node"),
            Err(crate::Error::IdentityState { .. })
        ));
    }
}
