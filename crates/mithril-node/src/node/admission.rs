use erebor_runtime_ipc::v1::RuntimeAdmissionPrepareRequest;
use snafu::OptionExt as _;

use super::NodeChassis;
use crate::error::IdentityStateSnafu;
use crate::policy_delivery::RuntimeBindingRollbackV1;
use crate::runtime_admission::{RuntimeAdmissionCall, ScheduledRuntimeBindingV1};
use crate::{CriRuntimeContainerObservationV1, NodeConfig, Result, WorkloadBindingConfig};

pub(super) struct RuntimePreparation<'a> {
    node: &'a mut NodeChassis,
    kernel: Option<String>,
    durable: Option<(RuntimeBindingRollbackV1, NodeConfig)>,
}

pub(super) struct RuntimeAdmissionFailureV1 {
    pub(super) source: crate::Error,
    pub(super) fatal: bool,
}

impl RuntimeAdmissionFailureV1 {
    fn fatal(source: crate::Error) -> Self {
        Self {
            source,
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
            source,
            fatal: false,
        }
    }
}

impl<'a> RuntimePreparation<'a> {
    pub(super) fn new(node: &'a mut NodeChassis) -> Self {
        Self {
            node,
            kernel: None,
            durable: None,
        }
    }

    pub(super) async fn prepare(
        &mut self,
        call: &RuntimeAdmissionCall,
        request: &RuntimeAdmissionPrepareRequest,
    ) -> std::result::Result<(), RuntimeAdmissionFailureV1> {
        call.ensure_active()?;
        snafu::ensure!(
            request.initial_pid > 0,
            IdentityStateSnafu {
                reason: "OCI runtime admission has no initial process"
            }
        );
        let readiness = *self.node.readiness.borrow();
        snafu::ensure!(
            readiness.admits_protected_runtime_start(self.node.policy.is_some()),
            IdentityStateSnafu {
                reason: "runtime admission has no healthy active prevention generation"
            }
        );
        let (scheduled, observation) = self
            .node
            .bindings
            .verify_runtime_preparation(&self.node.config.workload_bindings, request)
            .await?;
        let mut dynamic = self.node.config.clone();
        dynamic.workload_bindings[scheduled.binding_index] = scheduled.resolved.clone();
        dynamic.validate()?;
        call.ensure_active()?;

        self.publish(call, &scheduled, request.initial_pid, &observation)?;
        call.ensure_active()?;
        self.persist(&scheduled.resolved, dynamic)?;
        call.ensure_active()?;
        Ok(())
    }

    fn publish(
        &mut self,
        call: &RuntimeAdmissionCall,
        scheduled: &ScheduledRuntimeBindingV1,
        initial_pid: u32,
        observation: &CriRuntimeContainerObservationV1,
    ) -> std::result::Result<(), RuntimeAdmissionFailureV1> {
        let node = &mut self.node;
        let authority =
            node.policy.is_some() || node.policy_delivery.inventory_retirement().is_some();
        let host = node.host.as_mut().context(IdentityStateSnafu {
            reason: "runtime admission has no live kernel host",
        })?;

        // Check cancellation before changing either the old or the new authority.
        call.ensure_active()?;
        if let Some(previous) = scheduled.previous_binding_id.as_deref() {
            node.bindings
                .retire_binding_id(host, previous)
                .map_err(RuntimeAdmissionFailureV1::fatal)?;
        }
        call.ensure_active()?;
        node.bindings
            .publish_held_activated_root(host, &scheduled.resolved, initial_pid, observation)
            .map_err(RuntimeAdmissionFailureV1::fatal)?;
        self.kernel = Some(scheduled.resolved.binding_id.clone());

        // Verify the held task before persistence and the allow response.
        node.identity
            .activate_prepared_runtime_roots(host, authority)
            .and_then(|_report| {
                node.bindings.verify_prepared_initial_root(
                    host,
                    &scheduled.resolved.binding_id,
                    initial_pid,
                )
            })
            .map_err(RuntimeAdmissionFailureV1::fatal)?;
        Ok(())
    }

    fn persist(&mut self, binding: &WorkloadBindingConfig, dynamic: NodeConfig) -> Result<()> {
        let rollback = self.node.policy_delivery.record_runtime_binding(binding)?;
        let previous = std::mem::replace(&mut self.node.config, dynamic);
        self.durable = Some((rollback, previous));
        Ok(())
    }

    pub(super) fn rollback(self) -> Result<()> {
        let node = self.node;
        let kernel = match self.kernel {
            Some(binding_id) => node
                .host
                .as_ref()
                .context(IdentityStateSnafu {
                    reason: "runtime admission rollback has no live kernel host",
                })
                .and_then(|host| node.bindings.retire_binding_id(host, &binding_id)),
            None => Ok(()),
        };

        // Attempt durable cleanup even if kernel cleanup fails.
        let mut durable = Ok(());
        let mut exact = Ok(());
        if let Some((rollback, previous)) = self.durable {
            durable = node.policy_delivery.rollback_runtime_binding(rollback);
            if durable.is_ok() {
                node.config = previous;
                if kernel.is_ok() {
                    exact = node.reconcile_runtime_exact_bindings();
                }
            }
        }
        match (kernel, durable, exact) {
            (Ok(()), Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(()), Ok(()))
            | (Ok(()), Err(error), Ok(()))
            | (Ok(()), Ok(()), Err(error)) => Err(error),
            (kernel, durable, exact) => IdentityStateSnafu {
                reason: format!(
                    "runtime admission rollback is incomplete: kernel={kernel:?}; durable={durable:?}; exact_filesystem={exact:?}"
                ),
            }.fail(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeAdmissionFailureV1, RuntimePreparation};
    use crate::error::IdentityStateSnafu;
    use crate::node::tests::AdmissionFixture;

    #[test]
    fn rollback_tracks_kernel_publication() -> crate::Result<()> {
        let mut fixture = AdmissionFixture::new()?;
        RuntimePreparation::new(&mut fixture.node).rollback()?;

        let mut prepared = RuntimePreparation::new(&mut fixture.node);
        prepared.kernel = Some("published-binding".to_owned());
        let error = prepared.rollback().err().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "published binding rollback succeeded without a kernel host",
            }
            .build()
        })?;
        assert!(error
            .to_string()
            .contains("rollback has no live kernel host"));
        Ok(())
    }

    #[test]
    fn rollback_errors_remain_fatal() {
        for fatal in [false, true] {
            let failure = RuntimeAdmissionFailureV1 {
                source: IdentityStateSnafu {
                    reason: "preparation failed",
                }
                .build(),
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
