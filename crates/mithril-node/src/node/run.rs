use std::cmp;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mithril_control::CapabilityRecord;
use sha2::{Digest as _, Sha256};
use snafu::{OptionExt as _, ResultExt as _};
use tokio::sync::watch;

use super::{
    close_evidence_claims, close_identity_claims, next_runtime_admission, next_runtime_seccomp,
    restore_evidence_claims, restore_identity_claims, NodeChassis, NodeReadinessV1,
    PolicyControlStepV1, PolicyControlWorkV1, ReconciliationOutcome,
};
use crate::error::{EvidenceStateSnafu, IdentityStateSnafu, InterceptorSnafu, LocalTaskSnafu};
use crate::{
    AdministrativeControlRequest, CoverageGapReasonV1, NodeControlMessage,
    NodeDecommissionAcceptanceV1, Result, RuntimeIntegrationDecommissionV1,
    RuntimeIntegrationOwner, TrustCache,
};

type ConnectAttempt =
    Pin<Box<dyn Future<Output = (Result<crate::ControlConnection>, TrustCache)> + Send>>;

pub(super) struct NodeRun {
    node: NodeChassis,

    // Only one Control phase is active: connecting, connected, or backoff.
    connecting: Option<ConnectAttempt>,
    connection: Option<crate::ControlConnection>,
    reconnect: Option<Pin<Box<tokio::time::Sleep>>>,
    backoff: Duration,
    disconnected: tokio::time::Instant,
    failure_reported: bool,

    // Control loss closes admission but retains the last valid local policy.
    kernel_ready: bool,
    identity_ready: bool,
    evidence_ready: bool,
    prevention: bool,
    healthy_capabilities: Vec<CapabilityRecord>,
    healthy_claims: bool,

    // Advance uploads only after Control acknowledges the current batch.
    evidence_pending: bool,
    coverage_ack: Option<crate::control::CoverageAckV1>,
    coverage_snapshot: Option<crate::CoverageSnapshotV1>,
    coverage_pending: VecDeque<crate::CoverageIntervalV1>,
    coverage_acked: Option<(u64, u64)>,
    evidence_tick: tokio::time::Interval,
    policy_tick: tokio::time::Interval,
    policy_work: PolicyControlWorkV1,

    effect_stop: Arc<AtomicBool>,
    effect_task: Option<tokio::task::JoinHandle<erebor_interceptor::Result<()>>>,
    worker_task: Option<tokio::task::JoinHandle<()>>,
    local_task: Option<tokio::task::JoinHandle<Result<()>>>,
    admission_task: Option<tokio::task::JoinHandle<Result<()>>>,
    seccomp_task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl NodeRun {
    pub(super) async fn run(node: NodeChassis, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut state = Self::start(node, &shutdown);
        let evidence_configured = state.node.config.evidence.is_some();

        let result = async {
            while !*shutdown.borrow() {
                state.connect()?;
                let deadline = state.disconnected + state.node.evidence_control_delay();

                tokio::select! {
                    result = Self::wait(&mut state.connecting) => {
                        state.connected(result);
                    }
                    result = Self::next_message(&mut state.connection) => {
                        if state.control_message(result).await?.is_break() {
                            break;
                        }
                    }
                    _ = state.evidence_tick.tick(), if state.connection.is_some() => {
                        state.upload_evidence().await;
                    }
                    () = state.policy_work.pacing.wait_until_ready(&mut state.policy_tick),
                        if state.connection.is_some() => {
                        state.poll_policy().await?;
                    }

                    request = next_runtime_admission(&mut state.node.runtime_admission_requests) => {
                        state.node.answer_runtime_admission(request).await?;
                    }
                    notification = next_runtime_seccomp(&mut state.node.runtime_seccomp_notifications) => {
                        state.node.answer_runtime_seccomp(notification).await?;
                    }
                    () = state.node.bindings.wait_for_runtime_change(), if state.connecting.is_none() => {
                        state.reconcile_bindings().await;
                    }

                    _ = tokio::time::sleep_until(deadline),
                        if state.connecting.is_some() && state.evidence_ready && evidence_configured => {
                        state.control_delayed();
                    }
                    () = Self::wait(&mut state.reconnect) => {
                        state.reconnect = None;
                    }

                    result = Self::effect_reader_finished(&mut state.effect_task) => {
                        state.effect_task = None;
                        result?;
                        break;
                    }
                    result = Self::effect_worker_finished(&mut state.worker_task) => {
                        state.worker_task = None;
                        result?;
                        break;
                    }
                    result = Self::wait(&mut state.admission_task) => {
                        state.admission_task = None;
                        Self::listener_exit(&state.node.readiness,
                            result.context(LocalTaskSnafu)?, *shutdown.borrow(), "admission")?;
                        break;
                    }
                    result = Self::wait(&mut state.seccomp_task) => {
                        state.seccomp_task = None;
                        Self::listener_exit(&state.node.readiness,
                            result.context(LocalTaskSnafu)?, *shutdown.borrow(), "seccomp")?;
                        break;
                    }
                    _ = shutdown.changed() => break,
                }
            }
            Ok(())
        }.await;

        state.finish(result).await
    }

    fn start(mut node: NodeChassis, shutdown: &watch::Receiver<bool>) -> Self {
        let effect_stop = Arc::new(AtomicBool::new(false));
        let effect_task = node.effect_reader.take().map(|reader| {
            let stop = Arc::clone(&effect_stop);
            tokio::task::spawn_blocking(move || {
                while !stop.load(Ordering::Acquire) {
                    reader.poll(Duration::from_millis(100))?;
                }
                Ok(())
            })
        });
        let worker_task = node
            .effect_worker
            .take()
            .map(|worker| tokio::task::spawn_blocking(move || worker.run()));
        Self {
            connecting: None,
            connection: None,
            reconnect: None,
            backoff: node.config.control.reconnect_minimum(),
            disconnected: tokio::time::Instant::now(),
            failure_reported: false,
            kernel_ready: true,
            identity_ready: true,
            evidence_ready: node
                .registration
                .capabilities
                .iter()
                .find(|capability| capability.capability_id == "LOCAL_EFFECT_OBSERVATION")
                .is_none_or(|capability| capability.state != "UNHEALTHY"),
            prevention: node
                .policy
                .as_ref()
                .is_some_and(crate::NodePolicyGenerationOwner::prevention_enabled),
            healthy_capabilities: node.registration.capabilities.clone(),
            healthy_claims: node.registration.effect_prevention_claims_enabled,
            evidence_pending: false,
            coverage_ack: None,
            coverage_snapshot: None,
            coverage_pending: VecDeque::new(),
            coverage_acked: None,
            evidence_tick: Self::interval(Duration::from_millis(100)),
            policy_tick: Self::interval(Duration::from_millis(250)),
            policy_work: PolicyControlWorkV1::default(),
            effect_stop,
            effect_task,
            worker_task,
            local_task: node
                .local_server
                .take()
                .map(|server| tokio::spawn(server.serve(shutdown.clone()))),
            admission_task: node
                .runtime_admission_server
                .take()
                .map(|server| tokio::spawn(server.serve(shutdown.clone()))),
            seccomp_task: node
                .runtime_seccomp_server
                .take()
                .map(|server| tokio::spawn(server.serve(shutdown.clone()))),
            node,
        }
    }

    async fn effect_reader_finished(
        task: &mut Option<
            tokio::task::JoinHandle<std::result::Result<(), erebor_interceptor::Error>>,
        >,
    ) -> Result<()> {
        Self::wait(task)
            .await
            .context(LocalTaskSnafu)?
            .context(InterceptorSnafu)?;
        IdentityStateSnafu {
            reason: "effect observation reader stopped before node shutdown",
        }
        .fail()
    }

    async fn effect_worker_finished(task: &mut Option<tokio::task::JoinHandle<()>>) -> Result<()> {
        Self::wait(task).await.context(LocalTaskSnafu)?;
        IdentityStateSnafu {
            reason: "effect observation worker stopped before node shutdown",
        }
        .fail()
    }

    fn listener_exit(
        readiness: &watch::Sender<NodeReadinessV1>,
        result: Result<()>,
        shutdown: bool,
        listener: &str,
    ) -> Result<()> {
        if shutdown {
            return result;
        }
        readiness.send_modify(|readiness| readiness.admission_ready = false);
        result?;
        IdentityStateSnafu {
            reason: format!("runtime {listener} listener stopped before node shutdown"),
        }
        .fail()
    }

    fn interval(period: Duration) -> tokio::time::Interval {
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval
    }

    async fn wait<T>(future: &mut Option<impl Future<Output = T> + Unpin>) -> T {
        match future {
            Some(future) => future.await,
            None => std::future::pending().await,
        }
    }

    async fn next_message(
        connection: &mut Option<crate::ControlConnection>,
    ) -> Result<NodeControlMessage> {
        match connection {
            Some(connection) => connection.next_message().await,
            None => std::future::pending().await,
        }
    }

    fn admission_ready(&self) -> bool {
        self.kernel_ready && self.identity_ready && self.evidence_ready
    }

    fn publish_readiness(&self) {
        let connected = self.connection.is_some();
        self.node.readiness.send_replace(NodeReadinessV1 {
            kernel_ready: self.kernel_ready,
            identity_ready: self.identity_ready,
            control_ready: connected,
            admission_ready: connected && self.admission_ready(),
            effect_prevention_claims_enabled: NodeReadinessV1::prevention_claims_enabled(
                self.kernel_ready,
                self.identity_ready && self.evidence_ready,
                self.prevention,
            ),
        });
    }

    fn connect(&mut self) -> Result<()> {
        if self.connecting.is_none() && self.connection.is_none() && self.reconnect.is_none() {
            self.node.refresh_registration_authority_state()?;
            let connector = self.node.connector.clone();
            let registration = self.node.registration.clone();
            let ready = self.admission_ready();
            let mut trust = self.node.trust.connection_candidate();

            // Keep the same attempt while local admission requests are handled.
            self.connecting = Some(Box::pin(async move {
                let result = connector.connect(registration, ready, &mut trust).await;
                (result, trust)
            }));
        }
        Ok(())
    }

    fn connected(&mut self, result: (Result<crate::ControlConnection>, TrustCache)) {
        self.connecting = None;
        let (result, trust) = result;
        self.node.trust = trust;
        match result {
            Ok(connection) => {
                self.connection = Some(connection);
                self.failure_reported = false;
                self.backoff = self.node.config.control.reconnect_minimum();
                self.evidence_pending = false;
                self.coverage_ack = None;
                self.coverage_snapshot = None;
                self.coverage_pending.clear();
                self.coverage_acked = None;
                self.evidence_tick = Self::interval(Duration::from_millis(100));
                self.policy_tick = Self::interval(Duration::from_millis(250));
                self.policy_work = PolicyControlWorkV1::default();
                self.node.policy_delivery.begin_control_session();
                self.publish_readiness();
                erebor_telemetry::info!(
                    "connected to Mithril Control",
                    node_id = %self.node.config.node_id,
                    label_epoch = %self.node.label_epoch
                );
            }
            Err(error) => {
                if self.failure_reported {
                    erebor_telemetry::debug!(
                        "Mithril Control connection retry failed",
                        node_id = %self.node.config.node_id, error = %error
                    );
                } else {
                    erebor_telemetry::warn!(
                        error; "failed to connect to Mithril Control",
                        node_id = %self.node.config.node_id, retry = %"backoff"
                    );
                    self.failure_reported = true;
                }
                self.disconnect();
            }
        }
    }

    fn disconnect(&mut self) {
        self.connection = None;
        if let (Some(administrative), Some(host)) =
            (self.node.administrative.as_mut(), self.node.host.as_mut())
        {
            if administrative.cancel_armed_slots(host).is_err() {
                self.identity_ready = false;
                close_identity_claims(&mut self.node.registration);
            }
        }
        self.publish_readiness();
        self.disconnected = tokio::time::Instant::now();
        self.reconnect = Some(Box::pin(tokio::time::sleep(self.backoff)));
        self.backoff = cmp::min(
            self.backoff.saturating_mul(2),
            self.node.config.control.reconnect_maximum(),
        );
    }

    fn control_delayed(&mut self) {
        self.connecting = None;
        let _result = self
            .node
            .observations
            .mark_coverage_gapped(CoverageGapReasonV1::ControlDelay);
        self.evidence_ready = false;
        close_evidence_claims(&mut self.node.registration);
    }

    fn rpc_failed(&mut self, error: crate::Error, operation: &'static str) {
        let reuse = error.control_rpc_can_reuse_session();
        erebor_telemetry::warn!(
            error; "Mithril Control operation failed",
            node_id = %self.node.config.node_id, operation = %operation,
            retry = %if reuse { "same_session" } else { "reconnect" }
        );
        if !reuse {
            self.disconnect();
        }
    }

    async fn report_readiness(&mut self) {
        let ready = self.admission_ready();
        if let Some(connection) = self.connection.as_mut() {
            if let Err(error) = self
                .node
                .await_control_rpc(connection.report_readiness(self.kernel_ready, ready))
                .await
            {
                self.rpc_failed(error, "report readiness");
            }
        }
    }

    async fn control_message(
        &mut self,
        result: Result<NodeControlMessage>,
    ) -> Result<std::ops::ControlFlow<()>> {
        let message = match result {
            Ok(message) => message,
            Err(error) => {
                erebor_telemetry::warn!(
                    error; "lost the Mithril Control stream",
                    node_id = %self.node.config.node_id, retry = %"reconnect"
                );
                self.failure_reported = true;
                self.disconnect();
                return Ok(std::ops::ControlFlow::Continue(()));
            }
        };
        let Some(connection) = self.connection.as_mut() else {
            return Ok(std::ops::ControlFlow::Continue(()));
        };
        let (operation, result) = match message {
            NodeControlMessage::Administrative(AdministrativeControlRequest::Resolve(request)) => (
                "administrative resolution",
                connection
                    .send_resolution(self.node.resolve_administrative(request))
                    .await,
            ),
            NodeControlMessage::Administrative(AdministrativeControlRequest::Arm(request)) => (
                "administrative arm",
                connection
                    .send_arm_result(self.node.arm_administrative(request))
                    .await,
            ),
            NodeControlMessage::EvidenceAck(ack) => (
                "evidence acknowledgement",
                self.node
                    .observations
                    .acknowledge_evidence(ack)
                    .map(|complete| self.evidence_pending = !complete),
            ),
            NodeControlMessage::CoverageAck(ack) => {
                let result = (self.coverage_ack == Some(ack))
                    .then_some(())
                    .context(EvidenceStateSnafu {
                        reason: "Control returned a stale coverage acknowledgement",
                    })
                    .map(|()| {
                        self.coverage_ack = None;
                        if self.coverage_pending.is_empty() {
                            self.coverage_acked = Some((ack.source_epoch, ack.revision));
                            self.coverage_snapshot = None;
                        }
                    });
                ("coverage acknowledgement", result)
            }
            NodeControlMessage::Decommission(command) => return self.decommission(command).await,
        };
        if let Err(error) = result {
            erebor_telemetry::warn!(
                error; "failed to handle a Mithril Control message",
                node_id = %self.node.config.node_id, operation = %operation, retry = %"reconnect"
            );
            self.disconnect();
        }
        Ok(std::ops::ControlFlow::Continue(()))
    }

    async fn upload_evidence(&mut self) {
        if self.node.observations.evidence_errors() > 0 {
            if self.evidence_ready {
                erebor_telemetry::warn!(
                    "durable evidence became unhealthy",
                    node_id = %self.node.config.node_id,
                    error = %self.node.observations.first_evidence_error()
                        .unwrap_or_else(|| "the exact error is unavailable".to_owned()),
                    retry = %"after_reconciliation"
                );
                self.evidence_ready = false;
                close_evidence_claims(&mut self.node.registration);
                self.node.readiness.send_modify(|readiness| {
                    readiness.admission_ready = false;
                    readiness.effect_prevention_claims_enabled = false;
                });
                self.report_readiness().await;
            }
            return;
        }
        let Some(connection) = self.connection.as_mut() else {
            return;
        };
        if !self.evidence_pending {
            let batches = self.node.observations.next_evidence_batches();
            if !batches.is_empty() {
                match self
                    .node
                    .await_control_rpc(connection.send_evidence_group(batches))
                    .await
                {
                    Ok(()) => self.evidence_pending = true,
                    Err(error) => self.rpc_failed(error, "upload evidence"),
                }
                return;
            }
        }
        if self.coverage_snapshot.is_none()
            && self.coverage_ack.is_none()
            && self.coverage_pending.is_empty()
        {
            if let Some(snapshot) = self.node.observations.coverage_snapshot() {
                if self.coverage_acked != Some((snapshot.source_epoch, snapshot.revision)) {
                    self.coverage_pending = snapshot.current_intervals().into();
                    if self.coverage_pending.is_empty() {
                        erebor_telemetry::warn!(
                            "evidence coverage has no current source",
                            node_id = %self.node.config.node_id, retry = %"after_reconciliation"
                        );
                        self.disconnect();
                        return;
                    }
                    self.coverage_snapshot = Some(snapshot);
                }
            }
        }
        if self.coverage_ack.is_none() {
            if let (Some(snapshot), Some(current)) = (
                self.coverage_snapshot.as_ref(),
                self.coverage_pending.front(),
            ) {
                match self
                    .node
                    .await_control_rpc(connection.send_coverage_report(snapshot, current))
                    .await
                {
                    Ok(expected) => {
                        self.coverage_ack = Some(expected);
                        self.coverage_pending.pop_front();
                    }
                    Err(error) => self.rpc_failed(error, "report evidence coverage"),
                }
            }
        }
    }

    async fn poll_policy(&mut self) -> Result<()> {
        if let (Some(policy), Some(host)) = (self.node.policy.as_ref(), self.node.host.as_mut()) {
            if policy.retirement_pending() {
                policy.reconcile_policy_lifecycle(host)?;
            }
        }
        if !self.identity_ready || !self.evidence_ready {
            self.policy_work.pacing.mark_idle();
            return Ok(());
        }
        let Some(connection) = self.connection.as_mut() else {
            return Ok(());
        };
        self.policy_work.pacing.mark_pending();
        match self
            .node
            .advance_policy_control_step(connection, &mut self.policy_work, self.evidence_ready)
            .await?
        {
            PolicyControlStepV1::Continue => {}
            PolicyControlStepV1::Idle => self.policy_work.pacing.mark_idle(),
            PolicyControlStepV1::Reconnect => self.disconnect(),
            PolicyControlStepV1::Activated => {
                self.prevention = self
                    .node
                    .policy
                    .as_ref()
                    .is_some_and(crate::NodePolicyGenerationOwner::prevention_enabled);
                self.healthy_capabilities = self.node.registration.capabilities.clone();
                self.healthy_claims = self.node.registration.effect_prevention_claims_enabled;
            }
        }
        Ok(())
    }

    async fn reconcile_bindings(&mut self) {
        let connected = self.connection.is_some();
        let mut report = false;
        match self.node.reconcile_bindings(connected).await {
            ReconciliationOutcome::Healthy => {
                let evidence_recovered = connected && !self.evidence_ready;
                let identity_recovered = !self.identity_ready && self.kernel_ready;
                if evidence_recovered {
                    self.evidence_ready = true;
                    restore_evidence_claims(
                        &mut self.node.registration,
                        &mut self.healthy_capabilities,
                        self.prevention,
                    );
                    self.healthy_claims = self.prevention;
                    self.node.readiness.send_modify(|readiness| {
                        readiness.admission_ready = self.kernel_ready && self.identity_ready;
                        readiness.effect_prevention_claims_enabled =
                            NodeReadinessV1::prevention_claims_enabled(
                                self.kernel_ready,
                                self.identity_ready,
                                self.prevention,
                            );
                    });
                }
                if identity_recovered {
                    self.identity_ready = true;
                    restore_identity_claims(
                        &mut self.node.registration,
                        &self.healthy_capabilities,
                        self.healthy_claims && self.evidence_ready,
                    );
                    self.node.readiness.send_replace(NodeReadinessV1 {
                        kernel_ready: true,
                        identity_ready: true,
                        control_ready: connected,
                        admission_ready: connected,
                        effect_prevention_claims_enabled: connected && self.healthy_claims,
                    });
                }
                report = connected && (evidence_recovered || identity_recovered);
                if report {
                    erebor_telemetry::info!(
                        "recovered Mithril Node readiness",
                        node_id = %self.node.config.node_id, evidence_ready = %self.evidence_ready,
                        identity_ready = %self.identity_ready
                    );
                }
            }
            ReconciliationOutcome::EvidenceUnhealthy(reason) => {
                report = connected && self.evidence_ready;
                self.evidence_ready = false;
                close_evidence_claims(&mut self.node.registration);
                if report {
                    erebor_telemetry::warn!(
                        "evidence reconciliation became unhealthy",
                        node_id = %self.node.config.node_id, error = %reason, retry = %"after_reconciliation"
                    );
                    self.node.readiness.send_modify(|readiness| {
                        readiness.admission_ready = false;
                        readiness.effect_prevention_claims_enabled = false;
                    });
                }
            }
            ReconciliationOutcome::IdentityUnhealthy { owner, reason } => {
                report = connected && self.identity_ready;
                self.identity_ready = false;
                close_identity_claims(&mut self.node.registration);
                if report {
                    erebor_telemetry::warn!(
                        "identity reconciliation became unhealthy",
                        node_id = %self.node.config.node_id, owner = %owner,
                        error = %reason, retry = %"after_reconciliation"
                    );
                    self.publish_readiness();
                }
            }
            ReconciliationOutcome::KernelUnhealthy(reason) => {
                self.kernel_ready = false;
                self.identity_ready = false;
                self.node.close_kernel_claims();
                if connected {
                    erebor_telemetry::error!(
                        "kernel reconciliation became unhealthy",
                        node_id = %self.node.config.node_id, error = %reason
                    );
                    self.disconnect();
                }
            }
        }
        if report {
            self.report_readiness().await;
        }
    }

    fn accept_decommission(&mut self, artifact: &[u8]) -> Result<NodeDecommissionAcceptanceV1> {
        let count = self.node.policy_delivery.status().runtime_binding_count;
        self.node
            .decommission
            .as_mut()
            .context(IdentityStateSnafu {
                reason: "node decommission is not configured",
            })?
            .accept(artifact, count, crate::policy::current_utc_ns()?)
    }

    async fn decommission(
        &mut self,
        command: mithril_control::NodeDecommissionCommand,
    ) -> Result<std::ops::ControlFlow<()>> {
        let digest: [u8; 32] = Sha256::digest(&command.artifact).into();
        if !command.execute {
            let (state, reason) = match self.accept_decommission(&command.artifact) {
                Ok(acceptance) => {
                    erebor_telemetry::info!(
                        "accepted a signed node decommission",
                        node_id = %self.node.config.node_id, artifact_sha256 = %hex::encode(digest),
                        acceptance = %format!("{acceptance:?}")
                    );
                    ("ACCEPTED", String::new())
                }
                Err(error) => {
                    erebor_telemetry::warn!(
                        error; "rejected a signed node decommission",
                        node_id = %self.node.config.node_id, artifact_sha256 = %hex::encode(digest)
                    );
                    ("REJECTED", "AUTHORIZATION_REJECTED".to_owned())
                }
            };
            if let Some(connection) = self.connection.as_mut() {
                if let Err(error) = connection
                    .send_decommission_result(digest, state, reason)
                    .await
                {
                    erebor_telemetry::warn!(
                        error; "failed to return node decommission acceptance",
                        node_id = %self.node.config.node_id, retry = %"reconnect"
                    );
                    self.disconnect();
                }
            }
            return Ok(std::ops::ControlFlow::Continue(()));
        }
        // Close listeners before removing their sockets and runtime integration.
        Self::stop_server(&mut self.admission_task, true).await?;
        Self::stop_server(&mut self.seccomp_task, true).await?;
        self.node.runtime_admission_requests = None;
        self.node.runtime_seccomp_notifications = None;
        if let Some(admission) = &self.node.config.runtime_admission {
            for path in [
                admission.socket_path.clone(),
                crate::runtime_admission::seccomp_listener_path(&admission.socket_path),
            ] {
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(crate::Error::Io {
                            path,
                            source,
                            location: snafu::Location::default(),
                        })
                    }
                }
            }
        }
        let acceptance = self
            .accept_decommission(&command.artifact)
            .inspect_err(|error| {
                erebor_telemetry::warn!(
                    error; "deferred physical node decommission",
                    node_id = %self.node.config.node_id, artifact_sha256 = %hex::encode(digest),
                    retry = %"after_restart"
                );
            })?;
        if acceptance != NodeDecommissionAcceptanceV1::Completed {
            let config = self
                .node
                .config
                .decommission
                .as_ref()
                .context(IdentityStateSnafu {
                    reason: "node decommission is not configured",
                })?;
            let runtime = RuntimeIntegrationDecommissionV1 {
                owner: config.runtime_integration_owner.clone(),
                hook_directory: config.runtime_hook_directory.clone(),
                containerd_config_directory: config.containerd_config_directory.clone(),
                containerd_drop_in_directory: config.containerd_drop_in_directory.clone(),
                runtime_services: config.runtime_services.clone(),
            };
            RuntimeIntegrationOwner::decommission(&runtime).map_err(|source| crate::Error::Io {
                path: runtime.containerd_config_directory.clone(),
                source,
                location: snafu::Location::default(),
            })?;
            erebor_telemetry::info!(
                "removed the owned Mithril runtime integration",
                node_id = %self.node.config.node_id, artifact_sha256 = %hex::encode(digest)
            );
            Self::stop_server(&mut self.local_task, true).await?;
            self.stop_effects().await?;
            self.node
                .host
                .take()
                .context(IdentityStateSnafu {
                    reason: "node decommission has no kernel owner",
                })?
                .decommission()
                .context(InterceptorSnafu)?;
            erebor_telemetry::info!(
                "removed the owned Mithril kernel attachments",
                node_id = %self.node.config.node_id, artifact_sha256 = %hex::encode(digest)
            );
            self.node
                .decommission
                .as_mut()
                .context(IdentityStateSnafu {
                    reason: "node decommission owner disappeared",
                })?
                .complete(&command.artifact)?;
        }
        if let Some(connection) = self.connection.as_mut() {
            connection
                .send_decommission_result(digest, "COMPLETED", String::new())
                .await?;
        }
        erebor_telemetry::info!(
            "completed a Mithril node decommission",
            node_id = %self.node.config.node_id, artifact_sha256 = %hex::encode(digest)
        );
        Ok(std::ops::ControlFlow::Break(()))
    }

    async fn stop_effects(&mut self) -> Result<()> {
        // Stop the reader before the worker and kernel host stop.
        self.effect_stop.store(true, Ordering::Release);
        if let Some(task) = self.effect_task.take() {
            task.await
                .context(LocalTaskSnafu)?
                .context(InterceptorSnafu)?;
        }
        if let Some(task) = self.worker_task.take() {
            task.await.context(LocalTaskSnafu)?;
        }
        Ok(())
    }

    async fn stop_server(
        task: &mut Option<tokio::task::JoinHandle<Result<()>>>,
        abort: bool,
    ) -> Result<()> {
        if let Some(task) = task.take() {
            if abort {
                task.abort();
                let _result = task.await;
            } else {
                task.await.context(LocalTaskSnafu)??;
            }
        }
        Ok(())
    }

    async fn finish(&mut self, result: Result<()>) -> Result<()> {
        let _result = self
            .node
            .observations
            .mark_coverage_gapped(CoverageGapReasonV1::ReaderStopped);
        self.stop_effects().await?;
        if let Some(host) = self.node.host.take() {
            host.shutdown().context(InterceptorSnafu)?;
        }
        Self::stop_server(&mut self.local_task, result.is_err()).await?;
        Self::stop_server(&mut self.admission_task, result.is_err()).await?;
        Self::stop_server(&mut self.seccomp_task, result.is_err()).await?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_effect_reader_exit_is_a_node_failure() {
        let mut task = Some(tokio::spawn(async { Ok(()) }));
        assert!(NodeRun::effect_reader_finished(&mut task)
            .await
            .is_err_and(|error| error.to_string().contains("stopped before node shutdown")));
    }

    #[tokio::test]
    async fn an_effect_worker_exit_is_a_node_failure() {
        let mut task = Some(tokio::spawn(async {}));
        assert!(NodeRun::effect_worker_finished(&mut task)
            .await
            .is_err_and(|error| error.to_string().contains("stopped before node shutdown")));
    }

    #[tokio::test]
    async fn listener_exit_closes_admission() -> Result<()> {
        let (readiness, receiver) = watch::channel(NodeReadinessV1 {
            kernel_ready: true,
            identity_ready: true,
            control_ready: true,
            admission_ready: true,
            effect_prevention_claims_enabled: true,
        });
        for listener in ["admission", "seccomp"] {
            readiness.send_modify(|state| state.admission_ready = true);
            let mut task = Some(tokio::spawn(async { Ok(()) }));
            let result = NodeRun::wait(&mut task).await.context(LocalTaskSnafu)?;
            assert!(
                NodeRun::listener_exit(&readiness, result, false, listener).is_err_and(|error| {
                    error
                        .to_string()
                        .contains(&format!("{listener} listener stopped"))
                })
            );
            assert!(!receiver.borrow().admission_ready);
            assert!(!receiver.borrow().admits_new_work());

            assert!(NodeRun::listener_exit(&readiness, Ok(()), true, listener).is_ok());
            let error = IdentityStateSnafu {
                reason: "listener failed",
            }
            .build();
            assert!(
                NodeRun::listener_exit(&readiness, Err(error), true, listener)
                    .is_err_and(|error| error.to_string().contains("listener failed"))
            );
        }
        Ok(())
    }
}
