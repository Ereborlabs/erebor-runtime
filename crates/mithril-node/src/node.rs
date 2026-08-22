use erebor_interceptor::{EffectObservationReader, KernelHost, KernelHostConfig, KernelHostOwner};
use erebor_interceptor_abi::Id128V1;
use mithril_control::{
    AdministrativeExecArmResult, AdministrativeExecResolution, AdministrativeFileObject,
    CapabilityRecord, NodeRegistration, PolicyActivationAcknowledgement, PolicyBundleV1,
    RegisteredWorkloadTarget, ResolvedAdministrativeExecutable,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use std::cmp;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

use crate::administrative_exec::{
    AdministrativeExecOwner, AdministrativeResolutionV1, AdministrativeResolveRequestV1,
};
use crate::epoch::NodeEpochs;
use crate::error::{
    EvidenceStateSnafu, IdentityStateSnafu, InterceptorSnafu, JsonSnafu, LocalTaskSnafu,
};
use crate::{
    AdministrativeControlRequest, CoverageGapReasonV1, NativeSecurityStateOwner, NodeConfig,
    NodeControlConnector, NodeControlMessage, ObservationCanonicalizer, Result, TrustCache,
    WorkloadBindingOwner,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct NodeReadinessV1 {
    pub kernel_ready: bool,
    pub identity_ready: bool,
    pub control_ready: bool,
    pub admission_ready: bool,
    pub effect_prevention_claims_enabled: bool,
}

impl NodeReadinessV1 {
    #[must_use]
    pub const fn admits_new_work(self) -> bool {
        self.kernel_ready && self.identity_ready && self.control_ready && self.admission_ready
    }

    const fn prevention_claims_enabled(
        kernel_healthy: bool,
        identity_healthy: bool,
        prevention_configured: bool,
    ) -> bool {
        kernel_healthy && identity_healthy && prevention_configured
    }

    fn close_kernel_claims(&mut self) {
        self.kernel_ready = false;
        self.identity_ready = false;
        self.admission_ready = false;
        self.effect_prevention_claims_enabled = false;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconciliationOutcome {
    Healthy,
    EvidenceUnhealthy,
    IdentityUnhealthy,
    KernelUnhealthy,
}

pub struct NodeChassis {
    config: NodeConfig,
    effect_reader: Option<EffectObservationReader>,
    host: Option<KernelHost>,
    connector: NodeControlConnector,
    registration: NodeRegistration,
    local_server: Option<crate::RuntimeObservationServer>,
    runtime_admission_server: Option<crate::runtime_admission::RuntimeAdmissionServer>,
    runtime_admission_requests: Option<crate::runtime_admission::RuntimeAdmissionReceiver>,
    trust: TrustCache,
    bindings: WorkloadBindingOwner,
    identity: NativeSecurityStateOwner,
    policy: Option<crate::NodePolicyGenerationOwner>,
    policy_delivery: crate::policy_delivery::NodePolicyDeliveryOwner,
    administrative: Option<AdministrativeExecOwner>,
    readiness: watch::Sender<NodeReadinessV1>,
    observations: crate::EffectObservationStore,
    node_boot_id: Id128V1,
    label_epoch: u64,
}

impl NodeChassis {
    pub async fn start(config: NodeConfig) -> Result<Self> {
        Self::start_with_held_initial_pids(config, &[]).await
    }

    pub async fn start_with_held_initial_pids(
        mut config: NodeConfig,
        held_initial_pids: &[u32],
    ) -> Result<Self> {
        config.validate()?;
        let trust = TrustCache::load(&config.state_directory)?;
        let policy_delivery =
            crate::policy_delivery::NodePolicyDeliveryOwner::load(&config.state_directory)?;
        if !held_initial_pids.is_empty() {
            snafu::ensure!(
                config.container_runtime.is_none()
                    && held_initial_pids.len() == config.workload_bindings.len()
                    && config
                        .workload_bindings
                        .iter()
                        .all(|binding| binding.arm_initial_root)
                    && held_initial_pids.iter().all(|pid| *pid > 0),
                IdentityStateSnafu {
                    reason:
                        "prestart admission requires one held root for each armed static binding",
                }
            );
        }
        let boot_id = NodeEpochs::boot_id()?;
        let node_boot_id = boot_id.into();
        let recover_identity = config
            .interceptor
            .pin_root
            .join("maps/identity_config")
            .exists();
        snafu::ensure!(
            held_initial_pids.is_empty() || !recover_identity,
            IdentityStateSnafu {
                reason: "prestart admission requires a fresh identity pin root",
            }
        );
        let label_epoch = NodeEpochs::label_epoch(&config.state_directory, recover_identity)?;
        policy_delivery.restore_config_for_session(
            &mut config,
            &trust,
            crate::policy::current_utc_ns()?,
            &boot_id,
            label_epoch,
        )?;
        config.validate()?;
        let identity = match config.container_runtime.as_ref() {
            Some(runtime) => NativeSecurityStateOwner::for_effect_controller(
                node_boot_id,
                label_epoch,
                &runtime.effect_controller_cgroup_path,
            )?,
            None => NativeSecurityStateOwner::new(node_boot_id, label_epoch),
        };
        let owner = KernelHostOwner::new(KernelHostConfig::identity(
            &config.interceptor.runtime_btf_path,
            &config.interceptor.lease_path,
            Some(config.interceptor.pin_root.clone()),
            uuid::Uuid::from_bytes(boot_id).simple().to_string(),
            label_epoch,
        ));
        let mut host = owner.start().context(InterceptorSnafu)?;
        identity.claim_effect_controller(&host)?;
        let mut bindings = if let Some(runtime) = config.container_runtime.as_ref() {
            WorkloadBindingOwner::system_with_runtime(node_boot_id, label_epoch, runtime).await?
        } else {
            WorkloadBindingOwner::system(node_boot_id, label_epoch)?
        };
        if held_initial_pids.is_empty() {
            bindings
                .publish_configured(&host, &config.workload_bindings)
                .await?;
        } else {
            let created = config
                .workload_bindings
                .iter()
                .cloned()
                .zip(held_initial_pids.iter().copied())
                .collect::<Vec<_>>();
            bindings.publish_held_initial_roots(&host, &created)?;
        }
        let policy = if config.policy_candidates.is_empty() {
            None
        } else {
            Some(
                crate::NodePolicyGenerationOwner::load_and_install_for_bindings(
                    &config,
                    &mut host,
                    &bindings,
                    node_boot_id,
                    label_epoch,
                )?,
            )
        };
        if policy.is_some() {
            bindings.adopt_activated_profiles(&host, &config.workload_bindings)?;
        }
        let mut policy_delivery = policy_delivery;
        if policy.is_some() {
            policy_delivery.recover_pending_activation(&host, &config)?;
        }
        let dynamic_policy_capable = config.evidence.is_some()
            && (config.runtime_admission.is_some()
                || config.workload_bindings.iter().any(|binding| {
                    !binding.cluster_uid.is_empty()
                        && !binding.namespace_uid.is_empty()
                        && !binding.controller_uid.is_empty()
                        && !binding.service_account_uid.is_empty()
                }));
        let administrative_required = policy
            .as_ref()
            .is_some_and(crate::NodePolicyGenerationOwner::administrative_enabled);
        let mut administrative = match (
            config.administrative_authorization.as_ref(),
            administrative_required,
        ) {
            (Some(authorization), true) => Some(AdministrativeExecOwner::load(
                authorization,
                &config.state_directory,
                crate::policy::stable_node_id(&config.node_id)?,
                node_boot_id,
            )?),
            (None, true) => {
                return IdentityStateSnafu {
                    reason: "signed administrative entry policy has no authorization trust owner"
                        .to_owned(),
                }
                .fail()
            }
            (Some(authorization), false) if dynamic_policy_capable => {
                Some(AdministrativeExecOwner::load(
                    authorization,
                    &config.state_directory,
                    crate::policy::stable_node_id(&config.node_id)?,
                    node_boot_id,
                )?)
            }
            (Some(_), false) => {
                return IdentityStateSnafu {
                    reason: "administrative authorization is configured without a signed administrative entry plan"
                        .to_owned(),
                }
                .fail()
            }
            (None, false) => None,
        };
        if let Some(administrative) = administrative.as_mut() {
            administrative.reconcile(&host)?;
        }
        let policy_loaded = policy.is_some();
        let policy_observation_enabled = policy_loaded || dynamic_policy_capable;
        let prevention_enabled = policy
            .as_ref()
            .is_some_and(crate::NodePolicyGenerationOwner::prevention_enabled);
        let reconciliation = if held_initial_pids.is_empty() {
            identity.activate_with_effect_policy(&mut host, policy_loaded)?
        } else {
            identity.activate_held_initial_admission(&mut host, policy_loaded)?
        };
        let observations = if policy_observation_enabled {
            let evidence = config.evidence.as_ref().ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "effect policy has no durable evidence configuration".to_owned(),
                }
                .build()
            })?;
            let source_epoch = NodeEpochs::source_epoch(&config.state_directory, recover_identity)?;
            let (tenant_id, source_id) = evidence.identities()?;
            let canonicalizer =
                ObservationCanonicalizer::new(tenant_id, source_id, source_epoch, node_boot_id)?;
            crate::EffectObservationStore::durable(
                1_024,
                NodeEpochs::evidence_wal_directory(&config.state_directory),
                evidence.into(),
                canonicalizer,
            )?
        } else {
            crate::EffectObservationStore::default()
        };
        let effect_reader = policy_observation_enabled
            .then(|| {
                let sink = observations.clone();
                host.effect_observation_reader(move |bytes| {
                    sink.record_bytes(bytes);
                    0
                })
            })
            .transpose()
            .context(InterceptorSnafu)?;
        let evidence_healthy =
            !policy_observation_enabled || sample_effect_health(&host, &observations, true).is_ok();
        let manifest = host.manifest();
        let capabilities = vec![
            CapabilityRecord {
                capability_id: "EXACT_NATIVE_IDENTITY".to_owned(),
                state: "SUPPORTED".to_owned(),
                reason_code: if reconciliation == Default::default() {
                    "EXACT_ATTACH_AND_RECONCILIATION".to_owned()
                } else {
                    "CONSERVATIVE_IDENTITY_RESTRICTIONS_RETAINED".to_owned()
                },
            },
            CapabilityRecord {
                capability_id: "LOCAL_EFFECT_PREVENTION".to_owned(),
                state: if prevention_enabled || dynamic_policy_capable {
                    "SUPPORTED".to_owned()
                } else {
                    "UNSUPPORTED".to_owned()
                },
                reason_code: if prevention_enabled {
                    "SIGNED_ACTIVE_QUALIFIED_LOCAL_SLICE".to_owned()
                } else if dynamic_policy_capable {
                    "POLICY_ACTIVATION_OWNER_READY_NO_ACTIVE_GENERATION".to_owned()
                } else if policy_loaded {
                    "OBSERVE_ONLY_GENERATION".to_owned()
                } else {
                    "IDENTITY_GATE_ONLY_NO_PERMISSION_TABLE".to_owned()
                },
            },
            CapabilityRecord {
                capability_id: "LOCAL_EFFECT_OBSERVATION".to_owned(),
                state: if policy_observation_enabled && evidence_healthy {
                    "SUPPORTED".to_owned()
                } else if policy_observation_enabled {
                    "UNHEALTHY".to_owned()
                } else {
                    "UNSUPPORTED".to_owned()
                },
                reason_code: if policy_observation_enabled && evidence_healthy {
                    "DURABLE_LOSS_AWARE_KERNEL_COVERAGE".to_owned()
                } else if policy_observation_enabled {
                    "DURABLE_EVIDENCE_COVERAGE_GAPPED".to_owned()
                } else {
                    "NO_POLICY_CANDIDATE".to_owned()
                },
            },
            CapabilityRecord {
                capability_id: "RUNTIME_READ_ONLY_OBSERVATION".to_owned(),
                state: if config.runtime_observation.is_some() {
                    "SUPPORTED".to_owned()
                } else {
                    "UNSUPPORTED".to_owned()
                },
                reason_code: if config.runtime_observation.is_some() {
                    "PEER_CREDENTIAL_AND_CGROUP_SCOPED".to_owned()
                } else {
                    "NOT_CONFIGURED".to_owned()
                },
            },
            CapabilityRecord {
                capability_id: "LANDLOCK_TARGET_CONTEXT_FLOOR".to_owned(),
                state: "UNSUPPORTED".to_owned(),
                reason_code: "NO_QUALIFIED_TARGET_CONTEXT_INSTALL".to_owned(),
            },
        ];
        let registration = registration(
            manifest,
            label_epoch,
            prevention_enabled && evidence_healthy,
            capabilities.clone(),
            config.kubernetes_node_name.as_deref(),
            &config.workload_bindings,
        )?;
        let connector =
            NodeControlConnector::new(config.control.clone(), config.node_id.clone(), boot_id);
        let (readiness, _receiver) = watch::channel(NodeReadinessV1 {
            kernel_ready: true,
            identity_ready: true,
            control_ready: false,
            admission_ready: false,
            effect_prevention_claims_enabled: prevention_enabled && evidence_healthy,
        });
        let local_server = config
            .runtime_observation
            .clone()
            .map(|runtime| {
                crate::RuntimeObservationServer::bind_with_effects(
                    runtime,
                    manifest,
                    &capabilities,
                    observations.clone(),
                    config.interceptor.pin_root.clone(),
                    readiness.subscribe(),
                )
            })
            .transpose()?;
        let (runtime_admission_server, runtime_admission_requests) = config
            .runtime_admission
            .as_ref()
            .map(crate::runtime_admission::RuntimeAdmissionServer::bind)
            .transpose()?
            .map_or((None, None), |(server, requests)| {
                (Some(server), Some(requests))
            });
        Ok(Self {
            config,
            effect_reader,
            host: Some(host),
            connector,
            registration,
            local_server,
            runtime_admission_server,
            runtime_admission_requests,
            trust,
            bindings,
            identity,
            policy,
            policy_delivery,
            administrative,
            readiness,
            observations,
            node_boot_id,
            label_epoch,
        })
    }

    #[must_use]
    pub fn readiness(&self) -> watch::Receiver<NodeReadinessV1> {
        self.readiness.subscribe()
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut prevention_enabled = self
            .policy
            .as_ref()
            .is_some_and(crate::NodePolicyGenerationOwner::prevention_enabled);
        let effect_stop = Arc::new(AtomicBool::new(false));
        let mut effect_task = self.effect_reader.take().map(|reader| {
            let stop = Arc::clone(&effect_stop);
            tokio::task::spawn_blocking(move || -> erebor_interceptor::Result<()> {
                while !stop.load(Ordering::Acquire) {
                    reader.poll(Duration::from_millis(100))?;
                }
                Ok(())
            })
        });
        let mut local_task = self.local_server.take().map(|server| {
            let local_shutdown = shutdown.clone();
            tokio::spawn(server.serve(local_shutdown))
        });
        let mut runtime_admission_task = self.runtime_admission_server.take().map(|server| {
            let runtime_shutdown = shutdown.clone();
            tokio::spawn(server.serve(runtime_shutdown))
        });
        let mut backoff = self.config.control.reconnect_minimum();
        let mut kernel_healthy = true;
        let mut identity_healthy = true;
        let mut evidence_healthy = self
            .registration
            .capabilities
            .iter()
            .find(|capability| capability.capability_id == "LOCAL_EFFECT_OBSERVATION")
            .is_none_or(|capability| capability.state != "UNHEALTHY");
        let mut control_disconnected_since = tokio::time::Instant::now();
        let mut run_error = None;
        let mut healthy_identity_capabilities = self.registration.capabilities.clone();
        let mut healthy_effect_prevention_claims =
            self.registration.effect_prevention_claims_enabled;
        let mut reconciliation = tokio::time::interval(self.config.reconciliation_interval());
        reconciliation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        'running: loop {
            if *shutdown.borrow() {
                break;
            }
            let evidence_control_deadline =
                control_disconnected_since + self.evidence_control_delay();
            let evidence_configured =
                self.effect_reader.is_some() || self.config.evidence.is_some();
            let connection = tokio::select! {
                result = self.connector.connect(
                    self.registration.clone(),
                    kernel_healthy && identity_healthy && evidence_healthy,
                    &mut self.trust,
                ) => result,
                _instant = tokio::time::sleep_until(evidence_control_deadline),
                    if evidence_healthy && evidence_configured => {
                    let _result = self.observations.mark_coverage_gapped(
                        CoverageGapReasonV1::ControlDelay,
                    );
                    evidence_healthy = false;
                    close_evidence_claims(&mut self.registration);
                    continue 'running;
                }
                changed = shutdown.changed() => {
                    let _result = changed;
                    break;
                }
                request = next_runtime_admission(&mut self.runtime_admission_requests) => {
                    self.answer_runtime_admission(request).await;
                    continue 'running;
                }
                result = effect_reader_finished(&mut effect_task) => {
                    let _result = self.observations.mark_coverage_gapped(
                        CoverageGapReasonV1::ReaderStopped,
                    );
                    run_error = result.err();
                    effect_task = None;
                    break;
                }
            };
            match connection {
                Ok(mut connection) => {
                    self.readiness.send_replace(NodeReadinessV1 {
                        kernel_ready: kernel_healthy,
                        identity_ready: identity_healthy,
                        control_ready: true,
                        admission_ready: kernel_healthy && identity_healthy && evidence_healthy,
                        effect_prevention_claims_enabled:
                            NodeReadinessV1::prevention_claims_enabled(
                                kernel_healthy,
                                identity_healthy && evidence_healthy,
                                prevention_enabled,
                            ),
                    });
                    backoff = self.config.control.reconnect_minimum();
                    let mut evidence_in_flight = false;
                    let mut coverage_in_flight = None;
                    let mut acknowledged_coverage = None;
                    let mut evidence_upload = tokio::time::interval(Duration::from_millis(100));
                    evidence_upload
                        .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    let mut policy_poll = tokio::time::interval(Duration::from_millis(250));
                    policy_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    let mut rejected_candidate = None;
                    loop {
                        tokio::select! {
                            result = connection.next_message() => {
                                let message = match result {
                                    Ok(message) => message,
                                    Err(_error) => break,
                                };
                                match message {
                                    NodeControlMessage::Administrative(AdministrativeControlRequest::Resolve(request)) => {
                                        let response = self.resolve_administrative(request);
                                        if connection.send_resolution(response).await.is_err() {
                                            break;
                                        }
                                    }
                                    NodeControlMessage::Administrative(AdministrativeControlRequest::Arm(request)) => {
                                        let response = self.arm_administrative(request);
                                        if connection.send_arm_result(response).await.is_err() {
                                            break;
                                        }
                                    }
                                    NodeControlMessage::EvidenceAck(ack) => {
                                        let Ok(ack) = ack.try_into() else {
                                            break;
                                        };
                                        if self.observations.acknowledge_evidence(ack).is_err() {
                                            break;
                                        }
                                        evidence_in_flight = false;
                                    }
                                    NodeControlMessage::CoverageAck(ack) => {
                                        if coverage_in_flight.as_ref() != Some(&ack) {
                                            break;
                                        }
                                        acknowledged_coverage =
                                            Some((ack.source_epoch, ack.revision));
                                        coverage_in_flight = None;
                                    }
                                }
                            }
                            _instant = evidence_upload.tick() => {
                                if self.observations.evidence_errors() > 0 {
                                    evidence_healthy = false;
                                    close_evidence_claims(&mut self.registration);
                                    self.readiness.send_modify(|readiness| {
                                        readiness.admission_ready = false;
                                        readiness.effect_prevention_claims_enabled = false;
                                    });
                                    break;
                                }
                                if !evidence_in_flight {
                                    if let Some(batch) = self.observations.next_evidence_batch() {
                                    if connection.send_evidence_batch(batch).await.is_err() {
                                        break;
                                    }
                                    evidence_in_flight = true;
                                    }
                                }
                                if coverage_in_flight.is_none() {
                                    if let Some(snapshot) = self.observations.coverage_snapshot() {
                                        let key = (snapshot.source_epoch, snapshot.revision);
                                        if acknowledged_coverage != Some(key) {
                                            match connection.send_coverage_report(snapshot).await {
                                                Ok(expected) => coverage_in_flight = Some(expected),
                                                Err(_error) => break,
                                            }
                                        }
                                    }
                                }
                            }
                            _instant = policy_poll.tick() => {
                                let bundle = match self
                                    .policy_delivery
                                    .fetch_candidate(&mut connection)
                                    .await
                                {
                                    Ok(Some(bundle)) => bundle,
                                    Ok(None) => {
                                        if let Some(acknowledgement) =
                                            self.policy_delivery.pending_acknowledgement()
                                        {
                                            let candidate_content_id =
                                                acknowledgement.candidate_content_id.clone();
                                            if connection
                                                .acknowledge_policy(acknowledgement)
                                                .await
                                                .is_err()
                                            {
                                                break;
                                            }
                                            self.policy_delivery
                                                .acknowledge_control(&candidate_content_id)?;
                                        }
                                        continue;
                                    }
                                    Err(_error) => break,
                                };
                                if rejected_candidate.as_deref()
                                    == Some(bundle.candidate.candidate_content_id.as_str())
                                {
                                    continue;
                                }
                                let prepared = match self.prepare_control_policy(&bundle) {
                                    Ok(prepared) => prepared,
                                    Err(_error) => {
                                        rejected_candidate = Some(
                                            bundle.candidate.candidate_content_id.clone(),
                                        );
                                        if connection
                                            .acknowledge_policy(rejected_policy_acknowledgement(
                                                &bundle,
                                            )?)
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                        continue;
                                    }
                                };
                                self.activate_control_policy(
                                    &bundle,
                                    prepared,
                                    evidence_healthy,
                                )?;
                                prevention_enabled = self
                                    .policy
                                    .as_ref()
                                    .is_some_and(
                                        crate::NodePolicyGenerationOwner::prevention_enabled,
                                    );
                                healthy_identity_capabilities =
                                    self.registration.capabilities.clone();
                                healthy_effect_prevention_claims =
                                    self.registration.effect_prevention_claims_enabled;
                                if let Some(acknowledgement) =
                                    self.policy_delivery.pending_acknowledgement()
                                {
                                    let candidate_content_id =
                                        acknowledgement.candidate_content_id.clone();
                                    if connection
                                        .acknowledge_policy(acknowledgement)
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                    self.policy_delivery
                                        .acknowledge_control(&candidate_content_id)?;
                                }
                                break;
                            }
                            changed = shutdown.changed() => {
                                let _result = changed;
                                break 'running;
                            }
                            request = next_runtime_admission(&mut self.runtime_admission_requests) => {
                                self.answer_runtime_admission(request).await;
                            }
                            result = effect_reader_finished(&mut effect_task) => {
                                let _result = self.observations.mark_coverage_gapped(
                                    CoverageGapReasonV1::ReaderStopped,
                                );
                                run_error = result.err();
                                effect_task = None;
                                break 'running;
                            }
                            () = async {
                                tokio::select! {
                                    () = self.bindings.wait_for_runtime_change() => {}
                                    _instant = reconciliation.tick() => {}
                                }
                            } => {
                                match self.reconcile_bindings(true).await {
                                    ReconciliationOutcome::Healthy => {
                                        let recovered = !evidence_healthy
                                            || (!identity_healthy && kernel_healthy);
                                        if !evidence_healthy {
                                            evidence_healthy = true;
                                            restore_evidence_claims(
                                                &mut self.registration,
                                                &healthy_identity_capabilities,
                                                healthy_effect_prevention_claims,
                                            );
                                            self.readiness.send_modify(|readiness| {
                                                readiness.admission_ready =
                                                    kernel_healthy && identity_healthy;
                                                readiness.effect_prevention_claims_enabled =
                                                    NodeReadinessV1::prevention_claims_enabled(
                                                        kernel_healthy,
                                                        identity_healthy,
                                                        prevention_enabled,
                                                    );
                                            });
                                        }
                                        if !identity_healthy && kernel_healthy {
                                            identity_healthy = true;
                                            restore_identity_claims(
                                                &mut self.registration,
                                                &healthy_identity_capabilities,
                                                healthy_effect_prevention_claims
                                                    && evidence_healthy,
                                            );
                                            self.readiness.send_replace(NodeReadinessV1 {
                                                kernel_ready: true,
                                                identity_ready: true,
                                                control_ready: true,
                                                admission_ready: true,
                                                effect_prevention_claims_enabled:
                                                    healthy_effect_prevention_claims,
                                                });
                                        }
                                        if recovered {
                                            break;
                                        }
                                    }
                                    ReconciliationOutcome::EvidenceUnhealthy => {
                                        evidence_healthy = false;
                                        close_evidence_claims(&mut self.registration);
                                        self.readiness.send_modify(|readiness| {
                                            readiness.admission_ready = false;
                                            readiness.effect_prevention_claims_enabled = false;
                                        });
                                        break;
                                    }
                                    ReconciliationOutcome::IdentityUnhealthy => {
                                        identity_healthy = false;
                                        close_identity_claims(&mut self.registration);
                                        self.readiness.send_replace(NodeReadinessV1 {
                                            kernel_ready: kernel_healthy,
                                            identity_ready: false,
                                            control_ready: true,
                                            admission_ready: false,
                                            effect_prevention_claims_enabled: false,
                                        });
                                        break;
                                    }
                                    ReconciliationOutcome::KernelUnhealthy => {
                                        kernel_healthy = false;
                                        identity_healthy = false;
                                        self.close_kernel_claims();
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_error) => {}
            }
            if let (Some(administrative), Some(host)) =
                (self.administrative.as_mut(), self.host.as_mut())
            {
                if administrative.cancel_armed_slots(host).is_err() {
                    identity_healthy = false;
                    close_identity_claims(&mut self.registration);
                }
            }
            self.readiness.send_replace(NodeReadinessV1 {
                kernel_ready: kernel_healthy,
                identity_ready: identity_healthy,
                control_ready: false,
                admission_ready: false,
                effect_prevention_claims_enabled: NodeReadinessV1::prevention_claims_enabled(
                    kernel_healthy,
                    identity_healthy && evidence_healthy,
                    prevention_enabled,
                ),
            });
            control_disconnected_since = tokio::time::Instant::now();
            let reconnect = tokio::time::sleep(backoff);
            tokio::pin!(reconnect);
            loop {
                tokio::select! {
                    () = &mut reconnect => break,
                    changed = shutdown.changed() => {
                        let _result = changed;
                        break 'running;
                    }
                    request = next_runtime_admission(&mut self.runtime_admission_requests) => {
                        self.answer_runtime_admission(request).await;
                    }
                    result = effect_reader_finished(&mut effect_task) => {
                        let _result = self.observations.mark_coverage_gapped(
                            CoverageGapReasonV1::ReaderStopped,
                        );
                        run_error = result.err();
                        effect_task = None;
                        break 'running;
                    }
                    () = async {
                        tokio::select! {
                            () = self.bindings.wait_for_runtime_change() => {}
                            _instant = reconciliation.tick() => {}
                        }
                    } => {
                        match self.reconcile_bindings(false).await {
                            ReconciliationOutcome::Healthy => {
                                if !evidence_healthy {
                                    evidence_healthy = true;
                                    restore_evidence_claims(
                                        &mut self.registration,
                                        &healthy_identity_capabilities,
                                        healthy_effect_prevention_claims,
                                    );
                                }
                                if !identity_healthy && kernel_healthy {
                                    identity_healthy = true;
                                    restore_identity_claims(
                                        &mut self.registration,
                                        &healthy_identity_capabilities,
                                        healthy_effect_prevention_claims && evidence_healthy,
                                    );
                                    self.readiness.send_replace(NodeReadinessV1 {
                                        kernel_ready: true,
                                        identity_ready: true,
                                        control_ready: false,
                                        admission_ready: false,
                                        effect_prevention_claims_enabled: false,
                                    });
                                }
                            }
                            ReconciliationOutcome::EvidenceUnhealthy => {
                                evidence_healthy = false;
                                close_evidence_claims(&mut self.registration);
                            }
                            ReconciliationOutcome::IdentityUnhealthy => {
                                identity_healthy = false;
                                close_identity_claims(&mut self.registration);
                            }
                            ReconciliationOutcome::KernelUnhealthy => {
                                kernel_healthy = false;
                                identity_healthy = false;
                                self.close_kernel_claims();
                            }
                        }
                    }
                }
            }
            backoff = cmp::min(
                backoff.saturating_mul(2),
                self.config.control.reconnect_maximum(),
            );
        }
        let _result = self
            .observations
            .mark_coverage_gapped(CoverageGapReasonV1::ReaderStopped);
        effect_stop.store(true, Ordering::Release);
        if let Some(task) = effect_task {
            task.await
                .context(LocalTaskSnafu)?
                .context(InterceptorSnafu)?;
        }
        if let Some(host) = self.host.take() {
            host.shutdown().context(InterceptorSnafu)?;
        }
        if run_error.is_some() {
            if let Some(task) = local_task.take() {
                task.abort();
                let _result = task.await;
            }
        } else if let Some(task) = local_task {
            task.await.context(LocalTaskSnafu)??;
        }
        if run_error.is_some() {
            if let Some(task) = runtime_admission_task.take() {
                task.abort();
                let _result = task.await;
            }
        } else if let Some(task) = runtime_admission_task {
            task.await.context(LocalTaskSnafu)??;
        }
        if let Some(error) = run_error {
            return Err(error);
        }
        Ok(())
    }

    async fn answer_runtime_admission(
        &mut self,
        envelope: crate::runtime_admission::RuntimeAdmissionEnvelope,
    ) {
        let response = match self.admit_runtime_start(&envelope.request).await {
            Ok(()) => crate::RuntimeAdmissionResponseV1 {
                allowed: true,
                reason_code: "ACTIVE_POLICY_AND_BINDING_VERIFIED".to_owned(),
            },
            Err(_error) => crate::RuntimeAdmissionResponseV1 {
                allowed: false,
                reason_code: "RUNTIME_ADMISSION_REJECTED".to_owned(),
            },
        };
        let _result = envelope.response.send(response);
    }

    async fn admit_runtime_start(
        &mut self,
        request: &crate::RuntimeAdmissionRequestV1,
    ) -> Result<()> {
        let readiness = *self.readiness.borrow();
        snafu::ensure!(
            readiness.kernel_ready
                && readiness.identity_ready
                && readiness.effect_prevention_claims_enabled
                && self.policy.is_some(),
            IdentityStateSnafu {
                reason: "runtime admission has no healthy active prevention generation",
            }
        );
        let mut scheduled = crate::runtime_admission::resolve_scheduled_runtime_binding(
            &self.config.workload_bindings,
            request,
        )?;
        let mut dynamic = self.config.clone();
        dynamic.workload_bindings[scheduled.binding_index] = scheduled.resolved.clone();
        dynamic.validate()?;
        self.bindings
            .verify_runtime_admission(&mut scheduled.resolved)
            .await?;
        dynamic.workload_bindings[scheduled.binding_index] = scheduled.resolved.clone();
        let Some(host) = self.host.as_ref() else {
            self.bindings.cancel_runtime_admission();
            return IdentityStateSnafu {
                reason: "runtime admission has no live kernel host".to_owned(),
            }
            .fail();
        };
        if let Some(previous) = scheduled.previous_binding_id.as_deref() {
            if let Err(error) = self.bindings.retire_binding_id(host, previous) {
                self.bindings.cancel_runtime_admission();
                return Err(error);
            }
        }
        self.bindings.publish_held_activated_root(
            host,
            &scheduled.resolved,
            request.initial_pid,
        )?;
        if let Err(error) = self
            .policy_delivery
            .record_runtime_binding(&scheduled.resolved)
        {
            let _result = self
                .bindings
                .retire_binding_id(host, &scheduled.resolved.binding_id);
            return Err(error);
        }
        self.config = dynamic;
        Ok(())
    }

    async fn reconcile_bindings(&mut self, recover_evidence: bool) -> ReconciliationOutcome {
        let Some(host) = self.host.as_mut() else {
            return ReconciliationOutcome::KernelUnhealthy;
        };
        if host.verify_live_manifest().is_err() {
            let _result = self
                .observations
                .mark_coverage_gapped(CoverageGapReasonV1::KernelStateMismatch);
            return ReconciliationOutcome::KernelUnhealthy;
        }
        if self.policy.is_some()
            && (self.observations.evidence_errors() > 0
                || sample_effect_health(host, &self.observations, recover_evidence).is_err())
        {
            let _result = self
                .observations
                .mark_coverage_gapped(CoverageGapReasonV1::WalFailure);
            return ReconciliationOutcome::EvidenceUnhealthy;
        }
        if self
            .identity
            .reconcile(host, self.policy.is_some())
            .is_err()
        {
            return ReconciliationOutcome::IdentityUnhealthy;
        }
        if self
            .bindings
            .reconcile(host, &self.config.workload_bindings)
            .await
            .is_err()
        {
            return ReconciliationOutcome::IdentityUnhealthy;
        }
        if let Some(policy) = self.policy.as_mut() {
            if self
                .bindings
                .adopt_activated_profiles(host, &self.config.workload_bindings)
                .is_err()
                || policy
                    .reconcile_cri_exact_bindings(&self.config, host, &self.bindings)
                    .is_err()
                || policy.reconcile_mount_views(host).is_err()
            {
                return ReconciliationOutcome::IdentityUnhealthy;
            }
        }
        if self
            .administrative
            .as_mut()
            .is_some_and(|administrative| administrative.reconcile(host).is_err())
        {
            return ReconciliationOutcome::IdentityUnhealthy;
        }
        ReconciliationOutcome::Healthy
    }

    fn prepare_control_policy(
        &self,
        bundle: &PolicyBundleV1,
    ) -> Result<crate::policy_delivery::PreparedPolicyActivationV1> {
        let host = self.host.as_ref().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "the policy activation owner has no live kernel host".to_owned(),
            }
            .build()
        })?;
        let generation = crate::NodePolicyGenerationOwner::next_generation_ref_id(
            &self.config,
            host,
            self.node_boot_id,
            self.label_epoch,
        )?;
        let node_boot_id = self.node_boot_id.to_be_bytes();
        self.policy_delivery.prepare_activation_for_session(
            bundle,
            &self.trust,
            &self.config,
            &self.registration.capabilities,
            generation,
            crate::policy::current_utc_ns()?,
            &node_boot_id,
            self.label_epoch,
        )
    }

    fn activate_control_policy(
        &mut self,
        bundle: &PolicyBundleV1,
        prepared: crate::policy_delivery::PreparedPolicyActivationV1,
        evidence_healthy: bool,
    ) -> Result<()> {
        self.policy_delivery.begin_activation(bundle, &prepared)?;
        let host = self.host.as_mut().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "the policy activation owner has no live kernel host".to_owned(),
            }
            .build()
        })?;
        let owner = crate::NodePolicyGenerationOwner::load_and_install_for_bindings(
            &prepared.config,
            host,
            &self.bindings,
            self.node_boot_id,
            self.label_epoch,
        )?;
        self.identity.activate_with_effect_policy(host, true)?;
        self.bindings
            .adopt_activated_profiles(host, &prepared.config.workload_bindings)?;
        let receipt = crate::NodePolicyGenerationOwner::activation_receipt(
            host,
            &prepared.profile_id,
            prepared.profile_generation_ref_id,
        )?;
        snafu::ensure!(
            receipt.profile_generation_ref_id == prepared.profile_generation_ref_id,
            IdentityStateSnafu {
                reason: "the policy activation receipt names a different generation",
            }
        );
        self.policy_delivery.commit_activation(
            bundle,
            &prepared,
            crate::policy_delivery::PolicyActivationProofV1 {
                node_bound_generation_digest: receipt.node_bound_generation_digest,
                readback_digest: receipt.readback_digest,
                probe_result_digest: receipt.probe_result_digest,
                observed_utc_ns: crate::policy::current_utc_ns()?,
            },
        )?;
        let prevention_enabled = owner.prevention_enabled();
        self.config = prepared.config;
        self.policy = Some(owner);
        if let Some(capability) = self
            .registration
            .capabilities
            .iter_mut()
            .find(|capability| capability.capability_id == "LOCAL_EFFECT_PREVENTION")
        {
            capability.state = "SUPPORTED".to_owned();
            capability.reason_code = if prevention_enabled {
                "SIGNED_ACTIVE_QUALIFIED_LOCAL_SLICE".to_owned()
            } else {
                "OBSERVE_ONLY_GENERATION".to_owned()
            };
        }
        self.registration.effect_prevention_claims_enabled = prevention_enabled && evidence_healthy;
        self.readiness.send_modify(|readiness| {
            readiness.effect_prevention_claims_enabled = prevention_enabled && evidence_healthy;
        });
        Ok(())
    }

    fn resolve_administrative(
        &self,
        request: mithril_control::ResolveAdministrativeExec,
    ) -> AdministrativeExecResolution {
        let request_id = request.request_id.clone();
        let resolved = (|| {
            ensure_request_id(&request_id)?;
            let stream_flags = u8::try_from(request.stream_flags).map_err(|_| ())?;
            let administrative = self.administrative.as_ref().ok_or(())?;
            let host = self.host.as_ref().ok_or(())?;
            let policy = self.policy.as_ref().ok_or(())?;
            let resolution = administrative
                .resolve(
                    host,
                    &self.bindings,
                    policy,
                    AdministrativeResolveRequestV1 {
                        namespace: request.namespace,
                        pod_uid: request.pod_uid,
                        container_name: request.container_name,
                        full_container_id: request.full_container_id,
                        container_generation: request.container_generation,
                        argv: request.argv,
                        stream_flags,
                        approved_role_id: request.approved_role_id,
                    },
                )
                .map_err(|_| ())?;
            Ok((administrative.node_id(), resolution))
        })();
        match resolved {
            Ok((node_id, resolution)) => resolution_response(request_id, node_id, resolution),
            Err(()) => rejected_resolution(request_id),
        }
    }

    fn arm_administrative(
        &mut self,
        request: mithril_control::ArmAdministrativeExec,
    ) -> AdministrativeExecArmResult {
        let request_id = request.request_id.clone();
        let armed = (|| {
            ensure_request_id(&request_id)?;
            let body_sha256: [u8; 32] = request.body_sha256.try_into().map_err(|_| ())?;
            let host = self.host.as_ref().ok_or(())?;
            let policy = self.policy.as_ref().ok_or(())?;
            self.administrative
                .as_mut()
                .ok_or(())?
                .verify_and_arm(
                    host,
                    &self.bindings,
                    policy,
                    &request.signed_intent,
                    body_sha256,
                )
                .map_err(|_| ())
        })();
        match armed {
            Ok(receipt) => AdministrativeExecArmResult {
                request_id,
                armed: true,
                reason_code: "ARMED_AND_READ_BACK".to_owned(),
                proof_id: portable_id_bytes(receipt.proof_id),
                claim_slot_id: portable_id_bytes(receipt.claim_slot_id),
            },
            Err(()) => AdministrativeExecArmResult {
                request_id,
                armed: false,
                reason_code: "ADMINISTRATIVE_ARM_REJECTED".to_owned(),
                proof_id: Vec::new(),
                claim_slot_id: Vec::new(),
            },
        }
    }

    fn close_kernel_claims(&mut self) {
        close_kernel_claims(&mut self.registration, &self.readiness);
    }

    fn evidence_control_delay(&self) -> Duration {
        Duration::from_millis(
            self.config
                .evidence
                .as_ref()
                .map_or(30_000, |evidence| evidence.maximum_control_delay_ms),
        )
    }
}

fn rejected_policy_acknowledgement(
    bundle: &PolicyBundleV1,
) -> Result<PolicyActivationAcknowledgement> {
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

fn sample_effect_health(
    host: &KernelHost,
    observations: &crate::EffectObservationStore,
    recover: bool,
) -> Result<()> {
    if observations.evidence_errors() > 0 {
        return EvidenceStateSnafu {
            reason: "durable effect evidence has a prior write failure".to_owned(),
        }
        .fail();
    }
    let bytes = host
        .lookup_map("effect_observation_health", &0_u32.to_ne_bytes())
        .context(InterceptorSnafu)?
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: "effect observation health map has no per-CPU state".to_owned(),
            }
            .build()
        })?;
    observations.sample_coverage_health(&bytes)?;
    if !observations
        .coverage_snapshot()
        .is_some_and(|snapshot| snapshot.supports_negative_claim())
    {
        if recover {
            observations.recover_coverage_after_probe(&bytes)?;
        }
        if !observations
            .coverage_snapshot()
            .is_some_and(|snapshot| snapshot.supports_negative_claim())
        {
            return EvidenceStateSnafu {
                reason: "effect observation coverage cannot support a negative claim".to_owned(),
            }
            .fail();
        }
    }
    Ok(())
}

fn close_kernel_claims(
    registration: &mut NodeRegistration,
    readiness: &watch::Sender<NodeReadinessV1>,
) {
    registration.kernel_ready = false;
    registration.effect_prevention_claims_enabled = false;
    for capability in &mut registration.capabilities {
        if matches!(
            capability.capability_id.as_str(),
            "EXACT_NATIVE_IDENTITY" | "LOCAL_EFFECT_PREVENTION" | "LOCAL_EFFECT_OBSERVATION"
        ) {
            capability.state = "UNHEALTHY".to_owned();
            capability.reason_code = "LIVE_KERNEL_MANIFEST_MISMATCH".to_owned();
        }
    }
    readiness.send_modify(NodeReadinessV1::close_kernel_claims);
}

fn close_evidence_claims(registration: &mut NodeRegistration) {
    registration.effect_prevention_claims_enabled = false;
    for capability in &mut registration.capabilities {
        if capability.capability_id == "LOCAL_EFFECT_OBSERVATION" {
            capability.state = "UNHEALTHY".to_owned();
            capability.reason_code = "DURABLE_EVIDENCE_COVERAGE_GAPPED".to_owned();
        }
    }
}

fn restore_evidence_claims(
    registration: &mut NodeRegistration,
    healthy_capabilities: &[CapabilityRecord],
    effect_prevention_claims_enabled: bool,
) {
    registration.effect_prevention_claims_enabled = effect_prevention_claims_enabled;
    if let Some(healthy) = healthy_capabilities
        .iter()
        .find(|capability| capability.capability_id == "LOCAL_EFFECT_OBSERVATION")
    {
        if let Some(capability) = registration
            .capabilities
            .iter_mut()
            .find(|capability| capability.capability_id == "LOCAL_EFFECT_OBSERVATION")
        {
            capability.clone_from(healthy);
        }
    }
}

fn close_identity_claims(registration: &mut NodeRegistration) {
    registration.effect_prevention_claims_enabled = false;
    for capability in &mut registration.capabilities {
        if matches!(
            capability.capability_id.as_str(),
            "EXACT_NATIVE_IDENTITY" | "LOCAL_EFFECT_OBSERVATION"
        ) {
            capability.state = "UNHEALTHY".to_owned();
            capability.reason_code = "LIVE_IDENTITY_RECONCILIATION_FAILED".to_owned();
        }
    }
}

fn restore_identity_claims(
    registration: &mut NodeRegistration,
    healthy_capabilities: &[CapabilityRecord],
    effect_prevention_claims_enabled: bool,
) {
    registration.effect_prevention_claims_enabled = effect_prevention_claims_enabled;
    for capability in &mut registration.capabilities {
        if !matches!(
            capability.capability_id.as_str(),
            "EXACT_NATIVE_IDENTITY" | "LOCAL_EFFECT_OBSERVATION"
        ) {
            continue;
        }
        if let Some(healthy) = healthy_capabilities
            .iter()
            .find(|healthy| healthy.capability_id == capability.capability_id)
        {
            capability.clone_from(healthy);
        }
    }
}

async fn effect_reader_finished(
    task: &mut Option<tokio::task::JoinHandle<std::result::Result<(), erebor_interceptor::Error>>>,
) -> Result<()> {
    let outcome = match task.as_mut() {
        Some(task) => task.await.context(LocalTaskSnafu)?,
        None => std::future::pending().await,
    };
    outcome.context(InterceptorSnafu)?;
    IdentityStateSnafu {
        reason: "effect observation reader stopped before node shutdown",
    }
    .fail()
}

async fn next_runtime_admission(
    receiver: &mut Option<crate::runtime_admission::RuntimeAdmissionReceiver>,
) -> crate::runtime_admission::RuntimeAdmissionEnvelope {
    if let Some(receiver) = receiver {
        if let Some(request) = receiver.receive().await {
            return request;
        }
    }
    std::future::pending().await
}

fn ensure_request_id(request_id: &[u8]) -> std::result::Result<(), ()> {
    if request_id.len() != 16 || request_id.iter().all(|byte| *byte == 0) {
        return Err(());
    }
    Ok(())
}

fn portable_id_bytes(value: erebor_interceptor_abi::Id128V1) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn resolution_response(
    request_id: Vec<u8>,
    node_id: erebor_interceptor_abi::Id128V1,
    resolution: AdministrativeResolutionV1,
) -> AdministrativeExecResolution {
    let executable = resolution.policy.resolved_executable;
    let object = executable.executable_object;
    AdministrativeExecResolution {
        request_id,
        resolved: true,
        reason_code: "RESOLVED_AND_RECHECKED".to_owned(),
        target_node_id: portable_id_bytes(node_id),
        namespace: resolution.target.namespace.into_bytes(),
        pod_uid: resolution.target.pod_uid.into_bytes(),
        container_name: resolution.target.container_name.into_bytes(),
        full_container_id: resolution.target.full_container_id.into_bytes(),
        container_generation: resolution.target.container_generation,
        argv: resolution.arguments,
        stream_flags: u32::from(resolution.stream_flags),
        approved_role_id: resolution.approved_role_id,
        profile_id: portable_id_bytes(resolution.policy.profile.profile_id),
        profile_owner_generation: resolution.policy.profile.owner_generation,
        profile_artifact_sha256: resolution.policy.profile.artifact_sha256.to_vec(),
        resolved_executable: Some(ResolvedAdministrativeExecutable {
            requested_name: executable.requested_name,
            resolution_mode: u32::from(executable.resolution_mode),
            resolved_display_path: executable.resolved_display_path,
            container_working_directory: executable.container_working_directory,
            effective_path_entries: executable.effective_path_entries,
            target_mount_namespace_id: portable_id_bytes(executable.target_mount_namespace_id),
            target_mount_topology_generation: executable.target_mount_topology_generation,
            executable_object: Some(AdministrativeFileObject {
                mount_namespace_id: portable_id_bytes(object.mount_namespace_id),
                mount_topology_generation: object.mount_topology_generation,
                mount_id: object.mount_id,
                filesystem_instance_id: portable_id_bytes(object.filesystem_instance_id),
                inode: object.inode,
                inode_generation: object.inode_generation,
                exact_live_object_id: portable_id_bytes(object.exact_live_object_id),
                object_kind: u32::from(object.object_kind),
                backing_identity: portable_id_bytes(object.backing_identity),
                live_interval_id: portable_id_bytes(object.live_interval_id),
            }),
        }),
    }
}

fn rejected_resolution(request_id: Vec<u8>) -> AdministrativeExecResolution {
    AdministrativeExecResolution {
        request_id,
        resolved: false,
        reason_code: "ADMINISTRATIVE_RESOLUTION_REJECTED".to_owned(),
        target_node_id: Vec::new(),
        namespace: Vec::new(),
        pod_uid: Vec::new(),
        container_name: Vec::new(),
        full_container_id: Vec::new(),
        container_generation: 0,
        argv: Vec::new(),
        stream_flags: 0,
        approved_role_id: String::new(),
        profile_id: Vec::new(),
        profile_owner_generation: 0,
        profile_artifact_sha256: Vec::new(),
        resolved_executable: None,
    }
}

fn registration(
    manifest: &erebor_interceptor::KernelObjectManifestV1,
    label_epoch: u64,
    effect_prevention_claims_enabled: bool,
    capabilities: Vec<CapabilityRecord>,
    kubernetes_node_name: Option<&str>,
    workload_bindings: &[crate::WorkloadBindingConfig],
) -> Result<NodeRegistration> {
    let manifest_bytes = serde_json::to_vec(manifest).context(JsonSnafu {
        path: "in-memory kernel manifest",
    })?;
    Ok(NodeRegistration {
        platform_digest: format!("{:x}", Sha256::digest(&manifest_bytes)),
        program_digest: manifest.object_sha256.clone(),
        label_epoch,
        kernel_ready: manifest.ready,
        effect_prevention_claims_enabled,
        capabilities,
        kubernetes_node_name: kubernetes_node_name.unwrap_or_default().to_owned(),
        workload_targets: workload_bindings
            .iter()
            .filter(|binding| {
                !binding.cluster_uid.is_empty()
                    && !binding.namespace_uid.is_empty()
                    && !binding.controller_uid.is_empty()
                    && !binding.service_account_uid.is_empty()
            })
            .map(registered_workload_target)
            .collect::<Result<Vec<_>>>()?,
    })
}

fn registered_workload_target(
    binding: &crate::WorkloadBindingConfig,
) -> Result<RegisteredWorkloadTarget> {
    let workload_binding_generation_digest = workload_binding_generation_digest(binding)?;
    Ok(RegisteredWorkloadTarget {
        workload_binding_generation_digest,
        execution_set_id: binding.execution_set_id.clone(),
        cluster_uid: binding.cluster_uid.clone(),
        namespace_uid: binding.namespace_uid.clone(),
        controller_uid: binding.controller_uid.clone(),
        service_account_uid: binding.service_account_uid.clone(),
        pod_uid: binding.pod_uid.clone(),
        container_id: binding.container_id.clone(),
        container_name: binding.container_name.clone(),
        container_kind: match binding.container_kind {
            crate::ContainerKindV1::Init => "INIT",
            crate::ContainerKindV1::Sidecar => "SIDECAR",
            crate::ContainerKindV1::Application => "APPLICATION",
            crate::ContainerKindV1::Ephemeral => "EPHEMERAL",
        }
        .to_owned(),
        image_digest: binding.image_digest.clone(),
        pod_labels: binding
            .pod_labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    })
}

pub(crate) fn workload_binding_generation_digest(
    binding: &crate::WorkloadBindingConfig,
) -> Result<String> {
    let identity = serde_json::to_vec(&(
        binding.binding_id.as_str(),
        binding.lifecycle_generation,
        binding.execution_set_id.as_str(),
        binding.cluster_uid.as_str(),
        binding.namespace_uid.as_str(),
        binding.controller_uid.as_str(),
        binding.service_account_uid.as_str(),
        binding.pod_uid.as_str(),
        binding.container_id.as_str(),
        binding.container_name.as_str(),
        binding.image_digest.as_str(),
        &binding.pod_labels,
    ))
    .context(JsonSnafu {
        path: "in-memory workload target",
    })?;
    Ok(format!("{:x}", Sha256::digest(identity)))
}

#[cfg(test)]
mod tests {
    use super::{
        close_identity_claims, close_kernel_claims, effect_reader_finished,
        restore_identity_claims, NodeReadinessV1,
    };
    use mithril_control::{CapabilityRecord, NodeRegistration};
    use tokio::sync::watch;

    #[test]
    fn boot_admission_requires_complete_chassis_readiness_in_both_policy_modes() {
        assert!(!NodeReadinessV1::default().admits_new_work());
        let ready = NodeReadinessV1 {
            kernel_ready: true,
            identity_ready: true,
            control_ready: true,
            admission_ready: true,
            effect_prevention_claims_enabled: false,
        };
        assert!(ready.admits_new_work());
        assert!(!ready.effect_prevention_claims_enabled);
        assert!(NodeReadinessV1 {
            effect_prevention_claims_enabled: true,
            ..ready
        }
        .admits_new_work());
        assert!(!NodeReadinessV1 {
            control_ready: false,
            admission_ready: false,
            ..ready
        }
        .admits_new_work());
    }

    #[test]
    fn prevention_claims_require_healthy_kernel_and_identity() {
        assert!(NodeReadinessV1::prevention_claims_enabled(true, true, true));
        assert!(!NodeReadinessV1::prevention_claims_enabled(
            true, false, true
        ));
        assert!(!NodeReadinessV1::prevention_claims_enabled(
            false, true, true
        ));
        assert!(!NodeReadinessV1::prevention_claims_enabled(
            true, true, false
        ));
    }

    #[test]
    fn identity_failure_closes_dependent_registered_claims() {
        let mut registration = NodeRegistration {
            platform_digest: "a".repeat(64),
            program_digest: "b".repeat(64),
            label_epoch: 1,
            kernel_ready: true,
            effect_prevention_claims_enabled: true,
            kubernetes_node_name: String::new(),
            capabilities: [
                "EXACT_NATIVE_IDENTITY",
                "LOCAL_EFFECT_OBSERVATION",
                "RUNTIME_READ_ONLY_OBSERVATION",
            ]
            .into_iter()
            .map(|capability_id| CapabilityRecord {
                capability_id: capability_id.to_owned(),
                state: "SUPPORTED".to_owned(),
                reason_code: "INITIAL_STATE".to_owned(),
            })
            .collect(),
            workload_targets: Vec::new(),
        };

        close_identity_claims(&mut registration);

        assert!(registration.kernel_ready);
        assert!(!registration.effect_prevention_claims_enabled);
        assert!(registration.capabilities[..2].iter().all(|capability| {
            capability.state == "UNHEALTHY"
                && capability.reason_code == "LIVE_IDENTITY_RECONCILIATION_FAILED"
        }));
        assert_eq!(registration.capabilities[2].state, "SUPPORTED");
    }

    #[test]
    fn healthy_reconciliation_restores_identity_claims_from_the_startup_record() {
        let healthy_capabilities = vec![
            CapabilityRecord {
                capability_id: "EXACT_NATIVE_IDENTITY".to_owned(),
                state: "SUPPORTED".to_owned(),
                reason_code: "EXACT_ATTACH_AND_RECONCILIATION".to_owned(),
            },
            CapabilityRecord {
                capability_id: "LOCAL_EFFECT_OBSERVATION".to_owned(),
                state: "DEGRADED".to_owned(),
                reason_code: "SIGNED_ACTIVE_EXACT_FILE_SLICE_ONLY".to_owned(),
            },
            CapabilityRecord {
                capability_id: "RUNTIME_READ_ONLY_OBSERVATION".to_owned(),
                state: "SUPPORTED".to_owned(),
                reason_code: "PEER_CREDENTIAL_AND_CGROUP_SCOPED".to_owned(),
            },
        ];
        let mut registration = NodeRegistration {
            platform_digest: "a".repeat(64),
            program_digest: "b".repeat(64),
            label_epoch: 1,
            kernel_ready: true,
            effect_prevention_claims_enabled: true,
            kubernetes_node_name: String::new(),
            capabilities: healthy_capabilities.clone(),
            workload_targets: Vec::new(),
        };

        close_identity_claims(&mut registration);
        restore_identity_claims(&mut registration, &healthy_capabilities, true);

        assert!(registration.effect_prevention_claims_enabled);
        assert_eq!(registration.capabilities, healthy_capabilities);
    }

    #[test]
    fn kernel_mismatch_closes_readiness_and_prevention_claims() {
        let (readiness, receiver) = watch::channel(NodeReadinessV1 {
            kernel_ready: true,
            identity_ready: true,
            control_ready: true,
            admission_ready: true,
            effect_prevention_claims_enabled: true,
        });
        let mut registration = NodeRegistration {
            platform_digest: "a".repeat(64),
            program_digest: "b".repeat(64),
            label_epoch: 1,
            kernel_ready: true,
            effect_prevention_claims_enabled: true,
            kubernetes_node_name: String::new(),
            capabilities: vec![
                CapabilityRecord {
                    capability_id: "EXACT_NATIVE_IDENTITY".to_owned(),
                    state: "SUPPORTED".to_owned(),
                    reason_code: "EXACT_ATTACH_AND_RECONCILIATION".to_owned(),
                },
                CapabilityRecord {
                    capability_id: "LOCAL_EFFECT_PREVENTION".to_owned(),
                    state: "DEGRADED".to_owned(),
                    reason_code: "SIGNED_ACTIVE_QUALIFIED_LOCAL_SLICE".to_owned(),
                },
                CapabilityRecord {
                    capability_id: "LOCAL_EFFECT_OBSERVATION".to_owned(),
                    state: "DEGRADED".to_owned(),
                    reason_code: "SIGNED_ACTIVE_EXACT_FILE_SLICE_ONLY".to_owned(),
                },
                CapabilityRecord {
                    capability_id: "RUNTIME_READ_ONLY_OBSERVATION".to_owned(),
                    state: "SUPPORTED".to_owned(),
                    reason_code: "PEER_CREDENTIAL_AND_CGROUP_SCOPED".to_owned(),
                },
                CapabilityRecord {
                    capability_id: "LANDLOCK_TARGET_CONTEXT_FLOOR".to_owned(),
                    state: "UNSUPPORTED".to_owned(),
                    reason_code: "NO_QUALIFIED_TARGET_CONTEXT_INSTALL".to_owned(),
                },
            ],
            workload_targets: Vec::new(),
        };

        close_kernel_claims(&mut registration, &readiness);

        assert_eq!(
            *receiver.borrow(),
            NodeReadinessV1 {
                control_ready: true,
                ..NodeReadinessV1::default()
            }
        );
        assert!(!receiver.borrow().admits_new_work());
        assert!(!registration.kernel_ready);
        assert!(!registration.effect_prevention_claims_enabled);
        assert!(registration.capabilities[..3].iter().all(|capability| {
            capability.state == "UNHEALTHY"
                && capability.reason_code == "LIVE_KERNEL_MANIFEST_MISMATCH"
        }));
        assert_eq!(registration.capabilities[3].state, "SUPPORTED");
        assert_eq!(registration.capabilities[4].state, "UNSUPPORTED");
    }

    #[tokio::test]
    async fn an_effect_reader_exit_is_a_node_failure() {
        let mut task = Some(tokio::spawn(async { Ok(()) }));
        assert!(effect_reader_finished(&mut task)
            .await
            .is_err_and(|error| error.to_string().contains("stopped before node shutdown")));
    }
}
