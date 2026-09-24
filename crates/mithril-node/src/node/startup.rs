use erebor_interceptor::{EffectObservationReader, KernelHost, KernelHostConfig, KernelHostOwner};
use erebor_interceptor_abi::Id128V1;
use mithril_control::CapabilityRecord;
use snafu::{OptionExt as _, ResultExt as _};
use std::sync::Arc;
use tokio::sync::watch;

use super::{registration, sample_effect_health, NodeChassis, NodeReadinessV1};
use crate::administrative_exec::AdministrativeExecOwner;
use crate::epoch::NodeEpochs;
use crate::error::{IdentityStateSnafu, InterceptorSnafu};
use crate::{
    NativeSecurityStateOwner, NodeConfig, NodeControlConnector, NodeDecommissionOwner,
    ObservationCanonicalizer, ReconciliationReportV1, Result, TrustCache, WorkloadBindingOwner,
};

// Durable authority and the boot identity are restored before kernel acquisition.
pub(super) struct NodeState {
    base_config: NodeConfig,
    config: NodeConfig,
    trust: TrustCache,
    policy_delivery: crate::NodePolicyDeliveryOwner,
    decommission: Option<NodeDecommissionOwner>,
    identity: NativeSecurityStateOwner,
    node_boot_id: Id128V1,
    label_epoch: u64,
    recover_identity: bool,
}

impl NodeState {
    pub(super) fn restore(mut config: NodeConfig, held_initial_pids: &[u32]) -> Result<Self> {
        config.validate()?;
        let base_config = config.clone();
        // Load trust and delivery state before BPF recovery can accept dynamic policy material.
        let trust = TrustCache::load(&config.state_directory)?;
        let mut policy_delivery =
            crate::policy_delivery::NodePolicyDeliveryOwner::load(&config.state_directory)?;
        if !held_initial_pids.is_empty() {
            snafu::ensure!(
                config.container_runtime.is_none()
                    && held_initial_pids.len() == config.workload_bindings.len()
                    && held_initial_pids.iter().all(|pid| *pid > 0),
                IdentityStateSnafu {
                    reason:
                        "runtime admission requires one held root for each armed static binding",
                }
            );
        }
        let boot_id = NodeEpochs::boot_id()?;
        let node_boot_id = boot_id.into();
        let decommission = config
            .decommission
            .as_ref()
            .map(|decommission| {
                NodeDecommissionOwner::load(
                    decommission,
                    &config.state_directory,
                    config.node_id.clone(),
                    node_boot_id,
                )
            })
            .transpose()?;
        snafu::ensure!(
            decommission
                .as_ref()
                .is_none_or(|decommission| !decommission.completed()),
            IdentityStateSnafu {
                reason: "completed node decommission prevents enforcement restart",
            }
        );
        let recover_identity = config
            .interceptor
            .pin_root
            .join("maps/identity_config")
            .exists();
        snafu::ensure!(
            held_initial_pids.is_empty() || !recover_identity,
            IdentityStateSnafu {
                reason: "runtime admission requires a fresh identity pin root",
            }
        );
        let label_epoch = NodeEpochs::label_epoch(&config.state_directory, recover_identity)?;
        // Restore signed policy, but restore scheduled targets only for this boot and label epoch.
        policy_delivery.restore_config_for_session(&mut config, &trust, &boot_id, label_epoch)?;
        config.validate()?;
        let identity = match config.container_runtime.as_ref() {
            Some(runtime) => NativeSecurityStateOwner::for_effect_controller(
                node_boot_id,
                label_epoch,
                &runtime.effect_controller_cgroup_path,
            )?,
            None => NativeSecurityStateOwner::new(node_boot_id, label_epoch),
        };
        Ok(Self {
            base_config,
            config,
            trust,
            policy_delivery,
            decommission,
            identity,
            node_boot_id,
            label_epoch,
            recover_identity,
        })
    }

    pub(super) fn acquire_kernel(&self) -> Result<KernelHost> {
        let owner = KernelHostOwner::new(KernelHostConfig::identity(
            &self.config.interceptor.runtime_btf_path,
            &self.config.interceptor.lease_path,
            Some(self.config.interceptor.pin_root.clone()),
            uuid::Uuid::from_bytes(self.node_boot_id.to_be_bytes())
                .simple()
                .to_string(),
            self.label_epoch,
        ));
        owner.start().context(InterceptorSnafu)
    }

    pub(super) fn create_endpoints(
        self,
        host: KernelHost,
        enforcement: Enforcement,
        evidence: Evidence,
    ) -> Result<NodeChassis> {
        let Self {
            base_config,
            config,
            trust,
            policy_delivery,
            decommission,
            identity,
            node_boot_id,
            label_epoch,
            ..
        } = self;
        let manifest = host.manifest();
        let capabilities = enforcement.capabilities(&config, evidence.healthy);
        let registration = registration(
            manifest,
            label_epoch,
            enforcement.prevention_enabled && evidence.healthy,
            capabilities.clone(),
            config.kubernetes_node_name.as_deref(),
            &config.workload_bindings,
        )?;
        let connector = NodeControlConnector::new(
            config.control.clone(),
            config.node_id.clone(),
            node_boot_id.to_be_bytes(),
        );
        let (readiness, _receiver) = watch::channel(NodeReadinessV1 {
            kernel_ready: true,
            identity_ready: true,
            control_ready: false,
            admission_ready: false,
            effect_prevention_claims_enabled: enforcement.prevention_enabled && evidence.healthy,
        });
        let local_server = config
            .runtime_observation
            .clone()
            .map(|runtime| {
                crate::RuntimeObservationServer::bind_with_effects(
                    runtime,
                    manifest,
                    &capabilities,
                    evidence.observations.clone(),
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
        let (runtime_seccomp_server, runtime_seccomp_notifications) = config
            .runtime_admission
            .as_ref()
            .map(crate::runtime_seccomp::RuntimeSeccompServer::bind)
            .transpose()?
            .map_or((None, None), |(server, notifications)| {
                (Some(server), Some(notifications))
            });
        let trace = if let (Some(diagnostics), Some(evidence)) =
            (&config.diagnostics, &config.evidence)
        {
            match crate::NodeTraceOwner::open(
                &config.state_directory,
                evidence.identities()?.0.to_be_bytes(),
                config.node_id.clone(),
                node_boot_id.to_be_bytes(),
                diagnostics.clone(),
                erebor_interceptor::KernelStateReader::new(&config.interceptor.pin_root),
            ) {
                Ok(owner) => Some(Arc::new(std::sync::Mutex::new(owner))),
                Err(error) => {
                    erebor_telemetry::warn!(error; "diagnostic storage is unavailable; enforcement remains active");
                    None
                }
            }
        } else {
            None
        };
        let mut chassis = NodeChassis {
            trace,
            base_config,
            config,
            effect_reader: evidence.effect_reader,
            effect_worker: evidence.effect_worker,
            host: Some(host),
            decommission,
            connector,
            registration,
            local_server,
            runtime_admission_server,
            runtime_admission_requests,
            runtime_seccomp_server,
            runtime_seccomp_notifications,
            trust,
            bindings: enforcement.bindings,
            identity,
            policy: enforcement.policy,
            policy_delivery,
            administrative: enforcement.administrative,
            readiness,
            observations: evidence.observations,
            node_boot_id,
            label_epoch,
        };
        // Bound sockets do not serve until durable stale-policy retirement completes.
        chassis.reconcile_inventory_policy_retirement()?;
        chassis.refresh_registration_authority_state()?;
        erebor_telemetry::info!(
            "initialized Mithril Node",
            node_id = %chassis.config.node_id,
            node_boot_id = %hex::encode(chassis.node_boot_id.to_be_bytes()),
            label_epoch = %chassis.label_epoch
        );
        Ok(chassis)
    }
}

// These owners have completed publication, activation, and recovery readback.
pub(super) struct Enforcement {
    bindings: WorkloadBindingOwner,
    policy: Option<crate::NodePolicyGenerationOwner>,
    administrative: Option<AdministrativeExecOwner>,
    reconciliation: ReconciliationReportV1,
    policy_loaded: bool,
    policy_observation_enabled: bool,
    prevention_enabled: bool,
    dynamic_policy_capable: bool,
}

impl Enforcement {
    pub(super) async fn restore(
        state: &mut NodeState,
        host: &mut KernelHost,
        held_initial_pids: &[u32],
    ) -> Result<Self> {
        let config = &mut state.config;
        let trust = &state.trust;
        let policy_delivery = &mut state.policy_delivery;
        let identity = &state.identity;
        let node_boot_id = state.node_boot_id;
        let label_epoch = state.label_epoch;
        let boot_id = node_boot_id.to_be_bytes();
        policy_delivery.reconcile_old_session_delivery(
            host,
            trust,
            config,
            &boot_id,
            label_epoch,
        )?;
        let pending_policy = policy_delivery.validate_pending_activation_pointer(host)?;
        identity.claim_effect_controller(host)?;
        let mut bindings = if let Some(runtime) = config.container_runtime.as_ref() {
            WorkloadBindingOwner::system_with_runtime(node_boot_id, label_epoch, runtime).await?
        } else {
            WorkloadBindingOwner::system(node_boot_id, label_epoch)?
        };
        if held_initial_pids.is_empty() {
            let runtime_reconciliation = bindings
                .publish_configured(host, &config.workload_bindings)
                .await?;
            if !runtime_reconciliation.retired_binding_ids.is_empty() {
                policy_delivery
                    .retire_runtime_bindings(&runtime_reconciliation.retired_binding_ids)?;
                *config = state.base_config.clone();
                policy_delivery.restore_config_for_session(config, trust, &boot_id, label_epoch)?;
                config.validate()?;
            }
        } else {
            let created = config
                .workload_bindings
                .iter()
                .cloned()
                .zip(held_initial_pids.iter().copied())
                .collect::<Vec<_>>();
            bindings.publish_held_initial_roots(host, &created)?;
        }
        let policy = if config.policy_candidates.is_empty() {
            None
        } else {
            Some(
                crate::NodePolicyGenerationOwner::load_and_install_for_bindings(
                    config,
                    host,
                    &bindings,
                    node_boot_id,
                    label_epoch,
                )?,
            )
        };
        if policy.is_some() {
            bindings.adopt_activated_profiles(host, &config.workload_bindings)?;
        }
        if pending_policy {
            // Normal installation must finish the same durable candidate with exact readback.
            policy_delivery.commit_pending_activation_from_readback(
                host,
                config,
                crate::policy::current_utc_ns()?,
            )?;
        }
        // Reconcile durable exception intent before this node can report readiness to Control.
        let pending_exception = policy_delivery.reconcile_pending_exception(
            host,
            trust,
            config,
            &boot_id,
            label_epoch,
            crate::policy::current_utc_ns()?,
        )?;
        if let Some(prepared) = pending_exception.filter(|prepared| {
            prepared.candidate.operation == mithril_control::ExceptionDeliveryOperationV1::Revoke
        }) {
            match policy.as_ref() {
                Some(policy) => {
                    let observation = policy.apply_exception_candidate(
                        host,
                        &prepared.candidate,
                        prepared.grant_handle,
                    )?;
                    policy_delivery.commit_exception_result(
                        &prepared.candidate,
                        observation.state,
                        observation.consumed_uses,
                        crate::policy::current_utc_ns()?,
                    )?;
                }
                None => policy_delivery.commit_exception_result(
                    &prepared.candidate,
                    mithril_control::ExceptionActivationStateV1::Revoked,
                    0,
                    crate::policy::current_utc_ns()?,
                )?,
            }
        }
        // Dynamic policy needs evidence and either runtime admission or exact local target facts.
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
            (Some(authorization), _) if administrative_required || dynamic_policy_capable => {
                Some(AdministrativeExecOwner::load(
                    authorization,
                    &config.state_directory,
                    crate::policy::stable_node_id(&config.node_id)?,
                    node_boot_id,
                )?)
            }
            (None, true) => return IdentityStateSnafu {
                reason: "signed administrative entry policy has no authorization trust owner",
            }.fail(),
            (Some(_), _) => return IdentityStateSnafu {
                reason: "administrative authorization is configured without a signed administrative entry plan",
            }.fail(),
            (None, false) => None,
        };
        if let Some(administrative) = administrative.as_mut() {
            administrative.reconcile(host)?;
        }
        let policy_loaded = policy.is_some() || policy_delivery.inventory_retirement().is_some();
        // Start loss-aware evidence before the first dynamically delivered policy can activate.
        let policy_observation_enabled = policy_loaded || dynamic_policy_capable;
        let prevention_enabled = policy
            .as_ref()
            .is_some_and(crate::NodePolicyGenerationOwner::prevention_enabled);
        let reconciliation = if held_initial_pids.is_empty() {
            identity.activate_initial_with_effect_policy(host, policy_loaded)?
        } else {
            identity.activate_held_initial_admission(host, policy_loaded)?
        };
        bindings.read_back_recovered_activations(host)?;
        Ok(Self {
            bindings,
            policy,
            administrative,
            reconciliation,
            policy_loaded,
            policy_observation_enabled,
            prevention_enabled,
            dynamic_policy_capable,
        })
    }

    fn capabilities(&self, config: &NodeConfig, evidence_healthy: bool) -> Vec<CapabilityRecord> {
        let Self {
            reconciliation,
            policy_loaded,
            policy_observation_enabled,
            prevention_enabled,
            dynamic_policy_capable,
            ..
        } = *self;
        vec![
            Self::capability(
                "EXACT_NATIVE_IDENTITY",
                "SUPPORTED",
                if reconciliation == Default::default() {
                    "EXACT_ATTACH_AND_RECONCILIATION"
                } else {
                    "CONSERVATIVE_IDENTITY_RESTRICTIONS_RETAINED"
                },
            ),
            Self::capability(
                "LOCAL_EFFECT_PREVENTION",
                if prevention_enabled || dynamic_policy_capable {
                    "SUPPORTED"
                } else {
                    "UNSUPPORTED"
                },
                if prevention_enabled {
                    "SIGNED_ACTIVE_QUALIFIED_LOCAL_SLICE"
                } else if dynamic_policy_capable {
                    "POLICY_ACTIVATION_OWNER_READY_NO_ACTIVE_GENERATION"
                } else if policy_loaded {
                    "OBSERVE_ONLY_GENERATION"
                } else {
                    "IDENTITY_GATE_ONLY_NO_PERMISSION_TABLE"
                },
            ),
            Self::capability(
                "LOCAL_EFFECT_OBSERVATION",
                if policy_observation_enabled && evidence_healthy {
                    "SUPPORTED"
                } else if policy_observation_enabled {
                    "UNHEALTHY"
                } else {
                    "UNSUPPORTED"
                },
                if policy_observation_enabled && evidence_healthy {
                    "DURABLE_LOSS_AWARE_KERNEL_COVERAGE"
                } else if policy_observation_enabled {
                    "DURABLE_EVIDENCE_COVERAGE_GAPPED"
                } else {
                    "NO_POLICY_CANDIDATE"
                },
            ),
            Self::capability(
                "RUNTIME_READ_ONLY_OBSERVATION",
                if config.runtime_observation.is_some() {
                    "SUPPORTED"
                } else {
                    "UNSUPPORTED"
                },
                if config.runtime_observation.is_some() {
                    "PEER_CREDENTIAL_AND_CGROUP_SCOPED"
                } else {
                    "NOT_CONFIGURED"
                },
            ),
            Self::capability(
                "LANDLOCK_TARGET_CONTEXT_FLOOR",
                "UNSUPPORTED",
                "NO_QUALIFIED_TARGET_CONTEXT_INSTALL",
            ),
        ]
    }

    fn capability(id: &str, state: &str, reason: &str) -> CapabilityRecord {
        CapabilityRecord {
            capability_id: id.to_owned(),
            state: state.to_owned(),
            reason_code: reason.to_owned(),
        }
    }
}

// The WAL, queue, and reader are ready; NodeRun owns their polling tasks.
pub(super) struct Evidence {
    observations: crate::EffectObservationStore,
    effect_reader: Option<EffectObservationReader>,
    effect_worker: Option<crate::observation::EffectObservationWorker>,
    healthy: bool,
}

impl Evidence {
    pub(super) fn start(
        state: &NodeState,
        host: &KernelHost,
        enforcement: &Enforcement,
    ) -> Result<Self> {
        let config = &state.config;
        if !enforcement.policy_observation_enabled {
            return Ok(Self {
                observations: crate::EffectObservationStore::default(),
                effect_reader: None,
                effect_worker: None,
                healthy: true,
            });
        }
        let evidence = config.evidence.as_ref().context(IdentityStateSnafu {
            reason: "effect policy has no durable evidence configuration",
        })?;
        let source_epoch =
            NodeEpochs::source_epoch(&config.state_directory, state.recover_identity)?;
        let (tenant_id, source_id) = evidence.identities()?;
        let canonicalizer =
            ObservationCanonicalizer::new(tenant_id, source_id, source_epoch, state.node_boot_id)?;
        let observations = crate::EffectObservationStore::durable(
            1_024,
            NodeEpochs::evidence_wal_directory(&config.state_directory),
            evidence.into(),
            canonicalizer,
        )?;
        observations.set_discovery_context(
            enforcement
                .policy
                .as_ref()
                .map(crate::NodePolicyGenerationOwner::discovery_context),
        );
        let queue_capacity = evidence.maximum_reader_queue_records;
        let batch_capacity = evidence.maximum_batch_records.min(queue_capacity);
        let (ingress, worker) =
            observations.bounded_ingestion_queue(queue_capacity, batch_capacity)?;
        let reader = host
            .effect_observation_reader(move |bytes| {
                ingress.record_bytes(bytes);
                0
            })
            .context(InterceptorSnafu)?;
        let healthy = sample_effect_health(host, &observations, true).is_ok();
        Ok(Self {
            observations,
            effect_reader: Some(reader),
            effect_worker: Some(worker),
            healthy,
        })
    }
}
