use erebor_interceptor::{EffectObservationReader, KernelHost, KernelHostConfig, KernelHostOwner};
use mithril_control::{CapabilityRecord, NodeRegistration};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use std::cmp;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

use crate::epoch::NodeEpochs;
use crate::error::{IdentityStateSnafu, InterceptorSnafu, JsonSnafu, LocalTaskSnafu};
use crate::{
    NativeSecurityStateOwner, NodeConfig, NodeControlConnector, Result, TrustCache,
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
    trust: TrustCache,
    bindings: WorkloadBindingOwner,
    policy: Option<crate::NodePolicyGenerationOwner>,
    readiness: watch::Sender<NodeReadinessV1>,
}

impl NodeChassis {
    pub async fn start(config: NodeConfig) -> Result<Self> {
        config.validate()?;
        let boot_id = NodeEpochs::boot_id()?;
        let node_boot_id = id_from_uuid_bytes(boot_id);
        let recover_identity = config
            .interceptor
            .pin_root
            .join("maps/identity_config")
            .exists();
        let label_epoch = NodeEpochs::label_epoch(&config.state_directory, recover_identity)?;
        let owner = KernelHostOwner::new(KernelHostConfig::identity(
            &config.interceptor.runtime_btf_path,
            &config.interceptor.lease_path,
            Some(config.interceptor.pin_root.clone()),
            uuid::Uuid::from_bytes(boot_id).simple().to_string(),
            label_epoch,
        ));
        let mut host = owner.start().context(InterceptorSnafu)?;
        let mut bindings = if let Some(runtime) = config.container_runtime.as_ref() {
            WorkloadBindingOwner::system_with_runtime(node_boot_id, label_epoch, runtime).await?
        } else {
            WorkloadBindingOwner::system(node_boot_id, label_epoch)?
        };
        bindings
            .publish_configured(&host, &config.workload_bindings)
            .await?;
        let policy = if config.policy_candidates.is_empty() {
            None
        } else {
            Some(crate::NodePolicyGenerationOwner::load_and_install(
                &config,
                &host,
                node_boot_id,
                label_epoch,
            )?)
        };
        if policy.is_some() {
            bindings.adopt_activated_profiles(&host, &config.workload_bindings)?;
        }
        let policy_loaded = policy.is_some();
        let prevention_enabled = policy
            .as_ref()
            .is_some_and(crate::NodePolicyGenerationOwner::prevention_enabled);
        let identity = NativeSecurityStateOwner::new(node_boot_id, label_epoch);
        let reconciliation = identity.activate_with_effect_policy(&mut host, policy_loaded)?;
        let observations = crate::EffectObservationStore::default();
        let effect_reader = policy_loaded
            .then(|| {
                let sink = observations.clone();
                host.effect_observation_reader(move |bytes| {
                    sink.record_bytes(bytes);
                    0
                })
            })
            .transpose()
            .context(InterceptorSnafu)?;
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
                state: if prevention_enabled {
                    "DEGRADED".to_owned()
                } else {
                    "UNSUPPORTED".to_owned()
                },
                reason_code: if prevention_enabled {
                    "SIGNED_ACTIVE_QUALIFIED_LOCAL_SLICE".to_owned()
                } else if policy_loaded {
                    "OBSERVE_ONLY_GENERATION".to_owned()
                } else {
                    "IDENTITY_GATE_ONLY_NO_PERMISSION_TABLE".to_owned()
                },
            },
            CapabilityRecord {
                capability_id: "LOCAL_EFFECT_OBSERVATION".to_owned(),
                state: if policy_loaded {
                    "DEGRADED".to_owned()
                } else {
                    "UNSUPPORTED".to_owned()
                },
                reason_code: if policy_loaded {
                    "SIGNED_ACTIVE_EXACT_FILE_SLICE_ONLY".to_owned()
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
            prevention_enabled,
            capabilities.clone(),
        )?;
        let connector =
            NodeControlConnector::new(config.control.clone(), config.node_id.clone(), boot_id);
        let trust = TrustCache::load(&config.state_directory)?;
        let (readiness, _receiver) = watch::channel(NodeReadinessV1 {
            kernel_ready: true,
            identity_ready: true,
            control_ready: false,
            admission_ready: false,
            effect_prevention_claims_enabled: prevention_enabled,
        });
        let local_server = config
            .runtime_observation
            .clone()
            .map(|runtime| {
                crate::RuntimeObservationServer::bind_with_effects(
                    runtime,
                    manifest,
                    &capabilities,
                    observations,
                    config.interceptor.pin_root.clone(),
                    readiness.subscribe(),
                )
            })
            .transpose()?;
        Ok(Self {
            config,
            effect_reader,
            host: Some(host),
            connector,
            registration,
            local_server,
            trust,
            bindings,
            policy,
            readiness,
        })
    }

    #[must_use]
    pub fn readiness(&self) -> watch::Receiver<NodeReadinessV1> {
        self.readiness.subscribe()
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let prevention_enabled = self
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
        let mut backoff = self.config.control.reconnect_minimum();
        let mut kernel_healthy = true;
        let mut identity_healthy = true;
        let mut run_error = None;
        let mut reconciliation = tokio::time::interval(self.config.reconciliation_interval());
        reconciliation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        'running: loop {
            if *shutdown.borrow() {
                break;
            }
            let connection = tokio::select! {
                result = self.connector.connect(
                    self.registration.clone(),
                    kernel_healthy && identity_healthy,
                    &mut self.trust,
                ) => result,
                changed = shutdown.changed() => {
                    let _result = changed;
                    break;
                }
                result = effect_reader_finished(&mut effect_task) => {
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
                        admission_ready: kernel_healthy && identity_healthy,
                        effect_prevention_claims_enabled:
                            NodeReadinessV1::prevention_claims_enabled(
                                kernel_healthy,
                                identity_healthy,
                                prevention_enabled,
                            ),
                    });
                    backoff = self.config.control.reconnect_minimum();
                    loop {
                        tokio::select! {
                            result = connection.wait_for_disconnect() => {
                                let _error = result.err();
                                break;
                            }
                            changed = shutdown.changed() => {
                                let _result = changed;
                                break 'running;
                            }
                            result = effect_reader_finished(&mut effect_task) => {
                                run_error = result.err();
                                effect_task = None;
                                break 'running;
                            }
                            _instant = reconciliation.tick() => {
                                match self.reconcile_bindings().await {
                                    ReconciliationOutcome::Healthy => {}
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
            self.readiness.send_replace(NodeReadinessV1 {
                kernel_ready: kernel_healthy,
                identity_ready: identity_healthy,
                control_ready: false,
                admission_ready: false,
                effect_prevention_claims_enabled: NodeReadinessV1::prevention_claims_enabled(
                    kernel_healthy,
                    identity_healthy,
                    prevention_enabled,
                ),
            });
            let reconnect = tokio::time::sleep(backoff);
            tokio::pin!(reconnect);
            loop {
                tokio::select! {
                    () = &mut reconnect => break,
                    changed = shutdown.changed() => {
                        let _result = changed;
                        break 'running;
                    }
                    result = effect_reader_finished(&mut effect_task) => {
                        run_error = result.err();
                        effect_task = None;
                        break 'running;
                    }
                    _instant = reconciliation.tick() => {
                        match self.reconcile_bindings().await {
                            ReconciliationOutcome::Healthy => {}
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
        if let Some(error) = run_error {
            return Err(error);
        }
        Ok(())
    }

    async fn reconcile_bindings(&mut self) -> ReconciliationOutcome {
        let Some(host) = self.host.as_ref() else {
            return ReconciliationOutcome::KernelUnhealthy;
        };
        if host.verify_live_manifest().is_err() {
            return ReconciliationOutcome::KernelUnhealthy;
        }
        if self
            .bindings
            .reconcile(host, &self.config.workload_bindings)
            .await
            .is_err()
        {
            return ReconciliationOutcome::IdentityUnhealthy;
        }
        if self
            .policy
            .as_ref()
            .is_some_and(|policy| policy.reconcile_mount_views(host).is_err())
        {
            return ReconciliationOutcome::IdentityUnhealthy;
        }
        ReconciliationOutcome::Healthy
    }

    fn close_kernel_claims(&mut self) {
        close_kernel_claims(&mut self.registration, &self.readiness);
    }
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

fn id_from_uuid_bytes(bytes: [u8; 16]) -> erebor_interceptor_abi::Id128V1 {
    let value = u128::from_be_bytes(bytes);
    erebor_interceptor_abi::Id128V1::new((value >> 64) as u64, value as u64)
}

fn registration(
    manifest: &erebor_interceptor::KernelObjectManifestV1,
    label_epoch: u64,
    effect_prevention_claims_enabled: bool,
    capabilities: Vec<CapabilityRecord>,
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
    })
}

#[cfg(test)]
mod tests {
    use super::{
        close_identity_claims, close_kernel_claims, effect_reader_finished, NodeReadinessV1,
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

    #[test]
    fn reconciliation_checks_the_live_manifest_before_runtime_state() {
        let source = include_str!("node.rs");
        let method = source
            .split("async fn reconcile_bindings")
            .nth(1)
            .and_then(|source| source.split("fn close_kernel_claims").next())
            .unwrap_or_default();

        let manifest = method.find("host.verify_live_manifest()");
        let bindings = method.find(".bindings");
        assert!(
            manifest.is_some_and(|manifest| bindings.is_some_and(|bindings| manifest < bindings))
        );
    }

    #[test]
    fn identity_failure_drops_the_current_control_connection() {
        let source = include_str!("node.rs");
        let connected_loop = source
            .split("Ok(mut connection) =>")
            .nth(1)
            .and_then(|source| source.split("Err(_error)").next())
            .unwrap_or_default();
        let identity_failure = connected_loop
            .split("ReconciliationOutcome::IdentityUnhealthy =>")
            .nth(1)
            .and_then(|source| {
                source
                    .split("ReconciliationOutcome::KernelUnhealthy =>")
                    .next()
            })
            .unwrap_or_default();

        assert!(identity_failure.contains("identity_healthy = false;"));
        assert!(identity_failure.contains("break;"));
    }

    #[tokio::test]
    async fn an_effect_reader_exit_is_a_node_failure() {
        let mut task = Some(tokio::spawn(async { Ok(()) }));
        assert!(effect_reader_finished(&mut task)
            .await
            .is_err_and(|error| error.to_string().contains("stopped before node shutdown")));
    }
}
