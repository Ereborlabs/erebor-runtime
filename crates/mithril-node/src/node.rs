use erebor_interceptor::{KernelHost, KernelHostConfig, KernelHostOwner};
use mithril_control::{CapabilityRecord, NodeRegistration};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use std::cmp;
use tokio::sync::watch;

use crate::epoch::NodeEpochs;
use crate::error::{InterceptorSnafu, JsonSnafu, LocalTaskSnafu};
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
        self.kernel_ready
            && self.identity_ready
            && self.control_ready
            && self.admission_ready
            && !self.effect_prevention_claims_enabled
    }
}

pub struct NodeChassis {
    config: NodeConfig,
    host: Option<KernelHost>,
    connector: NodeControlConnector,
    registration: NodeRegistration,
    local_server: Option<crate::RuntimeObservationServer>,
    trust: TrustCache,
    bindings: WorkloadBindingOwner,
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
        let identity = NativeSecurityStateOwner::new(node_boot_id, label_epoch);
        let reconciliation = identity.activate(&mut host)?;
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
                state: "UNSUPPORTED".to_owned(),
                reason_code: "IDENTITY_GATE_ONLY_NO_PERMISSION_TABLE".to_owned(),
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
        ];
        let registration = registration(manifest, label_epoch, capabilities.clone())?;
        let connector =
            NodeControlConnector::new(config.control.clone(), config.node_id.clone(), boot_id);
        let trust = TrustCache::load(&config.state_directory)?;
        let local_server = config
            .runtime_observation
            .clone()
            .map(|runtime| crate::RuntimeObservationServer::bind(runtime, manifest, &capabilities))
            .transpose()?;
        let (readiness, _receiver) = watch::channel(NodeReadinessV1 {
            kernel_ready: true,
            identity_ready: true,
            control_ready: false,
            admission_ready: false,
            effect_prevention_claims_enabled: false,
        });
        Ok(Self {
            config,
            host: Some(host),
            connector,
            registration,
            local_server,
            trust,
            bindings,
            readiness,
        })
    }

    #[must_use]
    pub fn readiness(&self) -> watch::Receiver<NodeReadinessV1> {
        self.readiness.subscribe()
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let local_task = self.local_server.take().map(|server| {
            let local_shutdown = shutdown.clone();
            tokio::spawn(server.serve(local_shutdown))
        });
        let mut backoff = self.config.control.reconnect_minimum();
        let mut identity_healthy = true;
        let mut binding_reconciliation =
            self.config.binding_reconciliation_interval().map(|period| {
                let mut interval = tokio::time::interval(period);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                interval
            });
        'running: loop {
            if *shutdown.borrow() {
                break;
            }
            let connection = tokio::select! {
                result = self.connector.connect(
                    self.registration.clone(),
                    identity_healthy,
                    &mut self.trust,
                ) => result,
                changed = shutdown.changed() => {
                    let _result = changed;
                    break;
                }
            };
            match connection {
                Ok(mut connection) => {
                    self.readiness.send_replace(NodeReadinessV1 {
                        kernel_ready: true,
                        identity_ready: identity_healthy,
                        control_ready: true,
                        admission_ready: identity_healthy,
                        effect_prevention_claims_enabled: false,
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
                            () = next_reconciliation_tick(&mut binding_reconciliation) => {
                                if !self.reconcile_bindings().await {
                                    identity_healthy = false;
                                    self.readiness.send_replace(NodeReadinessV1 {
                                        kernel_ready: true,
                                        identity_ready: false,
                                        control_ready: true,
                                        admission_ready: false,
                                        effect_prevention_claims_enabled: false,
                                    });
                                }
                            }
                        }
                    }
                }
                Err(_error) => {}
            }
            self.readiness.send_replace(NodeReadinessV1 {
                kernel_ready: true,
                identity_ready: identity_healthy,
                control_ready: false,
                admission_ready: false,
                effect_prevention_claims_enabled: false,
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
                    () = next_reconciliation_tick(&mut binding_reconciliation) => {
                        if !self.reconcile_bindings().await {
                            identity_healthy = false;
                        }
                    }
                }
            }
            backoff = cmp::min(
                backoff.saturating_mul(2),
                self.config.control.reconnect_maximum(),
            );
        }
        if let Some(host) = self.host.take() {
            host.shutdown().context(InterceptorSnafu)?;
        }
        if let Some(task) = local_task {
            task.await.context(LocalTaskSnafu)??;
        }
        Ok(())
    }

    async fn reconcile_bindings(&mut self) -> bool {
        match self.host.as_ref() {
            Some(host) => self
                .bindings
                .reconcile(host, &self.config.workload_bindings)
                .await
                .is_ok(),
            None => false,
        }
    }
}

async fn next_reconciliation_tick(interval: &mut Option<tokio::time::Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

fn id_from_uuid_bytes(bytes: [u8; 16]) -> erebor_interceptor_abi::Id128V1 {
    let value = u128::from_be_bytes(bytes);
    erebor_interceptor_abi::Id128V1::new((value >> 64) as u64, value as u64)
}

fn registration(
    manifest: &erebor_interceptor::KernelObjectManifestV1,
    label_epoch: u64,
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
        effect_prevention_claims_enabled: false,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::NodeReadinessV1;

    #[test]
    fn boot_admission_requires_complete_chassis_readiness_and_never_claims_prevention() {
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
        assert!(!NodeReadinessV1 {
            control_ready: false,
            admission_ready: false,
            ..ready
        }
        .admits_new_work());
    }
}
