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
    NodeConfig, NodeControlConnector, Result, TrustCache, WorkloadInventory,
    WorkloadInventoryRecordV1,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct NodeReadinessV1 {
    pub kernel_ready: bool,
    pub control_ready: bool,
    pub admission_ready: bool,
    pub effect_prevention_claims_enabled: bool,
}

impl NodeReadinessV1 {
    #[must_use]
    pub const fn admits_new_work(self) -> bool {
        self.kernel_ready
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
    readiness: watch::Sender<NodeReadinessV1>,
}

impl NodeChassis {
    pub fn start(config: NodeConfig) -> Result<Self> {
        config.validate()?;
        let boot_id = NodeEpochs::boot_id()?;
        let label_epoch = NodeEpochs::next_label_epoch(&config.state_directory)?;
        let inventory = WorkloadInventory::system().scan()?;
        let owner = KernelHostOwner::new(KernelHostConfig::new(
            &config.interceptor.object_path,
            &config.interceptor.object_sha256,
            &config.interceptor.runtime_btf_path,
            &config.interceptor.lease_path,
            Some(config.interceptor.pin_root.clone()),
            uuid::Uuid::from_bytes(boot_id).simple().to_string(),
            label_epoch,
        ));
        let host = owner.start().context(InterceptorSnafu)?;
        let manifest = host.manifest();
        let capabilities = vec![
            CapabilityRecord {
                capability_id: "KERNEL_LSM_CHASSIS".to_owned(),
                state: "SUPPORTED".to_owned(),
                reason_code: "EXACT_ATTACH_READBACK".to_owned(),
            },
            CapabilityRecord {
                capability_id: "LOCAL_EFFECT_PREVENTION".to_owned(),
                state: "UNSUPPORTED".to_owned(),
                reason_code: "PHASE_1_CHASSIS_ONLY".to_owned(),
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
        let registration = registration(manifest, label_epoch, &inventory, capabilities.clone())?;
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
        loop {
            if *shutdown.borrow() {
                break;
            }
            let connection = self
                .connector
                .connect(self.registration.clone(), &mut self.trust)
                .await;
            match connection {
                Ok(mut connection) => {
                    self.readiness.send_replace(NodeReadinessV1 {
                        kernel_ready: true,
                        control_ready: true,
                        admission_ready: true,
                        effect_prevention_claims_enabled: false,
                    });
                    backoff = self.config.control.reconnect_minimum();
                    tokio::select! {
                        result = connection.wait_for_disconnect() => {
                            let _error = result.err();
                        }
                        changed = shutdown.changed() => {
                            let _result = changed;
                            break;
                        }
                    }
                }
                Err(_error) => {}
            }
            self.readiness.send_replace(NodeReadinessV1 {
                kernel_ready: true,
                control_ready: false,
                admission_ready: false,
                effect_prevention_claims_enabled: false,
            });
            tokio::select! {
                () = tokio::time::sleep(backoff) => {}
                changed = shutdown.changed() => {
                    let _result = changed;
                    break;
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
}

fn registration(
    manifest: &erebor_interceptor::KernelObjectManifestV1,
    label_epoch: u64,
    inventory: &WorkloadInventoryRecordV1,
    capabilities: Vec<CapabilityRecord>,
) -> Result<NodeRegistration> {
    let manifest_bytes = serde_json::to_vec(manifest).context(JsonSnafu {
        path: "in-memory kernel manifest",
    })?;
    Ok(NodeRegistration {
        platform_digest: format!("{:x}", Sha256::digest(&manifest_bytes)),
        program_digest: manifest.object_sha256.clone(),
        label_epoch,
        inventory_process_count: inventory.process_count,
        inventory_digest: inventory.cgroup_binding_digest.clone(),
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
