use std::fs::{self, File};
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;

use erebor_interceptor::KernelStateReader;
use erebor_interceptor_abi::{BindingLifecycleStateV1, ExecutionSetBindingStateV1};
use snafu::{ensure, OptionExt as _, ResultExt as _};
use zerocopy::TryFromBytes as _;

use crate::{
    error::{IdentityStateSnafu, InterceptorSnafu, IoSnafu},
    Result, TraceTargetV1,
};

pub struct TraceTargetLeaseV1 {
    target: TraceTargetV1,
    root_path: PathBuf,
    root_handle: File,
    #[cfg(feature = "test-support")]
    readback: Option<Box<dyn Fn() -> Result<Option<ExecutionSetBindingStateV1>> + Send + Sync>>,
}

impl TraceTargetLeaseV1 {
    pub fn new(target: TraceTargetV1, root_path: PathBuf, root_handle: File) -> Result<Self> {
        let lease = Self {
            target,
            root_path,
            root_handle,
            #[cfg(feature = "test-support")]
            readback: None,
        };
        lease.validate_path()?;
        Ok(lease)
    }

    pub fn target(&self) -> &TraceTargetV1 {
        &self.target
    }

    #[cfg(feature = "test-support")]
    pub fn fixture(
        target: TraceTargetV1,
        root_path: PathBuf,
        readback: impl Fn() -> Result<Option<ExecutionSetBindingStateV1>> + Send + Sync + 'static,
    ) -> Result<Self> {
        let root_handle = File::open(&root_path).context(IoSnafu { path: &root_path })?;
        let mut lease = Self::new(target, root_path, root_handle)?;
        lease.readback = Some(Box::new(readback));
        Ok(lease)
    }

    pub fn validate(&self, reader: &KernelStateReader) -> Result<()> {
        self.validate_path()?;
        #[cfg(feature = "test-support")]
        if let Some(readback) = &self.readback {
            return self.validate_state(&readback()?.context(IdentityStateSnafu {
                reason: "trace binding disappeared",
            })?);
        }
        let bytes = reader
            .lookup(
                "execution_set_bindings",
                &self.target.cgroup_id.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "trace binding disappeared",
            })?;
        let state = ExecutionSetBindingStateV1::try_read_from_bytes(&bytes).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("execution-set binding has an invalid ABI value: {error}"),
            }
            .build()
        })?;
        self.validate_state(&state)
    }

    fn validate_path(&self) -> Result<()> {
        let path = fs::metadata(&self.root_path).context(IoSnafu {
            path: &self.root_path,
        })?;
        let held = self.root_handle.metadata().context(IoSnafu {
            path: &self.root_path,
        })?;
        ensure!(
            path.dev() == held.dev()
                && path.ino() == held.ino()
                && held.ino() == self.target.cgroup_id,
            IdentityStateSnafu {
                reason: "trace cgroup lifetime changed"
            }
        );
        Ok(())
    }

    fn validate_state(&self, state: &ExecutionSetBindingStateV1) -> Result<()> {
        ensure!(
            (BindingLifecycleStateV1::Active as u8
                ..=BindingLifecycleStateV1::ActiveRecovered as u8)
                .contains(&(state.lifecycle_state as u8))
                && state.lifecycle_state != BindingLifecycleStateV1::Recovering
                && state.transition_guard == 0
                && state.node_boot_id.to_be_bytes() == self.target.node_boot_id
                && state.binding_id.to_be_bytes() == self.target.binding_id
                && state.binding_nonce.to_be_bytes() == self.target.binding_nonce
                && state.root_cgroup_live_interval_id.to_be_bytes()
                    == self.target.root_cgroup_live_interval_id
                && state.root_cgroup_id == self.target.cgroup_id
                && state.label_epoch == self.target.label_epoch
                && state.container_generation == self.target.container_generation,
            IdentityStateSnafu {
                reason: "trace binding was retired or replaced"
            }
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContainerKindV1, DiscoveryDigestV1, WorkloadTargetFactV1};
    use erebor_interceptor_abi::Id128V1;

    #[test]
    fn target_rejects_replaced_lifetime() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root)?;
        let fact = WorkloadTargetFactV1 {
            node_id: "node".into(),
            workload_binding_generation_digest: "generation".into(),
            execution_set_id: "execution".into(),
            cluster_uid: "cluster".into(),
            namespace_uid: "namespace".into(),
            controller_uid: "controller".into(),
            service_account_uid: "account".into(),
            pod_uid: "pod".into(),
            container_id: "container".into(),
            container_name: "worker".into(),
            container_kind: ContainerKindV1::Application,
            image_digest: "image".into(),
            pod_labels: Default::default(),
            kubernetes: None,
        };
        let target = TraceTargetV1 {
            fact_digest: DiscoveryDigestV1::of(&fact)?,
            fact,
            runtime_container_id: "container".into(),
            node_boot_id: [2; 16],
            cgroup_id: fs::metadata(&root)?.ino(),
            binding_id: [3; 16],
            binding_nonce: [4; 16],
            root_cgroup_live_interval_id: [5; 16],
            container_generation: 1,
            label_epoch: 3,
        };
        target.validate()?;
        let state = ExecutionSetBindingStateV1 {
            node_boot_id: target.node_boot_id.into(),
            binding_id: target.binding_id.into(),
            binding_nonce: target.binding_nonce.into(),
            root_cgroup_live_interval_id: target.root_cgroup_live_interval_id.into(),
            root_cgroup_id: target.cgroup_id,
            label_epoch: target.label_epoch,
            container_generation: target.container_generation,
            lifecycle_state: BindingLifecycleStateV1::Active,
            ..Default::default()
        };
        assert!(TraceTargetLeaseV1::new(
            target.clone(),
            root.clone(),
            File::open(temporary.path())?,
        )
        .is_err());
        let lease = TraceTargetLeaseV1::new(target.clone(), root.clone(), File::open(&root)?)?;
        assert_eq!(lease.target(), &target);
        lease.validate_path()?;
        lease.validate_state(&state)?;
        let mut replacement = state;
        replacement.binding_nonce = Id128V1::new(9, 9);
        assert!(lease.validate_state(&replacement).is_err());
        replacement = state;
        replacement.container_generation += 1;
        assert!(lease.validate_state(&replacement).is_err());
        replacement = state;
        replacement.label_epoch += 1;
        assert!(lease.validate_state(&replacement).is_err());
        #[cfg(feature = "test-support")]
        let fixture = {
            use std::sync::{
                atomic::{AtomicU64, Ordering},
                Arc,
            };
            let generation = Arc::new(AtomicU64::new(state.container_generation));
            let current = generation.clone();
            let fixture = TraceTargetLeaseV1::fixture(target, root.clone(), move || {
                let generation = current.load(Ordering::Acquire);
                Ok((generation != 0).then_some(ExecutionSetBindingStateV1 {
                    container_generation: generation,
                    ..state
                }))
            })?;
            let reader = KernelStateReader::new(temporary.path());
            fixture.validate(&reader)?;
            generation.store(state.container_generation + 1, Ordering::Release);
            assert!(fixture.validate(&reader).is_err());
            generation.store(0, Ordering::Release);
            assert!(fixture.validate(&reader).is_err());
            generation.store(state.container_generation, Ordering::Release);
            fixture.validate(&reader)?;
            fixture
        };
        fs::rename(&root, temporary.path().join("retired"))?;
        fs::create_dir(&root)?;
        assert!(lease.validate_path().is_err());
        #[cfg(feature = "test-support")]
        assert!(fixture
            .validate(&KernelStateReader::new(temporary.path()))
            .is_err());
        Ok(())
    }
}
