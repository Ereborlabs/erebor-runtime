use std::fs;
use std::mem::size_of;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{Id128V1, IdentityHealthV1, IdentityRuntimeConfigV1};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};
use zerocopy::{FromBytes as _, IntoBytes as _};

use crate::error::{IdentityStateSnafu, InterceptorSnafu, IoSnafu};
use crate::Result;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ReconciliationReportV1 {
    pub allocation_failures: u64,
    pub coordinate_failures: u64,
    pub placement_mismatches: u64,
    pub missing_identity_denials: u64,
    pub exec_guard_denials: u64,
    pub reconciliation_required: u64,
}

impl ReconciliationReportV1 {
    fn ensure_no_new_failures_since(self, before: Self) -> Result<()> {
        // A task can request another reconciliation while the current scan runs. That request is
        // pending work, not proof that the current scan failed.
        ensure!(
            self.allocation_failures == before.allocation_failures
                && self.coordinate_failures == before.coordinate_failures
                && self.placement_mismatches == before.placement_mismatches
                && self.reconciliation_required == before.reconciliation_required,
            IdentityStateSnafu {
                reason: format!(
                    "task reconciliation changed a failure counter: before {before:?}; after {self:?}"
                ),
            }
        );
        Ok(())
    }
}

pub struct NativeSecurityStateOwner {
    node_boot_id: Id128V1,
    label_epoch: u64,
    effect_controller_cgroup_id: u64,
}

struct EffectControllerCgroupV1 {
    id: u64,
}

impl EffectControllerCgroupV1 {
    fn acquire(expected: &Path) -> Result<Self> {
        let source_path = Path::new("/proc/self/cgroup");
        let source = fs::read_to_string(source_path).context(IoSnafu { path: source_path })?;
        let mut unified = source.lines().filter_map(|line| line.strip_prefix("0::"));
        let relative = unified.next().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "the effect controller has no unified cgroup".to_owned(),
            }
            .build()
        })?;
        ensure!(
            unified.next().is_none() && relative.starts_with('/'),
            IdentityStateSnafu {
                reason: "the effect controller has an ambiguous unified cgroup",
            }
        );
        let current = PathBuf::from("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
        let expected = fs::canonicalize(expected).context(IoSnafu { path: expected })?;
        let current = fs::canonicalize(&current).context(IoSnafu { path: &current })?;
        ensure!(
            expected == current && current != Path::new("/sys/fs/cgroup"),
            IdentityStateSnafu {
                reason: "the effect controller process is outside its dedicated cgroup",
            }
        );
        let procs_path = current.join("cgroup.procs");
        let processes = fs::read_to_string(&procs_path).context(IoSnafu { path: &procs_path })?;
        let processes = processes
            .lines()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("effect controller cgroup has an invalid PID: {error}"),
                }
                .build()
            })?;
        ensure!(
            processes.as_slice() == [std::process::id()],
            IdentityStateSnafu {
                reason: "the effect controller cgroup must contain only the node process",
            }
        );
        let metadata = fs::metadata(&current).context(IoSnafu { path: &current })?;
        ensure!(
            metadata.is_dir() && metadata.ino() > 0,
            IdentityStateSnafu {
                reason: "the effect controller cgroup has no live kernel identity",
            }
        );
        Ok(Self { id: metadata.ino() })
    }
}

impl NativeSecurityStateOwner {
    #[must_use]
    pub const fn new(node_boot_id: Id128V1, label_epoch: u64) -> Self {
        Self {
            node_boot_id,
            label_epoch,
            effect_controller_cgroup_id: 0,
        }
    }

    pub(crate) fn for_effect_controller(
        node_boot_id: Id128V1,
        label_epoch: u64,
        cgroup_path: &Path,
    ) -> Result<Self> {
        let effect_controller_cgroup_id = EffectControllerCgroupV1::acquire(cgroup_path)?.id;
        Ok(Self {
            node_boot_id,
            label_epoch,
            effect_controller_cgroup_id,
        })
    }

    pub(crate) fn claim_effect_controller(&self, host: &KernelHost) -> Result<()> {
        if self.effect_controller_cgroup_id == 0 {
            return Ok(());
        }
        let key = 0_u32.to_ne_bytes();
        let bytes = host
            .lookup_map("identity_config", &key)
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "identity config map has no zero-key record".to_owned(),
                }
                .build()
            })?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Ok(());
        }
        let mut config = IdentityRuntimeConfigV1::read_from_bytes(&bytes).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("identity config map has an invalid ABI value: {error}"),
            }
            .build()
        })?;
        ensure!(
            config.node_boot_id == self.node_boot_id
                && config.label_epoch == self.label_epoch
                && config.enabled == 1,
            IdentityStateSnafu {
                reason: "the recovered effect controller has a different identity",
            }
        );
        config.effect_controller_cgroup_id = self.effect_controller_cgroup_id;
        host.update_map("identity_config", &key, config.as_bytes())
            .context(InterceptorSnafu)?;
        ensure!(
            host.lookup_map("identity_config", &key)
                .context(InterceptorSnafu)?
                .as_deref()
                == Some(config.as_bytes()),
            IdentityStateSnafu {
                reason: "the effect controller cgroup failed kernel readback",
            }
        );
        Ok(())
    }

    pub fn activate(&self, host: &mut KernelHost) -> Result<ReconciliationReportV1> {
        self.activate_state(host, false, true)
    }

    pub fn activate_held_initial_admission(
        &self,
        host: &mut KernelHost,
        effect_policy_required: bool,
    ) -> Result<ReconciliationReportV1> {
        self.activate_state(host, effect_policy_required, false)
    }

    pub fn activate_initial_with_effect_policy(
        &self,
        host: &mut KernelHost,
        effect_policy_required: bool,
    ) -> Result<ReconciliationReportV1> {
        self.activate_state(host, effect_policy_required, true)
    }

    pub fn set_effect_policy(
        &self,
        host: &mut KernelHost,
        effect_policy_required: bool,
    ) -> Result<ReconciliationReportV1> {
        self.activate_state(host, effect_policy_required, false)
    }

    pub fn verify(
        &self,
        host: &KernelHost,
        effect_policy_required: bool,
    ) -> Result<ReconciliationReportV1> {
        let key = 0_u32.to_ne_bytes();
        let bytes = host
            .lookup_map("identity_config", &key)
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "identity config map has no zero-key record".to_owned(),
                }
                .build()
            })?;
        let config = IdentityRuntimeConfigV1::read_from_bytes(&bytes).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("identity config map has an invalid ABI value: {error}"),
            }
            .build()
        })?;
        ensure!(
            config.node_boot_id == self.node_boot_id
                && config.label_epoch == self.label_epoch
                && config.next_id > 0
                && config.effect_controller_cgroup_id == self.effect_controller_cgroup_id
                && config.enabled == 1
                && config.effect_policy_enabled <= 1
                && config.effect_policy_enabled >= u8::from(effect_policy_required)
                && config.first_effect_errno == -rustix::io::Errno::ACCESS.raw_os_error(),
            IdentityStateSnafu {
                reason: "live identity configuration differs from its node owner",
            }
        );
        self.health(host)
    }

    pub fn activate_prepared_runtime_roots(
        &self,
        host: &mut KernelHost,
        effect_policy_required: bool,
    ) -> Result<ReconciliationReportV1> {
        self.scan_tasks(host, effect_policy_required)
    }

    pub fn recover_tasks(
        &self,
        host: &mut KernelHost,
        effect_policy_required: bool,
    ) -> Result<ReconciliationReportV1> {
        self.scan_tasks(host, effect_policy_required)
    }

    fn scan_tasks(
        &self,
        host: &mut KernelHost,
        effect_policy_required: bool,
    ) -> Result<ReconciliationReportV1> {
        let before = self.verify(host, effect_policy_required)?;
        host.reconcile_tasks().context(InterceptorSnafu)?;
        let report = self.health(host)?;
        report.ensure_no_new_failures_since(before)?;
        Ok(report)
    }

    fn activate_state(
        &self,
        host: &mut KernelHost,
        effect_policy_required: bool,
        reconcile_tasks: bool,
    ) -> Result<ReconciliationReportV1> {
        let mut config = IdentityRuntimeConfigV1 {
            node_boot_id: self.node_boot_id,
            label_epoch: self.label_epoch,
            next_id: 1,
            effect_controller_cgroup_id: self.effect_controller_cgroup_id,
            first_effect_errno: -rustix::io::Errno::ACCESS.raw_os_error(),
            enabled: 1,
            effect_policy_enabled: u8::from(effect_policy_required),
            reserved: [0; 2],
        };
        let key = 0_u32.to_ne_bytes();
        let existing = host
            .lookup_map("identity_config", &key)
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "identity config map has no zero-key record".to_owned(),
                }
                .build()
            })?;
        let write_config = if existing.iter().all(|byte| *byte == 0) {
            true
        } else {
            recover_config(
                IdentityRuntimeConfigV1::read_from_bytes(&existing).map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("identity config map has an invalid ABI value: {error}"),
                    }
                    .build()
                })?,
                &mut config,
            )?
        };
        if write_config {
            host.update_map("identity_config", &key, config.as_bytes())
                .context(InterceptorSnafu)?;
        }
        let before = self.health(host)?;
        if reconcile_tasks {
            host.reconcile_tasks().context(InterceptorSnafu)?;
        }
        let report = self.health(host)?;
        report.ensure_no_new_failures_since(before)?;
        Ok(report)
    }

    pub fn health(&self, host: &KernelHost) -> Result<ReconciliationReportV1> {
        let bytes = host
            .lookup_map("identity_health", &0_u32.to_ne_bytes())
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "identity health map has no zero-key record".to_owned(),
                }
                .build()
            })?;
        aggregate_health(&bytes)
    }
}

fn aggregate_health(bytes: &[u8]) -> Result<ReconciliationReportV1> {
    ensure!(
        !bytes.is_empty() && bytes.len().is_multiple_of(size_of::<IdentityHealthV1>()),
        IdentityStateSnafu {
            reason: format!("identity health map returned {} bytes", bytes.len()),
        }
    );
    let mut report = ReconciliationReportV1::default();
    for value in bytes.chunks_exact(size_of::<IdentityHealthV1>()) {
        let value = IdentityHealthV1::read_from_bytes(value).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("identity health map has an invalid ABI value: {error}"),
            }
            .build()
        })?;
        report.allocation_failures += value.allocation_failures;
        report.coordinate_failures += value.coordinate_failures;
        report.placement_mismatches += value.placement_mismatches;
        report.missing_identity_denials += value.missing_identity_denials;
        report.exec_guard_denials += value.exec_guard_denials;
        report.reconciliation_required += value.reconciliation_required;
    }
    Ok(report)
}

fn recover_config(
    existing: IdentityRuntimeConfigV1,
    desired: &mut IdentityRuntimeConfigV1,
) -> Result<bool> {
    desired.next_id = existing.next_id;
    let mut recovered = *desired;
    recovered.effect_policy_enabled = existing.effect_policy_enabled;
    let enables_policy = recovered.effect_policy_enabled == 0 && desired.effect_policy_enabled == 1;
    let retains_policy = recovered.effect_policy_enabled == 1 && desired.effect_policy_enabled == 0;
    ensure!(
        desired.next_id > 0
            && recovered.effect_policy_enabled <= 1
            && existing == recovered
            && (recovered.effect_policy_enabled == desired.effect_policy_enabled
                || enables_policy
                || retains_policy),
        IdentityStateSnafu {
            reason: "recovered identity allocator has a different boot, epoch, or configuration"
                .to_owned(),
        }
    );
    if retains_policy {
        // The policy gate is monotonic for one boot. Authority cleanup removes
        // its exact maps but does not reopen the global enforcement bypass.
        desired.effect_policy_enabled = 1;
    }
    Ok(enables_policy)
}

#[cfg(test)]
mod tests {
    use erebor_interceptor_abi::{IdentityHealthV1, IdentityRuntimeConfigV1};
    use zerocopy::IntoBytes as _;

    use super::{aggregate_health, recover_config, ReconciliationReportV1};

    #[test]
    fn health_values_use_native_kernel_layout() -> crate::Result<()> {
        let report = aggregate_health(
            IdentityHealthV1 {
                reconciliation_required: 9,
                ..IdentityHealthV1::default()
            }
            .as_bytes(),
        )?;
        assert_eq!(report.reconciliation_required, 9);
        Ok(())
    }

    #[test]
    fn reconciliation_accepts_retained_history_and_rejects_new_failures() {
        let retained = ReconciliationReportV1 {
            allocation_failures: 2,
            coordinate_failures: 3,
            placement_mismatches: 5,
            reconciliation_required: 7,
            ..ReconciliationReportV1::default()
        };
        assert!(retained.ensure_no_new_failures_since(retained).is_ok());
        assert!(ReconciliationReportV1 {
            placement_mismatches: 6,
            ..retained
        }
        .ensure_no_new_failures_since(retained)
        .is_err());
        assert!(ReconciliationReportV1 {
            allocation_failures: 3,
            ..retained
        }
        .ensure_no_new_failures_since(retained)
        .is_err());
    }

    #[test]
    fn reconciliation_rejects_a_new_repair_request() {
        let before = ReconciliationReportV1::default();
        let after = ReconciliationReportV1 {
            reconciliation_required: 1,
            ..before
        };

        assert!(after.ensure_no_new_failures_since(before).is_err());
    }

    #[test]
    fn recovery_may_enable_policy_without_resetting_the_allocator() -> crate::Result<()> {
        let existing = IdentityRuntimeConfigV1 {
            next_id: 19,
            effect_policy_enabled: 0,
            enabled: 1,
            ..IdentityRuntimeConfigV1::default()
        };
        let mut desired = existing;
        desired.effect_policy_enabled = 1;
        desired.next_id = 1;

        assert!(recover_config(existing, &mut desired)?);
        assert_eq!(desired.next_id, 19);
        assert_eq!(desired.effect_policy_enabled, 1);
        Ok(())
    }

    #[test]
    fn recovery_rejects_changes_to_enforcement_configuration() {
        let existing = IdentityRuntimeConfigV1 {
            next_id: 19,
            first_effect_errno: -1,
            enabled: 1,
            ..IdentityRuntimeConfigV1::default()
        };
        let mut desired = existing;
        desired.first_effect_errno = -13;

        assert!(recover_config(existing, &mut desired).is_err());
    }

    #[test]
    fn recovery_retains_an_enabled_policy_gate() -> crate::Result<()> {
        let existing = IdentityRuntimeConfigV1 {
            next_id: 19,
            effect_policy_enabled: 1,
            enabled: 1,
            ..IdentityRuntimeConfigV1::default()
        };
        let mut desired = existing;
        desired.effect_policy_enabled = 0;

        assert!(!recover_config(existing, &mut desired)?);
        assert_eq!(desired.effect_policy_enabled, 1);
        Ok(())
    }
}
