use std::mem::size_of;

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{Id128V1, IdentityHealthV1, IdentityRuntimeConfigV1};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};
use zerocopy::{FromBytes as _, IntoBytes as _};

use crate::error::{IdentityStateSnafu, InterceptorSnafu};
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

pub struct NativeSecurityStateOwner {
    node_boot_id: Id128V1,
    label_epoch: u64,
}

impl NativeSecurityStateOwner {
    #[must_use]
    pub const fn new(node_boot_id: Id128V1, label_epoch: u64) -> Self {
        Self {
            node_boot_id,
            label_epoch,
        }
    }

    pub fn activate(&self, host: &mut KernelHost) -> Result<ReconciliationReportV1> {
        self.activate_state(host, false, true)
    }

    pub fn activate_held_initial_admission(
        &self,
        host: &mut KernelHost,
        effect_policy_enabled: bool,
    ) -> Result<ReconciliationReportV1> {
        self.activate_state(host, effect_policy_enabled, false)
    }

    pub fn activate_with_effect_policy(
        &self,
        host: &mut KernelHost,
        effect_policy_enabled: bool,
    ) -> Result<ReconciliationReportV1> {
        self.activate_state(host, effect_policy_enabled, true)
    }

    pub fn reconcile(&self, host: &mut KernelHost) -> Result<ReconciliationReportV1> {
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
                && config.enabled == 1
                && config.effect_policy_enabled <= 1
                && config.first_effect_errno == -rustix::io::Errno::ACCESS.raw_os_error(),
            IdentityStateSnafu {
                reason: "live identity configuration differs from its node owner",
            }
        );
        host.reconcile_tasks().context(InterceptorSnafu)?;
        let report = self.health(host)?;
        ensure_healthy(report)?;
        Ok(report)
    }

    fn activate_state(
        &self,
        host: &mut KernelHost,
        effect_policy_enabled: bool,
        reconcile_tasks: bool,
    ) -> Result<ReconciliationReportV1> {
        let mut config = IdentityRuntimeConfigV1 {
            node_boot_id: self.node_boot_id,
            label_epoch: self.label_epoch,
            next_id: 1,
            first_effect_errno: -rustix::io::Errno::ACCESS.raw_os_error(),
            enabled: 1,
            effect_policy_enabled: u8::from(effect_policy_enabled),
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
        if reconcile_tasks {
            host.reconcile_tasks().context(InterceptorSnafu)?;
        }
        let report = self.health(host)?;
        ensure_healthy(report)?;
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

fn ensure_healthy(report: ReconciliationReportV1) -> Result<()> {
    ensure!(
        report.allocation_failures == 0
            && report.coordinate_failures == 0
            && report.placement_mismatches == 0
            && report.reconciliation_required == 0,
        IdentityStateSnafu {
            reason: format!("task reconciliation did not close cleanly: {report:?}"),
        }
    );
    Ok(())
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
    ensure!(
        desired.next_id > 0
            && recovered.effect_policy_enabled <= 1
            && existing == recovered
            && (recovered.effect_policy_enabled == desired.effect_policy_enabled || enables_policy),
        IdentityStateSnafu {
            reason: "recovered identity allocator has a different boot, epoch, or configuration"
                .to_owned(),
        }
    );
    Ok(enables_policy)
}

#[cfg(test)]
mod tests {
    use erebor_interceptor_abi::{IdentityHealthV1, IdentityRuntimeConfigV1};
    use zerocopy::IntoBytes as _;

    use super::{aggregate_health, ensure_healthy, recover_config, ReconciliationReportV1};

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
    fn live_identity_health_rejects_capacity_and_placement_failures() {
        assert!(ensure_healthy(ReconciliationReportV1 {
            allocation_failures: 1,
            ..ReconciliationReportV1::default()
        })
        .is_err());
        assert!(ensure_healthy(ReconciliationReportV1 {
            placement_mismatches: 1,
            ..ReconciliationReportV1::default()
        })
        .is_err());
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
    fn recovery_cannot_disable_policy() {
        let existing = IdentityRuntimeConfigV1 {
            next_id: 19,
            effect_policy_enabled: 1,
            enabled: 1,
            ..IdentityRuntimeConfigV1::default()
        };
        let mut desired = existing;
        desired.effect_policy_enabled = 0;

        assert!(recover_config(existing, &mut desired).is_err());
    }
}
