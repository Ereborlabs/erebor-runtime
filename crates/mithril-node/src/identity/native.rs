use std::mem::{offset_of, size_of};

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{Id128V1, IdentityHealthV1, IdentityRuntimeConfigV1};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};
use zerocopy::IntoBytes as _;

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
        self.activate_with_effect_observation(host, false)
    }

    pub fn activate_with_effect_observation(
        &self,
        host: &mut KernelHost,
        effect_observation_enabled: bool,
    ) -> Result<ReconciliationReportV1> {
        let mut config = IdentityRuntimeConfigV1 {
            node_boot_id: self.node_boot_id,
            label_epoch: self.label_epoch,
            next_id: 1,
            first_effect_errno: -rustix::io::Errno::ACCESS.raw_os_error(),
            enabled: 1,
            effect_observation_enabled: u8::from(effect_observation_enabled),
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
        ensure!(
            existing.len() == size_of::<IdentityRuntimeConfigV1>(),
            IdentityStateSnafu {
                reason: format!("identity config map returned {} bytes", existing.len()),
            }
        );
        if existing.iter().all(|byte| *byte == 0) {
            host.update_map("identity_config", &key, config.as_bytes())
                .context(InterceptorSnafu)?;
        } else {
            if recover_config(&existing, &mut config)? {
                host.update_map("identity_config", &key, config.as_bytes())
                    .context(InterceptorSnafu)?;
            }
        }
        host.reconcile_tasks().context(InterceptorSnafu)?;
        let report = self.health(host)?;
        ensure!(
            report.allocation_failures == 0
                && report.coordinate_failures == 0
                && report.reconciliation_required == 0,
            IdentityStateSnafu {
                reason: format!("task reconciliation did not close cleanly: {report:?}"),
            }
        );
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
        ensure!(
            !bytes.is_empty() && bytes.len() % size_of::<IdentityHealthV1>() == 0,
            IdentityStateSnafu {
                reason: format!("identity health map returned {} bytes", bytes.len()),
            }
        );
        let mut report = ReconciliationReportV1::default();
        for value in bytes.chunks_exact(size_of::<IdentityHealthV1>()) {
            report.allocation_failures += read_u64(value, 0)?;
            report.coordinate_failures += read_u64(value, 8)?;
            report.placement_mismatches += read_u64(value, 16)?;
            report.missing_identity_denials += read_u64(value, 24)?;
            report.exec_guard_denials += read_u64(value, 32)?;
            report.reconciliation_required += read_u64(value, 40)?;
        }
        Ok(report)
    }
}

fn recover_config(existing: &[u8], desired: &mut IdentityRuntimeConfigV1) -> Result<bool> {
    desired.next_id = read_u64(existing, offset_of!(IdentityRuntimeConfigV1, next_id))?;
    let observation = offset_of!(IdentityRuntimeConfigV1, effect_observation_enabled);
    let mut recovered = *desired;
    recovered.effect_observation_enabled = existing.get(observation).copied().unwrap_or(u8::MAX);
    let enables_observation =
        recovered.effect_observation_enabled == 0 && desired.effect_observation_enabled == 1;
    ensure!(
        desired.next_id > 0
            && recovered.effect_observation_enabled <= 1
            && existing == recovered.as_bytes()
            && (recovered.effect_observation_enabled == desired.effect_observation_enabled
                || enables_observation),
        IdentityStateSnafu {
            reason: "recovered identity allocator has a different boot, epoch, or configuration"
                .to_owned(),
        }
    );
    Ok(enables_observation)
}

fn read_u64(value: &[u8], offset: usize) -> Result<u64> {
    let bytes = value
        .get(offset..offset + size_of::<u64>())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: "identity health value is truncated".to_owned(),
            }
            .build()
        })?;
    Ok(u64::from_ne_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use erebor_interceptor_abi::IdentityRuntimeConfigV1;
    use zerocopy::IntoBytes as _;

    use super::{read_u64, recover_config};

    #[test]
    fn health_values_use_native_kernel_layout() -> crate::Result<()> {
        let mut bytes = [0_u8; 48];
        bytes[40..48].copy_from_slice(&9_u64.to_ne_bytes());
        assert_eq!(read_u64(&bytes, 40)?, 9);
        Ok(())
    }

    #[test]
    fn recovery_may_enable_observation_without_resetting_the_allocator() -> crate::Result<()> {
        let existing = IdentityRuntimeConfigV1 {
            next_id: 19,
            effect_observation_enabled: 0,
            enabled: 1,
            ..IdentityRuntimeConfigV1::default()
        };
        let mut desired = existing;
        desired.effect_observation_enabled = 1;
        desired.next_id = 1;

        assert!(recover_config(existing.as_bytes(), &mut desired)?);
        assert_eq!(desired.next_id, 19);
        assert_eq!(desired.effect_observation_enabled, 1);
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

        assert!(recover_config(existing.as_bytes(), &mut desired).is_err());
    }

    #[test]
    fn recovery_cannot_disable_observation() {
        let existing = IdentityRuntimeConfigV1 {
            next_id: 19,
            effect_observation_enabled: 1,
            enabled: 1,
            ..IdentityRuntimeConfigV1::default()
        };
        let mut desired = existing;
        desired.effect_observation_enabled = 0;

        assert!(recover_config(existing.as_bytes(), &mut desired).is_err());
    }
}
