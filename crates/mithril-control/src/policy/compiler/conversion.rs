use super::CompiledPhysicalResultV1;
use crate::policy::source::{LocalObjectSelectorV1, PolicyDispositionV1, ProfileModeV1};

pub use araphor_data::CompiledOperationV1;

impl TryFrom<(PolicyDispositionV1, ProfileModeV1)> for CompiledPhysicalResultV1 {
    type Error = &'static str;

    fn try_from(
        (disposition, mode): (PolicyDispositionV1, ProfileModeV1),
    ) -> Result<Self, Self::Error> {
        match disposition {
            PolicyDispositionV1::Allow => Ok(Self::AllowEffect),
            PolicyDispositionV1::Alert => Ok(Self::AuditAllowEffect),
            PolicyDispositionV1::Deny => Ok(match mode {
                ProfileModeV1::Observe => Self::SimulatablePolicyDeny,
                ProfileModeV1::Protect => Self::DenyEffect,
            }),
            PolicyDispositionV1::Reject => Err("REJECT has no local physical result"),
        }
    }
}

impl From<&LocalObjectSelectorV1> for Vec<String> {
    fn from(selector: &LocalObjectSelectorV1) -> Self {
        match selector {
            LocalObjectSelectorV1::PathSelectors { path_selector_ids } => path_selector_ids
                .iter()
                .map(|id| format!("PATH:{id}"))
                .collect(),
            LocalObjectSelectorV1::ObjectClasses { object_class_ids } => object_class_ids
                .iter()
                .map(|id| format!("CLASS:{id}"))
                .collect(),
            LocalObjectSelectorV1::Destinations {
                destination_policy_ids,
            } => destination_policy_ids
                .iter()
                .map(|id| format!("DESTINATION:{id}"))
                .collect(),
            LocalObjectSelectorV1::Devices {
                device_class_ids,
                ioctl_command_ids,
            } => {
                let commands = if ioctl_command_ids.is_empty() {
                    vec!["*".to_owned()]
                } else {
                    ioctl_command_ids.iter().map(u32::to_string).collect()
                };
                device_class_ids
                    .iter()
                    .flat_map(|device| {
                        commands
                            .iter()
                            .map(move |command| format!("DEVICE:{device}:{command}"))
                    })
                    .collect()
            }
            LocalObjectSelectorV1::SecurityObjects {
                security_object_ids,
                target_selector_ids,
            } => {
                let targets = if target_selector_ids.is_empty() {
                    vec!["*".to_owned()]
                } else {
                    target_selector_ids.clone()
                };
                security_object_ids
                    .iter()
                    .flat_map(|object| {
                        targets
                            .iter()
                            .map(move |target| format!("SECURITY:{object}:{target}"))
                    })
                    .collect()
            }
        }
    }
}
