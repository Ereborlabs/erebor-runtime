use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};

use super::CompiledPhysicalResultV1;
use crate::policy::source::{
    EffectFamilyV1, LocalObjectSelectorV1, PolicyDispositionV1, ProfileModeV1,
};

/// A signed operation converted to its kernel operation and hook argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompiledOperationV1 {
    pub kernel_id: KernelEffectOperationV1,
    pub argument: u32,
    pub argument_wildcard: bool,
}

impl CompiledOperationV1 {
    #[must_use]
    pub const fn process_control(self) -> Option<Self> {
        match self.kernel_id {
            KernelEffectOperationV1::Ptrace | KernelEffectOperationV1::Signal => Some(self),
            _ => None,
        }
    }

    fn argument(operation: &str, prefix: &str) -> Option<u32> {
        let argument = operation.strip_prefix(prefix)?;
        if argument.is_empty() || (argument.len() > 1 && argument.starts_with('0')) {
            return None;
        }
        argument.parse().ok()
    }
}

impl TryFrom<&str> for CompiledOperationV1 {
    type Error = &'static str;

    fn try_from(operation: &str) -> Result<Self, Self::Error> {
        let process_control = match operation {
            "PTRACE" => Some((KernelEffectOperationV1::Ptrace, 0, true)),
            "SIGNAL" => Some((KernelEffectOperationV1::Signal, 0, true)),
            _ => Self::argument(operation, "PTRACE_ACCESS_")
                .map(|argument| (KernelEffectOperationV1::Ptrace, argument, false))
                .or_else(|| {
                    Self::argument(operation, "SIGNAL_")
                        .map(|argument| (KernelEffectOperationV1::Signal, argument, false))
                }),
        };
        if let Some((kernel_id, argument, argument_wildcard)) = process_control {
            return Ok(Self {
                kernel_id,
                argument,
                argument_wildcard,
            });
        }

        let kernel_id = match operation {
            "EXECUTE" => KernelEffectOperationV1::Execute,
            "OPEN_READ" => KernelEffectOperationV1::OpenRead,
            "OPEN_WRITE" => KernelEffectOperationV1::OpenWrite,
            "READ" => KernelEffectOperationV1::Read,
            "WRITE" => KernelEffectOperationV1::Write,
            "IOCTL" => KernelEffectOperationV1::Ioctl,
            "MMAP_READ" => KernelEffectOperationV1::MmapRead,
            "MMAP_WRITE" => KernelEffectOperationV1::MmapWrite,
            "MMAP_EXEC" => KernelEffectOperationV1::MmapExec,
            "MPROTECT" => KernelEffectOperationV1::Mprotect,
            "IPC_ACCESS" => KernelEffectOperationV1::IpcAccess,
            "CONNECT" => KernelEffectOperationV1::Connect,
            "SEND" => KernelEffectOperationV1::Send,
            "SOCKET_CREATE" => KernelEffectOperationV1::SocketCreate,
            "BIND" => KernelEffectOperationV1::Bind,
            "LISTEN" => KernelEffectOperationV1::Listen,
            "ACCEPT" => KernelEffectOperationV1::Accept,
            "RECEIVE" => KernelEffectOperationV1::Receive,
            "SHUTDOWN" => KernelEffectOperationV1::Shutdown,
            "SETSOCKOPT" => KernelEffectOperationV1::Setsockopt,
            "CREATE" => KernelEffectOperationV1::Create,
            "SETATTR" => KernelEffectOperationV1::Setattr,
            "UNLINK" => KernelEffectOperationV1::Unlink,
            "LINK" => KernelEffectOperationV1::Link,
            "RENAME" => KernelEffectOperationV1::Rename,
            "MOUNT" => KernelEffectOperationV1::Mount,
            "UNMOUNT" => KernelEffectOperationV1::Unmount,
            "PIVOT_ROOT" => KernelEffectOperationV1::PivotRoot,
            "MOVE_MOUNT" => KernelEffectOperationV1::MoveMount,
            "CAPABILITY" => KernelEffectOperationV1::Capability,
            "BPF" => KernelEffectOperationV1::Bpf,
            "IO_URING_SETUP" => KernelEffectOperationV1::IoUringSetup,
            "IO_URING_REGISTER" => KernelEffectOperationV1::IoUringRegister,
            "IO_URING_SQPOLL" => KernelEffectOperationV1::IoUringSqpoll,
            "IO_URING_OVERRIDE_CREDS" => KernelEffectOperationV1::IoUringOverrideCreds,
            "IO_URING_COMMAND" => KernelEffectOperationV1::IoUringCommand,
            _ => return Err("unknown signed kernel operation"),
        };
        Ok(Self {
            kernel_id,
            argument: 0,
            argument_wildcard: false,
        })
    }
}

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

impl From<EffectFamilyV1> for KernelEffectFamilyV1 {
    fn from(family: EffectFamilyV1) -> Self {
        match family {
            EffectFamilyV1::Exec => Self::Exec,
            EffectFamilyV1::File => Self::File,
            EffectFamilyV1::Network => Self::Network,
            EffectFamilyV1::Device => Self::Device,
            EffectFamilyV1::Privilege => Self::Privilege,
            EffectFamilyV1::Ipc => Self::Ipc,
            EffectFamilyV1::Mount => Self::Mount,
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
