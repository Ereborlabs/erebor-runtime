use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{DiscoveryPolicyKeyV1, Result};

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntryKindV1 {
    ContainerStart,
    ExternalRuntimeUnknown,
    DeclaredPostStart,
    DeclaredPreStop,
    DeclaredStartupProbe,
    DeclaredReadinessProbe,
    DeclaredLivenessProbe,
    QualifiedJoinedPurpose,
    ApprovedAdministrativeExec,
    RestoredUnknown,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectFamilyV1 {
    Exec,
    File,
    Network,
    Device,
    Privilege,
    Ipc,
    Mount,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingLifecycleV1 {
    Preparing,
    Active,
    Draining,
    Terminating,
    Tombstoned,
}

/// One exact selector key after the compiler expands all policy dimensions.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticDecisionKeyV1 {
    pub workload_selector_id: String,
    pub protected_scope_id: String,
    pub execution_set_id: String,
    pub entry_kind: EntryKindV1,
    pub role_id: String,
    pub process_state_id: String,
    pub effect_family: EffectFamilyV1,
    pub operation_id: String,
    pub object_selector: String,
    pub binding_lifecycle: BindingLifecycleV1,
}

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

    fn try_from(operation: &str) -> std::result::Result<Self, Self::Error> {
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

impl TryFrom<&StaticDecisionKeyV1> for DiscoveryPolicyKeyV1 {
    type Error = crate::Error;

    fn try_from(key: &StaticDecisionKeyV1) -> Result<Self> {
        let operation = CompiledOperationV1::try_from(key.operation_id.as_str()).map_err(|_| {
            crate::DiscoveryInvalidSnafu {
                field: "POLICY_KEY_OPERATION",
            }
            .build()
        })?;
        Ok(Self {
            workload_selector_id: key.workload_selector_id.clone(),
            protected_scope_id: key.protected_scope_id.clone(),
            execution_set_id: key.execution_set_id.clone(),
            entry_kind: enum_name(key.entry_kind)?,
            role_id: key.role_id.clone(),
            process_state_id: key.process_state_id.clone(),
            effect_family: KernelEffectFamilyV1::from(key.effect_family) as u16,
            operation_id: key.operation_id.clone(),
            operation: operation.kernel_id as u16,
            operation_argument: operation.argument,
            argument_wildcard: operation.argument_wildcard,
            object_selector: key.object_selector.clone(),
            binding_lifecycle: enum_name(key.binding_lifecycle)?,
        })
    }
}

impl TryFrom<&DiscoveryPolicyKeyV1> for StaticDecisionKeyV1 {
    type Error = crate::Error;

    fn try_from(key: &DiscoveryPolicyKeyV1) -> Result<Self> {
        let operation = CompiledOperationV1::try_from(key.operation_id.as_str()).map_err(|_| {
            crate::DiscoveryInvalidSnafu {
                field: "POLICY_KEY_OPERATION",
            }
            .build()
        })?;
        let effect_family = match key.effect_family {
            1 => EffectFamilyV1::Exec,
            2 => EffectFamilyV1::File,
            3 => EffectFamilyV1::Network,
            4 => EffectFamilyV1::Device,
            5 => EffectFamilyV1::Privilege,
            6 => EffectFamilyV1::Ipc,
            7 => EffectFamilyV1::Mount,
            _ => {
                return crate::DiscoveryInvalidSnafu {
                    field: "POLICY_KEY_FAMILY",
                }
                .fail();
            }
        };
        if key.operation != operation.kernel_id as u16
            || key.operation_argument != operation.argument
            || key.argument_wildcard != operation.argument_wildcard
        {
            return crate::DiscoveryInvalidSnafu {
                field: "POLICY_KEY_OPERATION",
            }
            .fail();
        }
        Ok(Self {
            workload_selector_id: key.workload_selector_id.clone(),
            protected_scope_id: key.protected_scope_id.clone(),
            execution_set_id: key.execution_set_id.clone(),
            entry_kind: enum_value(&key.entry_kind)?,
            role_id: key.role_id.clone(),
            process_state_id: key.process_state_id.clone(),
            effect_family,
            operation_id: key.operation_id.clone(),
            object_selector: key.object_selector.clone(),
            binding_lifecycle: enum_value(&key.binding_lifecycle)?,
        })
    }
}

fn enum_name(value: impl Serialize) -> Result<String> {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => Ok(name),
        _ => crate::DiscoveryInvalidSnafu {
            field: "POLICY_KEY_ENUM",
        }
        .fail(),
    }
}

fn enum_value<T: DeserializeOwned>(name: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(name.to_owned())).map_err(|_| {
        crate::DiscoveryInvalidSnafu {
            field: "POLICY_KEY_ENUM",
        }
        .build()
    })
}

impl EffectFamilyV1 {
    pub fn accepts(self, operation: &str) -> bool {
        match self {
            Self::Exec => matches!(operation, "EXECUTE" | "MMAP_EXEC" | "MPROTECT"),
            Self::File => matches!(
                operation,
                "OPEN_READ"
                    | "OPEN_WRITE"
                    | "READ"
                    | "WRITE"
                    | "MMAP_READ"
                    | "MMAP_WRITE"
                    | "MPROTECT"
                    | "CREATE"
                    | "SETATTR"
                    | "UNLINK"
                    | "LINK"
                    | "RENAME"
            ),
            Self::Network => matches!(
                operation,
                "SOCKET_CREATE"
                    | "BIND"
                    | "LISTEN"
                    | "ACCEPT"
                    | "CONNECT"
                    | "SEND"
                    | "RECEIVE"
                    | "SHUTDOWN"
                    | "SETSOCKOPT"
            ),
            Self::Device => operation == "IOCTL",
            Self::Privilege => {
                matches!(
                    operation,
                    "CAPABILITY"
                        | "BPF"
                        | "IO_URING_SETUP"
                        | "IO_URING_REGISTER"
                        | "IO_URING_SQPOLL"
                        | "IO_URING_OVERRIDE_CREDS"
                        | "IO_URING_COMMAND"
                ) || CompiledOperationV1::try_from(operation)
                    .ok()
                    .and_then(CompiledOperationV1::process_control)
                    .is_some()
            }
            Self::Ipc => operation == "IPC_ACCESS",
            Self::Mount => matches!(operation, "MOUNT" | "UNMOUNT" | "PIVOT_ROOT" | "MOVE_MOUNT"),
        }
    }
}
