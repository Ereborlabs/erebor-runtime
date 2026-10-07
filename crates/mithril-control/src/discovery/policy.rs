use araphor_data::DiscoveryPolicyKeyV1;
use erebor_interceptor_abi::KernelEffectFamilyV1;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    error::DiscoverySnafu, CompiledOperationV1, EffectFamilyV1, Result, StaticDecisionKeyV1,
};

impl TryFrom<&StaticDecisionKeyV1> for DiscoveryPolicyKeyV1 {
    type Error = crate::Error;

    fn try_from(key: &StaticDecisionKeyV1) -> Result<Self> {
        let operation =
            CompiledOperationV1::try_from(key.operation_id.as_str()).map_err(|reason| {
                DiscoverySnafu {
                    code: "POLICY_KEY_OPERATION",
                    reason,
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
        let operation =
            CompiledOperationV1::try_from(key.operation_id.as_str()).map_err(|reason| {
                DiscoverySnafu {
                    code: "POLICY_KEY_OPERATION",
                    reason,
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
                return DiscoverySnafu {
                    code: "POLICY_KEY_FAMILY",
                    reason: "the portable policy family is unsupported",
                }
                .fail();
            }
        };
        if key.operation != operation.kernel_id as u16
            || key.operation_argument != operation.argument
            || key.argument_wildcard != operation.argument_wildcard
        {
            return DiscoverySnafu {
                code: "POLICY_KEY_OPERATION",
                reason: "the portable operation differs from the native policy operation",
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
        _ => DiscoverySnafu {
            code: "POLICY_KEY_ENUM",
            reason: "the native policy enum has no portable name",
        }
        .fail(),
    }
}

fn enum_value<T: DeserializeOwned>(name: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(name.to_owned())).map_err(|_| {
        DiscoverySnafu {
            code: "POLICY_KEY_ENUM",
            reason: "the portable policy enum is unsupported",
        }
        .build()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_context_key_roundtrip() -> Result<()> {
        let policy = crate::PolicyDocumentV1::parse(
            std::path::Path::new("policy-v1.yaml"),
            include_bytes!("../../tests/fixtures/policy-v1.yaml"),
        )?;
        for cell in crate::PolicyCompiler.compile(&policy)?.compiled_cells {
            let key = DiscoveryPolicyKeyV1::try_from(&cell.key)?;
            assert_eq!(StaticDecisionKeyV1::try_from(&key)?, cell.key);
            for change in 0..6 {
                let mut changed = key.clone();
                match change {
                    0 => changed.operation += 1,
                    1 => changed.operation_argument += 1,
                    2 => changed.argument_wildcard = !changed.argument_wildcard,
                    3 => changed.entry_kind = "UNSUPPORTED".into(),
                    4 => changed.binding_lifecycle = "UNSUPPORTED".into(),
                    _ => changed.effect_family = 0,
                }
                assert!(StaticDecisionKeyV1::try_from(&changed).is_err());
            }
        }
        Ok(())
    }
}
