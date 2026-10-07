use std::collections::BTreeSet;

use araphor_data::{BehaviorSnapshotV1, DiscoveryInputManifestV1, DiscoveryOwner};
use serde::{Deserialize, Serialize};

use crate::{
    error::DiscoverySnafu, EffectFamilyV1, EffectSimulationV1, PolicyCompiler, PolicyDocumentV1,
    PolicySimulator, Result, StaticDecisionKeyV1,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryStaticPreviewV1 {
    pub snapshot: BehaviorSnapshotV1,
    pub source_policy_digest: String,
    pub simulations: Vec<EffectSimulationV1>,
}

pub struct DiscoveryPreviewOwner;

impl DiscoveryPreviewOwner {
    pub fn simulate_recorded(
        input: &DiscoveryInputManifestV1,
        candidate: &PolicyDocumentV1,
    ) -> Result<DiscoveryStaticPreviewV1> {
        let derived = DiscoveryOwner::derive_recorded(input)?;
        let compiled = PolicyCompiler.compile(candidate)?;
        let keys: BTreeSet<_> = derived
            .snapshot
            .atoms
            .iter()
            .map(|atom| &atom.key.static_key)
            .collect();
        let simulator = PolicySimulator::new(&compiled);
        let simulations = keys
            .into_iter()
            .map(|key| {
                let key = StaticDecisionKeyV1::try_from(key)?;
                if !matches!(
                    key.effect_family,
                    EffectFamilyV1::File | EffectFamilyV1::Exec
                ) {
                    return DiscoverySnafu {
                        code: "STATIC_FAMILY_UNSUPPORTED",
                        reason: "static preview supports exact file and execution keys",
                    }
                    .fail();
                }
                if compiled
                    .compiled_cells
                    .iter()
                    .any(|cell| cell.key == key && cell.consuming_exception_id.is_some())
                {
                    return DiscoverySnafu {
                        code: "DYNAMIC_EXCEPTION_UNSUPPORTED",
                        reason: "static preview cannot prove runtime exception authority",
                    }
                    .fail();
                }
                Ok(simulator.simulate(key, None))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(DiscoveryStaticPreviewV1 {
            snapshot: derived.snapshot,
            source_policy_digest: compiled.source_policy_digest,
            simulations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SimulatedDispositionV1, SimulatedPhysicalResultV1};
    use erebor_interceptor_abi::KernelEffectFamilyV1;

    type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn input() -> TestResult<DiscoveryInputManifestV1> {
        DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )
        .map_err(Into::into)
    }

    #[test]
    fn discovery_preview_native_compiler() -> TestResult<()> {
        let policy = PolicyDocumentV1::parse(
            std::path::Path::new("policy-v1.yaml"),
            include_bytes!("../../tests/fixtures/policy-v1.yaml"),
        )?;
        let preview = DiscoveryPreviewOwner::simulate_recorded(&input()?, &policy)?;
        assert_eq!(preview.simulations.len(), 1);
        assert_eq!(preview.snapshot.unresolved_records, 1);
        assert_eq!(
            preview.simulations[0].disposition,
            SimulatedDispositionV1::WouldDeny
        );
        assert_eq!(
            preview.simulations[0].physical_result,
            SimulatedPhysicalResultV1::NotAttempted
        );
        Ok(())
    }

    #[test]
    fn discovery_preview_family_rejection() -> TestResult<()> {
        let policy = PolicyDocumentV1::parse(
            std::path::Path::new("policy-v1.yaml"),
            include_bytes!("../../tests/fixtures/policy-v1.yaml"),
        )?;
        let mut input = input()?;
        let operation = crate::CompiledOperationV1::try_from("CONNECT")?;
        for context in &mut input.contexts {
            context.static_key.effect_family = KernelEffectFamilyV1::Network as u16;
            context.static_key.operation_id = "CONNECT".into();
            context.static_key.operation = operation.kernel_id as u16;
        }
        for record in &mut input.records {
            let mut wire = record.decode()?;
            wire.effect_family = KernelEffectFamilyV1::Network as u32;
            wire.operation = operation.kernel_id as u32;
            record.wire_record = Vec::<u8>::try_from(&wire)?;
        }
        assert!(matches!(
            DiscoveryPreviewOwner::simulate_recorded(&input, &policy),
            Err(crate::Error::Discovery {
                code: "STATIC_FAMILY_UNSUPPORTED",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn discovery_preview_native_lowering() -> TestResult<()> {
        let mut spec = crate::WorkloadProtectionPolicySpec::parse(
            std::path::Path::new("kubernetes-entry-roles-v1.yaml"),
            include_bytes!("../../tests/fixtures/kubernetes-entry-roles-v1.yaml"),
        )?;
        spec.roles[0].files[0].recursive = false;
        let mut resource = crate::policy_custom_resource("worker", "tenant-a", spec)?;
        resource.metadata.uid = Some("30000000-0000-4000-8000-000000000001".into());
        resource.metadata.generation = Some(1);
        let policy = crate::lower_kubernetes_policy(
            &resource,
            "10000000-0000-4000-8000-000000000001",
            "10000000-0000-4000-8000-000000000002",
            "10000000-0000-4000-8000-000000000003",
        )?;
        let compiled = PolicyCompiler.compile(&policy)?;
        let key = compiled
            .compiled_cells
            .iter()
            .find(|cell| {
                cell.key.effect_family == EffectFamilyV1::File
                    && cell.key.operation_id == "OPEN_READ"
                    && cell.key.entry_kind == crate::EntryKindV1::ContainerStart
            })
            .ok_or("lowered exact file key is absent")?;
        assert!(key.key.object_selector.starts_with("PATH:"));
        let mut input = input()?;
        for context in &mut input.contexts {
            context.static_key = araphor_data::DiscoveryPolicyKeyV1::try_from(&key.key)?;
        }
        let preview = DiscoveryPreviewOwner::simulate_recorded(&input, &policy)?;
        assert_eq!(preview.source_policy_digest, compiled.source_policy_digest);
        assert_eq!(preview.simulations.len(), 1);
        assert_eq!(
            preview.simulations[0].disposition,
            SimulatedDispositionV1::Deny
        );
        assert_eq!(
            preview.simulations[0].physical_result,
            SimulatedPhysicalResultV1::NotAttempted
        );
        Ok(())
    }
}
