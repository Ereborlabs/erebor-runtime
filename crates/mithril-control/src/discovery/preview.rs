use std::collections::BTreeSet;

use araphor_analysis::DiscoveryOwner;
use araphor_data::{BehaviorSnapshotV1, DiscoveryInputManifestV1};
use araphor_query::definition::{CallResult, PackageCall};
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

impl DiscoveryStaticPreviewV1 {
    pub fn recorded(
        input: &DiscoveryInputManifestV1,
        candidate: &PolicyDocumentV1,
        call: &PackageCall,
        result: &CallResult,
    ) -> Result<DiscoveryStaticPreviewV1> {
        let derived = DiscoveryOwner::recorded_result(input, call, result)?;
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
mod tests;
