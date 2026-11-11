use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;

use super::super::{ManagedCall, ManagedSpec};
use crate::{PackageErrorCodeV1 as Code, Result};

pub(in crate::analysis) struct GraphDeclarations {
    pub(in crate::analysis) relations: BTreeMap<String, sdk::GraphRelation>,
    pub(in crate::analysis) calls: Vec<u64>,
}

impl ManagedSpec {
    pub(in crate::analysis) fn graph_declarations(
        &self,
        mut contract: impl FnMut(u64, &ManagedCall) -> Result<sdk::Package>,
    ) -> Result<GraphDeclarations> {
        let mut declarations = GraphDeclarations {
            relations: BTreeMap::new(),
            calls: Vec::new(),
        };
        for (id, call) in &self.manifest.calls {
            let package = contract(*id, call)?;
            let model = package
                .exports
                .iter()
                .find(|model| model.name == call.export)
                .ok_or_else(|| Code::Invalid.error("Graph admitted export"))?;
            let Some(graph) = &model.graph else {
                continue;
            };
            for relation in &graph.relations {
                if declarations
                    .relations
                    .insert(relation.name.clone(), relation.clone())
                    .is_some_and(|prior| prior != *relation)
                {
                    return Err(Code::Invalid.error("Graph relation contract conflict"));
                }
            }
            declarations.calls.push(*id);
        }
        Ok(declarations)
    }
}
