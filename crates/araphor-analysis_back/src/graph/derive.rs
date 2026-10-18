use std::collections::{BTreeMap, BTreeSet};

use erebor_interceptor_abi::{
    EffectPhysicalResultV1, KernelEffectFamilyV1, KernelEffectOperationV1,
};
use snafu::ResultExt as _;

use super::*;
use crate::{
    ContextSensitivityV1, DiscoveryCoverageStateV1, DiscoveryRecordIdV1, DiscoveryRecordV1,
    EvidenceRecord, GraphEncodingSnafu, GraphInvalidSnafu, ProcessorScopeV1, Result,
};

struct GraphDerivation<'a> {
    input: &'a GraphReplayInputV1,
    revision: GraphRevisionV1,
    subjects: BTreeSet<GraphSubjectKeyV1>,
    edges: BTreeMap<GraphEdgeKeyV1, GraphEdgeV1>,
    branches: Vec<GraphBranchV1>,
    findings: BTreeMap<String, FindingV1>,
    facts: Vec<GraphFactV1>,
    packages: Vec<(araphor_analysis_sdk::Package, GraphPackageStateV1)>,
    output_bytes: usize,
}

impl GraphAndFindingOwner {
    pub fn derive(
        input: &GraphReplayInputV1,
        execution: &crate::InstalledAnalysis,
    ) -> Result<GraphSnapshotV1> {
        let execution = execution.snapshot(input.source.tenant_id)?;
        let input = input.normalized()?;
        let snapshot = Self::derive_candidate(&input, &execution)?;
        finish::WindowBytes::check(&snapshot)?;
        Ok(snapshot)
    }

    pub(super) fn derive_candidate(
        input: &GraphReplayInputV1,
        execution: &crate::InstalledAnalysis,
    ) -> Result<GraphSnapshotV1> {
        let mut owner = GraphDerivation::new(input)?;
        let mut packages = execution.descriptors(input.source.tenant_id)?;
        if FindingV1::PACKAGES.iter().any(|id| {
            !packages.iter().any(|package| {
                package.id == *id
                    && execution
                        .prepared_models(package)
                        .any(Self::supports_analysis)
            })
        }) {
            return GraphInvalidSnafu {
                field: "required installed graph package",
            }
            .fail()
            .map_err(Into::into);
        }
        packages.sort_by_key(|package| {
            (
                FindingV1::PACKAGES
                    .iter()
                    .position(|id| *id == package.id)
                    .unwrap_or(3),
                package.id.clone(),
            )
        });
        let mut evaluation = None;
        for package in packages {
            let models = execution
                .prepared_models(&package)
                .filter(|model| Self::supports_analysis(model))
                .collect::<Vec<_>>();
            if models.len() > 1 {
                return GraphInvalidSnafu {
                    field: "multiple graph exports",
                }
                .fail()
                .map_err(Into::into);
            }
            if let Some(model) = models.first() {
                if evaluation.is_none() {
                    evaluation = Some(owner.evaluation_for(model)?);
                }
                if let Some(evaluation) = &mut evaluation {
                    evaluation.export.clone_from(&model.name);
                    evaluation.context.limits = model.limits;
                    owner.evaluate(execution, &package, evaluation)?;
                }
            }
        }
        owner.finish()
    }
}

impl<'a> GraphDerivation<'a> {
    fn new(input: &'a GraphReplayInputV1) -> Result<Self> {
        input.validate()?;
        let revision = input.manifest();
        let facts = input
            .facts
            .iter()
            .map(GraphFactV1::try_from)
            .collect::<araphor_data::Result<Vec<_>>>()?;
        Ok(Self {
            input,
            revision,
            subjects: BTreeSet::new(),
            edges: BTreeMap::new(),
            branches: Vec::new(),
            findings: BTreeMap::new(),
            facts,
            packages: Vec::new(),
            output_bytes: 0,
        })
    }
}

mod adapter;
mod finding;
mod finish;
mod identity;
mod policy;
mod proof;
