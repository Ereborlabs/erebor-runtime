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
        let mut records = BTreeMap::new();
        for record in &input.records {
            if records
                .insert(record.id.clone(), record.clone())
                .is_some_and(|previous| previous != *record)
            {
                return GraphInvalidSnafu {
                    field: "conflicting observation",
                }
                .fail();
            }
        }
        let mut facts = BTreeMap::new();
        for fact in &input.facts {
            if fact.key.owner_id == "graph-packages-v1" {
                continue;
            }
            if facts
                .insert(fact.key.clone(), fact.clone())
                .is_some_and(|previous| previous != *fact)
            {
                return GraphInvalidSnafu {
                    field: "conflicting context version",
                }
                .fail();
            }
        }
        let mut coverage = input.coverage.clone();
        coverage.sort();
        coverage.dedup();
        let mut coverage_keys = input.coverage_keys.clone();
        coverage_keys.sort();
        coverage_keys.dedup();
        let mut gaps = input.missing_ranges.clone();
        gaps.sort();
        gaps.dedup();
        let input = GraphReplayInputV1 {
            source: input.source.clone(),
            records: records.into_values().collect(),
            coverage,
            coverage_keys,
            facts: facts.into_values().collect(),
            missing_ranges: gaps,
        };
        let mut owner = GraphDerivation::new(&input)?;
        let mut packages = execution.descriptors(input.source.tenant_id)?;
        if FindingV1::PACKAGES.iter().any(|id| {
            !packages.iter().any(|package| {
                package.id == *id && package.exports.iter().any(Self::supports_analysis)
            })
        }) {
            return GraphInvalidSnafu {
                field: "required installed graph package",
            }
            .fail();
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
        for package in packages {
            let models = package
                .exports
                .iter()
                .filter(|model| Self::supports_analysis(model))
                .collect::<Vec<_>>();
            if models.len() > 1 {
                return GraphInvalidSnafu {
                    field: "multiple graph exports",
                }
                .fail();
            }
            if let Some(model) = models.first() {
                let evaluation = owner.evaluation_for(model)?;
                owner.evaluate(&execution, &package, &evaluation)?;
            }
        }
        owner.finish()
    }
}

impl<'a> GraphDerivation<'a> {
    fn new(input: &'a GraphReplayInputV1) -> Result<Self> {
        input.validate()?;
        let revision = GraphRevisionV1 {
            evidence: input
                .records
                .iter()
                .map(|record| record.id.clone())
                .collect(),
            coverage: input.coverage_keys.clone(),
            context: input.facts.iter().map(|fact| fact.key.clone()).collect(),
            missing_ranges: input.missing_ranges.clone(),
        };
        let facts = input
            .facts
            .iter()
            .map(GraphFactV1::try_from)
            .collect::<Result<Vec<_>>>()?;
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
