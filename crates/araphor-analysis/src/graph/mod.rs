use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_builtins::{graph as algorithm, Rows};
use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisContractSnafu, ContextSensitivityV1, DeclaredFindingReasonV1, DiscoveryCoverageStateV1,
    DiscoveryRecordIdV1, DiscoveryRecordV1, FindingReasonV1, FindingStateV1, FindingV1,
    GraphBranchStateV1, GraphBranchV1, GraphCauseV1, GraphEdgeKeyV1, GraphEdgeTypeV1, GraphEdgeV1,
    GraphEffectV1, GraphEncodingSnafu, GraphFactV1, GraphFactValueV1, GraphInvalidSnafu,
    GraphPackageCheckpointV1, GraphPackageStateV1, GraphPhysicalResultV1, GraphReplayInputV1,
    GraphRevisionV1, GraphSnapshotV1, GraphSubjectAuthorityV1, GraphSubjectKeyV1,
    GraphSubjectKindV1, GraphValidate, GraphVersionV1, LocalSubjectBindingV1,
    OperationResultAuthorityV1, PolicyObservationProvenanceV1, PolicyProvenanceStateV1,
    ProcessorScopeV1, ProofIntegrityV1, ProofQualityV1, Result, TemporalCoverageV1,
    GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION, GRAPH_WINDOW_NS,
};
#[cfg(test)]
use araphor_data::{EvidenceRecord, GRAPH_WITNESS_TTL_NS};
use araphor_query::definition::{CallResult, PackageCall};
use erebor_interceptor_abi::{EffectPhysicalResultV1, KernelEffectFamilyV1};
use snafu::ResultExt as _;

mod assembly;
mod authority;
mod expiry;
mod feed;
mod input;
mod resolved;
pub use feed::{GraphOwner, GraphProgram};
mod native;
pub(crate) use native::GraphConversion;
pub use native::{GraphFacts, GraphPublication};

#[cfg(test)]
mod tests;

pub struct Graph<'a> {
    input: Cow<'a, GraphReplayInputV1>,
    projection: std::cell::OnceCell<[sdk::Dataset; 3]>,
    observations: Vec<algorithm::Observation>,
    revision: GraphRevisionV1,
    subjects: BTreeMap<GraphSubjectKeyV1, u32>,
    edges: BTreeMap<GraphEdgeKeyV1, GraphEdgeV1>,
    branches: Vec<GraphBranchV1>,
    findings: BTreeMap<String, FindingV1>,
    facts: Vec<GraphFactV1>,
    packages: Vec<GraphPackageCheckpointV1>,
    _memory: Option<datafusion::execution::memory_pool::MemoryReservation>,
}

impl<'a> Graph<'a> {
    pub fn new(input: &'a GraphReplayInputV1) -> Result<Self> {
        Self::from_input(Cow::Borrowed(input))
    }

    fn from_input(input: Cow<'a, GraphReplayInputV1>) -> Result<Self> {
        input.validate()?;
        let revision = input.manifest();
        revision.validate(input.source.tenant_id)?;
        let facts = input
            .facts
            .iter()
            .map(GraphFactV1::try_from)
            .collect::<Result<Vec<_>>>()?;
        let mut graph = Self {
            input,
            projection: std::cell::OnceCell::new(),
            observations: Vec::new(),
            revision,
            subjects: BTreeMap::new(),
            edges: BTreeMap::new(),
            branches: Vec::new(),
            findings: BTreeMap::new(),
            facts,
            packages: Vec::new(),
            _memory: None,
        };
        graph.observations = graph
            .input
            .records
            .iter()
            .map(|record| graph.qualify_record(record))
            .collect::<Result<Vec<_>>>()?;
        Ok(graph)
    }

    pub fn supports(model: &sdk::Model) -> bool {
        let expected = algorithm::Detector::Process.descriptor();
        let expected = &expected.exports[0];
        model
            .inputs
            .iter()
            .map(|input| &input.port)
            .eq(expected.inputs.iter().map(|input| &input.port))
            && model.outputs == expected.outputs
            && model.checkpoint == expected.checkpoint
    }

    pub fn apply(mut self, call: &PackageCall, result: &CallResult) -> Result<Self> {
        let package = call.descriptor();
        let evaluation = result.evaluation();
        if !result.belongs_to(call)
            || call.tenant() != self.input.source.tenant_id
            || call.package().package_id != package.id
            || call.package().revision != package.revision
            || call.export() != evaluation.export
            || self
                .packages
                .iter()
                .any(|previous| previous.package_id == package.id)
        {
            return GraphInvalidSnafu {
                field: "graph package call",
            }
            .fail();
        }
        let model = package
            .exports
            .iter()
            .find(|model| model.name == call.export())
            .filter(|model| Self::supports(model))
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph export contract",
                }
                .build()
            })?;
        self.check_inputs(model, evaluation)?;
        self.apply_output(package, evaluation, result.output())?;
        Ok(self)
    }
}

impl TryFrom<GraphReplayInputV1> for Graph<'static> {
    type Error = araphor_data::Error;

    fn try_from(input: GraphReplayInputV1) -> Result<Self> {
        Self::from_input(Cow::Owned(input))
    }
}
