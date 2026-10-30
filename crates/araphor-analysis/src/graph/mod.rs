use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_builtins::graph as algorithm;
use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisContractSnafu, ContextSensitivityV1, DiscoveryCoverageStateV1, DiscoveryRecordIdV1,
    DiscoveryRecordV1, FindingReasonV1, FindingStateV1, FindingV1, GraphBranchStateV1,
    GraphCauseV1, GraphEdgeKeyV1, GraphEdgeTypeV1, GraphEdgeV1, GraphEffectV1, GraphFactV1,
    GraphFactValueV1, GraphInvalidSnafu, GraphPackageCheckpointV1, GraphPackageStateV1,
    GraphPhysicalResultV1, GraphReplayInputV1, GraphRevisionV1, GraphSnapshotV1,
    GraphSubjectAuthorityV1, GraphSubjectKeyV1, GraphSubjectKindV1, GraphValidate, GraphVersionV1,
    LocalSubjectBindingV1, OperationResultAuthorityV1, PolicyObservationProvenanceV1,
    PolicyProvenanceStateV1, ProcessorScopeV1, ProofIntegrityV1, ProofQualityV1, Result,
    TemporalCoverageV1, GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION, GRAPH_WINDOW_NS,
};
#[cfg(test)]
use araphor_data::{EvidenceRecord, GRAPH_WITNESS_TTL_NS};
use araphor_query::definition::{CallResult, PackageCall};
use erebor_interceptor_abi::{EffectPhysicalResultV1, KernelEffectFamilyV1};
use snafu::ResultExt as _;

mod authority;
mod builder;
mod changes;
mod feed;
mod input;
mod native;

pub use builder::Graph;
pub use feed::{GraphOwner, GraphProgram};
pub(crate) use native::GraphConversion;
pub use native::{GraphFacts, GraphPublication};

#[cfg(test)]
mod tests;
