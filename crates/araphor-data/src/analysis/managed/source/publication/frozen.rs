use crate::{AnalysisContextRefV1, AnalysisContextVersionV1, DiscoveryRecordIdV1};

type FrozenSource = (
    crate::analysis::graph::GraphSourceSummary,
    Vec<(AnalysisContextVersionV1, AnalysisContextRefV1)>,
    Vec<(DiscoveryRecordIdV1, AnalysisContextRefV1)>,
);


