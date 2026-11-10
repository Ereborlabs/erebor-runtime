use serde::{Deserialize, Serialize};

use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageReportRef {
    pub source: EvidenceIntakeIdentityV1,
    pub revision: u64,
    pub position: StorePositionV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageRecord {
    pub reference: CoverageReportRef,
    pub encoded_report: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageChanges {
    pub meta: AnalysisStoreMetaV1,
    pub reports: Vec<CoverageRecord>,
}

impl CoverageReportRef {
    fn valid(&self) -> bool {
        self.source.valid()
            && self.revision != 0
            && self.position.commit_revision != 0
            && self.position.ordinal == 0
    }
}



#[cfg(test)]
mod tests;
