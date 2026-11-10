
use snafu::ResultExt as _;


use crate :: { Result } ;

pub struct RawIndexFixture {
    index: super::raw::RawIndex,
}

impl RawIndexFixture {
    pub fn counts(&self) -> (u64, usize, usize) {
        (
            self.index.revision,
            self.index.entries.size(),
            self.index.ranges.size(),
        )
    }

    pub fn receipt(
        &self,
        identity: &crate::EvidenceIntakeIdentityV1,
    ) -> Option<super::AnalysisSourceReceiptV1> {
        self.index
            .sources
            .get(&identity.key())
            .and_then(|source| source.receipt.evidence())
            .cloned()
    }
}




