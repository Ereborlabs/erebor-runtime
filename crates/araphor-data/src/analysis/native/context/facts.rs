use super::{DataView, Records};
use crate::{
    analysis::context::FactRecord, AnalysisContextVersionV1, PackageErrorCodeV1 as Code, Result,
};

impl DataView {
    pub(super) fn check_fact(
        id: u64,
        input: &AnalysisContextVersionV1,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<()> {
        let saved = Records::payload(&Records::key(b'K', id), get)?
            .map(|bytes| Records::decode::<FactRecord>(&bytes))
            .transpose()?;
        if saved != FactRecord::from_context(input)? {
            return Err(Code::Invalid.error("canonical fact index"));
        }
        Ok(())
    }
}
