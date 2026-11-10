use serde::{Deserialize, Serialize};



use super::AnalysisContextVersionV1;
use crate :: { GraphValidate as _ , PackageErrorCodeV1 as Code , Result } ;

#[derive(Deserialize, Eq, PartialEq, Serialize)]
pub(in crate::analysis) struct FactRecord {
    pub(in crate::analysis) record: Vec<u8>,
    pub(in crate::analysis) stream: Vec<u8>,
    pub(in crate::analysis) cursor: u64,
}

impl FactRecord {
    pub(in crate::analysis) fn from_context(
        input: &AnalysisContextVersionV1,
    ) -> Result<Option<FactRecord>> {
        let Ok(fact) = crate::GraphFactV1::decode_context(&input.body) else {
            return Ok(None);
        };
        fact.validate()?;
        if fact.record_id.stream.tenant_id != input.key.tenant_id {
            return Err(Code::Invalid.error("canonical fact tenant"));
        }
        araphor_analysis_types::DomainRelations::key(&fact.record_id)
            .map(|record| {
                Some(FactRecord {
                    record,
                    stream: fact.record_id.stream.key(),
                    cursor: fact.record_id.durable_cursor,
                })
            })
            .map_err(|source| crate::Error::AnalysisContract {
                source,
                location: snafu::location!(),
            })
    }
}


