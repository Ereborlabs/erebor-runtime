use super::*;
use crate::analysis::managed::PreparedMemory;

#[derive(Deserialize, PartialEq, Serialize)]
pub(super) struct Notice {
    pub scope: ProcessorScopeV1,
    pub result: PackageResultRefV1,
    pub revision: u64,
    pub facts: u64,
    pub coverage: u64,
}

impl Notice {
    pub(super) const PREFIX: &'static [u8] = b"\0data/@progress/notice/";

    pub(super) fn read(
        id: u64,
        head: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<Self>> {
        Records::charged_payload(&Processor::key(Self::PREFIX, id), get, charge)?
            .map(|bytes| {
                let row: Self = Records::decode(&bytes)?;
                if row.revision == 0
                    || row.revision > head
                    || row.result.commit_revision >= row.revision
                    || !row.scope.valid()
                {
                    return Err(Code::Invalid.error("profile notice"));
                }
                Ok(row)
            })
            .transpose()
    }
}

impl DataWrite<'_> {
    pub(super) fn stage_profile_notice(
        &mut self,
        scope: &ProcessorScopeV1,
        reference: &PackageResultRefV1,
        facts: u64,
        coverage: u64,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<bool> {
        let (id, result) = ResultRecord::read_header(
            &reference.result_id,
            self.revision,
            |key| Records::staged(key, &self.transaction),
            &mut |bytes| memory.charge(bytes),
        )?
        .ok_or_else(|| crate::AnalysisConflictSnafu.build())?;
        if result.request.scope != *scope
            || result.revision != reference.commit_revision
            || scope.processor_id != crate::DISCOVERY_PROCESSOR
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        let prior = Notice::read(
            id,
            self.revision,
            |key| Records::staged(key, &self.transaction),
            &mut |bytes| memory.charge(bytes),
        )?;
        let current = match prior {
            Some(prior) if prior.scope == *scope && prior.result == *reference => {
                (prior.facts, prior.coverage)
            }
            Some(_) => return Err(Code::Invalid.error("profile notice owner")),
            None => (
                result
                    .header
                    .facts_revision
                    .ok_or_else(|| Code::Invalid.error("profile notice facts"))?,
                result
                    .header
                    .coverage_revision
                    .ok_or_else(|| Code::Invalid.error("profile notice coverage"))?,
            ),
        };
        let next = (current.0.max(facts), current.1.max(coverage));
        if current == next {
            return Ok(false);
        }
        let notice = Notice {
            scope: scope.clone(),
            result: reference.clone(),
            revision: self.revision,
            facts: next.0,
            coverage: next.1,
        };
        Records::stage(
            &mut self.transaction,
            Processor::key(Notice::PREFIX, id),
            Records::named(&notice)?,
        );
        self.note_relation("result_notices", self.revision)?;
        self.note_relation("analysis_results", self.revision)?;
        Ok(true)
    }
}

impl DataView {
    pub(in crate::analysis::native) fn profile_notice(
        &self,
        id: u64,
        result: &ResultRecord,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<(u64, u64)> {
        let notice = Notice::read(
            id,
            self.metadata_revision,
            |key| Records::read(key, &self.snapshot),
            charge,
        )?;
        if let Some(notice) = notice {
            if notice.scope != result.request.scope
                || notice.result.result_id != result.request.result_id
                || notice.result.commit_revision != result.revision
            {
                return Err(Code::Invalid.error("profile notice owner"));
            }
            Ok((notice.facts, notice.coverage))
        } else {
            Ok((
                result.header.facts_revision.unwrap_or(0),
                result.header.coverage_revision.unwrap_or(0),
            ))
        }
    }
}
