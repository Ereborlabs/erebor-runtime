use super::{DataView, Records};
use crate :: { analysis :: context :: FactRecord , AnalysisContextVersionV1 , PackageErrorCodeV1 as Code , Result } ;

impl DataView {
    pub(super) fn check_fact(
        id: u64,
        input: &AnalysisContextVersionV1,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<()> {
        Self::fact_record(id, input, get, &mut |_| Ok(())).map(|_| ())
    }

    pub(in crate::analysis::native) fn fact_record(
        id: u64,
        input: &AnalysisContextVersionV1,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<FactRecord>> {
        let saved = Records::charged_payload(&Records::key(b'K', id), get, charge)?
            .map(|bytes| Records::decode::<FactRecord>(&bytes))
            .transpose()?;
        charge(input.body.len().saturating_mul(8))?;
        let expected = FactRecord::from_context(input)?;
        if saved != expected {
            return Err(Code::Invalid.error("canonical fact index"));
        }
        Ok(expected)
    }
}

impl DataView {
    pub(in crate::analysis::native) fn canonical_fact(
        &self,
        value: &AnalysisContextVersionV1,
        reference: &crate::AnalysisContextRefV1,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<crate::GraphFactV1>> {
        let (saved, revision) = self
            .context_charged(&reference.key, charge)?
            .ok_or_else(|| Code::Denied.error("canonical Graph context authority"))?;
        if revision != reference.commit_revision || saved != *value {
            return Err(Code::Denied.error("canonical Graph context authority"));
        }
        self.verify_context(&saved)?;
        let id =
            super::ContextRecord::id(&reference.key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| Code::Invalid.error("canonical Graph context identity"))?;
        Self::check_fact(id, value, |key| Records::read(key, &self.snapshot))?;
        if FactRecord::from_context(value)?.is_none() {
            return Ok(None);
        }
        charge(
            value
                .body
                .len()
                .saturating_mul(8)
                .saturating_add(4 * size_of::<crate::GraphFactV1>()),
        )?;
        crate::GraphFactV1::try_from(value).map(Some)
    }
}

impl DataView {
    pub(in crate::analysis::native) fn inspect_facts(
        &self,
        facts: &[crate::analysis::context::PreparedFact],
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<std::collections::BTreeMap<crate::AnalysisContextKeyV1, crate::AnalysisContextRefV1>>
    {
        let mut references = std::collections::BTreeMap::new();
        for fact in facts {
            let value = fact.value();
            self.verify_context(value)?;
            let saved = self.context_charged(&value.key, charge)?;
            let id =
                super::ContextRecord::id(&value.key, |key| Records::read(key, &self.snapshot))?;
            let Some((stored, revision)) = saved else {
                if let Some(id) = id {
                    if Records::read(&Records::key(b'K', id), &self.snapshot)?.is_some() {
                        return Err(Code::Invalid.error("canonical fact index"));
                    }
                }
                continue;
            };
            if stored != *value {
                return crate::AnalysisConflictSnafu.fail();
            }
            Self::check_fact(
                id.ok_or_else(|| Code::Invalid.error("canonical fact identity"))?,
                value,
                |key| Records::read(key, &self.snapshot),
            )?;
            references.insert(
                value.key.clone(),
                crate::AnalysisContextRefV1 {
                    key: value.key.clone(),
                    commit_revision: revision,
                },
            );
        }
        Ok(references)
    }
}
