use super::*;

impl SourceRecord {
    pub(in crate::analysis::native) const PREFIX: &'static [u8] = b"\0data/@source/header/";
    pub(super) const HEAD: &'static [u8] = b"\0data/@source/head/";
    pub(super) const MEMBER: &'static [u8] = b"\0data/@source/member/";
    pub(super) const FACT: &'static [u8] = b"\0data/@source/fact/";
    pub(super) const PROOF: &'static [u8] = b"\0data/@source/proof/";
    pub(super) const WINDOW: &'static [u8] = b"\0data/@source/window/";
    pub(in crate::analysis::native) const WINNER: &'static [u8] = b"\0data/@source/winner/";

    pub(in crate::analysis::native) fn winner_prefix(tenant: [u8; 16]) -> Vec<u8> {
        [Self::WINNER, tenant.as_slice()].concat()
    }

    pub(super) fn winner_key(tenant: [u8; 16], owner: u64, source: u64, first: u64) -> Vec<u8> {
        Self::key(&Self::winner_prefix(tenant), &[source, owner, first])
    }

    pub(in crate::analysis::native) fn key(prefix: &[u8], parts: &[u64]) -> Vec<u8> {
        prefix
            .iter()
            .copied()
            .chain(parts.iter().flat_map(|part| part.to_be_bytes()))
            .collect()
    }

    pub(super) fn identity(source: &EvidenceIntakeIdentityV1) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(b"source-publication".as_slice(), source))
            .context(crate::ManagedEncodingSnafu)
    }

    pub(super) fn member_key(prefix: &[u8], record: &DiscoveryRecordIdV1) -> Vec<u8> {
        [
            prefix,
            &record.cpu_id.to_be_bytes(),
            &record.durable_cursor.to_be_bytes(),
        ]
        .concat()
    }

    pub(super) fn header(
        id: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Self> {
        let bytes = Records::charged_payload(&Self::key(Self::PREFIX, &[id]), get, charge)?
            .ok_or_else(|| Code::Missing.error("source publication header"))?;
        Records::decode(&bytes)
    }

    pub(in crate::analysis::native) fn publication(
        id: u64,
        head: u64,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<(Self, StoredResult)> {
        let header = Self::header(id, &mut get, charge)?;
        let bytes = Records::charged_payload(&Records::key(b'X', id), get, charge)?
            .ok_or_else(|| Code::Missing.error("source publication result"))?;
        let result: StoredResult = Records::decode(&bytes)?;
        header.check_ranges()?;
        if result.revision == 0
            || result.revision > head
            || header.captured.commit_revision == 0
            || header.captured.commit_revision >= result.revision
            || !matches!(&result.body, ResultBody::Selected(step) if step.source.is_some())
        {
            return Err(Code::Invalid.error("source publication header"));
        }
        Ok((header, result))
    }

    pub(super) fn check_ranges(&self) -> Result<()> {
        if self
            .gaps
            .iter()
            .any(|(first, last)| *first == 0 || last < first)
            || self.gaps.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Code::Invalid.error("source publication gaps"));
        }
        Ok(())
    }

    pub(in crate::analysis::native) fn summary(
        &self,
        result: &StoredResult,
    ) -> Result<SourcePublication> {
        let ResultBody::Selected(step) = &result.body else {
            return Err(Code::Invalid.error("source publication kind"));
        };
        let source = step
            .source
            .as_ref()
            .ok_or_else(|| Code::Missing.error("source publication step"))?;
        Ok(SourcePublication {
            reference: PackageResultRefV1 {
                result_id: result.id.clone(),
                commit_revision: result.revision,
            },
            captured: self.captured,
            first: source.first,
            last: source.last,
            deadline: source.deadline,
            count: self.count,
            restricted: self.restricted,
        })
    }

    pub(super) fn head(
        tenant: [u8; 16],
        instance: &str,
        source: &EvidenceIntakeIdentityV1,
        head: u64,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<SourcePublication>> {
        let Some(owner) = Records::find(&InstanceRecord::identity(tenant, instance)?, &mut get)?
        else {
            return Ok(None);
        };
        let Some(source) = Records::find(&Self::identity(source)?, &mut get)? else {
            return Ok(None);
        };
        let Some(value) = get(&Self::key(Self::HEAD, &[owner, source]))? else {
            return Ok(None);
        };
        let (header, result) = Self::publication(NativeStore::number(&value)?, head, get, charge)?;
        if result.tenant != tenant || result.owner().0 != instance {
            return Err(Code::Invalid.error("source publication owner"));
        }
        header.summary(&result).map(Some)
    }
}

impl SourceRecord {
    pub(super) fn postings(
        selected: u64,
        step: &Step,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>> {
        let source = step
            .source
            .as_ref()
            .ok_or_else(|| Code::Missing.error("source posting step"))?;
        charge(source.records.len().saturating_mul(8 * size_of::<usize>()))?;
        let records = source
            .records
            .iter()
            .map(|(record, _)| record)
            .collect::<BTreeSet<_>>();
        let mut postings = std::collections::BTreeMap::new();
        for reference in crate::AnalysisContextRefV1::join(&step.contexts, &step.derived)? {
            let id = ContextRecord::id(&reference.key, &mut get)?
                .ok_or_else(|| Code::Missing.error("source posting context"))?;
            let bytes = Records::charged_payload(&Records::key(b'C', id), &mut get, charge)?
                .ok_or_else(|| Code::Missing.error("source posting context"))?;
            let row: ContextRecord = Records::decode(&bytes)?;
            ContextRecord::check(&row, &reference.key)?;
            if row.revision != reference.commit_revision {
                return Err(Code::Conflict.error("source posting revision"));
            }
            let fact = DataView::fact_record(id, &row.version, &mut get, charge)?;
            if fact.is_some() {
                let fact = crate::GraphFactV1::try_from(&row.version)?;
                if records.contains(&fact.record_id) {
                    charge(256)?;
                    let prefix = SourceRecord::member_key(
                        &SourceRecord::key(SourceRecord::FACT, &[selected]),
                        &fact.record_id,
                    );
                    postings.insert(
                        SourceRecord::key(&prefix, &[id]),
                        reference.commit_revision.to_be_bytes().to_vec(),
                    );
                }
            }
        }
        for (record, reference) in &step.proofs {
            if !records.contains(record) {
                continue;
            }
            charge(256)?;
            let id = ContextRecord::id(&reference.key, &mut get)?
                .ok_or_else(|| Code::Missing.error("source posting proof"))?;
            let prefix = SourceRecord::member_key(
                &SourceRecord::key(SourceRecord::PROOF, &[selected]),
                record,
            );
            postings.insert(
                SourceRecord::key(&prefix, &[id]),
                reference.commit_revision.to_be_bytes().to_vec(),
            );
        }
        Ok(postings)
    }
}
