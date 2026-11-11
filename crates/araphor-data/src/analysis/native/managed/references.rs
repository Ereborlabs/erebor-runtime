use super::{results::StoredResult, Records};
use crate::analysis::PackageResultRefV1;
use crate::analysis::{
    managed::PreparedMemory,
    native::{context::ContextRecord, DataWrite},
};
use crate::{AnalysisContextRefV1, AnalysisWitnessV1, PackageErrorCodeV1 as Code, Result};
use snafu::ResultExt as _;

mod pins;
mod read;

pub(in crate::analysis::native) use pins::RawPin;

pub(in crate::analysis::native) struct References;

impl References {
    pub(in crate::analysis::native) const RAW: &'static [u8] = b"\0data/ref/raw/";
    pub(in crate::analysis::native) const SEGMENT: &'static [u8] = b"\0data/ref/segment/";
    pub(super) const CONTEXT: &'static [u8] = b"\0data/ref/context/";
    pub(in crate::analysis::native) const CONTEXT_OWNER: &'static [u8] =
        b"\0data/ref/context-owner/";
    pub(super) const DEPENDENCY: &'static [u8] = b"\0data/ref/dependency/";
    pub(super) const ORIGIN: &'static [u8] = b"\0data/ref/origin/";
    pub(super) const IMPORT: &'static [u8] = b"\0data/ref/import/";

    pub(super) fn key(prefix: &[u8], parts: &[u64]) -> Vec<u8> {
        prefix
            .iter()
            .copied()
            .chain(parts.iter().flat_map(|value| value.to_be_bytes()))
            .collect()
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn stage_result_references(
        &mut self,
        tenant: [u8; 16],
        result: u64,
        witnesses: &[AnalysisWitnessV1],
        contexts: &[AnalysisContextRefV1],
        dependencies: &[PackageResultRefV1],
        origins: &[PackageResultRefV1],
        imports: &[AnalysisContextRefV1],
        evidence: (&[AnalysisWitnessV1], &[u64]),
        memory: &mut PreparedMemory<'_>,
    ) -> Result<()> {
        let pins = RawPin::collect(
            result,
            witnesses.iter().map(|witness| {
                let position = evidence
                    .0
                    .binary_search_by(|value| {
                        (&value.identity, value.cursor).cmp(&(&witness.identity, witness.cursor))
                    })
                    .map_err(|_| Code::Invalid.error("managed call witness segment"))?;
                let segment = *evidence
                    .1
                    .get(position)
                    .ok_or_else(|| Code::Invalid.error("managed call witness segment"))?;
                Ok((segment, witness.expires_utc_ns, witness.cursor))
            }),
            &mut |bytes| memory.charge(bytes),
        )?;
        for pin in pins {
            self.transaction.insert(pin.key(), pin.value()?);
            self.transaction
                .insert(pin.reverse(), pin.expires.to_be_bytes());
        }
        let mut imported = 0;
        for reference in contexts {
            memory.check()?;
            let mut temporary = Vec::new();
            let id = ContextRecord::id(&reference.key, |key| {
                Records::staged(key, &self.transaction)
            })?
            .ok_or_else(|| Code::Missing.error("managed result context"))?;
            let bytes = Records::charged_payload(
                &Records::key(b'C', id),
                |key| Records::staged(key, &self.transaction),
                &mut |bytes| {
                    temporary.push(memory.reserve(bytes)?);
                    Ok(())
                },
            )?
            .ok_or_else(|| Code::Missing.error("managed result context"))?;
            let row: ContextRecord = Records::decode(&bytes)?;
            ContextRecord::check(&row, &reference.key)?;
            if row.revision != reference.commit_revision {
                return crate::AnalysisConflictSnafu.fail();
            }
            self.verify_context(&row.version)?;
            memory.charge(256)?;
            self.transaction.insert(
                References::key(References::CONTEXT, &[result, id]),
                row.revision.to_be_bytes(),
            );
            self.transaction.insert(
                References::key(References::CONTEXT_OWNER, &[id, result]),
                row.revision.to_be_bytes(),
            );
            if let Ok(index) = imports.binary_search_by(|value| value.key.cmp(&reference.key)) {
                if imports[index] != *reference {
                    return Err(Code::Invalid.error("managed import context revision"));
                }
                memory.charge(128)?;
                self.transaction.insert(
                    References::key(References::IMPORT, &[result, id]),
                    row.revision.to_be_bytes(),
                );
                imported += 1;
            }
        }
        if imported != imports.len() {
            return Err(Code::Invalid.error("managed import context set"));
        }
        for (prefix, references) in [
            (References::DEPENDENCY, dependencies),
            (References::ORIGIN, origins),
        ] {
            for reference in references {
                memory.check()?;
                let mut temporary = Vec::new();
                let (id, revision) = crate::analysis::native::NativeStore::reference_id(
                    tenant,
                    &reference.result_id,
                    self.revision,
                    |key| Records::staged(key, &self.transaction),
                    &mut |bytes| {
                        temporary.push(memory.reserve(bytes)?);
                        Ok(())
                    },
                )?
                .ok_or_else(|| Code::Missing.error("managed result dependency"))?;
                if revision != reference.commit_revision {
                    return crate::AnalysisConflictSnafu.fail();
                }
                memory.charge(128)?;
                self.transaction.insert(
                    References::key(prefix, &[result, id]),
                    reference.commit_revision.to_be_bytes(),
                );
            }
        }
        Ok(())
    }
}

impl crate::analysis::native::NativeStore {
    fn validate_derived_references(
        &self,
        result_id: u64,
        result: &StoredResult,
        witnesses: &[AnalysisWitnessV1],
        captured: &[AnalysisContextRefV1],
        derived: &[AnalysisContextRefV1],
        origins: &[PackageResultRefV1],
        proofs: &[(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)],
    ) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>> {
        if derived.windows(2).any(|pair| pair[0].key >= pair[1].key) {
            return Err(Code::Invalid.error("derived evidence order"));
        }
        let view = self.view()?;
        let (instance, attempt) = result.owner();
        let attempt = view
            .managed_attempt(
                result.tenant,
                instance,
                attempt,
                &crate::AnalysisReadControl::default(),
            )?
            .ok_or_else(|| Code::Missing.error("managed derived owner"))?;
        let historical = self.source_origins(
            &attempt,
            origins.iter(),
            &crate::AnalysisReadControl::default(),
            &mut |_| Ok(()),
        )?;
        let source = self.read_at(attempt.captured_revision())?;
        crate::analysis::managed::source::SourceEvidence::check_proofs(
            (witnesses, derived, proofs),
            |id| {
                if source.source_receipt(&id.stream)?.is_none_or(|receipt| {
                    receipt.cpu_id != id.cpu_id || receipt.contiguous_cursor < id.durable_cursor
                }) {
                    return Err(Code::Invalid.error("source record proof pin"));
                }
                Ok(())
            },
        )?;
        let prefix = References::key(References::IMPORT, &[result_id]);
        let mut imports = std::collections::BTreeMap::new();
        for entry in view.snapshot.prefix(&prefix) {
            let (key, value) = entry.context(crate::NativeStorageSnafu {
                operation: "read derived import receipts",
            })?;
            if key.len() != prefix.len() + 8 {
                return Err(Code::Invalid.error("derived import key"));
            }
            imports.insert(Self::number(&key[prefix.len()..])?, Self::number(&value)?);
        }
        let mut expected = std::collections::BTreeMap::new();
        for reference in derived {
            if !reference.key.valid()
                || reference.key.tenant_id != result.tenant
                || reference.commit_revision == 0
                || reference.commit_revision > result.revision
            {
                return Err(Code::Invalid.error("derived context bounds"));
            }
            let id = ContextRecord::id(&reference.key, |key| Records::read(key, &view.snapshot))?
                .ok_or_else(|| Code::Missing.error("derived context identity"))?;
            let (value, revision) = view
                .context(&reference.key)?
                .ok_or_else(|| Code::Missing.error("derived context"))?;
            if revision != reference.commit_revision {
                return Err(Code::Conflict.error("derived immutable reference"));
            }
            let fact = view.canonical_fact(&value, reference, &mut |_| Ok(()))?;
            let imported = imports.remove(&id);
            if let Some(revision) = imported {
                if revision != reference.commit_revision {
                    return Err(Code::Invalid.error("derived import revision"));
                }
                expected.insert(
                    References::key(References::IMPORT, &[result_id, id]),
                    revision.to_be_bytes().to_vec(),
                );
            }
            if fact.as_ref().is_some_and(|fact| {
                !witnesses.iter().any(|witness| {
                    witness.identity
                        == crate::AnalysisStreamIdentityV1::Evidence(fact.record_id.stream.clone())
                        && witness.cursor == fact.record_id.durable_cursor
                })
            }) {
                return Err(Code::Denied.error("derived fact source witness"));
            }
            if !captured.contains(reference) && !(fact.is_some() && imported.is_some()) {
                let mut bound = false;
                for source in &historical {
                    if source.contains(id, reference, fact.as_ref(), witnesses)? {
                        bound = true;
                        break;
                    }
                }
                if !bound {
                    return Err(Code::Denied.error("unbound derived parent"));
                }
                let allowed = &attempt.0.capture.grant.selection.contexts;
                if !allowed.is_all() && !allowed.as_slice().contains(&reference.key) {
                    return Err(Code::Denied.error("derived historical context grant"));
                }
            }
        }
        if !imports.is_empty() {
            return Err(Code::Invalid.error("extra derived import pin"));
        }
        Ok(expected)
    }

    fn reference_keys(
        &self,
        view: &crate::analysis::native::DataView,
        id: u64,
        tenant: [u8; 16],
        revision: u64,
        witnesses: &[AnalysisWitnessV1],
        contexts: &[AnalysisContextRefV1],
        dependencies: &[PackageResultRefV1],
        origins: &[PackageResultRefV1],
        expected: &mut std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<()> {
        let segments = self.recover_witnesses(witnesses, revision - 1)?;
        let pins = RawPin::collect(
            id,
            witnesses
                .iter()
                .zip(segments)
                .map(|(witness, segment)| Ok((segment, witness.expires_utc_ns, witness.cursor))),
            &mut |_| Ok(()),
        )?;
        for pin in pins {
            expected.insert(pin.key(), pin.value()?);
            expected.insert(pin.reverse(), pin.expires.to_be_bytes().to_vec());
        }
        for reference in contexts {
            let context =
                ContextRecord::id(&reference.key, |key| Records::read(key, &view.snapshot))?
                    .ok_or_else(|| Code::Missing.error("managed referenced context"))?;
            if view
                .context(&reference.key)?
                .is_none_or(|(_, revision)| revision != reference.commit_revision)
            {
                return Err(Code::Invalid.error("managed context reference revision"));
            }
            expected.insert(
                References::key(References::CONTEXT, &[id, context]),
                reference.commit_revision.to_be_bytes().to_vec(),
            );
            expected.insert(
                References::key(References::CONTEXT_OWNER, &[context, id]),
                reference.commit_revision.to_be_bytes().to_vec(),
            );
        }
        for (prefix, references) in [
            (References::DEPENDENCY, dependencies),
            (References::ORIGIN, origins),
        ] {
            for reference in references {
                let (target, revision) = view
                    .result_reference(tenant, &reference.result_id, &mut |_| Ok(()))?
                    .ok_or_else(|| Code::Missing.error("result dependency"))?;
                if revision != reference.commit_revision {
                    return Err(Code::Invalid.error("managed result reference revision"));
                }
                expected.insert(
                    References::key(prefix, &[id, target]),
                    reference.commit_revision.to_be_bytes().to_vec(),
                );
            }
        }

        Ok(())
    }

    pub(super) fn validate_result_references(&self) -> Result<()> {
        let view = self.view()?;
        let mut expected = std::collections::BTreeMap::new();
        for entry in view.snapshot.prefix(b"\0data/X") {
            let (key, _) = entry.context(crate::NativeStorageSnafu {
                operation: "validate result reference owners",
            })?;
            if key.len() != 15 {
                continue;
            }
            let id = Self::number(&key[7..])?;
            let bytes = Records::payload(&key, |key| Records::read(key, &view.snapshot))?
                .ok_or_else(|| Code::Missing.error("managed reference result"))?;
            let result: StoredResult = Records::decode(&bytes)?;
            let (witnesses, contexts, derived, dependencies, origins, proofs) = match &result.body {
                super::results::ResultBody::Call(record) => (
                    &record.witnesses,
                    &record.contexts,
                    &record.derived,
                    &record.dependencies,
                    &record.origins,
                    &record.proofs,
                ),
                super::results::ResultBody::Selected(step) => (
                    &step.witnesses,
                    &step.contexts,
                    &step.derived,
                    &step.dependencies,
                    &step.origins,
                    &step.proofs,
                ),
            };
            let imports = self.validate_derived_references(
                id, &result, witnesses, contexts, derived, origins, proofs,
            )?;
            expected.extend(imports);
            self.reference_keys(
                &view,
                id,
                result.tenant,
                result.revision,
                witnesses,
                &crate::AnalysisContextRefV1::join(contexts, derived)?,
                dependencies,
                origins,
                &mut expected,
            )?;
        }
        use crate::analysis::native::progress::ResultRecord;
        for entry in view.snapshot.prefix(ResultRecord::PREFIX) {
            let (key, _) = entry.context(crate::NativeStorageSnafu {
                operation: "validate processor reference owners",
            })?;
            if key.len() != ResultRecord::PREFIX.len() + 8 {
                continue;
            }
            let id = Self::number(&key[ResultRecord::PREFIX.len()..])?;
            let bytes = Records::payload(&key, |key| Records::read(key, &view.snapshot))?
                .ok_or_else(|| Code::Missing.error("processor reference owner"))?;
            let result: ResultRecord = Records::decode(&bytes)?;
            self.reference_keys(
                &view,
                id,
                result.request.scope.identity.tenant_id,
                result.revision,
                &result.request.witnesses,
                &result.request.context_refs,
                &[],
                result
                    .producer
                    .as_ref()
                    .map(std::slice::from_ref)
                    .unwrap_or_default(),
                &mut expected,
            )?;
        }
        for entry in view.snapshot.prefix(b"\0data/ref/") {
            let (key, value) = entry.context(crate::NativeStorageSnafu {
                operation: "validate result reference index",
            })?;
            if expected.remove(key.as_ref()).as_deref() != Some(value.as_ref()) {
                return Err(Code::Invalid.error("managed result reference index"));
            }
        }
        if !expected.is_empty() {
            return Err(Code::Missing.error("managed result reference index"));
        }
        Ok(())
    }
}
