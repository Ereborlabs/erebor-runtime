use super::super::references::References;
use super::*;
use crate::{AnalysisContextRefV1, AnalysisWitnessV1, ManagedAttempt};

pub(in crate::analysis::native::managed) struct HistoricalSource {
    view: DataView,
    selected: u64,
    source: EvidenceIntakeIdentityV1,
    members: Vec<u8>,
    proofs: Vec<(DiscoveryRecordIdV1, AnalysisContextRefV1)>,
}

impl NativeStore {
    pub(in crate::analysis::native::managed) fn source_origins<'a>(
        &self,
        attempt: &ManagedAttempt,
        origins: impl Iterator<Item = &'a PackageResultRefV1>,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Vec<HistoricalSource>> {
        let mut sources = Vec::new();
        let mut previous = None::<&str>;
        for origin in origins {
            control.check()?;
            if previous.is_some_and(|previous| previous >= origin.result_id.as_str()) {
                return Err(Code::Invalid.error("derived origin order"));
            }
            previous = Some(&origin.result_id);
            let ManagedDestination::Graph { source, .. } = &attempt.instance().spec.destination
            else {
                return Err(Code::Denied.error("derived historical source scope"));
            };
            if !attempt.0.capture.grant.selection.includes_source(source)
                || origin.commit_revision == 0
                || origin.commit_revision > attempt.captured_revision()
            {
                return Err(Code::Denied.error("derived historical source grant"));
            }
            let view = self.read_at(origin.commit_revision)?;
            let (selected, stored, owner) =
                view.result_owner(source.tenant_id, &origin.result_id, control, charge)?;
            let header =
                SourceRecord::header(selected, |key| Records::read(key, &view.snapshot), charge)?;
            let ResultBody::Selected(step) = stored.body else {
                return Err(Code::Invalid.error("derived origin kind"));
            };
            if stored.revision != origin.commit_revision
                || header.captured.commit_revision != owner.captured_revision()
                || !matches!(&owner.instance().spec.destination,ManagedDestination::Graph { source: actual, .. } if actual == source)
                || owner.receipt().and_then(|receipt| receipt.graph.as_ref()) != Some(origin)
            {
                return Err(Code::Invalid.error("derived historical origin"));
            }
            charge(
                step.proofs
                    .len()
                    .saturating_mul(4 * size_of::<(DiscoveryRecordIdV1, AnalysisContextRefV1)>()),
            )?;
            let members = view.source_members(&owner)?;
            sources.push(HistoricalSource {
                view,
                selected,
                source: source.clone(),
                members,
                proofs: step.proofs,
            });
        }
        Ok(sources)
    }
}

impl HistoricalSource {
    pub(in crate::analysis::native::managed) fn contains(
        &self,
        context: u64,
        reference: &AnalysisContextRefV1,
        fact: Option<&crate::GraphFactV1>,
        witnesses: &[AnalysisWitnessV1],
    ) -> Result<bool> {
        if Records::read(
            &References::key(References::CONTEXT, &[self.selected, context]),
            &self.view.snapshot,
        )?
        .map(|value| NativeStore::number(&value))
        .transpose()?
            != Some(reference.commit_revision)
        {
            return Ok(false);
        }
        if let Some(fact) = fact {
            if fact.record_id.stream == self.source
                && Records::read(
                    &SourceRecord::member_key(&self.members, &fact.record_id),
                    &self.view.snapshot,
                )?
                .is_some()
            {
                return Ok(true);
            }
        }
        for (record, proof) in &self.proofs {
            if record.stream == self.source
                && proof == reference
                && witnesses.iter().any(|witness| {
                    witness.identity
                        == crate::AnalysisStreamIdentityV1::Evidence(record.stream.clone())
                        && witness.cursor == record.durable_cursor
                })
                && Records::read(
                    &SourceRecord::member_key(&self.members, record),
                    &self.view.snapshot,
                )?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
