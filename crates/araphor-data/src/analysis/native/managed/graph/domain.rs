use araphor_analysis_sdk as sdk;
use araphor_analysis_types::DomainRelations;
use araphor_graph::ReadOrigin;

use super::{ManagedGraphJournal, ManagedGraphTransaction};
use crate::analysis::managed::{
    graph::domain::{Basis, ContextInputs, DomainCommands, DomainPreparation, DomainScratch},
    source::{import::PreparedDerived, SourceEvidence},
    PreparedMemory,
};
use crate::{AnalysisReadControl, PackageErrorCodeV1 as Code, Result};

impl ManagedGraphJournal {
    pub(super) fn domain_contexts(
        &self,
        store: &crate::analysis::native::NativeStore,
        evidence: &SourceEvidence,
        derived: &PreparedDerived,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<ContextInputs> {
        ContextInputs::capture(
            &store.root,
            &self.call.attempt,
            self.call.call,
            &self.prepared.contexts,
            evidence,
            derived,
            memory,
        )
    }

    pub(super) fn prepare_domain(
        &self,
        contexts: ContextInputs,
        control: &AnalysisReadControl,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<Option<DomainPreparation>> {
        let mut scratch = DomainScratch {
            budget: self.budget.as_ref(),
            memory,
            bytes: 0,
            leases: Vec::new(),
        };
        let mut basis = Basis::default();
        for row in &self.work.reads {
            scratch.charge(0)?;
            if !self.work.origins.contains_key(&ReadOrigin {
                writer: row.writer,
                revision: row.revision,
            }) {
                return Err(Code::Denied.error("domain Graph read origin"));
            }
            let declaration = self
                .call
                .spec
                .relations
                .iter()
                .find(|declaration| self.call.relations[&declaration.name] == row.relation)
                .ok_or_else(|| Code::Invalid.error("domain Graph read relation"))?;
            if !DomainRelations::subjects(declaration)
                && !DomainRelations::relationships(declaration, &self.call.spec)
                && !DomainRelations::findings(declaration)
            {
                continue;
            }
            let Some(member) = self.prepared.view.member(
                row.writer,
                row.relation,
                &row.owner,
                &row.key,
                &|_, bytes, total| {
                    ManagedGraphTransaction::reserve(self.budget.as_ref(), control, bytes, total)
                },
            )?
            else {
                continue;
            };
            if member.writer != row.writer
                || member.relation != row.relation
                || member.owner != row.owner
                || member.key != row.key
                || member.revision != row.revision
            {
                continue;
            }
            basis.append(
                (row.relation, member.owner.as_slice(), member.key.as_slice()),
                declaration,
                &self.call.spec,
                member.properties().slice(member.row, 1),
                &mut scratch,
            )?;
        }
        let package = &self.prepared.package;
        let model = self.domain_model()?;
        let commands = DomainCommands::read(
            &self.work.journal,
            &self.call.spec,
            &self.call.relations,
            &basis,
            package,
            model,
            &mut scratch,
        )?;
        if commands.is_empty() {
            return Ok(None);
        }
        Ok(Some(DomainPreparation {
            commands,
            contexts,
            bytes: scratch.bytes,
            leases: scratch.leases,
        }))
    }

    pub(super) fn check_domain(
        &self,
        domain: DomainPreparation,
        derived: &PreparedDerived,
        restricted: bool,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<Option<crate::analysis::managed::GraphProof>> {
        let frame = self
            .call
            .attempt
            .5
            .as_ref()
            .ok_or_else(|| Code::Denied.error("domain Graph canonical source"))?;
        domain.validate(
            self.call.attempt.1.spec.tenant,
            frame,
            &self.call.input_calls(),
            &self.prepared.package,
            self.domain_model()?,
            derived.values(self.call.call),
            restricted,
            self.budget.as_ref(),
            memory,
            |records, contexts, scratch| {
                let mut facts = Vec::new();
                for (value, reference) in contexts {
                    scratch.charge(0)?;
                    if let Some(fact) =
                        self.prepared
                            .snapshot
                            .canonical_fact(value, reference, &mut |bytes| scratch.charge(bytes))?
                    {
                        if records.contains(&fact.record_id) {
                            facts.push((value.clone(), fact));
                        }
                    }
                }
                Ok(facts)
            },
        )
    }

    fn domain_model(&self) -> Result<&sdk::Model> {
        let declaration = &self.call.attempt.1.spec.manifest.calls[&self.call.call];
        self.prepared
            .package
            .exports
            .iter()
            .find(|model| model.name == declaration.export)
            .ok_or_else(|| Code::Invalid.error("domain Graph export"))
    }
}
