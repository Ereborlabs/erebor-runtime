use super::*;
use crate::AnalysisContextRefV1;

pub(in crate::analysis) struct PreparedDerived {
    sources: BTreeMap<u64, Vec<Arc<ManagedDerivedSource>>>,
    selected: PreparedImport,
    imports: BTreeMap<u64, PreparedImport>,
    union: PreparedImport,
    step: Option<super::super::model::SourceStep>,
    versions: BTreeMap<crate::AnalysisContextKeyV1, Vec<u8>>,
    records: BTreeMap<crate::DiscoveryRecordIdV1, (Vec<u8>, Vec<u8>)>,
    pub(in crate::analysis) facts: Vec<crate::analysis::context::PreparedFact>,
    pub(in crate::analysis) saved: BTreeMap<crate::AnalysisContextKeyV1, AnalysisContextRefV1>,
}

impl PreparedDerived {
    pub(in crate::analysis) fn origin_refs(&self) -> impl Iterator<Item = &PackageResultRefV1> {
        self.union.origins.iter()
    }

    pub(in crate::analysis) fn values(
        &self,
        call: u64,
    ) -> impl Iterator<Item = &crate::AnalysisContextVersionV1> {
        self.sources
            .get(&call)
            .into_iter()
            .flatten()
            .flat_map(|source| &source.contexts)
    }

    pub(in crate::analysis) fn contexts(&self, call: u64) -> Vec<AnalysisContextRefV1> {
        self.values(call)
            .filter_map(|value| self.saved.get(&value.key).cloned())
            .collect()
    }
}

#[derive(Default)]
pub(in crate::analysis) struct ImportedSource {
    pub(in crate::analysis) calls: BTreeMap<u64, Vec<AnalysisContextRefV1>>,
    pub(in crate::analysis) origins: BTreeMap<u64, Vec<PackageResultRefV1>>,
    resolved: BTreeMap<u64, Vec<AnalysisContextRefV1>>,
    selected: SourceImport,
    union: SourceImport,
    pub(in crate::analysis) proofs:
        BTreeMap<u64, Vec<(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)>>,
}

#[derive(Default)]
struct SourceImport {
    refs: Vec<AnalysisContextRefV1>,
    resolved: Vec<AnalysisContextRefV1>,
    origins: Vec<PackageResultRefV1>,
    proofs: Vec<(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)>,
}

#[derive(Default)]
struct PreparedImport {
    refs: Vec<(crate::AnalysisContextKeyV1, ContextSlot)>,
    origins: Vec<PackageResultRefV1>,
    proofs: Vec<(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)>,
}

#[derive(Default)]
struct ContextSlot {
    fact: Option<usize>,
    fixed: Option<AnalysisContextRefV1>,
    resolved: bool,
}

impl PreparedImport {
    fn new(
        values: &[Arc<ManagedDerivedSource>],
        indices: &BTreeMap<&crate::AnalysisContextKeyV1, usize>,
    ) -> Result<Self> {
        let mut refs = BTreeMap::<crate::AnalysisContextKeyV1, ContextSlot>::new();
        let mut origins = BTreeMap::new();
        let mut proofs = BTreeMap::new();
        for value in values {
            for context in &value.contexts {
                let slot = refs.entry(context.key.clone()).or_default();
                slot.fact = Some(
                    *indices
                        .get(&context.key)
                        .ok_or_else(|| Code::Invalid.error("derived context slot"))?,
                );
                if let Some(reference) = value.references.get(&context.key) {
                    if slot
                        .fixed
                        .replace(reference.clone())
                        .is_some_and(|prior| prior != *reference)
                    {
                        return Err(Code::Conflict.error("derived historical reference"));
                    }
                } else {
                    slot.resolved = true;
                }
            }
            for (record, reference) in &value.proofs {
                if proofs
                    .insert((record.clone(), reference.key.clone()), reference.clone())
                    .is_some_and(|prior| prior != *reference)
                {
                    return Err(Code::Conflict.error("derived record proof reference"));
                }
                let slot = refs.entry(reference.key.clone()).or_default();
                if slot
                    .fixed
                    .replace(reference.clone())
                    .is_some_and(|prior| prior != *reference)
                {
                    return Err(Code::Conflict.error("derived record proof reference"));
                }
            }
            if let Some(history) = &value.history {
                origins.insert(history.result.result_id.clone(), history.result.clone());
            }
        }
        Ok(Self {
            refs: refs.into_iter().collect(),
            origins: origins.into_values().collect(),
            proofs: proofs
                .into_iter()
                .map(|((record, _), reference)| (record, reference))
                .collect(),
        })
    }

    fn bind(
        self,
        references: &BTreeMap<crate::AnalysisContextKeyV1, AnalysisContextRefV1>,
        facts: &[crate::analysis::context::PreparedFact],
    ) -> Result<SourceImport> {
        let mut refs = Vec::with_capacity(self.refs.len());
        let mut resolved = Vec::new();
        for (key, slot) in self.refs {
            let bound = slot
                .fact
                .map(|ordinal| {
                    references
                        .get(&facts[ordinal].value().key)
                        .ok_or_else(|| Code::Invalid.error("derived context binding"))
                })
                .transpose()?;
            if bound.is_some_and(|reference| {
                slot.fixed.as_ref().is_some_and(|fixed| fixed != reference)
            }) {
                return Err(Code::Conflict.error("derived historical reference"));
            }
            let reference = bound
                .cloned()
                .or(slot.fixed)
                .ok_or_else(|| Code::Invalid.error("derived context slot"))?;
            if reference.key != key {
                return Err(Code::Invalid.error("derived context slot identity"));
            }
            if slot.resolved {
                resolved.push(reference.clone());
            }
            refs.push(reference);
        }
        Ok(SourceImport {
            refs,
            resolved,
            origins: self.origins,
            proofs: self.proofs,
        })
    }
}

impl ImportedSource {
    pub(in crate::analysis) fn resolved(&self, call: u64) -> &[AnalysisContextRefV1] {
        self.resolved.get(&call).map_or(&[], Vec::as_slice)
    }

    pub(in crate::analysis) fn selected_imports(&self) -> &[AnalysisContextRefV1] {
        &self.union.resolved
    }

    pub(in crate::analysis) fn source_step(
        &self,
        prepared: &mut PreparedDerived,
    ) -> Result<Option<super::super::model::SourceStep>> {
        let Some(mut step) = prepared.step.take() else {
            return Ok(None);
        };
        step.derived = self.selected.refs.clone();
        step.origins = self.selected.origins.clone();
        step.proofs = self.selected.proofs.clone();
        Ok(Some(step))
    }

    
    pub(in crate::analysis) fn selected_proofs(
        &self,
    ) -> Result<Vec<(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)>> {
        Ok(self.union.proofs.clone())
    }
    pub(in crate::analysis) fn references(&self) -> Vec<AnalysisContextRefV1> {
        self.union.refs.clone()
    }
    pub(in crate::analysis) fn history(&self) -> Vec<PackageResultRefV1> {
        self.union.origins.clone()
    }
}



impl PreparedDerived {
    pub(in crate::analysis) fn prepare(
        attempt: &crate::ManagedAttempt,
        returns: impl ExactSizeIterator<Item = (u64, bool)>,
        revision: u64,
        memory: &mut super::super::budget::PreparedMemory<'_>,
        mut inspect: impl FnMut(
            &[crate::analysis::context::PreparedFact],
            u64,
            &mut super::super::budget::PreparedMemory<'_>,
        )
            -> Result<BTreeMap<crate::AnalysisContextKeyV1, AnalysisContextRefV1>>,
    ) -> Result<Self> {
        let Some(frame) = &attempt.5 else {
            return Ok(PreparedDerived {
                sources: BTreeMap::new(),
                selected: PreparedImport::default(),
                imports: BTreeMap::new(),
                union: PreparedImport::default(),
                step: None,
                versions: BTreeMap::new(),
                records: BTreeMap::new(),
                facts: Vec::new(),
                saved: BTreeMap::new(),
            });
        };
        let mut calls = BTreeSet::new();
        calls.extend(attempt.1.spec.manifest.calls.keys().copied());
        frame.charge_contexts(&calls, &mut |bytes| memory.charge(bytes))?;
        memory.charge(
            returns
                .len()
                .checked_add(1)
                .and_then(|count| count.checked_mul(24 * std::mem::size_of::<PreparedImport>()))
                .ok_or_else(|| Code::Limit.error("derived attribution memory"))?,
        )?;
        let manifest = &attempt.1.spec.manifest;
        let mut sources = BTreeMap::new();
        for (call, retained) in returns {
            if retained {
                continue;
            }
            let mut calls = BTreeSet::new();
            let mut pending = vec![call];
            while let Some(call) = pending.pop() {
                if calls.insert(call) {
                    pending.extend(&manifest.calls[&call].dependencies);
                }
            }
            let values = frame.call_derived(&calls)?;
            if !values.is_empty() {
                sources.insert(call, values);
            }
        }
        let selected = frame
            .input_selection()?
            .map(|selection| Arc::clone(&selection.derived))
            .into_iter()
            .collect::<Vec<_>>();
        let mut contexts = BTreeMap::new();
        for source in sources.values().flatten().chain(&selected) {
            for (ordinal, context) in source.contexts.iter().enumerate() {
                memory.check()?;
                if let Some((prior, index)) = contexts.get(&context.key) {
                    let prior: &Arc<ManagedDerivedSource> = prior;
                    if &prior.contexts[*index] != context {
                        return Err(Code::Conflict.error("derived context collision"));
                    }
                } else {
                    memory.charge(
                        context
                            .key
                            .allocated_bytes()
                            .checked_mul(4)
                            .and_then(|bytes| {
                                bytes.checked_add(
                                    12 * std::mem::size_of::<(
                                        crate::AnalysisContextKeyV1,
                                        (Arc<ManagedDerivedSource>, usize),
                                    )>(),
                                )
                            })
                            .ok_or_else(|| Code::Limit.error("derived context key memory"))?,
                    )?;
                    contexts.insert(context.key.clone(), (Arc::clone(source), ordinal));
                }
            }
        }
        let mut facts = Vec::new();
        for (source, ordinal) in contexts.into_values() {
            facts.push(crate::analysis::context::PreparedFact::new(
                source,
                ordinal,
                &mut |bytes| memory.reserve(bytes),
            )?);
        }
        let saved = inspect(&facts, revision, memory)?;
        for source in sources.values().flatten().chain(&selected) {
            for (key, reference) in &source.references {
                if saved.get(key) != Some(reference) {
                    return Err(Code::Conflict.error("derived historical reference"));
                }
            }
        }
        let indices = facts
            .iter()
            .enumerate()
            .map(|(ordinal, fact)| (&fact.value().key, ordinal))
            .collect::<BTreeMap<_, _>>();
        let mut versions = BTreeMap::new();
        let mut records = BTreeMap::new();
        for source in sources.values().flatten().chain(&selected) {
            for context in &source.contexts {
                if !versions.contains_key(&context.key) {
                    memory.charge(
                        context
                            .key
                            .allocated_bytes()
                            .checked_add(std::mem::size_of_val(&context.key))
                            .and_then(|bytes| bytes.checked_mul(24))
                            .ok_or_else(|| Code::Limit.error("derived version key memory"))?,
                    )?;
                    versions.insert(
                        context.key.clone(),
                        crate::analysis::context::version_key(&context.key)?,
                    );
                }
            }
            for (record, reference) in &source.proofs {
                memory.charge(
                    reference
                        .key
                        .allocated_bytes()
                        .checked_add(record.allocated_bytes())
                        .and_then(|bytes| {
                            bytes.checked_add(
                                24 * std::mem::size_of::<(
                                    crate::DiscoveryRecordIdV1,
                                    AnalysisContextRefV1,
                                )>(),
                            )
                        })
                        .and_then(|bytes| bytes.checked_mul(16))
                        .ok_or_else(|| Code::Limit.error("derived proof memory"))?,
                )?;
                if !versions.contains_key(&reference.key) {
                    versions.insert(
                        reference.key.clone(),
                        crate::analysis::context::version_key(&reference.key)?,
                    );
                }
                if !records.contains_key(record) {
                    records.insert(
                        record.clone(),
                        (
                            araphor_analysis_types::DomainRelations::key(record)
                                .context(crate::AnalysisContractSnafu)?,
                            record.stream.key(),
                        ),
                    );
                }
            }
        }
        let mut copies = 0usize;
        for value in sources.values().flatten().chain(&selected) {
            for context in &value.contexts {
                copies = copies
                    .checked_add(context.key.allocated_bytes())
                    .and_then(|bytes| {
                        bytes.checked_add(
                            16 * std::mem::size_of::<(crate::AnalysisContextKeyV1, ContextSlot)>(),
                        )
                    })
                    .ok_or_else(|| Code::Limit.error("derived slot memory"))?;
            }
            if let Some(history) = &value.history {
                copies = copies
                    .checked_add(
                        history
                            .result
                            .result_id
                            .capacity()
                            .checked_mul(8)
                            .ok_or_else(|| Code::Limit.error("derived origin memory"))?,
                    )
                    .ok_or_else(|| Code::Limit.error("derived origin memory"))?;
            }
        }
        memory.charge(
            copies
                .checked_mul(16)
                .ok_or_else(|| Code::Limit.error("derived slot memory"))?,
        )?;
        let all = sources
            .values()
            .flatten()
            .chain(&selected)
            .cloned()
            .collect::<Vec<_>>();
        let union = PreparedImport::new(&all, &indices)?;
        let mut imports = BTreeMap::new();
        for (call, values) in &sources {
            imports.insert(*call, PreparedImport::new(values, &indices)?);
        }
        let selected = PreparedImport::new(&selected, &indices)?;
        let step = if let Some(selection) = frame.input_selection()? {
            let mut bytes = selection
                .records
                .len()
                .checked_mul(
                    4 * std::mem::size_of::<(crate::DiscoveryRecordIdV1, StorePositionV1)>(),
                )
                .ok_or_else(|| Code::Limit.error("source step memory"))?;
            for (record, _) in &selection.records {
                bytes = bytes
                    .checked_add(
                        record
                            .allocated_bytes()
                            .checked_mul(4)
                            .ok_or_else(|| Code::Limit.error("source step memory"))?,
                    )
                    .ok_or_else(|| Code::Limit.error("source step memory"))?;
            }
            for coverage in &selection.coverage {
                bytes = bytes
                    .checked_add(4 * std::mem::size_of_val(coverage))
                    .and_then(|bytes| {
                        bytes.checked_add(coverage.source.node_id.capacity().checked_mul(4)?)
                    })
                    .and_then(|bytes| {
                        bytes.checked_add(
                            coverage
                                .gap_reasons
                                .capacity()
                                .checked_mul(4 * std::mem::size_of::<String>())?,
                        )
                    })
                    .ok_or_else(|| Code::Limit.error("source coverage memory"))?;
                for reason in &coverage.gap_reasons {
                    bytes = bytes
                        .checked_add(
                            reason
                                .capacity()
                                .checked_mul(4)
                                .ok_or_else(|| Code::Limit.error("source coverage memory"))?,
                        )
                        .ok_or_else(|| Code::Limit.error("source coverage memory"))?;
                }
            }
            memory.charge(bytes)?;
            Some(super::super::model::SourceStep {
                expired: selection.expired,
                coverage: selection.coverage.clone(),
                first: selection.first,
                last: selection.last,
                deadline: selection.deadline,
                base: selection.base.clone(),
                records: selection.records.clone(),
                derived: Vec::new(),
                origins: Vec::new(),
                proofs: Vec::new(),
            })
        } else {
            None
        };
        Ok(PreparedDerived {
            sources,
            selected,
            imports,
            union,
            step,
            versions,
            records,
            facts,
            saved,
        })
    }

    pub(in crate::analysis) fn bind(
        &mut self,
        references: &BTreeMap<crate::AnalysisContextKeyV1, AnalysisContextRefV1>,
    ) -> Result<ImportedSource> {
        let mut imported = ImportedSource {
            selected: std::mem::take(&mut self.selected).bind(&references, &self.facts)?,
            union: std::mem::take(&mut self.union).bind(&references, &self.facts)?,
            ..Default::default()
        };
        for (call, value) in std::mem::take(&mut self.imports) {
            let value = value.bind(&references, &self.facts)?;
            imported.calls.insert(call, value.refs);
            imported.proofs.insert(call, value.proofs);
            imported.resolved.insert(call, value.resolved);
            imported.origins.insert(call, value.origins);
        }
        Ok(imported)
    }
}
