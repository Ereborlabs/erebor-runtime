use super::*;
use crate::analysis::context::VerifiedPackages;
use crate::{AnalysisContextRefV1, ManagedCommit};

pub(in crate::analysis::managed) struct PreparedDerived {
    sources: BTreeMap<u64, Vec<Arc<ManagedDerivedSource>>>,
    selected: PreparedImport,
    imports: BTreeMap<u64, PreparedImport>,
    union: PreparedImport,
    step: Option<super::super::model::SourceStep>,
    versions: BTreeMap<crate::AnalysisContextKeyV1, Vec<u8>>,
    records: BTreeMap<crate::DiscoveryRecordIdV1, (Vec<u8>, Vec<u8>)>,
    pub(in crate::analysis::managed) facts: Vec<crate::analysis::context::PreparedFact>,
    pub(in crate::analysis::managed) saved:
        BTreeMap<crate::AnalysisContextKeyV1, AnalysisContextRefV1>,
}

impl PreparedDerived {
    pub(in crate::analysis::managed) fn values(
        &self,
        call: u64,
    ) -> impl Iterator<Item = &crate::AnalysisContextVersionV1> {
        self.sources
            .get(&call)
            .into_iter()
            .flatten()
            .flat_map(|source| &source.contexts)
    }

    pub(in crate::analysis::managed) fn contexts(&self, call: u64) -> Vec<AnalysisContextRefV1> {
        self.values(call)
            .filter_map(|value| self.saved.get(&value.key).cloned())
            .collect()
    }
}

#[derive(Default)]
pub(in crate::analysis::managed) struct ImportedSource {
    pub(in crate::analysis::managed) calls: BTreeMap<u64, Vec<AnalysisContextRefV1>>,
    pub(in crate::analysis::managed) origins: BTreeMap<u64, Vec<PackageResultRefV1>>,
    resolved: BTreeMap<u64, Vec<AnalysisContextRefV1>>,
    selected: SourceImport,
    union: SourceImport,
    pub(in crate::analysis::managed) proofs:
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
    pub(in crate::analysis::managed) fn source_step(
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

    pub(in crate::analysis::managed) fn pin(
        &self,
        connection: &Connection,
        receipt: &crate::ManagedReceipt,
        prepared: &PreparedDerived,
    ) -> Result<()> {
        {
            let mut appender =
                connection
                    .appender("managed_source_proofs")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open source record proof pins",
                    })?;
            for (call, values) in &self.proofs {
                for (record, reference) in values {
                    appender
                        .append_row(params![
                            receipt.results[call].result_id,
                            prepared.records[record].0,
                            prepared.versions[&reference.key],
                            reference.commit_revision,
                            prepared.records[record].1,
                            record.cpu_id,
                            record.durable_cursor
                        ])
                        .context(AnalysisDatabaseSnafu {
                            operation: "append source record proof pin",
                        })?;
                }
            }
            for (record, reference) in &self.union.proofs {
                appender
                    .append_row(params![
                        receipt.selected.result_id,
                        prepared.records[record].0,
                        prepared.versions[&reference.key],
                        reference.commit_revision,
                        prepared.records[record].1,
                        record.cpu_id,
                        record.durable_cursor
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append selected source proof pin",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush source record proof pins",
            })?;
        }
        {
            let mut appender =
                connection
                    .appender("managed_context_imports")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open derived import pins",
                    })?;
            for (call, values) in &self.resolved {
                for value in values {
                    appender
                        .append_row(params![
                            receipt.results[call].result_id,
                            prepared.versions[&value.key],
                            value.commit_revision
                        ])
                        .context(AnalysisDatabaseSnafu {
                            operation: "append derived import pin",
                        })?;
                }
            }
            for value in &self.union.resolved {
                appender
                    .append_row(params![
                        receipt.selected.result_id,
                        prepared.versions[&value.key],
                        value.commit_revision
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append selected import pin",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush derived import pins",
            })?;
        }
        {
            let mut appender =
                connection
                    .appender("managed_source_reads")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open derived origin pins",
                    })?;
            for (call, values) in &self.origins {
                for value in values {
                    appender
                        .append_row(params![
                            receipt.results[call].result_id,
                            value.result_id,
                            value.commit_revision
                        ])
                        .context(AnalysisDatabaseSnafu {
                            operation: "append derived origin pin",
                        })?;
                }
            }
            for value in &self.union.origins {
                appender
                    .append_row(params![
                        receipt.selected.result_id,
                        value.result_id,
                        value.commit_revision
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append selected origin pin",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush derived origin pins",
            })?;
        }
        Ok(())
    }
    pub(in crate::analysis::managed) fn selected_proofs(
        &self,
    ) -> Result<Vec<(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)>> {
        Ok(self.union.proofs.clone())
    }
    pub(in crate::analysis::managed) fn references(&self) -> Vec<AnalysisContextRefV1> {
        self.union.refs.clone()
    }
    pub(in crate::analysis::managed) fn history(&self) -> Vec<PackageResultRefV1> {
        self.union.origins.clone()
    }
}

impl AnalysisStore {
    pub(in crate::analysis::managed) fn source_origins(
        connection: &Connection,
        result: &str,
    ) -> Result<Vec<PackageResultRefV1>> {
        connection.prepare("SELECT producer_id,revision FROM managed_source_reads WHERE result_id=? ORDER BY producer_id")
            .and_then(|mut query| query.query_map(params![result],|row| Ok(PackageResultRefV1 { result_id:row.get(0)?,commit_revision:row.get(1)? }))?.collect())
            .context(AnalysisDatabaseSnafu { operation:"read derived origin pins" })
    }

    pub(in crate::analysis::managed) fn join_contexts(
        before: &[AnalysisContextRefV1],
        after: &[AnalysisContextRefV1],
    ) -> Result<Vec<AnalysisContextRefV1>> {
        let mut values = BTreeMap::new();
        for value in before.iter().chain(after) {
            if values
                .insert(value.key.clone(), value.clone())
                .is_some_and(|prior| prior != *value)
            {
                return Err(Code::Conflict.error("derived immutable context"));
            }
        }
        Ok(values.into_values().collect())
    }

    pub(in crate::analysis::managed) fn prepare_derived(
        &self,
        connection: &Connection,
        input: &ManagedCommit<'_>,
        revision: u64,
        verified: &mut VerifiedPackages,
        memory: &mut super::super::budget::PreparedMemory<'_>,
    ) -> Result<PreparedDerived> {
        let Some(frame) = &input.attempt.5 else {
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
        calls.extend(input.attempt.1.spec.manifest.calls.keys().copied());
        frame.charge_contexts(&calls, &mut |bytes| memory.charge(bytes))?;
        memory.charge(
            input
                .returns
                .len()
                .checked_add(1)
                .and_then(|count| count.checked_mul(24 * std::mem::size_of::<PreparedImport>()))
                .ok_or_else(|| Code::Limit.error("derived attribution memory"))?,
        )?;
        let manifest = &input.attempt.1.spec.manifest;
        let mut sources = BTreeMap::new();
        for returned in input.returns {
            if returned.retained.is_some() {
                continue;
            }
            let mut calls = BTreeSet::new();
            let mut pending = vec![returned.call];
            while let Some(call) = pending.pop() {
                if calls.insert(call) {
                    pending.extend(&manifest.calls[&call].dependencies);
                }
            }
            let values = frame.call_derived(&calls)?;
            if !values.is_empty() {
                sources.insert(returned.call, values);
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
        let saved = self.inspect_fact_rows(connection, &facts, revision, verified)?;
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

    pub(in crate::analysis::managed) fn import_derived(
        &self,
        connection: &duckdb::Transaction<'_>,
        prepared: &mut PreparedDerived,
        revision: u64,
        verified: &mut VerifiedPackages,
        cached: bool,
    ) -> Result<ImportedSource> {
        let references =
            self.import_fact_rows(connection, &prepared.facts, revision, verified, cached)?;
        let mut imported = ImportedSource {
            selected: std::mem::take(&mut prepared.selected).bind(&references, &prepared.facts)?,
            union: std::mem::take(&mut prepared.union).bind(&references, &prepared.facts)?,
            ..Default::default()
        };
        for (call, value) in std::mem::take(&mut prepared.imports) {
            let value = value.bind(&references, &prepared.facts)?;
            imported.calls.insert(call, value.refs);
            imported.proofs.insert(call, value.proofs);
            imported.resolved.insert(call, value.resolved);
            imported.origins.insert(call, value.origins);
        }
        Ok(imported)
    }
}
