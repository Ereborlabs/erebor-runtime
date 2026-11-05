use super::*;
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, DiscoveryRecordIdV1,
    GraphReplayInputV1,
};
use sdk::arrow_array::UInt32Array;

pub struct ManagedSourceHistory {
    pub(in crate::analysis) scope: Arc<SourceScope>,
    pub(in crate::analysis) proof: Arc<OnceLock<Arc<PackageResultRefV1>>>,
    pub(in crate::analysis) result: PackageResultRefV1,
    pub(in crate::analysis) contexts:
        BTreeMap<AnalysisContextKeyV1, (AnalysisContextVersionV1, AnalysisContextRefV1)>,
    pub(in crate::analysis) proofs:
        BTreeMap<(DiscoveryRecordIdV1, AnalysisContextKeyV1), AnalysisContextRefV1>,
}

pub struct ManagedDerivedSource {
    pub(super) scope: Arc<SourceScope>,
    pub(super) proof: Arc<OnceLock<Arc<PackageResultRefV1>>>,
    pub(in crate::analysis::managed) records: Vec<(DiscoveryRecordIdV1, StorePositionV1)>,
    pub(in crate::analysis::managed) contexts: Vec<AnalysisContextVersionV1>,
    pub(in crate::analysis::managed) references:
        BTreeMap<AnalysisContextKeyV1, AnalysisContextRefV1>,
    pub(in crate::analysis::managed) proofs: Vec<(DiscoveryRecordIdV1, AnalysisContextRefV1)>,
    pub(in crate::analysis::managed) history: Option<Arc<ManagedSourceHistory>>,
    _lease: Arc<dyn std::any::Any + Send + Sync>,
}

impl ManagedDerivedSource {
    pub(in crate::analysis) fn context_values(&self) -> &[AnalysisContextVersionV1] {
        &self.contexts
    }
}

impl std::fmt::Debug for ManagedDerivedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedDerivedSource")
            .field("records", &self.records.len())
            .field("contexts", &self.contexts.len())
            .finish_non_exhaustive()
    }
}

impl ManagedSourceHistory {
    pub fn contexts(
        &self,
    ) -> impl Iterator<Item = &(AnalysisContextVersionV1, AnalysisContextRefV1)> {
        self.contexts.values()
    }
    pub fn proofs(&self) -> impl Iterator<Item = (&DiscoveryRecordIdV1, &AnalysisContextRefV1)> {
        self.proofs
            .iter()
            .map(|((record, _), reference)| (record, reference))
    }
    pub fn allocated_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>().checked_add(self.result.result_id.len())?;
        for (key, (value, reference)) in &self.contexts {
            bytes = bytes
                .checked_add(
                    2 * std::mem::size_of::<(
                        AnalysisContextKeyV1,
                        (AnalysisContextVersionV1, AnalysisContextRefV1),
                    )>(),
                )?
                .checked_add(value.body.len())?;
            for key in [key, &value.key, &reference.key] {
                bytes = bytes
                    .checked_add(key.owner_id.len())?
                    .checked_add(key.entity_key.len())?
                    .checked_add(key.lifetime_key.len())?;
            }
        }
        for ((id, key), reference) in &self.proofs {
            bytes = bytes
                .checked_add(
                    2 * std::mem::size_of::<(
                        (DiscoveryRecordIdV1, AnalysisContextKeyV1),
                        AnalysisContextRefV1,
                    )>(),
                )?
                .checked_add(id.allocated_bytes())?;
            for key in [key, &reference.key] {
                bytes = bytes
                    .checked_add(key.owner_id.len())?
                    .checked_add(key.entity_key.len())?
                    .checked_add(key.lifetime_key.len())?;
            }
        }
        Some(bytes)
    }
}

impl ManagedSourceFrame {
    pub(in crate::analysis) fn seal_history(
        &self,
        result: PackageResultRefV1,
        contexts: Vec<(AnalysisContextVersionV1, AnalysisContextRefV1)>,
        proofs: Vec<(DiscoveryRecordIdV1, AnalysisContextRefV1)>,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Arc<ManagedSourceHistory>> {
        let mut bytes =
            std::mem::size_of::<ManagedSourceHistory>().saturating_add(result.result_id.len());
        for (value, reference) in &contexts {
            bytes = bytes
                .saturating_add(
                    2 * std::mem::size_of::<(
                        AnalysisContextKeyV1,
                        (AnalysisContextVersionV1, AnalysisContextRefV1),
                    )>(),
                )
                .saturating_add(value.key.owner_id.len())
                .saturating_add(value.key.entity_key.len())
                .saturating_add(value.key.lifetime_key.len());
            if value.key != reference.key {
                return Err(Code::Invalid.error("historical context identity"));
            }
        }
        for (id, reference) in &proofs {
            bytes = bytes
                .saturating_add(
                    2 * std::mem::size_of::<(
                        (DiscoveryRecordIdV1, AnalysisContextKeyV1),
                        AnalysisContextRefV1,
                    )>(),
                )
                .saturating_add(id.allocated_bytes())
                .saturating_add(reference.key.owner_id.len())
                .saturating_add(reference.key.entity_key.len())
                .saturating_add(reference.key.lifetime_key.len());
        }
        charge(0, bytes)?;
        Ok(Arc::new(ManagedSourceHistory {
            scope: Arc::clone(&self.scope),
            proof: Arc::clone(&self.proof),
            result,
            contexts: contexts
                .into_iter()
                .map(|(value, reference)| (value.key.clone(), (value, reference)))
                .collect(),
            proofs: proofs
                .into_iter()
                .map(|(id, reference)| ((id, reference.key.clone()), reference))
                .collect(),
        }))
    }

    pub fn derived_bytes(
        input: &GraphReplayInputV1,
        references: &BTreeMap<AnalysisContextKeyV1, AnalysisContextRefV1>,
        proofs: &[(DiscoveryRecordIdV1, AnalysisContextRefV1)],
    ) -> Option<usize> {
        let key_bytes = |key: &AnalysisContextKeyV1| {
            key.owner_id
                .len()
                .checked_add(key.entity_key.len())?
                .checked_add(key.lifetime_key.len())
        };
        let mut bytes = std::mem::size_of::<ManagedDerivedSource>()
            .checked_add(8 * std::mem::size_of::<usize>())?;
        for (id, _) in &input.input_positions {
            bytes = bytes
                .checked_add(std::mem::size_of::<(DiscoveryRecordIdV1, StorePositionV1)>())?
                .checked_add(id.allocated_bytes())?;
        }
        for value in &input.facts {
            bytes = bytes
                .checked_add(std::mem::size_of::<AnalysisContextVersionV1>())?
                .checked_add(key_bytes(&value.key)?)?
                .checked_add(value.body.len())?;
        }
        for (key, reference) in references {
            bytes = bytes
                .checked_add(
                    2 * std::mem::size_of::<(AnalysisContextKeyV1, AnalysisContextRefV1)>(),
                )?
                .checked_add(key_bytes(key)?)?
                .checked_add(key_bytes(&reference.key)?)?;
        }
        for (id, reference) in proofs {
            bytes = bytes
                .checked_add(std::mem::size_of::<(
                    DiscoveryRecordIdV1,
                    AnalysisContextRefV1,
                )>())?
                .checked_add(id.allocated_bytes())?
                .checked_add(key_bytes(&reference.key)?)?;
        }
        Some(bytes)
    }

    pub(super) fn check_events(
        &self,
        input: &GraphReplayInputV1,
        selected: &SourceSelection,
    ) -> Result<()> {
        let records = input
            .records
            .iter()
            .map(|record| (&record.id, record))
            .collect::<BTreeMap<_, _>>();
        let positions = input
            .input_positions
            .iter()
            .map(|(id, position)| (id, position))
            .collect::<BTreeMap<_, _>>();
        let mut found = BTreeSet::new();
        for cells in &selected.cells {
            if cells.table.as_ref() != "events" {
                continue;
            }
            for index in &cells.indices {
                let SourceRow::Event(witness, position) = &cells.rows[*index] else {
                    return Err(Code::Invalid.error("derived event cells"));
                };
                let AnalysisStreamIdentityV1::Evidence(source) = &witness.identity else {
                    return Err(Code::Invalid.error("derived event identity"));
                };
                if source != &input.source {
                    continue;
                }
                let id = DiscoveryRecordIdV1 {
                    stream: source.clone(),
                    cpu_id: SourceRow::array::<UInt32Array>(&cells.batch, "cpu_id")?.value(*index),
                    durable_cursor: witness.cursor,
                };
                let Some(record) = records.get(&id) else {
                    continue;
                };
                let bytes = SourceRow::array::<sdk::arrow_array::BinaryArray>(
                    &cells.batch,
                    "framed_record",
                )?
                .value(*index);
                if record.wire_record.as_slice() != bytes
                    || positions.get(&id).copied() != Some(position)
                {
                    return Err(Code::Denied.error("derived canonical event mismatch"));
                }
                found.insert(id);
            }
        }
        if found.len() != records.len() {
            return Err(Code::Denied.error("unread derived event"));
        }
        Ok(())
    }

    pub fn seal_derived(
        &self,
        input: &GraphReplayInputV1,
        references: &BTreeMap<AnalysisContextKeyV1, AnalysisContextRefV1>,
        proofs: &[(DiscoveryRecordIdV1, AnalysisContextRefV1)],
        history: Option<Arc<ManagedSourceHistory>>,
        lease: Arc<dyn std::any::Any + Send + Sync>,
    ) -> Result<Arc<ManagedDerivedSource>> {
        if let Some(history) = &history {
            if !Arc::ptr_eq(&history.scope, &self.scope)
                || !Arc::ptr_eq(&history.proof, &self.proof)
            {
                return Err(Code::Denied.error("derived historical source owner"));
            }
        }
        if input.records.is_empty() {
            if !input.input_positions.is_empty()
                || !input.facts.is_empty()
                || !references.is_empty()
                || !proofs.is_empty()
            {
                return Err(Code::Invalid.error("empty derived source"));
            }
        } else {
            input.validate()?;
        }
        self.check_coverage(input)?;
        let selected = self
            .selected
            .lock()
            .map_err(|_| Code::Conflict.error("derived source lock"))?;
        if selected.frozen {
            return Err(Code::Conflict.error("frozen derived source"));
        }
        self.check_events(input, &selected)?;
        let records = input
            .records
            .iter()
            .map(|record| (&record.id, record))
            .collect::<BTreeMap<_, _>>();
        for value in &input.facts {
            let fact = crate::GraphFactV1::try_from(value)?;
            if !value.valid()
                || value.key.tenant_id != self.scope.tenant
                || !records.contains_key(&fact.record_id)
            {
                return Err(Code::Invalid.error("derived context source"));
            }
        }
        let facts = input
            .facts
            .iter()
            .map(|value| (&value.key, value))
            .collect::<BTreeMap<_, _>>();
        for (key, reference) in references {
            if key != &reference.key
                || !history.as_ref().is_some_and(|history| {
                    history.contexts.get(key).is_some_and(|(value, saved)| {
                        saved == reference && facts.get(key).copied() == Some(value)
                    })
                })
            {
                return Err(Code::Denied.error("derived historical context"));
            }
        }
        for (record, reference) in proofs {
            let raw = selected
                .contexts
                .get(&(reference.key.clone(), reference.commit_revision))
                == Some(reference);
            let historical = history.as_ref().is_some_and(|history| {
                history.proofs.get(&(record.clone(), reference.key.clone())) == Some(reference)
            });
            if !records.contains_key(record) || (!raw && !historical) {
                return Err(Code::Denied.error("derived canonical parent"));
            }
        }
        drop(selected);
        Ok(Arc::new(ManagedDerivedSource {
            scope: Arc::clone(&self.scope),
            proof: Arc::clone(&self.proof),
            records: input.input_positions.clone(),
            contexts: input.facts.clone(),
            references: references.clone(),
            proofs: proofs.to_vec(),
            history,
            _lease: lease,
        }))
    }

    pub fn attribution_bytes(rows: &[Arc<ManagedSourceRows>]) -> Option<usize> {
        rows.iter().try_fold(0usize, |bytes, rows| {
            bytes.checked_add(rows.cells.indices.len().checked_mul(
                2 * std::mem::size_of::<(DiscoveryRecordIdV1, AnalysisContextRefV1)>(),
            )?)
        })
    }

    pub(super) fn check_derived_lineage(
        &self,
        rows: &[Arc<ManagedSourceRows>],
        values: &[Arc<ManagedDerivedSource>],
    ) -> Result<()> {
        if values.is_empty() {
            return Ok(());
        }
        let mut events = BTreeMap::new();
        let mut contexts = BTreeMap::new();
        for rows in rows {
            for index in &rows.cells.indices {
                match &rows.cells.rows[*index] {
                    SourceRow::Event(witness, position) => {
                        let AnalysisStreamIdentityV1::Evidence(source) = &witness.identity else {
                            return Err(Code::Invalid.error("derived lineage stream"));
                        };
                        let cpu = SourceRow::array::<UInt32Array>(&rows.cells.batch, "cpu_id")?
                            .value(*index);
                        events.insert((source, cpu, witness.cursor), position);
                    }
                    SourceRow::Context(reference) => {
                        contexts.insert(&reference.key, reference.commit_revision);
                    }
                }
            }
        }
        for value in values {
            if !Arc::ptr_eq(&value.scope, &self.scope) || !Arc::ptr_eq(&value.proof, &self.proof) {
                return Err(Code::Denied.error("derived call owner"));
            }
            for (record, position) in &value.records {
                if events
                    .get(&(&record.stream, record.cpu_id, record.durable_cursor))
                    .copied()
                    != Some(position)
                {
                    return Err(Code::Denied.error("derived call event lineage"));
                }
            }
            for (record, reference) in &value.proofs {
                let raw = contexts.get(&reference.key).copied() == Some(reference.commit_revision);
                let historical = value.history.as_ref().is_some_and(|history| {
                    history.proofs.get(&(record.clone(), reference.key.clone())) == Some(reference)
                });
                if !raw && !historical {
                    return Err(Code::Denied.error("derived call parent lineage"));
                }
            }
        }
        Ok(())
    }

    pub(in crate::analysis::managed) fn call_derived(
        &self,
        calls: &BTreeSet<u64>,
    ) -> Result<Vec<Arc<ManagedDerivedSource>>> {
        let selected = self
            .selected
            .lock()
            .map_err(|_| Code::Conflict.error("derived call lock"))?;
        let mut values = BTreeMap::new();
        for value in calls
            .iter()
            .filter_map(|call| selected.calls.get(call))
            .flat_map(|call| &call.derived)
        {
            values.insert(Arc::as_ptr(value) as usize, Arc::clone(value));
        }
        Ok(values.into_values().collect())
    }
}
