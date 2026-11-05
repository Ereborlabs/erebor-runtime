use sdk::arrow_array::{Array, BinaryArray, StringArray, UInt32Array, UInt64Array};

use super::*;
use crate::AnalysisContextRefV1;

impl ManagedSourceFrame {
    pub(in crate::analysis::managed) fn call_evidence(
        &self,
        calls: &BTreeSet<u64>,
        capture: &super::super::model::Capture,
        evidence: &SourceEvidence,
    ) -> Result<SourceEvidence> {
        let selected = self
            .selected
            .lock()
            .map_err(|_| Code::Conflict.error("canonical source lock"))?;
        if !selected.frozen {
            return Err(Code::Conflict.error("unfrozen call evidence"));
        }
        let mut witnesses = BTreeMap::new();
        let mut contexts = BTreeMap::new();
        for cells in calls
            .iter()
            .filter_map(|call| selected.calls.get(call))
            .flat_map(|call| &call.cells)
        {
            for index in &cells.indices {
                match &cells.rows[*index] {
                    SourceRow::Event(witness, _) => {
                        let index = evidence
                            .witnesses
                            .binary_search_by(|value| {
                                (&value.identity, value.cursor)
                                    .cmp(&(&witness.identity, witness.cursor))
                            })
                            .map_err(|_| Code::Denied.error("unselected call witness"))?;
                        let witness = &evidence.witnesses[index];
                        witnesses
                            .insert((witness.identity.clone(), witness.cursor), witness.clone());
                    }
                    SourceRow::Context(reference) => {
                        if evidence
                            .contexts
                            .binary_search_by(|value| value.key.cmp(&reference.key))
                            .ok()
                            .is_none_or(|index| evidence.contexts[index] != *reference)
                        {
                            return Err(Code::Denied.error("unselected call context"));
                        }
                        contexts.insert(reference.key.clone(), reference.clone());
                    }
                }
            }
        }
        for witness in &capture.witnesses {
            witnesses.insert((witness.identity.clone(), witness.cursor), witness.clone());
        }
        for reference in &capture.contexts {
            contexts.insert(reference.key.clone(), reference.clone());
        }
        Ok(SourceEvidence {
            witnesses: witnesses.into_values().collect(),
            contexts: contexts.into_values().collect(),
        })
    }

    pub(in crate::analysis::managed) fn call_contexts(
        &self,
        calls: &BTreeSet<u64>,
    ) -> Result<Vec<AnalysisContextRefV1>> {
        let selected = self
            .selected
            .lock()
            .map_err(|_| Code::Conflict.error("canonical source lock"))?;
        let mut contexts = BTreeMap::new();
        for cells in calls
            .iter()
            .filter_map(|call| selected.calls.get(call))
            .flat_map(|call| &call.cells)
        {
            for index in &cells.indices {
                if let SourceRow::Context(reference) = &cells.rows[*index] {
                    if contexts
                        .insert(reference.key.clone(), reference.clone())
                        .is_some_and(|prior| prior != *reference)
                    {
                        return Err(Code::Conflict.error("canonical context revisions"));
                    }
                }
            }
        }
        Ok(contexts.into_values().collect())
    }

    pub(in crate::analysis::managed) fn canonical_contexts(
        &self,
        calls: &BTreeSet<u64>,
        root: &std::path::Path,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<
        BTreeMap<
            crate::AnalysisContextKeyV1,
            (crate::AnalysisContextVersionV1, AnalysisContextRefV1),
        >,
    > {
        let selected = self
            .selected
            .lock()
            .map_err(|_| Code::Conflict.error("canonical source lock"))?;
        let mut result = BTreeMap::<
            crate::AnalysisContextKeyV1,
            (crate::AnalysisContextVersionV1, AnalysisContextRefV1),
        >::new();
        for cells in calls
            .iter()
            .filter_map(|call| selected.calls.get(call))
            .flat_map(|call| &call.cells)
        {
            if cells.table.as_ref() != "context_versions" {
                continue;
            }
            for index in &cells.indices {
                charge(0)?;
                let SourceRow::Context(reference) = &cells.rows[*index] else {
                    return Err(Code::Invalid.error("canonical context handle"));
                };
                let body = SourceRow::array::<BinaryArray>(&cells.batch, "body")?.value(*index);
                let nullable = |name| -> Result<Option<u64>> {
                    let array = cells
                        .batch
                        .column_by_name(name)
                        .and_then(|array| array.as_any().downcast_ref::<UInt64Array>())
                        .ok_or_else(|| Code::Invalid.error("canonical context validity"))?;
                    Ok((!array.is_null(*index)).then(|| array.value(*index)))
                };
                let from = nullable("valid_from_utc_ns")?;
                let until = nullable("valid_until_utc_ns")?;
                let sensitivity =
                    SourceRow::array::<StringArray>(&cells.batch, "sensitivity")?.value(*index);
                let revision =
                    SourceRow::array::<UInt64Array>(&cells.batch, "commit_revision")?.value(*index);
                if revision != reference.commit_revision {
                    return Err(Code::Conflict.error("canonical context revisions"));
                }
                if let Some((prior, prior_ref)) = result.get(&reference.key) {
                    let prior_sensitivity: &str = prior.sensitivity.into();
                    if prior_ref != reference
                        || prior.body != body
                        || prior.valid_from_utc_ns != from
                        || prior.valid_until_utc_ns != until
                        || prior_sensitivity != sensitivity
                    {
                        return Err(Code::Conflict.error("canonical context cells"));
                    }
                    continue;
                }
                charge(
                    body.len()
                        .saturating_mul(8)
                        .saturating_add(reference.key.allocated_bytes().saturating_mul(4))
                        .saturating_add(
                            12 * size_of::<(crate::AnalysisContextVersionV1, AnalysisContextRefV1)>(
                            ),
                        ),
                )?;
                let (value, _) = AnalysisStore::decode_context_row(
                    root,
                    reference.key.clone(),
                    (from, until, sensitivity.to_owned(), body.to_vec(), revision),
                )?;
                result.insert(reference.key.clone(), (value, reference.clone()));
            }
        }
        Ok(result)
    }

    pub(in crate::analysis::managed) fn canonical_events(
        &self,
        requested: &BTreeSet<crate::DiscoveryRecordIdV1>,
        calls: &BTreeSet<u64>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<BTreeMap<crate::DiscoveryRecordIdV1, (crate::DiscoveryRecordV1, StorePositionV1)>>
    {
        let selected = self
            .selected
            .lock()
            .map_err(|_| Code::Conflict.error("canonical source lock"))?;
        let mut result = BTreeMap::<
            crate::DiscoveryRecordIdV1,
            (crate::DiscoveryRecordV1, StorePositionV1),
        >::new();
        let keys = requested
            .iter()
            .map(|id| (&id.stream, id.durable_cursor))
            .collect::<BTreeSet<_>>();
        for cells in calls
            .iter()
            .filter_map(|call| selected.calls.get(call))
            .flat_map(|call| &call.cells)
        {
            if cells.table.as_ref() != "events" {
                continue;
            }
            for index in &cells.indices {
                charge(0)?;
                let SourceRow::Event(witness, position) = &cells.rows[*index] else {
                    return Err(Code::Invalid.error("canonical event handle"));
                };
                let AnalysisStreamIdentityV1::Evidence(source) = &witness.identity else {
                    return Err(Code::Invalid.error("canonical event source"));
                };
                if !keys.contains(&(source, witness.cursor)) {
                    continue;
                }
                let id = crate::DiscoveryRecordIdV1 {
                    stream: source.clone(),
                    cpu_id: SourceRow::array::<UInt32Array>(&cells.batch, "cpu_id")?.value(*index),
                    durable_cursor: witness.cursor,
                };
                if !requested.contains(&id) {
                    continue;
                }
                let bytes =
                    SourceRow::array::<BinaryArray>(&cells.batch, "framed_record")?.value(*index);
                if let Some((prior, cut)) = result.get(&id) {
                    if prior.wire_record.as_slice() != bytes || cut != position {
                        return Err(Code::Conflict.error("canonical event cells"));
                    }
                    continue;
                }
                charge(
                    bytes
                        .len()
                        .checked_mul(8)
                        .and_then(|bytes| {
                            bytes.checked_add(
                                8 * std::mem::size_of::<crate::DiscoveryRecordV1>()
                                    + 4 * std::mem::size_of::<araphor_analysis_types::Observation>(
                                    ),
                            )
                        })
                        .ok_or_else(|| Code::Limit.error("canonical Graph event memory"))?,
                )?;
                let record = crate::DiscoveryRecordV1::try_from((id.clone(), bytes))?;
                if let Some((prior, cut)) = result.insert(id, (record.clone(), *position)) {
                    if prior != record || cut != *position {
                        return Err(Code::Conflict.error("canonical event cells"));
                    }
                }
            }
        }
        if result.len() != requested.len() {
            return Err(Code::Denied.error("unread canonical event"));
        }
        Ok(result)
    }

    pub(in crate::analysis::managed) fn charge_contexts(
        &self,
        calls: &BTreeSet<u64>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<()> {
        let selected = self
            .selected
            .lock()
            .map_err(|_| Code::Conflict.error("canonical source lock"))?;
        for cells in calls
            .iter()
            .filter_map(|call| selected.calls.get(call))
            .flat_map(|call| &call.cells)
        {
            for index in &cells.indices {
                charge(0)?;
                if let SourceRow::Context(reference) = &cells.rows[*index] {
                    charge(
                        reference
                            .key
                            .allocated_bytes()
                            .checked_add(4 * std::mem::size_of::<AnalysisContextRefV1>())
                            .and_then(|bytes| bytes.checked_mul(4))
                            .ok_or_else(|| Code::Limit.error("canonical Graph context memory"))?,
                    )?;
                }
            }
        }
        Ok(())
    }
}
