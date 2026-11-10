

use super::*;

mod check;
mod frozen;
mod read;
mod revision;

#[derive(Debug, Eq, PartialEq)]
pub(in crate::analysis) struct SourcePublication {
    pub reference: PackageResultRefV1,
    pub captured: StorePositionV1,
    pub first: u64,
    pub last: u64,
    pub deadline: u64,
    pub count: u64,
    pub restricted: u64,
}

pub(in crate::analysis) struct PreparedSource {
    pub(in crate::analysis) selection: Arc<ManagedInputSelection>,
    pub(in crate::analysis) prior: Option<SourcePublication>,
    pub(in crate::analysis) stream: Vec<u8>,
    pub(in crate::analysis) rows: Vec<(Vec<u8>, u32, u64, StorePositionV1, u64)>,
    pub(in crate::analysis) coverage: u64,
    pub(in crate::analysis) gaps: Vec<(u64, u64)>,
    pub(in crate::analysis) count: u64,
    pub(in crate::analysis) restricted: u64,
    pub(in crate::analysis) roots: BTreeMap<u64, (u64, u64)>,
}

impl SourcePublication {
    

    

    

    
}

impl PreparedSource {
    pub(in crate::analysis) fn prepare<'a>(
        attempt: &crate::ManagedAttempt,
        selection: &Arc<ManagedInputSelection>,
        prior: Option<SourcePublication>,
        returns: impl ExactSizeIterator<Item = (u64, &'a araphor_analysis_sdk::Evaluation)>,
        memory: &mut super::super::budget::PreparedMemory<'_>,
    ) -> Result<Self> {
        let spec = &attempt.instance().spec;
        let frame = attempt
            .5
            .as_ref()
            .ok_or_else(|| Code::Denied.error("native source publication frame"))?;
        let registered = frame
            .input_selection()?
            .ok_or_else(|| Code::Incomplete.error("native source selection"))?;
        if !Arc::ptr_eq(&registered, selection)
            || !Arc::ptr_eq(&selection.scope, &frame.scope)
            || !Arc::ptr_eq(&selection.proof, &frame.proof)
            || selection.scope.position.commit_revision != attempt.captured_revision()
            || !matches!(&spec.destination, super::super::model::ManagedDestination::Graph { source,
                operation: super::super::model::ManagedGraphOperation::Evaluate, .. } if source == &selection.source)
        {
            return Err(Code::Denied.error("native source publication owner"));
        }
        memory.charge(
            selection
                .source
                .node_id
                .capacity()
                .checked_add(std::mem::size_of_val(&selection.source))
                .and_then(|bytes| bytes.checked_mul(8))
                .and_then(|bytes| {
                    bytes.checked_add(
                        selection
                            .base
                            .as_ref()
                            .map_or(0, |base| base.result_id.capacity())
                            .checked_mul(4)?,
                    )
                })
                .ok_or_else(|| Code::Limit.error("source preparation metadata"))?,
        )?;
        let stream = selection.source.key();
        if prior.as_ref().map(|prior| &prior.reference) != selection.base.as_ref()
            || selection.expired
                && prior.as_ref().is_none_or(|prior| {
                    prior.first != selection.first
                        || prior.last != selection.last
                        || prior.deadline != selection.deadline
                })
            || selection.append
                && prior.as_ref().is_none_or(|prior| {
                    selection.parent.as_ref().is_none_or(|parent| {
                        parent.result != prior.reference || parent.position != prior.captured
                    }) || prior.first != selection.first
                        || prior.last > selection.last
                        || prior.deadline != selection.deadline
                })
        {
            return Err(Code::Conflict.error("native source publication parent"));
        }
        let (coverage, gaps) = frame.source_metadata(&selection.source)?;
        memory.charge(
            gaps.len()
                .checked_add(usize::from(selection.expired))
                .and_then(|count| count.checked_mul(4 * std::mem::size_of::<(u64, u64)>()))
                .ok_or_else(|| Code::Limit.error("source preparation gap memory"))?,
        )?;
        let mut gaps = gaps.to_vec();
        if selection.expired {
            gaps.push((selection.first, selection.last));
            gaps.sort_unstable();
            gaps.dedup();
        }
        memory.charge(
            selection
                .records
                .len()
                .checked_mul(4 * std::mem::size_of::<(Vec<u8>, u32, u64, StorePositionV1, u64)>())
                .and_then(|bytes| {
                    bytes.checked_add(
                        gaps.capacity()
                            .checked_mul(std::mem::size_of::<(u64, u64)>())?,
                    )
                })
                .ok_or_else(|| Code::Limit.error("source preparation memory"))?,
        )?;
        let mut rows = Vec::with_capacity(selection.records.len());
        let mut added = 0u64;
        for (id, position) in &selection.records {
            memory.check()?;
            memory.charge(
                id.allocated_bytes()
                    .checked_add(std::mem::size_of_val(id))
                    .and_then(|bytes| bytes.checked_mul(4))
                    .ok_or_else(|| Code::Limit.error("source record key memory"))?,
            )?;
            let key = araphor_analysis_types::DomainRelations::key(id)
                .context(crate::AnalysisContractSnafu)?;
            let restricted = selection.restricted.get(id).copied().unwrap_or(0);
            added = added
                .checked_add(restricted)
                .ok_or_else(|| Code::Limit.error("native source disclosure count"))?;
            rows.push((key, id.cpu_id, id.durable_cursor, *position, restricted));
        }
        let count = (rows.len() as u64)
            .checked_add(if selection.append || selection.expired {
                prior.as_ref().map_or(0, |prior| prior.count)
            } else {
                0
            })
            .ok_or_else(|| Code::Limit.error("native source membership count"))?;
        let restricted = added
            .checked_add(if selection.append || selection.expired {
                prior.as_ref().map_or(0, |prior| prior.restricted)
            } else {
                0
            })
            .ok_or_else(|| Code::Limit.error("native source disclosure count"))?;
        if selection
            .prefix
            .as_ref()
            .is_some_and(|proof| !usize::try_from(count).is_ok_and(|count| proof.has_count(count)))
        {
            return Err(Code::Conflict.error("native source prefix count"));
        }
        memory.charge(
            returns
                .len()
                .checked_mul(12 * std::mem::size_of::<(u64, (u64, u64))>())
                .ok_or_else(|| Code::Limit.error("source root metadata memory"))?,
        )?;
        let mut roots = BTreeMap::new();
        for (call, evaluation) in returns {
            use araphor_analysis_sdk::arrow_array::{Array as _, StructArray, UInt64Array};
            let mut bounds = None::<(u64, u64)>;
            for batch in evaluation
                .inputs
                .iter()
                .filter(|input| input.data.name == "units")
                .flat_map(|input| &input.data.batches)
            {
                let Some(records) = batch
                    .column_by_name("record")
                    .and_then(|column| column.as_any().downcast_ref::<StructArray>())
                else {
                    continue;
                };
                let Some(cursors) = records
                    .column_by_name("durable_cursor")
                    .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
                else {
                    continue;
                };
                for cursor in cursors.iter().flatten() {
                    bounds = Some(bounds.map_or((cursor, cursor), |(first, last)| {
                        (first.min(cursor), last.max(cursor))
                    }));
                }
            }
            if let Some(bounds) = bounds {
                roots.insert(call, bounds);
            }
        }
        Ok(PreparedSource {
            selection: Arc::clone(selection),
            prior,
            stream,
            rows,
            coverage,
            gaps,
            count,
            restricted,
            roots,
        })
    }
}
