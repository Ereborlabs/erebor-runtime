use std::collections::{BTreeMap, VecDeque};

use super::window::WindowHeads;
use super::*;
use crate::{AnalysisSourceStatusV1, DiscoveryRecordIdV1, GraphInvalidSnafu, StorePositionV1};

impl GraphAndFindingOwner {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn commit_chunks(
        &self,
        status: &AnalysisSourceStatusV1,
        heads: &WindowHeads,
        first: u64,
        read_first: u64,
        consumed: u64,
        advance: bool,
        now: u64,
        notice: u64,
        records: Vec<DiscoveryRecordV1>,
        positions: Vec<(DiscoveryRecordIdV1, StorePositionV1)>,
        by_record: BTreeMap<DiscoveryRecordIdV1, Vec<AnalysisContextVersionV1>>,
    ) -> Result<bool> {
        let mut chunks = Self::context_chunks(records, &by_record)?;
        let mut changed = false;
        while let Some(records) = chunks.pop_front() {
            let (_, chunk_last) = Self::chunk_bounds(&records)?;
            if advance && chunk_last <= consumed {
                continue;
            }
            let result = self.commit_chunk(
                status, heads, first, read_first, consumed, advance, now, notice, &records,
                &positions, &by_record,
            )?;
            let Some(committed) = result else {
                if records.len() < 2 {
                    return GraphInvalidSnafu {
                        field: "one observation result bound",
                    }
                    .fail();
                }
                let midpoint = records.len() / 2;
                let mut prefix = records;
                let tail = prefix.split_off(midpoint);
                chunks.push_front(tail);
                chunks.push_front(prefix);
                continue;
            };
            changed |= committed;
            if advance {
                break;
            }
        }
        Ok(changed)
    }

    fn context_chunks(
        records: Vec<DiscoveryRecordV1>,
        by_record: &BTreeMap<DiscoveryRecordIdV1, Vec<AnalysisContextVersionV1>>,
    ) -> Result<VecDeque<Vec<DiscoveryRecordV1>>> {
        let mut chunks = VecDeque::new();
        let mut chunk = Vec::new();
        let mut context_count = 0;
        for record in records {
            let count = by_record.get(&record.id).map_or(0, Vec::len);
            if count > 256 {
                return GraphInvalidSnafu {
                    field: "one observation context bound",
                }
                .fail();
            }
            if !chunk.is_empty() && context_count + count > 256 {
                chunks.push_back(std::mem::take(&mut chunk));
                context_count = 0;
            }
            context_count += count;
            chunk.push(record);
        }
        if !chunk.is_empty() {
            chunks.push_back(chunk);
        }
        Ok(chunks)
    }

    pub(super) fn chunk_bounds(records: &[DiscoveryRecordV1]) -> Result<(u64, u64)> {
        records
            .first()
            .zip(records.last())
            .map(|(first, last)| (first.id.durable_cursor, last.id.durable_cursor))
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "bounded window",
                }
                .build()
            })
    }
}
