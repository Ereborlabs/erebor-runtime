use super::*;
use crate::analysis::extraction::*;
use crate::analysis::native::NativeStore as AnalysisStore;
use crate::analysis::raw::RawIdentity;
use crate::analysis::segments::SegmentRange;
use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisReferenceOriginV1, AnalysisReferenceV1,
    AnalysisResultCommitV1, AnalysisTableRequests, ContextSensitivityV1, EvidenceIntakeIdentityV1,
    EvidenceRecord, EvidenceRetentionOwner, ProcessorClassV1, ProcessorScopeV1, RetentionLimitsV1,
    Selection, TraceBatchV1, TraceFrameKindV1, TraceFrameV1, TraceStateV1,
    ValidatedEvidenceBatchV1,
};
use araphor_analysis_sdk::arrow_array::{Array, BinaryArray, UInt32Array, UInt64Array};
use araphor_analysis_sdk::{self as sdk, RecordBatch};
use snafu::ResultExt as _;
use std::{collections::BTreeMap, ops::Bound, sync::Arc};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const KEY_LIMIT: usize = 1024;
const INPUT_BYTES: usize = 64 * 1024 * 1024;

mod bounds;
mod changes;
mod lifecycle;
mod positions;
mod selection;
mod snapshot;

fn read(
    store: &AnalysisStore,
    selection: &AnalysisSelectionV1,
    requested: &[(&str, &[&str])],
    mode: AnalysisReadModeV1,
    limits: AnalysisExtractLimits,
    control: &AnalysisReadControl,
) -> Result<AnalysisPositionPageV1> {
    let columns = requested
        .iter()
        .map(|(name, fields)| {
            let schema = &crate::AnalysisStore::table_schemas()[*name];
            let indices = fields
                .iter()
                .map(|field| {
                    schema
                        .index_of(field)
                        .map_err(araphor_analysis_sdk::Error::from)
                        .context(crate::AnalysisContractSnafu)
                })
                .collect::<Result<BTreeSet<_>>>()?;
            Ok(((*name).to_owned(), Some(indices)))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    store.read_tables(
        selection,
        AnalysisTableRead {
            requests: &columns,
            event_ranges: None,
            mode,
            now: 0,
        },
        limits,
        control,
    )
}

fn unsigned(page: &AnalysisPositionPageV1, table: &str, field: &str) -> TestResult<Vec<u64>> {
    let mut values = Vec::new();
    for batch in page.tables.get(table).into_iter().flatten() {
        let array = batch
            .column_by_name(field)
            .ok_or("unsigned column absent")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("column is not UInt64")?;
        assert_eq!(array.null_count(), 0);
        values.extend_from_slice(array.values());
    }
    Ok(values)
}

fn binary(page: &AnalysisPositionPageV1, table: &str, field: &str) -> TestResult<Vec<Vec<u8>>> {
    let mut values = Vec::new();
    for batch in page.tables.get(table).into_iter().flatten() {
        let array = batch
            .column_by_name(field)
            .ok_or("binary column absent")?
            .as_any()
            .downcast_ref::<BinaryArray>()
            .ok_or("column is not Binary")?;
        assert_eq!(array.null_count(), 0);
        for value in array {
            values.push(value.ok_or("binary value is null")?.to_vec());
        }
    }
    Ok(values)
}

fn positions(page: &AnalysisPositionPageV1) -> TestResult<Vec<StorePositionV1>> {
    let mut values = Vec::new();
    for batch in page.tables.get("events").into_iter().flatten() {
        let revisions = batch
            .column_by_name("commit_revision")
            .ok_or("commit revision absent")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("commit revision is not UInt64")?;
        let ordinals = batch
            .column_by_name("ordinal")
            .ok_or("ordinal absent")?
            .as_any()
            .downcast_ref::<UInt32Array>()
            .ok_or("ordinal is not UInt32")?;
        values.extend((0..batch.num_rows()).map(|index| StorePositionV1 {
            commit_revision: revisions.value(index),
            ordinal: ordinals.value(index),
        }));
    }
    Ok(values)
}

fn row_count(page: &AnalysisPositionPageV1, table: &str) -> usize {
    page.tables
        .get(table)
        .into_iter()
        .flatten()
        .map(RecordBatch::num_rows)
        .sum()
}

fn identity(tenant: u8) -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [tenant; 16],
        node_id: "n".into(),
        ..crate::analysis::tests::identity()
    }
}

fn batch(first: u64, count: usize, received: u64) -> Result<ValidatedEvidenceBatchV1> {
    records(
        first,
        received,
        (first..first + count as u64).map(|cursor| EvidenceRecord {
            observed_boottime_ns: cursor,
            ..Default::default()
        }),
    )
}

fn records(
    first: u64,
    received: u64,
    records: impl IntoIterator<Item = EvidenceRecord>,
) -> Result<ValidatedEvidenceBatchV1> {
    let mut framed = Vec::new();
    let mut ends = Vec::new();
    for record in records {
        framed.extend(Vec::<u8>::try_from(&record)?);
        ends.push(framed.len());
    }
    Ok(ValidatedEvidenceBatchV1 {
        cpu_id: 0,
        first_cursor: first,
        last_cursor: first + ends.len() as u64 - 1,
        intake_utc_ns: received,
        framed_records: framed.into(),
        frame_ends: ends,
    })
}

fn padded_batch(
    first: u64,
    count: usize,
    received: u64,
    frame_bytes: usize,
) -> ValidatedEvidenceBatchV1 {
    use prost::Message as _;

    let mut framed = Vec::new();
    let mut ends = Vec::new();
    for cursor in first..first + count as u64 {
        let record = EvidenceRecord {
            observed_boottime_ns: cursor,
            decision_context: Some(crate::EvidenceDecisionContext {
                catalog_json: vec![7; frame_bytes - 128],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut payload = record.encode_to_vec();
        let mut padding = vec![0; frame_bytes - 8 - payload.len()];
        let overhead = prost::encoding::bytes::encoded_len(100, &padding) - padding.len();
        padding.truncate(padding.len() - overhead);
        prost::encoding::bytes::encode(100, &padding, &mut payload);
        assert_eq!(payload.len() + 8, frame_bytes);
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend(payload);
        frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
        assert!(EvidenceRecord::try_from(frame.as_slice()).is_ok());
        framed.extend(frame);
        ends.push(framed.len());
    }
    ValidatedEvidenceBatchV1 {
        cpu_id: 0,
        first_cursor: first,
        last_cursor: first + count as u64 - 1,
        intake_utc_ns: received,
        framed_records: framed.into(),
        frame_ends: ends,
    }
}

fn owned_bytes(page: &AnalysisPositionPageV1) -> usize {
    page.extraction.allocation_bytes()
        + page
            .tables
            .values()
            .map(|batches| {
                batches.capacity() * size_of::<RecordBatch>()
                    + batches
                        .iter()
                        .map(|batch| {
                            batch.num_columns()
                                * size_of::<araphor_analysis_sdk::arrow_array::ArrayRef>()
                                + batch.get_array_memory_size()
                        })
                        .sum::<usize>()
            })
            .sum::<usize>()
}
