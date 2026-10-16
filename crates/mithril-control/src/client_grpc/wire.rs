use std::mem::size_of;

use araphor_data::{
    AnalysisContextKeyV1, AnalysisGapV1, AnalysisSourceSnapshotV1, StorePositionV1,
};
use araphor_query::{
    follow::{Cursor, Operation},
    planner::Planner,
    sources::ArrowSnapshot,
};
use arrow_array::types::{
    validate_decimal_precision_and_scale, Decimal128Type, Decimal256Type, DecimalType,
};
use arrow_array::{
    Array, BinaryArray, BinaryViewArray, FixedSizeBinaryArray, LargeBinaryArray, LargeStringArray,
    RecordBatch, StringArray, StringViewArray,
};
use arrow_schema::{DataType, Field, TimeUnit};
use datafusion_common::ScalarValue;
use erebor_runtime_ipc::araphor as proto;
use tonic::Status;

pub(super) struct Parameters(pub(super) Vec<ScalarValue>);

impl TryFrom<Vec<proto::QueryValue>> for Parameters {
    type Error = Status;

    fn try_from(values: Vec<proto::QueryValue>) -> Result<Self, Self::Error> {
        if values.len() > Planner::PARAMETER_COUNT {
            return Err(Status::invalid_argument(
                "SQL parameter count exceeds its bound.",
            ));
        }
        let mut bytes = 0_usize;
        for value in &values {
            bytes = bytes.saturating_add(size_of::<ScalarValue>());
            match value.kind.as_ref() {
                Some(proto::query_value::Kind::Null(true))
                | Some(proto::query_value::Kind::Boolean(_))
                | Some(proto::query_value::Kind::Signed(_))
                | Some(proto::query_value::Kind::Unsigned(_)) => {}
                Some(proto::query_value::Kind::Real(value)) if value.is_finite() => {}
                Some(proto::query_value::Kind::Text(value)) => {
                    bytes = bytes.saturating_add(value.capacity());
                }
                Some(proto::query_value::Kind::Binary(value)) => {
                    bytes = bytes.saturating_add(value.capacity());
                }
                Some(proto::query_value::Kind::Timestamp(value)) => {
                    Self::timestamp(value)?;
                }
                Some(proto::query_value::Kind::Decimal(value)) => {
                    bytes = bytes.saturating_add(value.unscaled.capacity());
                }
                Some(proto::query_value::Kind::Date(_))
                | Some(proto::query_value::Kind::Time(_))
                | Some(proto::query_value::Kind::Interval(_)) => {}
                Some(proto::query_value::Kind::Integer128(_))
                | Some(proto::query_value::Kind::Unsigned128(_)) => {
                    return Err(Status::unimplemented(
                        "SQL 128-bit integer parameters have no native Arrow type.",
                    ))
                }
                _ => return Err(Status::invalid_argument("SQL parameter type is invalid.")),
            }
            if bytes > Planner::PARAMETER_BYTES {
                return Err(Status::invalid_argument(
                    "SQL parameters exceed their byte bound.",
                ));
            }
        }
        let mut parameters = Vec::new();
        parameters
            .try_reserve_exact(values.len())
            .map_err(|_| Status::resource_exhausted("SQL parameter allocation failed."))?;
        for value in values {
            let value = match value.kind {
                Some(proto::query_value::Kind::Null(true)) => ScalarValue::Null,
                Some(proto::query_value::Kind::Boolean(value)) => ScalarValue::Boolean(Some(value)),
                Some(proto::query_value::Kind::Signed(value)) => ScalarValue::Int64(Some(value)),
                Some(proto::query_value::Kind::Unsigned(value)) => ScalarValue::UInt64(Some(value)),
                Some(proto::query_value::Kind::Real(value)) => ScalarValue::Float64(Some(value)),
                Some(proto::query_value::Kind::Text(value)) => ScalarValue::Utf8(Some(value)),
                Some(proto::query_value::Kind::Binary(value)) => ScalarValue::Binary(Some(value)),
                Some(proto::query_value::Kind::Timestamp(value)) => Self::timestamp(&value)?,
                Some(proto::query_value::Kind::Decimal(value)) => Self::decimal(&value)?,
                Some(proto::query_value::Kind::Date(value)) => ScalarValue::Date32(Some(value)),
                Some(proto::query_value::Kind::Time(value)) => Self::time(&value)?,
                Some(proto::query_value::Kind::Interval(value)) => {
                    ScalarValue::new_interval_mdn(value.months, value.days, value.nanoseconds)
                }
                _ => return Err(Status::invalid_argument("SQL parameter type is invalid.")),
            };
            parameters.push(value);
        }
        Ok(Self(parameters))
    }
}

impl Parameters {
    fn decimal(value: &proto::QueryDecimal) -> Result<ScalarValue, Status> {
        let invalid = || Status::invalid_argument("SQL decimal parameter is invalid.");
        let precision = u8::try_from(value.width).map_err(|_| invalid())?;
        let scale = i8::try_from(value.scale).map_err(|_| invalid())?;
        if precision <= 38 {
            let unscaled = value.unscaled.parse::<i128>().map_err(|_| invalid())?;
            validate_decimal_precision_and_scale::<Decimal128Type>(precision, scale)
                .map_err(|_| invalid())?;
            Decimal128Type::validate_decimal_precision(unscaled, precision, scale)
                .map_err(|_| invalid())?;
            ScalarValue::try_new_decimal128(unscaled, precision, scale).map_err(|_| invalid())
        } else {
            let unscaled = value
                .unscaled
                .parse::<araphor_query::datafusion::arrow::datatypes::i256>()
                .map_err(|_| invalid())?;
            validate_decimal_precision_and_scale::<Decimal256Type>(precision, scale)
                .map_err(|_| invalid())?;
            Decimal256Type::validate_decimal_precision(unscaled, precision, scale)
                .map_err(|_| invalid())?;
            Ok(ScalarValue::Decimal256(Some(unscaled), precision, scale))
        }
    }

    fn time(value: &proto::QueryTimestamp) -> Result<ScalarValue, Status> {
        use arrow_array::temporal_conversions::{
            time32ms_to_time, time32s_to_time, time64ns_to_time, time64us_to_time,
        };
        let invalid = || Status::invalid_argument("SQL time parameter is invalid.");
        match value.unit.as_str() {
            "second" => {
                let value = i32::try_from(value.value).map_err(|_| invalid())?;
                time32s_to_time(value).ok_or_else(invalid)?;
                Ok(ScalarValue::Time32Second(Some(value)))
            }
            "millisecond" => {
                let value = i32::try_from(value.value).map_err(|_| invalid())?;
                time32ms_to_time(value).ok_or_else(invalid)?;
                Ok(ScalarValue::Time32Millisecond(Some(value)))
            }
            "microsecond" => {
                time64us_to_time(value.value).ok_or_else(invalid)?;
                Ok(ScalarValue::Time64Microsecond(Some(value.value)))
            }
            "nanosecond" => {
                time64ns_to_time(value.value).ok_or_else(invalid)?;
                Ok(ScalarValue::Time64Nanosecond(Some(value.value)))
            }
            _ => Err(invalid()),
        }
    }

    fn timestamp(value: &proto::QueryTimestamp) -> Result<ScalarValue, Status> {
        let unit = match value.unit.as_str() {
            "second" => TimeUnit::Second,
            "millisecond" => TimeUnit::Millisecond,
            "microsecond" => TimeUnit::Microsecond,
            "nanosecond" => TimeUnit::Nanosecond,
            _ => {
                return Err(Status::invalid_argument(
                    "SQL timestamp parameter is invalid.",
                ))
            }
        };
        Ok(match unit {
            TimeUnit::Second => ScalarValue::TimestampSecond(Some(value.value), None),
            TimeUnit::Millisecond => ScalarValue::TimestampMillisecond(Some(value.value), None),
            TimeUnit::Microsecond => ScalarValue::TimestampMicrosecond(Some(value.value), None),
            TimeUnit::Nanosecond => ScalarValue::TimestampNanosecond(Some(value.value), None),
        })
    }
}

pub(super) struct Wire;

impl Wire {
    fn value(value: ScalarValue) -> Result<proto::QueryValue, Status> {
        use proto::query_value::Kind;
        if value.is_null() {
            return Ok(proto::QueryValue {
                kind: Some(Kind::Null(true)),
            });
        }
        let kind = match value {
            ScalarValue::Boolean(Some(value)) => Kind::Boolean(value),
            ScalarValue::Int8(Some(value)) => Kind::Signed(i64::from(value)),
            ScalarValue::Int16(Some(value)) => Kind::Signed(i64::from(value)),
            ScalarValue::Int32(Some(value)) => Kind::Signed(i64::from(value)),
            ScalarValue::Int64(Some(value)) => Kind::Signed(value),
            ScalarValue::UInt8(Some(value)) => Kind::Unsigned(u64::from(value)),
            ScalarValue::UInt16(Some(value)) => Kind::Unsigned(u64::from(value)),
            ScalarValue::UInt32(Some(value)) => Kind::Unsigned(u64::from(value)),
            ScalarValue::UInt64(Some(value)) => Kind::Unsigned(value),
            ScalarValue::Float16(Some(value)) => Kind::Real(f64::from(value)),
            ScalarValue::Float32(Some(value)) => Kind::Real(f64::from(value)),
            ScalarValue::Float64(Some(value)) => Kind::Real(value),
            ScalarValue::Decimal32(Some(value), width, scale) => {
                Self::decimal(width, scale, value.to_string())?
            }
            ScalarValue::Decimal64(Some(value), width, scale) => {
                Self::decimal(width, scale, value.to_string())?
            }
            ScalarValue::Decimal128(Some(value), width, scale) => {
                Self::decimal(width, scale, value.to_string())?
            }
            ScalarValue::Decimal256(Some(value), width, scale) => {
                Self::decimal(width, scale, value.to_string())?
            }
            ScalarValue::TimestampSecond(Some(value), _) => {
                Kind::Timestamp(Self::timestamp(TimeUnit::Second, value))
            }
            ScalarValue::TimestampMillisecond(Some(value), _) => {
                Kind::Timestamp(Self::timestamp(TimeUnit::Millisecond, value))
            }
            ScalarValue::TimestampMicrosecond(Some(value), _) => {
                Kind::Timestamp(Self::timestamp(TimeUnit::Microsecond, value))
            }
            ScalarValue::TimestampNanosecond(Some(value), _) => {
                Kind::Timestamp(Self::timestamp(TimeUnit::Nanosecond, value))
            }
            ScalarValue::Utf8(Some(value))
            | ScalarValue::Utf8View(Some(value))
            | ScalarValue::LargeUtf8(Some(value)) => Kind::Text(value),
            ScalarValue::Binary(Some(value))
            | ScalarValue::BinaryView(Some(value))
            | ScalarValue::LargeBinary(Some(value))
            | ScalarValue::FixedSizeBinary(_, Some(value)) => Kind::Binary(value),
            ScalarValue::Date32(Some(value)) => Kind::Date(value),
            ScalarValue::Date64(Some(value)) if value % 86_400_000 == 0 => Kind::Date(
                i32::try_from(value / 86_400_000)
                    .map_err(|_| Status::unimplemented("The query date exceeds the wire range."))?,
            ),
            ScalarValue::Time32Second(Some(value)) => {
                Kind::Time(Self::timestamp(TimeUnit::Second, i64::from(value)))
            }
            ScalarValue::Time32Millisecond(Some(value)) => {
                Kind::Time(Self::timestamp(TimeUnit::Millisecond, i64::from(value)))
            }
            ScalarValue::Time64Microsecond(Some(value)) => {
                Kind::Time(Self::timestamp(TimeUnit::Microsecond, value))
            }
            ScalarValue::Time64Nanosecond(Some(value)) => {
                Kind::Time(Self::timestamp(TimeUnit::Nanosecond, value))
            }
            ScalarValue::IntervalYearMonth(Some(months)) => Kind::Interval(proto::QueryInterval {
                months,
                days: 0,
                nanoseconds: 0,
            }),
            ScalarValue::IntervalDayTime(Some(value)) => Kind::Interval(proto::QueryInterval {
                months: 0,
                days: value.days,
                nanoseconds: i64::from(value.milliseconds) * 1_000_000,
            }),
            ScalarValue::IntervalMonthDayNano(Some(value)) => {
                Kind::Interval(proto::QueryInterval {
                    months: value.months,
                    days: value.days,
                    nanoseconds: value.nanoseconds,
                })
            }
            _ => {
                return Err(Status::unimplemented(
                    "The query value type is unsupported.",
                ))
            }
        };
        Ok(proto::QueryValue { kind: Some(kind) })
    }

    fn decimal(width: u8, scale: i8, unscaled: String) -> Result<proto::query_value::Kind, Status> {
        Ok(proto::query_value::Kind::Decimal(proto::QueryDecimal {
            width: u32::from(width),
            scale: u32::try_from(scale)
                .map_err(|_| Status::unimplemented("The query decimal scale is unsupported."))?,
            unscaled,
        }))
    }

    #[cfg(test)]
    fn signed128(value: i128) -> proto::QueryValue {
        proto::QueryValue {
            kind: Some(proto::query_value::Kind::Integer128(value.to_string())),
        }
    }

    #[cfg(test)]
    fn unsigned128(value: u128) -> proto::QueryValue {
        proto::QueryValue {
            kind: Some(proto::query_value::Kind::Unsigned128(value.to_string())),
        }
    }

    fn timestamp(unit: TimeUnit, value: i64) -> proto::QueryTimestamp {
        proto::QueryTimestamp {
            value,
            unit: match unit {
                TimeUnit::Second => "second",
                TimeUnit::Millisecond => "millisecond",
                TimeUnit::Microsecond => "microsecond",
                TimeUnit::Nanosecond => "nanosecond",
            }
            .into(),
        }
    }

    pub(super) fn header(
        snapshot: &ArrowSnapshot,
        operation: Operation,
        clock_changed: bool,
    ) -> proto::QueryFrame {
        let extraction = &snapshot.page.extraction;
        let meta = &extraction.meta;
        proto::QueryFrame {
            schema_version: 1,
            operation: match operation {
                Operation::Append => proto::QueryOperation::Append as i32,
                Operation::Replace => proto::QueryOperation::Replace as i32,
            },
            store_uuid: meta.store_uuid.as_bytes().to_vec(),
            recovery_epoch: meta.recovery_epoch,
            read_revision: meta.commit_revision,
            clock_changed,
            coverage: extraction.sources.iter().map(Self::coverage).collect(),
            payload: None,
        }
    }

    pub(super) fn conversion_bytes(batches: &[RecordBatch]) -> Result<usize, Status> {
        let mut bytes = batches
            .iter()
            .map(RecordBatch::num_rows)
            .sum::<usize>()
            .saturating_mul(size_of::<proto::QueryRow>());
        for batch in batches {
            bytes = bytes.saturating_add(
                batch
                    .num_rows()
                    .saturating_mul(batch.num_columns())
                    .saturating_mul(size_of::<proto::QueryValue>()),
            );
            for array in batch.columns() {
                for row in 0..array.len() {
                    if array.is_null(row) {
                        continue;
                    }
                    let extra = match array.data_type() {
                        DataType::Utf8 => array
                            .as_any()
                            .downcast_ref::<StringArray>()
                            .map(|array| array.value(row).len()),
                        DataType::LargeUtf8 => array
                            .as_any()
                            .downcast_ref::<LargeStringArray>()
                            .map(|array| array.value(row).len()),
                        DataType::Utf8View => array
                            .as_any()
                            .downcast_ref::<StringViewArray>()
                            .map(|array| array.value(row).len()),
                        DataType::Binary => array
                            .as_any()
                            .downcast_ref::<BinaryArray>()
                            .map(|array| array.value(row).len()),
                        DataType::LargeBinary => array
                            .as_any()
                            .downcast_ref::<LargeBinaryArray>()
                            .map(|array| array.value(row).len()),
                        DataType::BinaryView => array
                            .as_any()
                            .downcast_ref::<BinaryViewArray>()
                            .map(|array| array.value(row).len()),
                        DataType::FixedSizeBinary(_) => array
                            .as_any()
                            .downcast_ref::<FixedSizeBinaryArray>()
                            .map(|array| array.value(row).len()),
                        DataType::Decimal32(_, _)
                        | DataType::Decimal64(_, _)
                        | DataType::Decimal128(_, _)
                        | DataType::Decimal256(_, _) => Some(160),
                        DataType::Timestamp(_, _) | DataType::Time32(_) | DataType::Time64(_) => {
                            Some("microsecond".len())
                        }
                        _ => Some(0),
                    }
                    .ok_or_else(|| Status::internal("The query Arrow type is invalid."))?;
                    bytes = bytes.saturating_add(extra);
                }
            }
        }
        Ok(bytes)
    }

    pub(super) fn receipt_bytes(snapshot: &ArrowSnapshot) -> usize {
        let extraction = &snapshot.page.extraction;
        let mut bytes = size_of::<proto::QueryFrame>() + 16;
        for source in &extraction.sources {
            bytes = bytes.saturating_add(
                size_of::<proto::QueryCoverage>()
                    + size_of::<proto::SourceIdentity>()
                    + 48
                    + source.receipt.identity.node_id.len()
                    + "Reported".len(),
            );
            bytes = bytes.saturating_add(
                (source.expired.len() + source.recovery.len() + source.pending.len())
                    .saturating_mul(size_of::<proto::SourceGap>()),
            );
        }
        bytes
    }

    pub(super) fn row_receipts(snapshot: &ArrowSnapshot) -> usize {
        let extraction = &snapshot.page.extraction;
        let mut bytes = 0_usize;
        for key in &extraction.missing_contexts {
            bytes = bytes.saturating_add(
                size_of::<proto::ContextKey>()
                    + key.owner_id.len()
                    + key.entity_key.len()
                    + key.lifetime_key.len(),
            );
        }
        if let Some(receipt) = extraction.graph_traversal() {
            bytes = bytes.saturating_add(size_of::<proto::GraphTraversalReceipt>());
            for result in &receipt.result_ids {
                bytes = bytes.saturating_add(size_of::<String>() + result.len());
            }
        }
        bytes
    }

    pub(super) fn column_bytes(column: &Field) -> usize {
        let metadata = column.metadata();
        size_of::<proto::QueryColumn>()
            + column.name().len()
            + column.data_type().to_string().len().saturating_mul(2)
            + [
                "araphor.units",
                "araphor.null_meaning",
                "araphor.join_keys",
                "araphor.owner",
                "araphor.readiness",
            ]
            .iter()
            .map(|key| metadata.get(*key).map_or(16, String::len))
            .sum::<usize>()
    }

    pub(super) fn trace_detail_bytes(detail: &proto::TraceDetail) -> usize {
        let mut bytes = size_of::<proto::TraceDetail>()
            + detail.source.capacity()
            + detail.recipe.capacity()
            + detail.principal.capacity()
            + detail.finding_reference.capacity()
            + detail
                .targets
                .capacity()
                .saturating_mul(size_of::<proto::TraceTarget>())
            + detail
                .unresolved
                .capacity()
                .saturating_mul(size_of::<proto::TraceParticipant>());
        if let Some(receipt) = &detail.receipt {
            bytes = bytes
                .saturating_add(receipt.trace_id.capacity() + receipt.source_sha256.capacity());
        }
        for target in &detail.targets {
            bytes = bytes.saturating_add(
                target.node_boot_id.capacity()
                    + target.binding_id.capacity()
                    + target.node_id.capacity()
                    + target.cluster_uid.capacity()
                    + target.namespace_uid.capacity()
                    + target.pod_uid.capacity()
                    + target.container_id.capacity()
                    + target.container_name.capacity()
                    + target.namespace_name.capacity()
                    + target.pod_name.capacity(),
            );
        }
        for participant in &detail.unresolved {
            bytes = bytes
                .saturating_add(participant.fact_digest.capacity() + participant.state.capacity());
        }
        if let Some(selection) = &detail.requested {
            bytes = bytes.saturating_add(
                selection.target.capacity()
                    + selection.cluster.capacity()
                    + selection.container.capacity()
                    + selection
                        .node_ids
                        .capacity()
                        .saturating_mul(size_of::<String>())
                    + selection
                        .node_ids
                        .iter()
                        .map(String::capacity)
                        .sum::<usize>(),
            );
        }
        bytes
    }

    pub(super) fn rows(
        batches: &[RecordBatch],
        snapshot: &ArrowSnapshot,
        positions: &[StorePositionV1],
        evaluated_utc_ns: u64,
        limited: bool,
    ) -> Result<proto::QueryRows, Status> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(batches.iter().map(RecordBatch::num_rows).sum())
            .map_err(|_| Status::resource_exhausted("The query row allocation failed."))?;
        for batch in batches {
            for row in 0..batch.num_rows() {
                let mut values = Vec::new();
                values.try_reserve_exact(batch.num_columns()).map_err(|_| {
                    Status::resource_exhausted("The query value allocation failed.")
                })?;
                for array in batch.columns() {
                    let scalar = ScalarValue::try_from_array(array, row).map_err(|_| {
                        Status::unimplemented("The query Arrow type is unsupported.")
                    })?;
                    values.push(Self::value(scalar)?);
                }
                rows.push(proto::QueryRow { values });
            }
        }
        Ok(proto::QueryRows {
            rows,
            positions: positions.iter().copied().map(Self::position).collect(),
            limited,
            evaluated_utc_ns,
            missing_contexts: snapshot
                .page
                .extraction
                .missing_contexts
                .iter()
                .cloned()
                .map(Self::context)
                .collect(),
            graph_traversal: snapshot.page.extraction.graph_traversal().map(|receipt| {
                proto::GraphTraversalReceipt {
                    result_ids: receipt.result_ids.clone(),
                    unique_subject_count: receipt.unique_subject_count as u64,
                    versioned_subject_count: receipt.versioned_subject_count as u64,
                    relationship_count: receipt.relationship_count as u64,
                    max_hops: receipt.max_hops,
                    hop_boundary: receipt.hop_boundary,
                }
            }),
        })
    }

    #[cfg(test)]
    fn scalar_row(values: Vec<ScalarValue>) -> Result<proto::QueryRow, Status> {
        Ok(proto::QueryRow {
            values: values
                .into_iter()
                .map(Self::value)
                .collect::<Result<_, _>>()?,
        })
    }

    pub(super) fn column(column: &Field) -> proto::QueryColumn {
        let metadata = column.metadata();
        let property = |name: &str, default: &str| {
            metadata
                .get(name)
                .map_or_else(|| default.to_owned(), Clone::clone)
        };
        proto::QueryColumn {
            name: column.name().clone(),
            data_type: column.data_type().to_string(),
            units: property("araphor.units", ""),
            null_meaning: property(
                "araphor.null_meaning",
                if column.is_nullable() { "SQL NULL" } else { "" },
            ),
            join_keys: property("araphor.join_keys", ""),
            owner: property("araphor.owner", "query"),
            readiness: property("araphor.readiness", "available"),
        }
    }

    pub(super) fn position(position: StorePositionV1) -> proto::StorePosition {
        proto::StorePosition {
            commit_revision: position.commit_revision,
            ordinal: position.ordinal,
        }
    }

    fn context(context: AnalysisContextKeyV1) -> proto::ContextKey {
        proto::ContextKey {
            owner_id: context.owner_id,
            entity_key: context.entity_key,
            lifetime_key: context.lifetime_key,
            owner_revision: context.owner_revision,
        }
    }

    pub(super) fn bookmark(checkpoint: Option<&Cursor>) -> Result<Vec<u8>, Status> {
        checkpoint.map_or_else(
            || Ok(Vec::new()),
            |checkpoint| {
                checkpoint
                    .encode()
                    .map_err(|_| Status::internal("The query checkpoint is invalid."))
            },
        )
    }

    pub(super) fn coverage(coverage: &AnalysisSourceSnapshotV1) -> proto::QueryCoverage {
        let receipt = &coverage.receipt;
        let identity = &receipt.identity;
        proto::QueryCoverage {
            source: Some(proto::SourceIdentity {
                tenant_id: identity.tenant_id.to_vec(),
                node_id: identity.node_id.clone(),
                node_boot_id: identity.node_boot_id.to_vec(),
                label_epoch: identity.label_epoch,
                source_id: identity.source_id.to_vec(),
                source_epoch: identity.source_epoch,
            }),
            cpu_id: receipt.cpu_id,
            contiguous_cursor: receipt.contiguous_cursor,
            coverage_revision: receipt.coverage_revision,
            retained_floor: receipt.retained_floor,
            state: if !coverage.expired.is_empty()
                || !coverage.recovery.is_empty()
                || !coverage.pending.is_empty()
            {
                "Gapped"
            } else if coverage.coverage_report.is_some() {
                "Reported"
            } else {
                "Unknown"
            }
            .into(),
            expired: coverage.expired.iter().copied().map(Self::gap).collect(),
            recovery: coverage.recovery.iter().copied().map(Self::gap).collect(),
            pending: coverage.pending.iter().copied().map(Self::gap).collect(),
        }
    }

    fn gap(gap: AnalysisGapV1) -> proto::SourceGap {
        proto::SourceGap {
            first_cursor: gap.first_cursor,
            last_cursor: gap.last_cursor,
            commit_revision: gap.commit_revision,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use araphor_data::{AnalysisSourceReceiptV1, EvidenceIntakeIdentityV1};
    use proto::query_value::Kind;

    #[test]
    fn integer_precision_is_exact() -> Result<(), Status> {
        for (native, kind) in [
            (ScalarValue::Int64(Some(i64::MIN)), Kind::Signed(i64::MIN)),
            (
                ScalarValue::UInt64(Some(u64::MAX)),
                Kind::Unsigned(u64::MAX),
            ),
        ] {
            assert_eq!(Wire::value(native)?.kind, Some(kind));
        }
        for value in [i128::MIN, i128::MAX] {
            assert_eq!(
                Wire::signed128(value).kind,
                Some(Kind::Integer128(value.to_string()))
            );
        }
        assert_eq!(
            Wire::unsigned128(u128::MAX).kind,
            Some(Kind::Unsigned128(u128::MAX.to_string()))
        );
        let parameters = Parameters::try_from(vec![
            proto::QueryValue {
                kind: Some(Kind::Signed(i64::MIN)),
            },
            proto::QueryValue {
                kind: Some(Kind::Unsigned(u64::MAX)),
            },
        ])?;
        assert_eq!(
            parameters.0,
            vec![
                ScalarValue::Int64(Some(i64::MIN)),
                ScalarValue::UInt64(Some(u64::MAX))
            ]
        );
        Ok(())
    }

    #[test]
    fn scalar_payload_is_exact() -> Result<(), Box<dyn std::error::Error>> {
        let values = vec![
            ScalarValue::Null,
            ScalarValue::Boolean(Some(false)),
            ScalarValue::Utf8(Some("a\0b".into())),
            ScalarValue::Binary(Some(vec![0, 128, 255])),
            ScalarValue::Decimal128(Some(-12345), 38, 5),
            ScalarValue::TimestampNanosecond(Some(-1234), None),
            ScalarValue::Date32(Some(i32::MIN)),
            ScalarValue::Time64Microsecond(Some(i64::MAX)),
            ScalarValue::new_interval_mdn(-2, 3, i64::MIN),
        ];
        let (ScalarValue::Utf8(Some(text)), ScalarValue::Binary(Some(binary))) =
            (&values[2], &values[3])
        else {
            return Err("scalar buffers absent".into());
        };
        let owned = (text.as_ptr(), binary.as_ptr());
        let row = Wire::scalar_row(values)?;
        let (Some(Kind::Text(text)), Some(Kind::Binary(binary))) =
            (&row.values[2].kind, &row.values[3].kind)
        else {
            return Err("wire scalar buffers absent".into());
        };
        assert_eq!((text.as_ptr(), binary.as_ptr()), owned);
        assert_eq!(
            row.values,
            vec![
                proto::QueryValue {
                    kind: Some(Kind::Null(true))
                },
                proto::QueryValue {
                    kind: Some(Kind::Boolean(false))
                },
                proto::QueryValue {
                    kind: Some(Kind::Text("a\0b".into()))
                },
                proto::QueryValue {
                    kind: Some(Kind::Binary(vec![0, 128, 255]))
                },
                proto::QueryValue {
                    kind: Some(Kind::Decimal(proto::QueryDecimal {
                        width: 38,
                        scale: 5,
                        unscaled: "-12345".into(),
                    }))
                },
                proto::QueryValue {
                    kind: Some(Kind::Timestamp(proto::QueryTimestamp {
                        value: -1234,
                        unit: "nanosecond".into(),
                    }))
                },
                proto::QueryValue {
                    kind: Some(Kind::Date(i32::MIN))
                },
                proto::QueryValue {
                    kind: Some(Kind::Time(proto::QueryTimestamp {
                        value: i64::MAX,
                        unit: "microsecond".into(),
                    }))
                },
                proto::QueryValue {
                    kind: Some(Kind::Interval(proto::QueryInterval {
                        months: -2,
                        days: 3,
                        nanoseconds: i64::MIN,
                    }))
                },
            ]
        );
        assert!(Wire::value(ScalarValue::List(ScalarValue::new_list(
            &[ScalarValue::Null],
            &DataType::Null,
            true
        )))
        .is_err());
        Ok(())
    }

    #[test]
    fn parameter_payload_is_moved() -> Result<(), Status> {
        let text = "bounded text".to_owned();
        let text_ptr = text.as_ptr();
        let binary = vec![0, 128, 255];
        let binary_ptr = binary.as_ptr();
        let parameters = Parameters::try_from(vec![
            proto::QueryValue {
                kind: Some(Kind::Text(text)),
            },
            proto::QueryValue {
                kind: Some(Kind::Binary(binary)),
            },
            proto::QueryValue {
                kind: Some(Kind::Null(true)),
            },
        ])?;
        assert!(
            matches!(&parameters.0[0], ScalarValue::Utf8(Some(value)) if value.as_ptr() == text_ptr)
        );
        assert!(
            matches!(&parameters.0[1], ScalarValue::Binary(Some(value)) if value.as_ptr() == binary_ptr)
        );
        assert_eq!(parameters.0[2], ScalarValue::Null);
        Ok(())
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        for kind in [
            None,
            Some(Kind::Null(false)),
            Some(Kind::Real(f64::NAN)),
            Some(Kind::Real(f64::INFINITY)),
            Some(Kind::Integer128("1".into())),
            Some(Kind::Unsigned128("1".into())),
        ] {
            assert!(Parameters::try_from(vec![proto::QueryValue { kind }]).is_err());
        }
    }

    #[test]
    fn native_parameters_round_trip() -> Result<(), Status> {
        for (kind, native_type) in [
            (
                Kind::Decimal(proto::QueryDecimal {
                    width: 38,
                    scale: 5,
                    unscaled: format!("-{}", "9".repeat(38)),
                }),
                DataType::Decimal128(38, 5),
            ),
            (
                Kind::Decimal(proto::QueryDecimal {
                    width: 76,
                    scale: 76,
                    unscaled: "9".repeat(76),
                }),
                DataType::Decimal256(76, 76),
            ),
            (Kind::Date(i32::MIN), DataType::Date32),
            (Kind::Date(i32::MAX), DataType::Date32),
            (
                Kind::Time(proto::QueryTimestamp {
                    value: 86_399,
                    unit: "second".into(),
                }),
                DataType::Time32(TimeUnit::Second),
            ),
            (
                Kind::Time(proto::QueryTimestamp {
                    value: 86_399_999,
                    unit: "millisecond".into(),
                }),
                DataType::Time32(TimeUnit::Millisecond),
            ),
            (
                Kind::Time(proto::QueryTimestamp {
                    value: 86_399_999_999,
                    unit: "microsecond".into(),
                }),
                DataType::Time64(TimeUnit::Microsecond),
            ),
            (
                Kind::Time(proto::QueryTimestamp {
                    value: 86_399_999_999_999,
                    unit: "nanosecond".into(),
                }),
                DataType::Time64(TimeUnit::Nanosecond),
            ),
            (
                Kind::Interval(proto::QueryInterval {
                    months: i32::MIN,
                    days: i32::MAX,
                    nanoseconds: i64::MIN,
                }),
                DataType::Interval(arrow_schema::IntervalUnit::MonthDayNano),
            ),
        ] {
            let wire = proto::QueryValue { kind: Some(kind) };
            let mut parameters = Parameters::try_from(vec![wire.clone()])?.0;
            let native = parameters
                .pop()
                .ok_or_else(|| Status::internal("The native parameter is absent."))?;
            assert_eq!(native.data_type(), native_type);
            assert_eq!(Wire::value(native)?, wire);
        }
        Ok(())
    }

    #[test]
    fn native_parameter_bounds() {
        for (width, scale, unscaled) in [
            (0, 0, "0".into()),
            (77, 0, "0".into()),
            (256, 0, "0".into()),
            (4, 5, "1".into()),
            (4, u32::MAX, "1".into()),
            (2, 0, "100".into()),
            (38, 0, "9".repeat(39)),
            (76, 0, "9".repeat(77)),
            (4, 0, "1.5".into()),
            (4, 0, "".into()),
        ] {
            let error = Parameters::try_from(vec![proto::QueryValue {
                kind: Some(Kind::Decimal(proto::QueryDecimal {
                    width,
                    scale,
                    unscaled,
                })),
            }])
            .err();
            assert_eq!(
                error.map(|error| error.code()),
                Some(tonic::Code::InvalidArgument)
            );
        }
        for (unit, end) in [
            ("second", 86_400),
            ("millisecond", 86_400_000),
            ("microsecond", 86_400_000_000),
            ("nanosecond", 86_400_000_000_000),
            ("boot", 1),
        ] {
            for value in [-1, end, i64::MAX] {
                let error = Parameters::try_from(vec![proto::QueryValue {
                    kind: Some(Kind::Time(proto::QueryTimestamp {
                        value,
                        unit: unit.into(),
                    })),
                }])
                .err();
                assert_eq!(
                    error.map(|error| error.code()),
                    Some(tonic::Code::InvalidArgument)
                );
            }
        }
        for kind in [
            Kind::Integer128(i128::MIN.to_string()),
            Kind::Unsigned128(u128::MAX.to_string()),
        ] {
            let error = Parameters::try_from(vec![proto::QueryValue { kind: Some(kind) }]).err();
            assert_eq!(
                error.map(|error| error.code()),
                Some(tonic::Code::Unimplemented)
            );
        }
    }

    #[test]
    fn parameter_bounds_are_exact() -> Result<(), Status> {
        let values = vec![
            proto::QueryValue {
                kind: Some(Kind::Null(true))
            };
            Planner::PARAMETER_COUNT
        ];
        assert_eq!(
            Parameters::try_from(values)?.0.len(),
            Planner::PARAMETER_COUNT
        );
        let values = vec![
            proto::QueryValue {
                kind: Some(Kind::Null(true))
            };
            Planner::PARAMETER_COUNT + 1
        ];
        assert!(Parameters::try_from(values).is_err());
        let size = Planner::PARAMETER_BYTES - size_of::<ScalarValue>();
        assert!(Parameters::try_from(vec![proto::QueryValue {
            kind: Some(Kind::Binary(vec![0; size])),
        }])
        .is_ok());
        assert!(Parameters::try_from(vec![proto::QueryValue {
            kind: Some(Kind::Binary(vec![0; size + 1])),
        }])
        .is_err());
        Ok(())
    }

    #[test]
    fn timestamp_parameters_are_exact() -> Result<(), Status> {
        for (unit, value, native) in [
            ("second", i64::MAX, TimeUnit::Second),
            ("millisecond", i64::MIN, TimeUnit::Millisecond),
            ("microsecond", i64::MAX, TimeUnit::Microsecond),
            ("nanosecond", -1, TimeUnit::Nanosecond),
        ] {
            let parameters = Parameters::try_from(vec![proto::QueryValue {
                kind: Some(Kind::Timestamp(proto::QueryTimestamp {
                    value,
                    unit: unit.into(),
                })),
            }])?;
            assert_eq!(
                parameters.0,
                vec![match native {
                    TimeUnit::Second => ScalarValue::TimestampSecond(Some(value), None),
                    TimeUnit::Millisecond => ScalarValue::TimestampMillisecond(Some(value), None),
                    TimeUnit::Microsecond => ScalarValue::TimestampMicrosecond(Some(value), None),
                    TimeUnit::Nanosecond => ScalarValue::TimestampNanosecond(Some(value), None),
                }]
            );
        }
        assert!(Parameters::try_from(vec![proto::QueryValue {
            kind: Some(Kind::Timestamp(proto::QueryTimestamp {
                value: 1,
                unit: "boot".into()
            })),
        }])
        .is_err());
        Ok(())
    }

    #[test]
    fn metadata_fields_are_exact() {
        let source = Field::new("cursor", DataType::UInt64, false).with_metadata(
            std::collections::HashMap::from([
                ("araphor.units".into(), "source cursor".into()),
                ("araphor.null_meaning".into(), "unavailable".into()),
                ("araphor.join_keys".into(), "source_id,cpu_id".into()),
                ("araphor.owner".into(), "source receipt".into()),
                ("araphor.readiness".into(), "Reported".into()),
            ]),
        );
        let owned = source.name().as_ptr();
        let column = Wire::column(&source);
        assert_eq!(source.name().as_ptr(), owned);
        assert_eq!(
            column,
            proto::QueryColumn {
                name: "cursor".into(),
                data_type: "UInt64".into(),
                units: "source cursor".into(),
                null_meaning: "unavailable".into(),
                join_keys: "source_id,cpu_id".into(),
                owner: "source receipt".into(),
                readiness: "Reported".into(),
            }
        );
        let position = Wire::position(StorePositionV1 {
            commit_revision: u64::MAX,
            ordinal: u32::MAX,
        });
        assert_eq!(position.commit_revision, u64::MAX);
        assert_eq!(position.ordinal, u32::MAX);
        let context = AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "owner".into(),
            entity_key: vec![0, 255],
            lifetime_key: vec![128, 0],
            owner_revision: u64::MAX,
        };
        let owned = (
            context.owner_id.as_ptr(),
            context.entity_key.as_ptr(),
            context.lifetime_key.as_ptr(),
        );
        let context = Wire::context(context);
        assert_eq!(
            (
                context.owner_id.as_ptr(),
                context.entity_key.as_ptr(),
                context.lifetime_key.as_ptr()
            ),
            owned
        );
        assert_eq!(
            context,
            proto::ContextKey {
                owner_id: "owner".into(),
                entity_key: vec![0, 255],
                lifetime_key: vec![128, 0],
                owner_revision: u64::MAX,
            }
        );
    }

    #[test]
    fn empty_bookmark_is_empty() -> Result<(), Status> {
        assert!(Wire::bookmark(None)?.is_empty());
        Ok(())
    }

    #[test]
    fn coverage_fields_are_exact() {
        let gap = AnalysisGapV1 {
            first_cursor: 7,
            last_cursor: 9,
            commit_revision: u64::MAX,
        };
        let mut coverage = AnalysisSourceSnapshotV1 {
            receipt: AnalysisSourceReceiptV1 {
                identity: EvidenceIntakeIdentityV1 {
                    tenant_id: [1; 16],
                    node_id: "node".into(),
                    node_boot_id: [2; 16],
                    label_epoch: 3,
                    source_id: [4; 16],
                    source_epoch: 5,
                },
                cpu_id: u32::MAX,
                contiguous_cursor: 6,
                coverage_revision: 10,
                retained_floor: 2,
            },
            expired: vec![gap],
            recovery: vec![gap],
            pending: vec![gap],
            coverage_report: None,
        };
        let wire = Wire::coverage(&coverage);
        assert_eq!(
            wire.source,
            Some(proto::SourceIdentity {
                tenant_id: vec![1; 16],
                node_id: "node".into(),
                node_boot_id: vec![2; 16],
                label_epoch: 3,
                source_id: vec![4; 16],
                source_epoch: 5,
            })
        );
        assert_eq!(wire.cpu_id, u32::MAX);
        assert_eq!(wire.contiguous_cursor, 6);
        assert_eq!(wire.coverage_revision, 10);
        assert_eq!(wire.retained_floor, 2);
        assert_eq!(wire.state, "Gapped");
        assert_eq!(wire.expired, vec![Wire::gap(gap)]);
        assert_eq!(wire.recovery, wire.expired);
        assert_eq!(wire.pending, wire.expired);
        coverage.expired.clear();
        coverage.recovery.clear();
        coverage.pending.clear();
        for (report, expected) in [(None, "Unknown"), (Some(vec![1]), "Reported")] {
            coverage.coverage_report = report;
            assert_eq!(Wire::coverage(&coverage).state, expected);
        }
    }
}
