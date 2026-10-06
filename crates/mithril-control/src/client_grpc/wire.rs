use std::mem::size_of;

use araphor_data::{
    AnalysisContextKeyV1, AnalysisGapV1, QueryCheckpoint, QueryColumn, QueryCoverage,
    QueryCoverageState, QueryFrame, QueryOperation, QueryPayload, QueryResult, QuerySql,
    StorePositionV1,
};
use duckdb::types::{TimeUnit, Value};
use erebor_runtime_ipc::araphor as proto;
use tonic::Status;

pub(super) struct Parameters(pub(super) Vec<Value>);

impl TryFrom<Vec<proto::QueryValue>> for Parameters {
    type Error = Status;

    fn try_from(values: Vec<proto::QueryValue>) -> Result<Self, Self::Error> {
        if values.len() > QuerySql::PARAMETER_COUNT {
            return Err(Status::invalid_argument(
                "SQL parameter count exceeds its bound.",
            ));
        }
        let mut bytes = 0_usize;
        for value in &values {
            bytes = bytes.saturating_add(size_of::<Value>());
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
                _ => return Err(Status::invalid_argument("SQL parameter type is invalid.")),
            }
            if bytes > QuerySql::PARAMETER_BYTES {
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
                Some(proto::query_value::Kind::Null(true)) => Value::Null,
                Some(proto::query_value::Kind::Boolean(value)) => Value::Boolean(value),
                Some(proto::query_value::Kind::Signed(value)) => Value::BigInt(value),
                Some(proto::query_value::Kind::Unsigned(value)) => Value::UBigInt(value),
                Some(proto::query_value::Kind::Real(value)) => Value::Double(value),
                Some(proto::query_value::Kind::Text(value)) => Value::Text(value),
                Some(proto::query_value::Kind::Binary(value)) => Value::Blob(value),
                Some(proto::query_value::Kind::Timestamp(value)) => Self::timestamp(&value)?,
                _ => return Err(Status::invalid_argument("SQL parameter type is invalid.")),
            };
            parameters.push(value);
        }
        Ok(Self(parameters))
    }
}

impl Parameters {
    fn timestamp(value: &proto::QueryTimestamp) -> Result<Value, Status> {
        let unit = match value.unit.as_str() {
            "second" if value.value.checked_mul(1_000_000).is_some() => TimeUnit::Second,
            "millisecond" if value.value.checked_mul(1_000).is_some() => TimeUnit::Millisecond,
            "microsecond" => TimeUnit::Microsecond,
            "nanosecond" if value.value % 1_000 == 0 => TimeUnit::Nanosecond,
            _ => {
                return Err(Status::invalid_argument(
                    "SQL timestamp parameter is invalid.",
                ))
            }
        };
        Ok(Value::Timestamp(unit, value.value))
    }
}

pub(super) struct WireValue(pub(super) proto::QueryValue);

impl TryFrom<&Value> for WireValue {
    type Error = Status;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        use proto::query_value::Kind;

        let kind = match value {
            Value::Null => Kind::Null(true),
            Value::Boolean(value) => Kind::Boolean(*value),
            Value::TinyInt(value) => Kind::Signed(i64::from(*value)),
            Value::SmallInt(value) => Kind::Signed(i64::from(*value)),
            Value::Int(value) => Kind::Signed(i64::from(*value)),
            Value::BigInt(value) => Kind::Signed(*value),
            Value::HugeInt(value) => Kind::Integer128(value.to_string()),
            Value::UHugeInt(value) => Kind::Unsigned128(value.to_string()),
            Value::UTinyInt(value) => Kind::Unsigned(u64::from(*value)),
            Value::USmallInt(value) => Kind::Unsigned(u64::from(*value)),
            Value::UInt(value) => Kind::Unsigned(u64::from(*value)),
            Value::UBigInt(value) => Kind::Unsigned(*value),
            Value::Float(value) => Kind::Real(f64::from(*value)),
            Value::Double(value) => Kind::Real(*value),
            Value::Decimal(value) => Kind::Decimal(proto::QueryDecimal {
                width: u32::from(value.width()),
                scale: u32::from(value.scale()),
                unscaled: value.value().to_string(),
            }),
            Value::Timestamp(unit, value) => Kind::Timestamp(Self::timestamp(*unit, *value)),
            Value::Text(value) => Kind::Text(value.clone()),
            Value::Blob(value) => Kind::Binary(value.clone()),
            Value::Date32(value) => Kind::Date(*value),
            Value::Time64(unit, value) => Kind::Time(Self::timestamp(*unit, *value)),
            Value::Interval {
                months,
                days,
                nanos,
            } => Kind::Interval(proto::QueryInterval {
                months: *months,
                days: *days,
                nanoseconds: *nanos,
            }),
            _ => {
                return Err(Status::unimplemented(
                    "The query value type is unsupported.",
                ))
            }
        };
        Ok(Self(proto::QueryValue { kind: Some(kind) }))
    }
}

impl WireValue {
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
}

pub(super) struct WireFrame {
    pub(super) message: proto::QueryFrame,
    // Keep the native output lease until the transport advances or closes.
    pub(super) owner: QueryFrame,
}

impl TryFrom<QueryFrame> for WireFrame {
    type Error = Status;

    fn try_from(owner: QueryFrame) -> Result<Self, Self::Error> {
        use proto::query_frame::Payload;

        let coverage = owner.coverage().iter().map(Self::coverage).collect();
        let payload = match &owner.payload {
            QueryPayload::Metadata(metadata) => Payload::Metadata(proto::QueryMetadata {
                columns: metadata.columns.iter().map(Self::column).collect(),
                evaluated_utc_ns: metadata.evaluated_utc_ns,
                dependency_revision: metadata.dependency_revision,
                row_limit: metadata.row_limit as u64,
                byte_limit: metadata.byte_limit as u64,
                moving_resolution_ns: metadata.moving_resolution_ns,
                resume_semantics: metadata.resume_semantics.into(),
            }),
            QueryPayload::Append { result } | QueryPayload::Replace { result } => {
                Payload::Rows(Self::rows(result)?)
            }
            QueryPayload::Checkpoint { checkpoint, .. } => {
                Payload::Checkpoint(Self::bookmark(Some(checkpoint))?)
            }
            QueryPayload::Health {
                dependency_revision,
                storage_health,
                ..
            } => Payload::Health(proto::QueryHealth {
                dependency_revision: *dependency_revision,
                write_ready: storage_health.write_ready,
                retention_healthy: storage_health.retention_healthy,
                intake_capacity: storage_health.intake_capacity,
                maintenance_capacity: storage_health.maintenance_capacity,
            }),
            QueryPayload::Error {
                code,
                reason,
                position,
                floor,
                last_checkpoint,
                ..
            } => Payload::Error(proto::QueryError {
                code: format!("{code:?}"),
                reason: (*reason).into(),
                last_checkpoint: Self::bookmark(last_checkpoint.as_ref())?,
                position: position.map(Self::position),
                floor: floor.map(Self::position),
            }),
            QueryPayload::Terminal {
                reason,
                last_checkpoint,
                ..
            } => Payload::Terminal(proto::QueryTerminal {
                reason: format!("{reason:?}"),
                last_checkpoint: Self::bookmark(last_checkpoint.as_ref())?,
            }),
        };
        let message = proto::QueryFrame {
            schema_version: owner.schema_version,
            operation: match owner.operation {
                QueryOperation::Append => proto::QueryOperation::Append as i32,
                QueryOperation::Replace => proto::QueryOperation::Replace as i32,
            },
            store_uuid: owner.store_uuid.to_vec(),
            recovery_epoch: owner.recovery_epoch,
            read_revision: owner.read_revision,
            clock_changed: owner.clock_changed,
            coverage,
            payload: Some(payload),
        };
        Ok(Self { message, owner })
    }
}

impl WireFrame {
    fn rows(result: &QueryResult) -> Result<proto::QueryRows, Status> {
        Ok(proto::QueryRows {
            rows: result
                .rows
                .iter()
                .map(|row| Self::row(row))
                .collect::<Result<_, _>>()?,
            positions: result
                .positions
                .iter()
                .copied()
                .map(Self::position)
                .collect(),
            limited: result.limited,
            evaluated_utc_ns: result.evaluated_utc_ns,
            missing_contexts: result.missing_contexts.iter().map(Self::context).collect(),
        })
    }

    fn row(values: &[Value]) -> Result<proto::QueryRow, Status> {
        Ok(proto::QueryRow {
            values: values
                .iter()
                .map(|value| WireValue::try_from(value).map(|value| value.0))
                .collect::<Result<_, _>>()?,
        })
    }

    fn column(column: &QueryColumn) -> proto::QueryColumn {
        proto::QueryColumn {
            name: column.name.clone(),
            data_type: column.data_type.clone(),
            units: column.units.into(),
            null_meaning: column.null_meaning.into(),
            join_keys: column.join_keys.into(),
            owner: column.owner.into(),
            readiness: column.readiness.into(),
        }
    }

    fn position(position: StorePositionV1) -> proto::StorePosition {
        proto::StorePosition {
            commit_revision: position.commit_revision,
            ordinal: position.ordinal,
        }
    }

    fn context(context: &AnalysisContextKeyV1) -> proto::ContextKey {
        proto::ContextKey {
            owner_id: context.owner_id.clone(),
            entity_key: context.entity_key.clone(),
            lifetime_key: context.lifetime_key.clone(),
            owner_revision: context.owner_revision,
        }
    }

    fn bookmark(checkpoint: Option<&QueryCheckpoint>) -> Result<Vec<u8>, Status> {
        checkpoint.map_or_else(
            || Ok(Vec::new()),
            |checkpoint| {
                checkpoint
                    .encode()
                    .map_err(|_| Status::internal("The query checkpoint is invalid."))
            },
        )
    }

    pub(super) fn coverage(coverage: &QueryCoverage) -> proto::QueryCoverage {
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
            state: match coverage.state {
                QueryCoverageState::Unknown => "Unknown",
                QueryCoverageState::Reported => "Reported",
                QueryCoverageState::Gapped => "Gapped",
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
    use duckdb::types::Decimal;
    use proto::query_value::Kind;

    #[test]
    fn integer_precision_is_exact() -> Result<(), Status> {
        for (native, kind) in [
            (Value::BigInt(i64::MIN), Kind::Signed(i64::MIN)),
            (Value::UBigInt(u64::MAX), Kind::Unsigned(u64::MAX)),
            (
                Value::HugeInt(i128::MIN),
                Kind::Integer128(i128::MIN.to_string()),
            ),
            (
                Value::HugeInt(i128::MAX),
                Kind::Integer128(i128::MAX.to_string()),
            ),
            (
                Value::UHugeInt(u128::MAX),
                Kind::Unsigned128(u128::MAX.to_string()),
            ),
        ] {
            assert_eq!(WireValue::try_from(&native)?.0.kind, Some(kind));
        }
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
            vec![Value::BigInt(i64::MIN), Value::UBigInt(u64::MAX)]
        );
        Ok(())
    }

    #[test]
    fn scalar_payload_is_exact() -> Result<(), Box<dyn std::error::Error>> {
        let values = vec![
            Value::Null,
            Value::Boolean(false),
            Value::Text("a\0b".into()),
            Value::Blob(vec![0, 128, 255]),
            Value::Decimal(Decimal::new(38, 5, -12345)?),
            Value::Timestamp(TimeUnit::Nanosecond, -1234),
            Value::Date32(i32::MIN),
            Value::Time64(TimeUnit::Microsecond, i64::MAX),
            Value::Interval {
                months: -2,
                days: 3,
                nanos: i64::MIN,
            },
        ];
        let row = WireFrame::row(&values)?;
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
        assert!(WireValue::try_from(&Value::List(vec![Value::Null])).is_err());
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
        assert!(matches!(&parameters.0[0], Value::Text(value) if value.as_ptr() == text_ptr));
        assert!(matches!(&parameters.0[1], Value::Blob(value) if value.as_ptr() == binary_ptr));
        assert_eq!(parameters.0[2], Value::Null);
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
            Some(Kind::Decimal(proto::QueryDecimal {
                width: 4,
                scale: 1,
                unscaled: "1".into(),
            })),
            Some(Kind::Date(1)),
            Some(Kind::Time(proto::QueryTimestamp {
                value: 1,
                unit: "microsecond".into(),
            })),
            Some(Kind::Interval(proto::QueryInterval {
                months: 1,
                days: 1,
                nanoseconds: 1,
            })),
        ] {
            assert!(Parameters::try_from(vec![proto::QueryValue { kind }]).is_err());
        }
    }

    #[test]
    fn parameter_bounds_are_exact() -> Result<(), Status> {
        let values = vec![
            proto::QueryValue {
                kind: Some(Kind::Null(true))
            };
            QuerySql::PARAMETER_COUNT
        ];
        assert_eq!(
            Parameters::try_from(values)?.0.len(),
            QuerySql::PARAMETER_COUNT
        );
        let values = vec![
            proto::QueryValue {
                kind: Some(Kind::Null(true))
            };
            QuerySql::PARAMETER_COUNT + 1
        ];
        assert!(Parameters::try_from(values).is_err());
        let size = QuerySql::PARAMETER_BYTES - size_of::<Value>();
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
            ("second", -9, TimeUnit::Second),
            ("millisecond", -9, TimeUnit::Millisecond),
            ("microsecond", i64::MAX, TimeUnit::Microsecond),
            ("nanosecond", -9000, TimeUnit::Nanosecond),
        ] {
            let parameters = Parameters::try_from(vec![proto::QueryValue {
                kind: Some(Kind::Timestamp(proto::QueryTimestamp {
                    value,
                    unit: unit.into(),
                })),
            }])?;
            assert_eq!(parameters.0, vec![Value::Timestamp(native, value)]);
        }
        for (unit, value) in [
            ("boot", 1),
            ("second", i64::MAX),
            ("millisecond", i64::MIN),
            ("nanosecond", -1),
        ] {
            assert!(Parameters::try_from(vec![proto::QueryValue {
                kind: Some(Kind::Timestamp(proto::QueryTimestamp {
                    value,
                    unit: unit.into()
                })),
            }])
            .is_err());
        }
        Ok(())
    }

    #[test]
    fn metadata_fields_are_exact() {
        let column = QueryColumn {
            name: "cursor".into(),
            data_type: "UBIGINT".into(),
            units: "source cursor",
            null_meaning: "unavailable",
            join_keys: "source_id,cpu_id",
            owner: "source receipt",
            readiness: "Reported",
        };
        assert_eq!(
            WireFrame::column(&column),
            proto::QueryColumn {
                name: column.name,
                data_type: column.data_type,
                units: "source cursor".into(),
                null_meaning: "unavailable".into(),
                join_keys: "source_id,cpu_id".into(),
                owner: "source receipt".into(),
                readiness: "Reported".into(),
            }
        );
        let position = WireFrame::position(StorePositionV1 {
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
        assert_eq!(
            WireFrame::context(&context),
            proto::ContextKey {
                owner_id: "owner".into(),
                entity_key: vec![0, 255],
                lifetime_key: vec![128, 0],
                owner_revision: u64::MAX,
            }
        );
    }

    #[test]
    fn bookmark_fields_are_exact() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = br#"{"schema_version":1,"store_uuid":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"recovery_epoch":9,"operation":"Append","position":{"commit_revision":18446744073709551615,"ordinal":4294967295},"read_revision":18446744073709551615}"#;
        let checkpoint = QueryCheckpoint::try_from(encoded.as_slice())?;
        assert_eq!(WireFrame::bookmark(Some(&checkpoint))?, encoded);
        assert_eq!(checkpoint.read_revision(), u64::MAX);
        let position = WireFrame::position(checkpoint.position().ok_or("missing position")?);
        assert_eq!(position.commit_revision, u64::MAX);
        assert_eq!(position.ordinal, u32::MAX);
        assert!(WireFrame::bookmark(None)?.is_empty());
        Ok(())
    }

    #[test]
    fn coverage_fields_are_exact() {
        let gap = AnalysisGapV1 {
            first_cursor: 7,
            last_cursor: 9,
            commit_revision: u64::MAX,
        };
        let mut coverage = QueryCoverage {
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
            state: QueryCoverageState::Gapped,
        };
        let wire = WireFrame::coverage(&coverage);
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
        assert_eq!(wire.expired, vec![WireFrame::gap(gap)]);
        assert_eq!(wire.recovery, wire.expired);
        assert_eq!(wire.pending, wire.expired);
        for (state, expected) in [
            (QueryCoverageState::Unknown, "Unknown"),
            (QueryCoverageState::Reported, "Reported"),
        ] {
            coverage.state = state;
            assert_eq!(WireFrame::coverage(&coverage).state, expected);
        }
    }
}
