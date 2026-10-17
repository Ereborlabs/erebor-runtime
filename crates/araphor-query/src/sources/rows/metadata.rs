use std::fmt::Write as _;
use std::mem::size_of;
use std::sync::Arc;

use araphor_data::{AnalysisPositionPageV1, AnalysisReadControl, AnalysisTableRequests};
use datafusion::arrow::array::{
    builder::{BooleanBuilder, StringBuilder, UInt32Builder},
    ArrayRef, BooleanArray, RecordBatch, RecordBatchOptions, StringArray, UInt32Array,
};
use datafusion::arrow::buffer::Buffer;
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};

use super::SourceSnapshot;

impl SourceSnapshot {
    pub(super) fn catalog(
        requests: &AnalysisTableRequests,
        page: &mut AnalysisPositionPageV1,
        limit: usize,
        control: &AnalysisReadControl,
    ) -> araphor_data::Result<()> {
        let Some(indices) = requests.get("catalog").and_then(Option::as_ref) else {
            return Ok(());
        };
        let schemas = Self::schemas();
        let canonical = schemas
            .get("catalog")
            .ok_or_else(|| Self::catalog_invalid("the catalog has no native Arrow schema"))?;
        let rows = schemas.values().try_fold(0usize, |rows, schema| {
            rows.checked_add(schema.fields().len())
                .ok_or_else(Self::catalog_overflow)
        })?;
        let enabled = (
            page.extraction.discovery_enabled,
            page.extraction.graph_enabled,
            page.extraction.notification_enabled,
        );
        let field_capacity = if indices.is_empty() {
            0
        } else {
            indices
                .len()
                .max(4)
                .checked_next_power_of_two()
                .ok_or_else(Self::catalog_overflow)?
        };
        let mut bytes = size_of::<RecordBatch>()
            .checked_add(size_of::<(String, Vec<RecordBatch>)>())
            .and_then(|bytes| bytes.checked_add("catalog".len()))
            .and_then(|bytes| bytes.checked_add(size_of::<Schema>() + 4 * size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(field_capacity.checked_mul(size_of::<FieldRef>())?))
            .and_then(|bytes| {
                bytes.checked_add(indices.len().checked_mul(
                    size_of::<ArrayRef>() + size_of::<FieldRef>() + size_of::<usize>(),
                )?)
            })
            .ok_or_else(Self::catalog_overflow)?;
        let mut projected = 0usize;
        for index in indices {
            control.check()?;
            let column = canonical
                .fields()
                .get(*index)
                .ok_or_else(|| Self::catalog_invalid("the catalog column index is invalid"))?;
            let (allocated, logical) = Self::catalog_bytes(column.name(), rows, enabled)?;
            bytes = bytes
                .checked_add(allocated)
                .ok_or_else(Self::catalog_overflow)?;
            projected = projected
                .checked_add(logical)
                .ok_or_else(Self::catalog_overflow)?;
        }
        page.extraction.input_bytes = page
            .extraction
            .input_bytes
            .checked_add(bytes)
            .filter(|bytes| *bytes <= limit)
            .ok_or_else(Self::catalog_overflow)?;
        let projected = page
            .extraction
            .projected_bytes
            .checked_add(projected)
            .ok_or_else(Self::catalog_overflow)?;
        let indices = indices.iter().copied().collect::<Vec<_>>();
        let schema = Arc::new(canonical.project(&indices).map_err(Self::catalog_arrow)?);
        let mut arrays = Vec::<ArrayRef>::with_capacity(indices.len());
        for index in indices {
            let column = canonical.field(index).name().as_str();
            let array: ArrayRef = match column {
                "ordinal" => {
                    let mut builder = UInt32Builder::with_capacity(rows);
                    for schema in schemas.values() {
                        for ordinal in 0..schema.fields().len() {
                            control.check()?;
                            builder.append_value(
                                u32::try_from(ordinal).map_err(|_| Self::catalog_overflow())?,
                            );
                        }
                    }
                    Arc::new(builder.finish())
                }
                "nullable" => {
                    let mut builder = BooleanBuilder::with_capacity(rows);
                    for schema in schemas.values() {
                        for field in schema.fields() {
                            control.check()?;
                            builder.append_value(field.is_nullable());
                        }
                    }
                    Arc::new(builder.finish())
                }
                _ => {
                    let values = Self::catalog_values(column, enabled)?;
                    let mut builder = StringBuilder::with_capacity(rows, values);
                    for (relation, schema) in schemas {
                        let readiness = Self::catalog_readiness(relation, enabled);
                        for field in schema.fields() {
                            control.check()?;
                            if column == "data_type" {
                                write!(&mut builder, "{}", field.data_type())
                                    .map_err(|_| Self::catalog_overflow())?;
                                builder.append_value("");
                            } else {
                                builder.append_value(Self::catalog_text(
                                    column, relation, field, readiness,
                                )?);
                            }
                        }
                    }
                    Arc::new(builder.finish())
                }
            };
            arrays.push(array);
        }
        let batch = RecordBatch::try_new_with_options(
            schema,
            arrays,
            &RecordBatchOptions::new().with_row_count(Some(rows)),
        )
        .map_err(Self::catalog_arrow)?;
        page.extraction.projected_bytes = projected;
        page.tables.insert("catalog".into(), vec![batch]);
        Ok(())
    }

    fn catalog_bytes(
        column: &str,
        rows: usize,
        enabled: (bool, bool, bool),
    ) -> araphor_data::Result<(usize, usize)> {
        let (bytes, projected) = match column {
            "ordinal" => (
                rows.checked_mul(size_of::<u32>())
                    .and_then(|bytes| bytes.checked_add(size_of::<UInt32Array>())),
                rows.checked_mul(5),
            ),
            "nullable" => (
                rows.div_ceil(512)
                    .checked_mul(64)
                    .and_then(|bytes| bytes.checked_add(size_of::<BooleanArray>())),
                rows.checked_mul(2),
            ),
            _ => {
                let values = Self::catalog_values(column, enabled)?;
                (
                    rows.checked_add(1)
                        .and_then(|rows| rows.checked_mul(size_of::<i32>()))
                        .and_then(|bytes| bytes.checked_add(values))
                        .and_then(|bytes| {
                            bytes.checked_add(size_of::<StringArray>() + 4 * size_of::<i32>())
                        }),
                    rows.checked_mul(5)
                        .and_then(|bytes| bytes.checked_add(values)),
                )
            }
        };
        Ok((
            bytes
                .and_then(|bytes| {
                    bytes.checked_add(2 * size_of::<usize>() + 4 * size_of::<Buffer>())
                })
                .ok_or_else(Self::catalog_overflow)?,
            projected.ok_or_else(Self::catalog_overflow)?,
        ))
    }

    fn catalog_values(column: &str, enabled: (bool, bool, bool)) -> araphor_data::Result<usize> {
        let mut size = CatalogSize { bytes: 0 };
        for (relation, schema) in Self::schemas() {
            let readiness = Self::catalog_readiness(relation, enabled);
            for field in schema.fields() {
                if column == "data_type" {
                    write!(&mut size, "{}", field.data_type())
                        .map_err(|_| Self::catalog_overflow())?;
                } else {
                    size.write_str(Self::catalog_text(column, relation, field, readiness)?)
                        .map_err(|_| Self::catalog_overflow())?;
                }
            }
        }
        if size.bytes > i32::MAX as usize {
            return Err(Self::catalog_overflow());
        }
        Ok(size.bytes)
    }

    fn catalog_text<'a>(
        column: &str,
        relation: &'a str,
        field: &'a Field,
        readiness: &'a str,
    ) -> araphor_data::Result<&'a str> {
        Ok(match column {
            "relation" => relation,
            "column_name" => field.name(),
            "units" => field
                .metadata()
                .get("araphor.units")
                .map_or("", String::as_str),
            "null_meaning" => field
                .metadata()
                .get("araphor.null_meaning")
                .map_or("", String::as_str),
            "join_keys" => field
                .metadata()
                .get("araphor.join_keys")
                .map_or("", String::as_str),
            "owner" => field
                .metadata()
                .get("araphor.owner")
                .map_or("araphor-data.AnalysisStore", String::as_str),
            "readiness" => readiness,
            "description" => field
                .metadata()
                .get("araphor.description")
                .map_or("", String::as_str),
            _ => {
                return Err(Self::catalog_invalid(
                    "the catalog column has no native builder",
                ))
            }
        })
    }

    fn catalog_readiness(relation: &str, enabled: (bool, bool, bool)) -> &'static str {
        let available = match relation {
            "behaviors" => enabled.0,
            "findings"
            | "relationships"
            | "graph_subjects"
            | "graph_branches"
            | "correlation_packages"
            | "policy_observations"
            | "graph_manifest" => enabled.1,
            "notifications" => enabled.2,
            _ => return "available",
        };
        if available {
            "enabled"
        } else {
            "disabled"
        }
    }

    fn catalog_overflow() -> araphor_data::Error {
        araphor_data::Error::AnalysisInputTooLarge {
            resource: "native source Arrow allocation",
            location: snafu::location!(),
        }
    }

    fn catalog_invalid(reason: &'static str) -> araphor_data::Error {
        araphor_data::Error::AnalysisState {
            path: "<query catalog>".into(),
            reason: reason.into(),
            location: snafu::location!(),
        }
    }

    fn catalog_arrow(source: datafusion::arrow::error::ArrowError) -> araphor_data::Error {
        araphor_data::Error::AnalysisContract {
            source: source.into(),
            location: snafu::location!(),
        }
    }
}

struct CatalogSize {
    bytes: usize,
}

impl std::fmt::Write for CatalogSize {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.bytes = self.bytes.checked_add(value.len()).ok_or(std::fmt::Error)?;
        Ok(())
    }
}
