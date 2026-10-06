use duckdb::types::{Value, ValueRef};
use duckdb::{params_from_iter, Config, Connection};
use snafu::ResultExt as _;

use super::input::InputRelations;
use super::{QueryOperation, QueryOwner};
use crate::{AnalysisReadControl, Result, StorePositionV1};

pub(super) struct EvaluationLimits {
    pub rows: usize,
    pub bytes: usize,
    pub summary_bytes: usize,
    pub operation: QueryOperation,
    pub complete: bool,
}

pub(super) struct EvaluationResult {
    pub columns: Vec<String>,
    pub types: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub output_bytes: usize,
    pub limited: bool,
    pub scanned_through: StorePositionV1,
}

pub(super) struct QueryEvaluation;

impl QueryEvaluation {
    pub(super) fn run(
        input: &InputRelations,
        sql: &str,
        parameters: &[Value],
        limits: EvaluationLimits,
        position: StorePositionV1,
        control: &AnalysisReadControl,
        #[cfg(test)] native_failed: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<EvaluationResult> {
        let mut config = Config::default()
            .with("temp_directory", "")
            .and_then(|config| config.enable_external_access(false))
            .and_then(|config| config.enable_autoload_extension(false))
            .and_then(|config| config.threads(1))
            .context(crate::AnalysisDatabaseSnafu {
                operation: "configure query evaluation",
            })?;
        for (name, value) in [
            ("autoinstall_known_extensions", "false"),
            ("allow_unsigned_extensions", "false"),
            ("memory_limit", "64MiB"),
        ] {
            config = config
                .with(name, value)
                .context(crate::AnalysisDatabaseSnafu {
                    operation: "bound query evaluation",
                })?;
        }
        let connection = Connection::open_in_memory_with_flags(config).context(
            crate::AnalysisDatabaseSnafu {
                operation: "open query evaluation",
            },
        )?;
        control.query_run(&connection, || {
            input.register(&connection)?;
            let sql = format!(
                "SELECT * FROM ({sql}) AS query_result LIMIT {}",
                limits.rows + 1
            );
            let mut statement = connection
                .prepare(&sql)
                .context(crate::AnalysisDatabaseSnafu {
                    operation: "prepare query evaluation",
                })?;
            let native = statement.query(params_from_iter(parameters.iter()));
            #[cfg(test)]
            if let Some(failed) = native_failed {
                failed.store(native.is_err(), std::sync::atomic::Ordering::Release);
            }
            let mut result = native.context(crate::AnalysisDatabaseSnafu {
                operation: "execute query evaluation",
            })?;
            let schema = result.as_ref().ok_or_else(|| {
                crate::QueryInvalidSnafu {
                    field: "query result schema",
                }
                .build()
            })?;
            let columns = schema.column_names();
            let types: Vec<_> = (0..schema.column_count())
                .map(|index| format!("{:?}", schema.column_logical_type(index).id()))
                .collect();
            let mut output_bytes = limits.summary_bytes;
            for fields in [&columns, &types] {
                output_bytes = output_bytes.saturating_add(
                    fields
                        .capacity()
                        .saturating_mul(std::mem::size_of::<String>()),
                );
                for field in fields {
                    output_bytes = output_bytes.saturating_add(field.capacity());
                }
            }
            limits.check_output(output_bytes)?;
            let mut output = EvaluationResult {
                columns,
                types,
                rows: Vec::new(),
                output_bytes,
                limited: false,
                scanned_through: position,
            };
            while let Some(row) = result.next().context(crate::AnalysisDatabaseSnafu {
                operation: "read query evaluation",
            })? {
                control.check()?;
                if output.rows.len() == limits.rows {
                    output.limit_at(row, limits.operation)?;
                    break;
                }
                let count = row.as_ref().column_count();
                let mut row_bytes = count.saturating_mul(std::mem::size_of::<Value>());
                let descriptor = if output.rows.len() == output.rows.capacity() {
                    std::mem::size_of::<Vec<Value>>()
                } else {
                    0
                };
                if output
                    .output_bytes
                    .saturating_add(row_bytes)
                    .saturating_add(descriptor)
                    > limits.bytes
                {
                    if output.rows.is_empty() {
                        limits.check_output(limits.bytes.saturating_add(1))?;
                    }
                    output.limit_at(row, limits.operation)?;
                    break;
                }
                let mut values = Vec::with_capacity(count);
                for index in 0..count {
                    let value = row.get_ref(index).context(crate::AnalysisDatabaseSnafu {
                        operation: "read query value",
                    })?;
                    let bytes = match &value {
                        ValueRef::Text(value) | ValueRef::Blob(value) => value.len(),
                        _ => 0,
                    };
                    row_bytes = row_bytes.saturating_add(bytes);
                    if output
                        .output_bytes
                        .saturating_add(row_bytes)
                        .saturating_add(descriptor)
                        > limits.bytes
                    {
                        output.limited = true;
                        break;
                    }
                    values.push(value.to_owned());
                }
                if output.limited {
                    if output.rows.is_empty() {
                        limits.check_output(limits.bytes.saturating_add(1))?;
                    }
                    output.limit_at(row, limits.operation)?;
                    break;
                }
                let capacity = output.rows.capacity();
                output.rows.try_reserve_exact(1).map_err(|_| {
                    crate::QueryLimitSnafu {
                        resource: "query output allocation",
                        limit: limits.bytes,
                    }
                    .build()
                })?;
                output.output_bytes = output
                    .output_bytes
                    .saturating_add(row_bytes)
                    .saturating_add(
                        (output.rows.capacity() - capacity) * std::mem::size_of::<Vec<Value>>(),
                    );
                limits.check_output(output.output_bytes)?;
                output.rows.push(values);
            }
            if output.limited && limits.complete && limits.operation == QueryOperation::Replace {
                return crate::QueryLimitSnafu {
                    resource: "complete replacement output",
                    limit: limits.bytes,
                }
                .fail();
            }
            Ok(output)
        })
    }
}

impl EvaluationLimits {
    fn check_output(&self, bytes: usize) -> Result<()> {
        if bytes > self.bytes {
            return crate::QueryLimitSnafu {
                resource: "query output bytes",
                limit: self.bytes,
            }
            .fail();
        }
        Ok(())
    }
}

impl EvaluationResult {
    fn limit_at(&mut self, row: &duckdb::Row<'_>, operation: QueryOperation) -> Result<()> {
        self.limited = true;
        if operation == QueryOperation::Append {
            self.scanned_through = QueryOwner::before_row(row)?;
        }
        Ok(())
    }
}
