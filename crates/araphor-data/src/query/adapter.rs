use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use duckdb::core::{DataChunkHandle, FlatVector, Inserter, LogicalTypeId};
use duckdb::types::{TimeUnit, Value};
use duckdb::vtab::{BindInfo, InitInfo, TableFunctionInfo, VTab};
use duckdb::Connection;
use snafu::ResultExt as _;

use crate::{AnalysisDatabaseSnafu, AnalysisStateSnafu, Result};

type CallbackResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[cfg(test)]
pub(super) type ScanGate = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);

pub(super) struct InputColumn(pub(super) &'static str, pub(super) LogicalTypeId);

#[cfg_attr(test, derive(Default))]
pub(super) struct InputTable {
    pub(super) columns: Vec<InputColumn>,
    pub(super) rows: Vec<Vec<Value>>,
    #[cfg(test)]
    pub(super) scan_gate: std::sync::Mutex<Option<ScanGate>>,
}

impl InputTable {
    pub(super) fn register(
        self: &Arc<Self>,
        connection: &Connection,
        function: &'static str,
        view: &'static str,
    ) -> Result<()> {
        self.validate(function, view).map_err(|reason| {
            AnalysisStateSnafu {
                path: Path::new("<query-input>"),
                reason,
            }
            .build()
        })?;
        connection
            .register_table_function_with_extra_info::<InputScan, _>(function, self)
            .context(AnalysisDatabaseSnafu {
                operation: "register query input",
            })?;
        connection
            .execute_batch(&format!(
                "CREATE TEMP VIEW \"{view}\" AS SELECT * FROM \"{function}\"()"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "create query input view",
            })
    }

    fn validate(&self, function: &str, view: &str) -> std::result::Result<(), &'static str> {
        if !InputColumn::valid_name(function) || !InputColumn::valid_name(view) {
            return Err("query input function or view name is invalid");
        }
        let mut names = BTreeSet::new();
        if self.columns.is_empty()
            || self.columns.iter().any(|column| {
                !InputColumn::valid_name(column.0)
                    || !names.insert(column.0)
                    || !matches!(
                        column.1,
                        LogicalTypeId::Boolean
                            | LogicalTypeId::UInteger
                            | LogicalTypeId::UBigint
                            | LogicalTypeId::Integer
                            | LogicalTypeId::Bigint
                            | LogicalTypeId::Varchar
                            | LogicalTypeId::Blob
                            | LogicalTypeId::Timestamp
                    )
            })
        {
            return Err("query input columns are invalid");
        }
        for row in &self.rows {
            if row.len() != self.columns.len() {
                return Err("query input row width differs from its columns");
            }
            if row
                .iter()
                .zip(&self.columns)
                .any(|(value, column)| !column.accepts(value))
            {
                return Err("query input value type differs from its column");
            }
        }
        Ok(())
    }
}

impl InputColumn {
    fn valid_name(name: &str) -> bool {
        name.as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    }

    fn accepts(&self, value: &Value) -> bool {
        matches!(
            (self.1, value),
            (_, Value::Null)
                | (LogicalTypeId::Boolean, Value::Boolean(_))
                | (LogicalTypeId::UInteger, Value::UInt(_))
                | (LogicalTypeId::UBigint, Value::UBigInt(_))
                | (LogicalTypeId::Integer, Value::Int(_))
                | (LogicalTypeId::Bigint, Value::BigInt(_))
                | (LogicalTypeId::Varchar, Value::Text(_))
                | (LogicalTypeId::Blob, Value::Blob(_))
                | (
                    LogicalTypeId::Timestamp,
                    Value::Timestamp(TimeUnit::Microsecond, _)
                )
        )
    }

    #[allow(unsafe_code)]
    fn write(
        &self,
        vector: &mut FlatVector<'_>,
        rows: &[Vec<Value>],
        column: usize,
    ) -> CallbackResult<()> {
        if rows.len() > vector.capacity() || vector.logical_type().id() != self.1 {
            return Err("query input vector does not match its column".into());
        }
        for (index, row) in rows.iter().enumerate() {
            let value = row
                .get(column)
                .ok_or("query input row has no value for its column")?;
            // SAFETY: Each numeric arm matches the vector type. The row is in bounds.
            unsafe {
                match (self.1, value) {
                    (_, Value::Null) => vector.set_null(index),
                    (LogicalTypeId::Boolean, Value::Boolean(value)) => {
                        vector.as_mut_ptr::<bool>().add(index).write(*value);
                    }
                    (LogicalTypeId::UInteger, Value::UInt(value)) => {
                        vector.as_mut_ptr::<u32>().add(index).write(*value);
                    }
                    (LogicalTypeId::UBigint, Value::UBigInt(value)) => {
                        vector.as_mut_ptr::<u64>().add(index).write(*value);
                    }
                    (LogicalTypeId::Integer, Value::Int(value)) => {
                        vector.as_mut_ptr::<i32>().add(index).write(*value);
                    }
                    (LogicalTypeId::Bigint, Value::BigInt(value))
                    | (LogicalTypeId::Timestamp, Value::Timestamp(TimeUnit::Microsecond, value)) => {
                        vector.as_mut_ptr::<i64>().add(index).write(*value);
                    }
                    (LogicalTypeId::Varchar, Value::Text(value)) => vector.insert(index, value),
                    (LogicalTypeId::Blob, Value::Blob(value)) => vector.insert(index, value),
                    _ => return Err("query input value type differs from its column".into()),
                }
            }
        }
        Ok(())
    }
}

struct InputScan;

impl VTab for InputScan {
    type BindData = Arc<InputTable>;
    type InitData = AtomicUsize;

    #[allow(unsafe_code)]
    fn bind(bind: &BindInfo) -> CallbackResult<Self::BindData> {
        // SAFETY: Registration stores this exact Arc type until the connection closes.
        let input = unsafe { bind.get_extra_info::<Arc<InputTable>>().as_ref() }
            .ok_or("query input is absent")?;
        for column in &input.columns {
            bind.add_result_column(column.0, column.1.into());
        }
        Ok(Arc::clone(input))
    }

    fn init(init: &InitInfo) -> CallbackResult<Self::InitData> {
        init.set_max_threads(1);
        Ok(AtomicUsize::new(0))
    }

    fn func(func: &TableFunctionInfo<Self>, output: &mut DataChunkHandle) -> CallbackResult<()> {
        output.set_len(0);
        let input = func.get_bind_data();
        if output.num_columns() != input.columns.len() || input.columns.is_empty() {
            return Err("query input output columns are invalid".into());
        }
        let capacity = output.flat_vector(0).capacity();
        let start = func.get_init_data().fetch_add(capacity, Ordering::Relaxed);
        if start >= input.rows.len() {
            return Ok(());
        }
        let count = capacity.min(input.rows.len() - start);
        let rows = &input.rows[start..start + count];
        for (index, column) in input.columns.iter().enumerate() {
            column.write(&mut output.flat_vector(index), rows, index)?;
        }
        output.set_len(count);
        #[cfg(test)]
        if let Some((entered, release)) = input
            .scan_gate
            .lock()
            .map_err(|_| "scan gate lock poisoned")?
            .take()
        {
            entered.send(())?;
            release.recv_timeout(std::time::Duration::from_secs(5))?;
            entered.send(())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use duckdb::Config;

    use super::*;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn connection() -> TestResult<Connection> {
        let config = Config::default()
            .enable_external_access(false)?
            .enable_autoload_extension(false)?;
        Ok(Connection::open_in_memory_with_flags(config)?)
    }

    fn query_rows(connection: &Connection, sql: &str) -> TestResult<Vec<Vec<Value>>> {
        let mut statement = connection.prepare(sql)?;
        let rows = statement
            .query_map([], |row| {
                (0..row.as_ref().column_count())
                    .map(|index| row.get::<_, Value>(index))
                    .collect::<duckdb::Result<Vec<_>>>()
            })?
            .collect::<duckdb::Result<Vec<_>>>()?;
        Ok(rows)
    }

    #[test]
    fn query_input_adapter_values() -> TestResult {
        let input = Arc::new(InputTable {
            columns: vec![
                InputColumn("id", LogicalTypeId::UBigint),
                InputColumn("boolean", LogicalTypeId::Boolean),
                InputColumn("uint", LogicalTypeId::UInteger),
                InputColumn("ulong", LogicalTypeId::UBigint),
                InputColumn("int", LogicalTypeId::Integer),
                InputColumn("long", LogicalTypeId::Bigint),
                InputColumn("text", LogicalTypeId::Varchar),
                InputColumn("blob", LogicalTypeId::Blob),
                InputColumn("time", LogicalTypeId::Timestamp),
            ],
            rows: vec![
                vec![
                    Value::UBigInt(0),
                    Value::Boolean(false),
                    Value::UInt(0),
                    Value::UBigInt(u64::MAX),
                    Value::Int(i32::MIN),
                    Value::BigInt(i64::MIN),
                    Value::Text("a\0b".into()),
                    Value::Blob(vec![0, 255, 128, 0]),
                    Value::Timestamp(TimeUnit::Microsecond, -1_234_567),
                ],
                vec![
                    Value::UBigInt(1),
                    Value::Boolean(true),
                    Value::UInt(u32::MAX),
                    Value::UBigInt(0),
                    Value::Int(i32::MAX),
                    Value::BigInt(i64::MAX),
                    Value::Text(String::new()),
                    Value::Blob(Vec::new()),
                    Value::Timestamp(TimeUnit::Microsecond, 1_791_000_000_987_654),
                ],
                [vec![Value::UBigInt(2)], vec![Value::Null; 8]].concat(),
            ],
            ..Default::default()
        });
        let connection = connection()?;
        input.register(&connection, "_query_events", "events")?;
        assert_eq!(
            query_rows(&connection, "SELECT * FROM events ORDER BY id")?,
            input.rows
        );
        Ok(())
    }

    #[test]
    fn query_input_adapter_scans() -> TestResult {
        let chunk = DataChunkHandle::new(&[LogicalTypeId::UBigint.into()]);
        let capacity = chunk.flat_vector(0).capacity();
        let count = capacity * 2 + 3;
        let input = Arc::new(InputTable {
            columns: vec![
                InputColumn("id", LogicalTypeId::UBigint),
                InputColumn("value", LogicalTypeId::UBigint),
            ],
            rows: (0..count)
                .map(|id| {
                    vec![
                        Value::UBigInt(id as u64),
                        if id < capacity {
                            Value::Null
                        } else {
                            Value::UBigInt(id as u64)
                        },
                    ]
                })
                .collect(),
            ..Default::default()
        });
        let connection = connection()?;
        input.register(&connection, "_query_events", "events")?;
        for _ in 0..2 {
            assert_eq!(
                query_rows(&connection, "SELECT * FROM events ORDER BY id")?,
                input.rows
            );
        }
        let joined: u64 = connection.query_row(
            "SELECT COUNT(*) FROM events a JOIN events b ON a.id = b.id",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(joined, count as u64);
        let nonnull: u64 =
            connection.query_row("SELECT COUNT(value) FROM events", [], |row| row.get(0))?;
        assert_eq!(nonnull, (count - capacity) as u64);
        let repeated: u64 = connection.query_row(
            "SELECT COUNT(*) FROM (SELECT id FROM events UNION ALL SELECT id FROM events)",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(repeated, (count * 2) as u64);
        Ok(())
    }

    #[test]
    fn query_input_adapter_lifetime() -> TestResult {
        for _ in 0..4 {
            for (sql, succeeds) in [
                ("SELECT id FROM events", true),
                ("SELECT absent FROM events", false),
                ("SELECT CAST('invalid' AS INTEGER) FROM events", false),
            ] {
                let input = Arc::new(InputTable {
                    columns: vec![InputColumn("id", LogicalTypeId::UBigint)],
                    rows: vec![vec![Value::UBigInt(7)]],
                    ..Default::default()
                });
                let weak = Arc::downgrade(&input);
                let connection = connection()?;
                input.register(&connection, "_query_events", "events")?;
                drop(input);
                assert!(weak.upgrade().is_some());
                assert_eq!(query_rows(&connection, sql).is_ok(), succeeds);
                assert_eq!(
                    query_rows(&connection, "SELECT id FROM events")?,
                    vec![vec![Value::UBigInt(7)]]
                );
                drop(connection);
                assert!(weak.upgrade().is_none());
            }
        }
        Ok(())
    }

    #[test]
    fn query_input_adapter_invalid() -> TestResult {
        let connection = connection()?;
        for input in [
            InputTable {
                columns: Vec::new(),
                rows: Vec::new(),
                ..Default::default()
            },
            InputTable {
                columns: vec![InputColumn("id", LogicalTypeId::UBigint)],
                rows: vec![Vec::new()],
                ..Default::default()
            },
            InputTable {
                columns: vec![InputColumn("id", LogicalTypeId::UBigint)],
                rows: vec![vec![Value::UBigInt(1), Value::UBigInt(2)]],
                ..Default::default()
            },
            InputTable {
                columns: vec![InputColumn("id", LogicalTypeId::UBigint)],
                rows: vec![vec![Value::BigInt(-1)]],
                ..Default::default()
            },
            InputTable {
                columns: vec![InputColumn("id", LogicalTypeId::Double)],
                rows: vec![vec![Value::Double(1.0)]],
                ..Default::default()
            },
            InputTable {
                columns: vec![InputColumn("time", LogicalTypeId::Timestamp)],
                rows: vec![vec![Value::Timestamp(TimeUnit::Nanosecond, 1)]],
                ..Default::default()
            },
            InputTable {
                columns: vec![
                    InputColumn("id", LogicalTypeId::UBigint),
                    InputColumn("id", LogicalTypeId::UBigint),
                ],
                rows: Vec::new(),
                ..Default::default()
            },
            InputTable {
                columns: vec![InputColumn("bad\0name", LogicalTypeId::UBigint)],
                rows: Vec::new(),
                ..Default::default()
            },
        ] {
            assert!(Arc::new(input)
                .register(&connection, "_query_invalid", "invalid")
                .is_err());
        }
        let input = Arc::new(InputTable {
            columns: vec![InputColumn("id", LogicalTypeId::UBigint)],
            rows: Vec::new(),
            ..Default::default()
        });
        assert!(input
            .register(&connection, "invalid(); SELECT 1", "events")
            .is_err());
        input.register(&connection, "_query_events", "events")?;
        assert!(query_rows(&connection, "SELECT id FROM events")?.is_empty());
        Ok(())
    }
}
