use super::*;
use duckdb::{params, params_from_iter, Connection};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

struct Fixture;

#[test]
fn admitted_program_sharing() -> TestResult {
    let sql = Fixture::admit("SELECT CAST(? AS BIGINT) AS value", vec![Value::Int(7)])?;
    let copied = sql.clone();
    assert!(Arc::ptr_eq(&sql.program, &copied.program));
    assert_eq!(sql, copied);
    assert_eq!(sql.allocated_bytes(), copied.allocated_bytes());
    assert!(sql.allocated_bytes() >= std::mem::size_of::<AdmittedSql>());
    assert!(std::mem::size_of::<crate::QueryTemplate>() <= 64);
    assert_eq!(
        sql,
        Fixture::admit("SELECT CAST(? AS BIGINT) AS value", vec![Value::Int(7)])?
    );
    assert_ne!(
        sql,
        Fixture::admit("SELECT CAST(? AS BIGINT) AS value", vec![Value::Int(8)])?
    );
    assert!(format!("{sql:?}").contains(sql.original()));
    drop(sql);
    assert_eq!(copied.bind_complete(0)?.parameters, vec![Value::Int(7)]);
    Ok(())
}

#[test]
fn retained_literal_charge() -> TestResult {
    let short = Fixture::admit("SELECT 'x' AS value", vec![])?;
    let long = Fixture::admit(&format!("SELECT '{}' AS value", "x".repeat(8_000)), vec![])?;
    let added = long.allocated_bytes() - short.allocated_bytes();
    assert!(added >= 16_000);
    assert!(added < 32 * 1024);
    Ok(())
}

impl Fixture {
    fn admit(sql: &str, parameters: Vec<Value>) -> Result<QuerySql> {
        QuerySql::admit(sql, parameters, false)
    }

    fn scope_sql(sql: &str, parameters: Vec<Value>, allowed: &[&str]) -> Result<QuerySql> {
        let relations = allowed
            .iter()
            .map(|relation| {
                let fields = if *relation == "events" {
                    vec!["id", "received_at", "operation"]
                } else {
                    vec!["operation"]
                };
                let fields = fields
                    .into_iter()
                    .map(|name| {
                        let kind = match name {
                            "id" => datafusion::arrow::datatypes::DataType::Int64,
                            "received_at" => datafusion::arrow::datatypes::DataType::Timestamp(
                                datafusion::arrow::datatypes::TimeUnit::Microsecond,
                                None,
                            ),
                            _ => datafusion::arrow::datatypes::DataType::Utf8,
                        };
                        Field::new(name, kind, true)
                    })
                    .collect::<Vec<_>>();
                ((*relation).to_owned(), Arc::new(Schema::new(fields)))
            })
            .collect();
        QuerySql::admit_with(sql, parameters, false, Some(relations))
    }

    fn scope_database() -> std::result::Result<Connection, Box<dyn std::error::Error>> {
        let config = duckdb::Config::default()
            .enable_external_access(false)?
            .enable_autoload_extension(false)?;
        let connection = Connection::open_in_memory_with_flags(config)?;
        connection.execute_batch(
            "CREATE TABLE events(id BIGINT, received_at TIMESTAMP, operation VARCHAR);
             CREATE TABLE coverage(operation VARCHAR);",
        )?;
        Ok(connection)
    }

    fn database(
        binding: Option<&QueryBinding>,
    ) -> std::result::Result<Connection, Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("SET TimeZone = 'UTC'")?;
        for schema in SCHEMAS
            .iter()
            .filter(|schema| matches!(schema.name, "events" | "coverage"))
        {
            let fields = schema
                .columns
                .iter()
                .map(|field| format!("\"{}\" {}", field.0, field.sql_type()))
                .collect::<Vec<_>>()
                .join(", ");
            let positions = if schema.name == "events" {
                ", __araphor_commit_revision UBIGINT, __araphor_ordinal UINTEGER"
            } else {
                ""
            };
            connection.execute_batch(&format!(
                "CREATE TABLE {}({fields}{positions})",
                schema.name
            ))?;
        }
        connection.execute_batch(
            "INSERT INTO coverage(node_id, state) VALUES ('node', 'healthy'), ('other', NULL)",
        )?;
        for (index, nanos) in [
            0,
            999,
            1_000,
            1_001,
            1_999,
            2_000,
            2_999,
            3_000,
            60_000_000_000,
            240_000_000_000,
            300_000_000_000,
            420_000_000_000,
        ]
        .into_iter()
        .enumerate()
        {
            if binding.is_some_and(|binding| !Self::contains(binding, nanos)) {
                continue;
            }
            connection.execute(
                "INSERT INTO events(node_id, source_cursor, received_at, operation, __araphor_commit_revision, __araphor_ordinal, policy_rule_id, commit_revision, ordinal) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    "node",
                    index as u64 + 1,
                    Value::Timestamp(TimeUnit::Microsecond, (nanos / 1_000) as i64),
                    (index % 3) as u32,
                    7_u64,
                    index as u32,
                    42_u64,
                    7_u64,
                    index as u32,
                ],
            )?;
        }
        Ok(connection)
    }

    fn contains(binding: &QueryBinding, nanos: u64) -> bool {
        let lower = match binding.received_from {
            Bound::Unbounded => true,
            Bound::Included(value) => nanos >= value,
            Bound::Excluded(value) => nanos > value,
        };
        let upper = match binding.received_until {
            Bound::Unbounded => true,
            Bound::Included(value) => nanos <= value,
            Bound::Excluded(value) => nanos < value,
        };
        lower && upper
    }

    fn rows(
        connection: &Connection,
        sql: &str,
        values: &[Value],
    ) -> std::result::Result<Vec<Vec<Value>>, Box<dyn std::error::Error>> {
        let mut statement = connection.prepare(sql)?;
        let mut rows = statement.query(params_from_iter(values.iter()))?;
        let columns = rows
            .as_ref()
            .ok_or("query statement is absent")?
            .column_count();
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let mut values = Vec::with_capacity(columns);
            for column in 0..columns {
                values.push(row.get(column)?);
            }
            result.push(values);
        }
        Ok(result)
    }

    fn equivalent(
        sql: &str,
        parameters: Vec<Value>,
    ) -> std::result::Result<QueryBinding, Box<dyn std::error::Error>> {
        let admitted = Self::admit(sql, parameters.clone())?;
        let binding = admitted.bind_at(480_000_000_000)?;
        let full = Self::database(None)?;
        let selected = Self::database(Some(&binding))?;
        let expected = Self::rows(&full, sql, &parameters)?;
        let mut actual = Self::rows(&selected, &binding.sql, &binding.parameters)?;
        if binding.append {
            for row in &mut actual {
                row.truncate(row.len().saturating_sub(2));
            }
        }
        assert_eq!(actual, expected, "{sql}");
        Ok(binding)
    }
}

#[test]
fn query_admission_fields() -> TestResult {
    let admitted = Fixture::admit("SELECT e.* FROM events AS e", vec![])?;
    let binding = admitted.bind_at(1)?;
    assert!(!binding.sql.contains('*'));
    assert!(binding.sql.contains("catalog_json"));
    assert!(binding.append);
    let connection = Fixture::database(None)?;
    let mut actual = Fixture::rows(&connection, &binding.sql, &binding.parameters)?;
    let mut expected = Fixture::rows(&connection, "SELECT e.* FROM events AS e", &[])?;
    for row in actual.iter_mut().chain(&mut expected) {
        row.truncate(row.len() - 2);
    }
    assert_eq!(actual, expected);
    for sql in [
        "SELECT missing_field FROM events",
        "SELECT operation FROM events WHERE missing_field IS NULL",
        "SELECT operation FROM events ORDER BY missing_field",
        "SELECT COUNT(*) FROM events HAVING MAX(missing_field) IS NULL",
        "SELECT CASE WHEN missing_field IS NULL THEN operation ELSE 0 END FROM events",
        "SELECT e.operation FROM events e JOIN coverage c ON e.missing_field = c.state",
        "WITH unused AS (SELECT missing_field FROM events) SELECT operation FROM events",
        "SELECT lag(operation) OVER (ORDER BY missing_field) FROM events",
        "SELECT operation FROM events WINDOW unused AS (ORDER BY missing_field)",
        "SELECT __araphor_commit_revision FROM events",
        "SELECT operation AS __araphor_ordinal FROM events",
    ] {
        let error = Fixture::admit(sql, vec![])
            .err()
            .ok_or("invalid field was admitted")?;
        let message = error.to_string();
        assert!(!message.contains("missing_field"));
        assert!(!message.contains("__araphor_"));
        assert!(!message.contains(sql));
    }
    Fixture::equivalent(
        "SELECT operation AS catalog_json FROM events ORDER BY catalog_json",
        vec![],
    )?;
    let binding = Fixture::equivalent(
        "SELECT COUNT(*) FROM events WHERE policy_rule_id = 42",
        vec![],
    )?;
    assert_eq!(
        Fixture::rows(&Fixture::database(None)?, &binding.sql, &binding.parameters)?,
        vec![vec![Value::BigInt(12)]]
    );
    Ok(())
}

#[test]
fn query_catalog_admission() -> TestResult {
    for relation in ["targets", "trace_recipes"] {
        let sql = Fixture::admit(&format!("SELECT * FROM {relation}"), vec![])?;
        assert_eq!(sql.operation(), super::super::QueryOperation::Replace);
        assert_eq!(
            sql.dependencies(),
            &std::collections::BTreeSet::from([relation.to_owned()])
        );
        let bound = sql.bind_at(100)?;
        assert_eq!(bound.received_from, Bound::Unbounded);
        assert_eq!(bound.received_until, Bound::Unbounded);
        assert!(bound.parameters.is_empty());
        assert!(Fixture::admit(&format!("SELECT missing_field FROM {relation}"), vec![]).is_err());
    }
    Ok(())
}

#[test]
fn query_admission_closed_shapes() -> TestResult {
    for sql in [
        "DELETE FROM events",
        "SELECT 1; SELECT 2",
        "PRAGMA version",
        "SELECT * FROM read_csv('/etc/passwd')",
        "SELECT * FROM duckdb_tables()",
        "SELECT COUNT(*) FROM main.events",
        "SELECT current_setting('home_directory')",
        "SELECT coalesce(operation, current_setting('threads')) FROM events",
        "SELECT random() FROM events",
        "SELECT CAST(operation AS secret_type) FROM events",
        "SELECT e FROM events e",
        "SELECT row_to_json(e) FROM events e",
        "SELECT * EXCLUDE(catalog_json) FROM events",
        "SELECT * FROM events NATURAL JOIN coverage",
        "SELECT e.operation FROM events e JOIN coverage c ON e.node_id <> c.node_id",
        "WITH RECURSIVE x AS (SELECT 1 AS value UNION ALL SELECT value + 1 FROM x) SELECT * FROM x",
        "SELECT * FROM events WHERE EXISTS (SELECT 1 FROM coverage)",
        "SELECT COUNT(*) OVER (ORDER BY source_cursor) FROM events",
        "SELECT lag(operation, 201) OVER (ORDER BY source_cursor) FROM events",
        "SELECT operation FROM events LIMIT source_cursor",
    ] {
        assert!(Fixture::admit(sql, vec![]).is_err(), "{sql}");
    }
    assert!(Fixture::admit("SELECT * FROM unknown", vec![]).is_err());
    Ok(())
}

#[test]
fn query_trace_admission() -> TestResult {
    for (sql, operation) in [
        (
            "SELECT sequence FROM trace_output WHERE request_id = ?",
            QueryOperation::Append,
        ),
        (
            "SELECT sequence FROM trace_output ORDER BY sequence",
            QueryOperation::Replace,
        ),
        (
            "SELECT count FROM trace_measurements",
            QueryOperation::Replace,
        ),
        ("SELECT execution_id FROM traces", QueryOperation::Replace),
    ] {
        let parameters = if sql.contains('?') {
            vec![Value::Blob(vec![1; 16])]
        } else {
            Vec::new()
        };
        let admitted = QuerySql::admit(sql, parameters, true)?;
        assert_eq!(admitted.operation(), operation);
        let binding = admitted.bind_at(100)?;
        assert_eq!(binding.received_from, Bound::Unbounded);
        assert_eq!(binding.received_until, Bound::Unbounded);
    }
    Ok(())
}

#[test]
fn query_admission_scopes() -> TestResult {
    for sql in [
        "SELECT \"E\".\"Operation\" FROM \"EVENTS\" AS \"E\" ORDER BY \"E\".source_cursor",
        "WITH recent AS (SELECT source_cursor, operation FROM events) SELECT r.operation FROM recent r ORDER BY r.source_cursor",
        "WITH recent AS (SELECT source_cursor, operation FROM events) SELECT a.operation FROM recent a JOIN recent b ON a.source_cursor = b.source_cursor ORDER BY a.source_cursor",
        "WITH events AS (SELECT node_id, state FROM coverage) SELECT state FROM events ORDER BY node_id",
        "WITH first(x) AS (SELECT operation FROM events) SELECT x FROM first ORDER BY x",
        "SELECT value FROM (SELECT operation AS value FROM events) e ORDER BY value",
        "SELECT e.operation, c.state FROM events e LEFT JOIN coverage c ON e.node_id = c.node_id ORDER BY e.source_cursor",
        "SELECT c.node_id, COUNT(e.operation) AS total FROM coverage c LEFT JOIN events e ON c.node_id = e.node_id GROUP BY c.node_id ORDER BY c.node_id",
        "SELECT operation AS value, COUNT(*) AS total FROM events GROUP BY value HAVING total > 0 ORDER BY value",
        "SELECT operation, lag(operation) OVER subject AS prior FROM events WINDOW subject AS (PARTITION BY node_id ORDER BY source_cursor) ORDER BY source_cursor",
        "SELECT operation, SUM(operation) OVER (ORDER BY source_cursor ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) AS total FROM events ORDER BY source_cursor",
    ] {
        Fixture::equivalent(sql, vec![])?;
    }
    let shadow = Fixture::admit(
        "WITH events AS (SELECT state FROM coverage) SELECT state FROM events",
        vec![],
    )?;
    assert_eq!(
        shadow.dependencies(),
        &BTreeSet::from(["coverage".to_owned()])
    );
    for sql in [
        "SELECT node_id FROM events e JOIN coverage c ON e.node_id = c.node_id",
        "WITH recent AS (SELECT operation FROM events) SELECT recent.catalog_json FROM recent",
        "WITH recent AS (SELECT operation AS known FROM events) SELECT operation FROM recent",
        "SELECT e.operation FROM events e JOIN events e ON e.source_cursor = e.source_cursor",
        "SELECT operation FROM events GROUP BY 2",
    ] {
        assert!(Fixture::admit(sql, vec![]).is_err(), "{sql}");
    }
    Ok(())
}

#[test]
fn query_admission_having_aliases() -> TestResult {
    for sql in [
        "SELECT operation AS source_cursor, COUNT(*) AS amount FROM events GROUP BY operation HAVING source_cursor > 1 ORDER BY source_cursor",
        "SELECT COUNT(*) AS operation FROM events GROUP BY operation HAVING operation = 2 ORDER BY 1",
    ] {
        Fixture::equivalent(sql, vec![])?;
    }
    Ok(())
}

#[test]
fn query_admission_time_bounds() -> TestResult {
    for (predicate, first, last) in [
        ("received_at >= TIMESTAMP '1970-01-01 00:00:00.000001'", Some(1_000), None),
        ("received_at > TIMESTAMP '1970-01-01 00:00:00.000001'", Some(2_000), None),
        ("received_at <= TIMESTAMP '1970-01-01 00:00:00.000001'", None, Some(1_999)),
        ("received_at < TIMESTAMP '1970-01-01 00:00:00.000001'", None, Some(999)),
        ("received_at = TIMESTAMP '1970-01-01 00:00:00.000001'", Some(1_000), Some(1_999)),
        ("received_at BETWEEN TIMESTAMP '1970-01-01 00:00:00.000001' AND TIMESTAMP '1970-01-01 00:00:00.000002'", Some(1_000), Some(2_999)),
        ("TIMESTAMP '1970-01-01 00:00:00.000001' < e.received_at", Some(2_000), None),
        ("operation IS NOT NULL AND (e.received_at >= TIMESTAMP '1970-01-01T00:00:00.000001Z')", Some(1_000), None),
        ("received_at < TIMESTAMP '1969-12-31 23:59:59.999999'", Some(1), Some(0)),
        ("received_at >= TIMESTAMP '1970-01-01 00:00:00.000002' AND received_at < TIMESTAMP '1970-01-01 00:00:00.000001'", Some(1), Some(0)),
    ] {
        let sql = format!("SELECT source_cursor FROM events e WHERE {predicate} ORDER BY source_cursor");
        let binding = Fixture::equivalent(&sql, vec![])?;
        assert_eq!(binding.received_from, first.map_or(Bound::Unbounded, Bound::Included), "{predicate}");
        assert_eq!(binding.received_until, last.map_or(Bound::Unbounded, Bound::Included), "{predicate}");
    }
    let binding = Fixture::equivalent(
        "SELECT source_cursor FROM events WHERE received_at >= $2 AND received_at <= $1 ORDER BY source_cursor",
        vec![Value::Timestamp(TimeUnit::Microsecond, 2), Value::Timestamp(TimeUnit::Microsecond, 1)],
    )?;
    assert_eq!(binding.received_from, Bound::Included(1_000));
    assert_eq!(binding.received_until, Bound::Included(2_999));
    Fixture::equivalent(
        "SELECT ? AS value FROM events WHERE received_at >= ? ORDER BY source_cursor",
        vec![Value::Int(42), Value::Timestamp(TimeUnit::Microsecond, 1)],
    )?;
    Ok(())
}

#[test]
fn query_admission_bound_fallback() -> TestResult {
    for sql in [
        "SELECT source_cursor FROM events WHERE received_at >= TIMESTAMP '1970-01-01 00:00:00.000002' OR operation = 0 ORDER BY source_cursor",
        "SELECT source_cursor FROM events WHERE NOT(received_at < TIMESTAMP '1970-01-01 00:00:00.000002') ORDER BY source_cursor",
        "SELECT received_at, COUNT(*) FROM events GROUP BY received_at HAVING received_at >= TIMESTAMP '1970-01-01 00:00:00.000002' ORDER BY received_at",
        "SELECT source_cursor FROM events WHERE CAST(received_at AS TIMESTAMP) >= TIMESTAMP '1970-01-01 00:00:00.000002' ORDER BY source_cursor",
        "WITH recent AS (SELECT source_cursor FROM events WHERE received_at >= TIMESTAMP '1970-01-01 00:00:00.000002') SELECT source_cursor FROM recent ORDER BY source_cursor",
        "SELECT a.source_cursor, b.source_cursor FROM events a JOIN events b ON a.operation = b.operation WHERE a.received_at >= TIMESTAMP '1970-01-01 00:00:00.000002' ORDER BY a.source_cursor, b.source_cursor",
        "SELECT c.node_id, e.operation FROM coverage c LEFT JOIN events e ON c.node_id = e.node_id WHERE e.received_at >= TIMESTAMP '1970-01-01 00:00:00.000002' ORDER BY e.source_cursor",
        "SELECT source_cursor FROM events WHERE received_at >= TIMESTAMP '1970-01-01 00:00:00.0000019' ORDER BY source_cursor",
        "SELECT source_cursor FROM events WHERE received_at >= TIMESTAMP '1970-01-01 01:00:00+01:00' ORDER BY source_cursor",
        "SELECT source_cursor FROM events WHERE received_at >= TIMESTAMPTZ '1970-01-01 01:00:00+01:00' ORDER BY source_cursor",
    ] {
        let binding = Fixture::equivalent(sql, vec![])?;
        assert_eq!(binding.received_from, Bound::Unbounded, "{sql}");
        assert_eq!(binding.received_until, Bound::Unbounded, "{sql}");
    }
    Fixture::equivalent(
        "SELECT source_cursor FROM events WHERE received_at >= ? ORDER BY source_cursor",
        vec![Value::Null],
    )?;
    Ok(())
}

#[test]
fn query_admission_frozen_clock() -> TestResult {
    let sql = "SELECT COUNT(*) FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '300 seconds'";
    let admitted = QuerySql::admit(sql, vec![], true)?;
    assert_eq!(admitted.operation(), QueryOperation::Replace);
    assert_eq!(admitted.moving_seconds(), Some(300));
    let full = Fixture::database(None)?;
    for (now, first, count) in [
        (480_000_000_000, 180_000_000_000, 3),
        (600_000_000_000, 300_000_000_000, 2),
    ] {
        let binding = admitted.bind_at(now)?;
        assert_eq!(binding.received_from, Bound::Included(first));
        assert_eq!(
            binding.parameters,
            vec![Value::Timestamp(
                TimeUnit::Microsecond,
                (now / 1_000) as i64
            )]
        );
        assert!(!binding
            .sql
            .to_ascii_lowercase()
            .contains("current_timestamp"));
        assert!(binding.sql.contains("WHERE"));
        let selected = Fixture::database(Some(&binding))?;
        assert_eq!(
            Fixture::rows(&selected, &binding.sql, &binding.parameters)?,
            vec![vec![Value::BigInt(count)]]
        );
        assert_eq!(
            Fixture::rows(&selected, &binding.sql, &binding.parameters)?,
            Fixture::rows(&full, &binding.sql, &binding.parameters)?
        );
    }
    let direct = Fixture::admit(
        "SELECT CURRENT_TIMESTAMP AS first, CURRENT_TIMESTAMP AS second",
        vec![],
    )?
    .bind_at(12_345)?;
    assert_eq!(direct.parameters.len(), 1);
    assert_eq!(
        Fixture::rows(&full, &direct.sql, &direct.parameters)?,
        vec![vec![
            Value::Timestamp(TimeUnit::Microsecond, 12),
            Value::Timestamp(TimeUnit::Microsecond, 12),
        ]]
    );
    Ok(())
}

#[test]
fn query_admission_moving_rejection() -> TestResult {
    for sql in [
        "SELECT COUNT(*) FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '5 minutes'",
        "SELECT COUNT(*) FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '86401 seconds'",
        "SELECT COUNT(*) FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '300 seconds' OR operation = 0",
        "SELECT COUNT(*) FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '300 seconds' OR received_at >= CURRENT_TIMESTAMP - INTERVAL '60 seconds'",
        "SELECT COUNT(*) FROM events WHERE (received_at >= CURRENT_TIMESTAMP - INTERVAL '300 seconds' AND received_at >= TIMESTAMP '1970-01-01 00:00:00') OR received_at >= TIMESTAMP '1970-01-01 00:00:00'",
        "SELECT COUNT(*) FROM events WHERE NOT(received_at < CURRENT_TIMESTAMP - INTERVAL '300 seconds')",
        "SELECT COUNT(*) FROM events WHERE received_at <= CURRENT_TIMESTAMP - INTERVAL '300 seconds'",
        "WITH recent AS (SELECT operation FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '300 seconds') SELECT COUNT(*) FROM recent",
        "SELECT a.operation FROM events a JOIN events b ON a.source_cursor = b.source_cursor WHERE a.received_at >= CURRENT_TIMESTAMP - INTERVAL '300 seconds'",
        "SELECT CURRENT_TIMESTAMP FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '300 seconds'",
    ] {
        assert!(QuerySql::admit(sql, vec![], true).is_err(), "{sql}");
    }
    Ok(())
}

#[test]
fn query_admission_bucket_width() -> TestResult {
    for width in [
        "1 microsecond",
        "1 millisecond",
        "1 second",
        "5 minutes",
        "1 hour",
        "1 day",
        "5 MINUTES",
    ] {
        let sql = format!("SELECT time_bucket(INTERVAL '{width}', received_at, TIMESTAMP '1970-01-01 00:00:00') AS bucket, COUNT(*) FROM events GROUP BY bucket ORDER BY bucket");
        Fixture::equivalent(&sql, vec![])?;
    }
    for width in [
        "0 seconds",
        "-1 second",
        "1 month",
        "1 year",
        "18446744073709551615 days",
    ] {
        let sql = format!("SELECT time_bucket(INTERVAL '{width}', received_at) FROM events");
        assert!(Fixture::admit(&sql, vec![]).is_err(), "{width}");
    }
    assert!(Fixture::admit(
        "SELECT time_bucket(received_at, received_at) FROM events",
        vec![]
    )
    .is_err());
    Ok(())
}

#[test]
fn query_admission_append_positions() -> TestResult {
    let admitted = Fixture::admit("SELECT operation FROM events e WHERE operation = 1", vec![])?;
    let binding = admitted.bind_at(1)?;
    assert_eq!(admitted.operation(), QueryOperation::Append);
    assert!(binding.append);
    let connection = Fixture::database(None)?;
    let rows = Fixture::rows(&connection, &binding.sql, &binding.parameters)?;
    assert!(!rows.is_empty());
    assert!(rows
        .iter()
        .all(|row| row.len() == 3 && row[1] == Value::UBigInt(7)));
    let mut statement = connection.prepare(&binding.sql)?;
    let cursor = statement.query([])?;
    let names = cursor
        .as_ref()
        .ok_or("query statement is absent")?
        .column_names();
    assert_eq!(names, ["operation", POSITION_FIELDS[0], POSITION_FIELDS[1]]);
    for sql in [
        "SELECT operation FROM events ORDER BY operation",
        "SELECT operation FROM events LIMIT 1",
        "SELECT DISTINCT operation FROM events",
        "SELECT COUNT(*) FROM events",
    ] {
        let admitted = Fixture::admit(sql, vec![])?;
        assert_eq!(admitted.operation(), QueryOperation::Replace);
        assert!(!admitted.bind_at(1)?.append);
    }
    Ok(())
}

#[test]
fn query_admission_normal_stack() -> TestResult {
    std::thread::Builder::new()
        .name("query-parser-stack".into())
        .stack_size(2 * 1024 * 1024)
        .spawn(|| -> crate::Result<()> {
            let valid = format!("SELECT {}1{} AS value", "(".repeat(32), ")".repeat(32),);
            let admitted = Fixture::admit(&valid, Vec::new())?;
            let bound = admitted.bind_complete(0)?;
            assert_eq!(bound.plan.schema().fields().len(), 1);
            assert_eq!(bound.plan.schema().field(0).name(), "value");
            let trusted = QueryBinding::trusted(valid, Vec::new(), 0)?;
            assert_eq!(trusted.plan.schema().field(0).name(), "value");
            let rejected = format!(
                "SELECT {}1{}",
                "(".repeat(AST_DEPTH + 1),
                ")".repeat(AST_DEPTH + 1),
            );
            assert!(matches!(
                Fixture::admit(&rejected, Vec::new()),
                Err(crate::Error::QueryInvalid {
                    field: "SQL syntax",
                    ..
                }),
            ));
            assert!(matches!(
                QueryBinding::trusted(rejected, Vec::new(), 0),
                Err(crate::Error::QueryInvalid {
                    field: "trusted SQL syntax",
                    ..
                }),
            ));
            Ok(())
        })?
        .join()
        .map_err(|_| "parser thread panicked")??;
    Ok(())
}

#[test]
fn query_admission_parameters() -> TestResult {
    for (sql, parameters) in [
        ("SELECT ?", vec![]),
        ("SELECT $0", vec![Value::Int(1)]),
        ("SELECT $2", vec![Value::Int(1), Value::Int(2)]),
        ("SELECT ?, $1", vec![Value::Int(1)]),
        ("SELECT $name", vec![Value::Int(1)]),
        ("SELECT 1", vec![Value::Int(1)]),
        ("SELECT ?", vec![Value::Double(f64::NAN)]),
        ("SELECT ?", vec![Value::Text("x".repeat(PARAMETER_BYTES))]),
    ] {
        assert!(Fixture::admit(sql, parameters).is_err(), "{sql}");
    }
    Fixture::equivalent("SELECT $1 AS value, $1 AS repeated", vec![Value::Int(7)])?;
    let sql = format!("SELECT 1 --{}", "x".repeat(SQL_BYTES - 11));
    assert_eq!(sql.len(), SQL_BYTES);
    Fixture::admit(&sql, vec![])?;
    assert!(Fixture::admit(&(sql + "x"), vec![]).is_err());
    let nested = format!(
        "SELECT {}1{}",
        "(".repeat(AST_DEPTH + 1),
        ")".repeat(AST_DEPTH + 1)
    );
    assert!(Fixture::admit(&nested, vec![]).is_err());
    Ok(())
}

#[test]
fn analysis_sql_admission_dependencies() -> TestResult {
    for (sql, parameters, expected) in [
        (
            "WITH recent AS (SELECT e.operation FROM \"events\" e WHERE e.received_at >= ?)
             SELECT r.operation, COUNT(*) FROM recent r LEFT JOIN coverage c ON c.operation = r.operation
             WHERE r.operation IS NOT NULL GROUP BY r.operation",
            vec![Value::Timestamp(TimeUnit::Microsecond, 0)],
            &["coverage", "events"][..],
        ),
        (
            "WITH recent AS (SELECT operation FROM coverage) SELECT * FROM recent",
            vec![],
            &["coverage"][..],
        ),
        (
            "WITH recent AS (SELECT operation FROM events) SELECT a.operation FROM recent a JOIN recent b ON a.operation = b.operation",
            vec![],
            &["events"][..],
        ),
        (
            "WITH events AS (SELECT operation FROM coverage) SELECT * FROM events",
            vec![],
            &["coverage"][..],
        ),
    ] {
        let admitted = Fixture::scope_sql(sql, parameters, &["events", "coverage"])?;
        assert_eq!(
            admitted.dependencies(),
            &expected
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<BTreeSet<_>>(),
            "{sql}"
        );
    }
    Ok(())
}

#[test]
fn analysis_sql_admission_escapes() {
    for sql in [
        "SELECT * FROM events; DELETE FROM events",
        "COPY events TO '/tmp/forbidden.csv'",
        "SELECT * INTO copy FROM events",
        "SELECT * FROM read_csv('/etc/passwd')",
        "SELECT read_text('/etc/passwd') FROM events",
        "SELECT * FROM main.events",
        "SELECT * FROM coverage",
    ] {
        assert!(
            Fixture::scope_sql(sql, vec![], &["events"]).is_err(),
            "{sql}"
        );
    }
}

#[test]
fn analysis_sql_authorized_binding() -> TestResult {
    let worker = Fixture::scope_database()?;
    for sql in [
        "SELECT id FROM events WHERE received_at >= TIMESTAMP '2026-01-01 00:00:00'",
        "WITH recent AS (SELECT operation FROM events) SELECT r.operation FROM recent r LEFT JOIN coverage c ON c.operation = r.operation",
        "SELECT id FROM events WHERE (operation IS NULL OR id = 3)",
        "SELECT \"operation\", COUNT(*) FROM \"events\" GROUP BY \"operation\"",
    ] {
        let admitted = Fixture::scope_sql(sql, vec![], &["events", "coverage"])?;
        worker.prepare(sql)?;
        worker.prepare(&admitted.bind_complete(1)?.sql)?;
    }
    for sql in [
        "SELECT secret FROM events",
        "SELECT id FROM events WHERE secret = 'x'",
        "SELECT id FROM events ORDER BY secret",
        "SELECT COUNT(secret) FROM events",
    ] {
        assert!(
            matches!(
                Fixture::scope_sql(sql, vec![], &["events", "coverage"]),
                Err(crate::Error::QueryInvalid { .. })
            ),
            "{sql}"
        );
        assert!(worker.prepare(sql).is_err(), "bound hidden column in {sql}");
    }
    assert!(worker
        .prepare("SELECT * FROM read_csv('/etc/passwd')")
        .is_err());
    Ok(())
}

#[test]
fn analysis_sql_bound_equivalence() -> TestResult {
    const BOUND: i64 = 1_767_225_600_000_000;
    let cases = [
        (
            "SELECT COUNT(*) FROM events WHERE received_at >= TIMESTAMP '2026-01-01 00:00:00'",
            vec![],
            Some(BOUND as u64 * 1_000),
            None,
            2,
        ),
        (
            "SELECT COUNT(*) FROM events e WHERE e.received_at >= ? AND e.operation = 'normal'",
            vec![Value::Timestamp(TimeUnit::Microsecond, BOUND)],
            Some(BOUND as u64 * 1_000),
            None,
            2,
        ),
        (
            "SELECT COUNT(*) FROM events WHERE received_at > TIMESTAMP '2026-01-01 00:00:00'",
            vec![],
            Some((BOUND as u64 + 1) * 1_000),
            None,
            1,
        ),
        (
            "SELECT COUNT(*) FROM events WHERE received_at BETWEEN TIMESTAMP '2026-01-01 00:00:00' AND TIMESTAMP '2026-01-01 00:00:01'",
            vec![],
            Some(BOUND as u64 * 1_000),
            Some((BOUND as u64 + 1_000_000) * 1_000 + 999),
            2,
        ),
        (
            "SELECT COUNT(*) FROM events WHERE operation = 'rare' OR received_at >= TIMESTAMP '2026-01-01 00:00:00'",
            vec![],
            None,
            None,
            3,
        ),
        (
            "SELECT COUNT(*) FROM events WHERE (received_at >= TIMESTAMP '2026-01-01 00:00:00' AND operation = 'normal') OR received_at >= TIMESTAMP '2025-12-31 23:59:59'",
            vec![],
            Some((BOUND as u64 - 1_000_000) * 1_000),
            None,
            3,
        ),
        (
            "SELECT COUNT(*) FROM events WHERE received_at >= CAST(NULL AS TIMESTAMP)",
            vec![],
            None,
            None,
            0,
        ),
        (
            "SELECT COUNT(*) FROM events WHERE (received_at >= TIMESTAMP '2025-12-31 23:59:59' AND received_at >= TIMESTAMP '2026-01-01 00:00:00' AND operation = 'normal') OR received_at >= TIMESTAMP '2026-01-01 00:00:01'",
            vec![],
            Some(BOUND as u64 * 1_000),
            None,
            2,
        ),
        (
            "SELECT COUNT(*) FROM events WHERE (received_at > TIMESTAMP '2026-01-01 00:00:00' AND operation = 'normal') OR received_at > TIMESTAMP '2025-12-31 23:59:59'",
            vec![],
            Some((BOUND as u64 - 1_000_000 + 1) * 1_000),
            None,
            2,
        ),
        (
            "SELECT COUNT(*) FROM events WHERE received_at > TIMESTAMP '2026-01-01 00:00:00' OR received_at >= TIMESTAMP '2026-01-01 00:00:00'",
            vec![],
            Some(BOUND as u64 * 1_000),
            None,
            2,
        ),
    ];
    for (sql, parameters, first, last, expected) in cases {
        let admitted = Fixture::scope_sql(sql, parameters.clone(), &["events"])?;
        let binding = admitted.bind_complete(BOUND as u64 * 1_000)?;
        assert_eq!(
            binding.received_from,
            first.map_or(Bound::Unbounded, Bound::Included),
            "{sql}"
        );
        assert_eq!(
            binding.received_until,
            last.map_or(Bound::Unbounded, Bound::Included),
            "{sql}"
        );
        let full = Fixture::scope_database()?;
        let extracted = Fixture::scope_database()?;
        for (id, timestamp, operation) in [
            (1_i64, BOUND - 1_000_000, "rare"),
            (2, BOUND, "normal"),
            (3, BOUND + 1_000_000, "normal"),
        ] {
            let value = Value::Timestamp(TimeUnit::Microsecond, timestamp);
            full.execute(
                "INSERT INTO events VALUES (?, ?, ?)",
                params![id, value.clone(), operation],
            )?;
            if Fixture::contains(&binding, timestamp as u64 * 1_000) {
                extracted.execute(
                    "INSERT INTO events VALUES (?, ?, ?)",
                    params![id, value, operation],
                )?;
            }
        }
        let full_count: i64 =
            full.query_row(sql, params_from_iter(parameters.iter()), |row| row.get(0))?;
        let extracted_count: i64 = extracted.query_row(
            &binding.sql,
            params_from_iter(binding.parameters.iter()),
            |row| row.get(0),
        )?;
        assert_eq!(full_count, expected, "{sql}");
        assert_eq!(extracted_count, full_count, "partial input changed {sql}");
    }
    for (sql, parameters, allowed) in [
        (
            "SELECT COUNT(*) FROM events WHERE received_at >= ?",
            vec![Value::Text("2026-01-01".to_owned())],
            &["events"][..],
        ),
        (
            "SELECT COUNT(*) FROM events WHERE received_at NOT BETWEEN TIMESTAMP '2026-01-01 00:00:00' AND TIMESTAMP '2026-01-01 00:00:01'",
            vec![],
            &["events"][..],
        ),
        (
            "WITH recent AS (SELECT * FROM events) SELECT COUNT(*) FROM recent",
            vec![],
            &["events"][..],
        ),
        (
            "SELECT COUNT(*) FROM events e JOIN coverage c ON e.operation = c.operation WHERE e.received_at >= TIMESTAMP '2026-01-01 00:00:00'",
            vec![],
            &["events", "coverage"][..],
        ),
    ] {
        let binding = Fixture::scope_sql(sql, parameters, allowed)?.bind_complete(1)?;
        assert_eq!(binding.received_from, Bound::Unbounded, "{sql}");
        assert_eq!(binding.received_until, Bound::Unbounded, "{sql}");
    }
    Ok(())
}
