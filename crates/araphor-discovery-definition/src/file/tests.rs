use super::*;
use sqlparser::ast::SetExpr;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    directory: tempfile::TempDir,
    path: PathBuf,
}

impl Fixture {
    fn new(yaml: &str) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("definition.yaml");
        std::fs::write(&path, yaml)?;
        Ok(Self { directory, path })
    }

    fn read(&self) -> Result<Definition> {
        Definition::read(&self.path)
    }

    fn args(definition: &Definition) -> TestResult<Vec<FunctionArg>> {
        let query = Call::query(definition.program.source().inline()?)?;
        let SetExpr::Select(select) = *query.body else {
            return Err("call has no SELECT".into());
        };
        let relation = select
            .from
            .into_iter()
            .next()
            .ok_or("call has no relation")?;
        let TableFactor::Table {
            args: Some(args), ..
        } = relation.relation
        else {
            return Err("call has no arguments".into());
        };
        Ok(args.args)
    }
}

#[test]
fn yaml_program_sources() -> TestResult {
    for (kind, source) in [
        ("sql", "SELECT source_cursor FROM events\n"),
        ("prql", "from events | select {source_cursor}\n"),
    ] {
        for file in [false, true] {
            let input = if file {
                format!("{kind}: {{file: source.{kind}}}\n")
            } else {
                format!("{kind}: |\n  {}", source.replace('\n', "\n  ").trim_end())
            };
            let fixture = Fixture::new(&format!(
                "name: retained\ndescription: selected source\nlabels: {{owner: test}}\n{input}\n"
            ))?;
            let source_path = fixture.directory.path().join(format!("source.{kind}"));
            if file {
                std::fs::write(&source_path, source)?;
            }
            let definition = fixture.read()?;
            assert_eq!(definition.name, "retained");
            assert_eq!(definition.description, "selected source");
            assert_eq!(
                definition.labels.get("owner").map(String::as_str),
                Some("test")
            );
            assert_eq!(definition.program.source().inline()?, source);
            assert!(matches!(
                (&definition.program, kind),
                (Program::Sql { .. }, "sql") | (Program::Prql { .. }, "prql")
            ));
            if file {
                std::fs::write(&source_path, "changed")?;
                std::fs::remove_file(&source_path)?;
                assert_eq!(definition.program.source().inline()?, source);
            }
        }
    }
    Ok(())
}

#[test]
fn yaml_strict_forms() -> TestResult {
    for yaml in [
        "sql: SELECT 1",
        "name: ''\nsql: SELECT 1",
        "name: test",
        "name: test\nsql: SELECT 1\nprql: from events",
        "name: test\nsql: SELECT 1\ncall: {package: fixture, revision: r1, export: count}",
        "name: test\nsql: SELECT 1\nunknown: true",
        "name: test\nsql: {inline: SELECT 1}",
        "name: test\nsql: {file: source.sql, unknown: true}",
        "name: test\nsql: ''",
        "name: test\nsql: {file: ''}",
        "name: test\nsql: true",
        "name: null\nsql: SELECT 1",
        "name: test\ndescription: null\nsql: SELECT 1",
        "name: test\nlabels: null\nsql: SELECT 1",
        "name: test\nsql: null",
        "name: test\nprql: null",
        "name: test\ncall: null",
        "name: test\ncall: {package: fixture, revision: r1, export: count, output: null}",
        "name: test\ncall: {package: fixture, revision: r1, export: count, inputs: null}",
        "name: test\ncall: {package: fixture, revision: r1, export: count, parameters: null}",
        "name: test\ncall: {package: fixture, revision: r1, export: count, unknown: true}",
        "name: test\ncall: {package: '', revision: r1, export: count}",
        "name: test\ncall: {package: fixture, revision: '', export: count}",
        "name: test\ncall: {package: fixture, revision: r1, export: ''}",
        "name: test\ncall: {package: fixture, revision: r1, export: count, output: ''}",
        "name: test\ncall: {package: fixture, revision: r1, export: count, parameters: {' ': 2}}",
        "name: test\nsql: SELECT 1\nsql: SELECT 2",
        "name: test\nlabels: {owner: first, owner: second}\nsql: SELECT 1",
        "name: test\ncall: {package: fixture, revision: r1, export: count, inputs: {source: SELECT 1, source: SELECT 2}}",
        "name: test\ncall: {package: fixture, revision: r1, export: count, parameters: {increment: 2, increment: 3}}",
        "name: test\ncall: {package: fixture, revision: r1, export: count, parameters: {nested: {value: 1, value: 2}}}",
        "name: test\nsql: SELECT 1\n<<: {description: merged}",
        "name: first\nsql: SELECT 1\n---\nname: second\nsql: SELECT 2",
    ] {
        let fixture = Fixture::new(yaml)?;
        assert!(fixture.read().is_err(), "accepted {yaml}");
    }
    Ok(())
}

#[test]
fn yaml_call_quoting() -> TestResult {
    let fixture = Fixture::new(
        r#"name: quoted
call:
  package: 'fixture".id'
  revision: 'r"1'
  export: 'co"unt'
  output: 'row''s'
  inputs:
    'so"urce': {file: input.sql}
  parameters:
    'mes"sage': "O'Reilly'); DROP TABLE events; --"
"#,
    )?;
    let path = fixture.directory.path().join("input.sql");
    std::fs::write(&path, "SELECT source_cursor AS value FROM events")?;
    let definition = fixture.read()?;
    std::fs::write(&path, "SELECT missing FROM absent")?;
    std::fs::remove_file(&path)?;
    let query = Call::query(definition.program.source().inline()?)?;
    let SetExpr::Select(select) = *query.body else {
        return Err("call has no SELECT".into());
    };
    let relation = select
        .from
        .into_iter()
        .next()
        .ok_or("call has no relation")?;
    let TableFactor::Table {
        name,
        args: Some(args),
        ..
    } = relation.relation
    else {
        return Err("call has no arguments".into());
    };
    assert_eq!(
        name.0
            .iter()
            .map(|part| part.as_ident().map(|ident| ident.value.as_str()))
            .collect::<Option<Vec<_>>>(),
        Some(vec!["fixture\".id", "r\"1", "co\"unt"])
    );
    assert_eq!(args.args.len(), 3);
    assert!(
        matches!(&args.args[0], FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(value))) if value.value == SqlValue::SingleQuotedString("row's".into()))
    );
    assert!(
        matches!(&args.args[1], FunctionArg::Named { name, arg: FunctionArgExpr::Expr(Expr::Subquery(query)), .. } if name.value == "so\"urce" && query.to_string() == "SELECT source_cursor AS value FROM events")
    );
    assert!(
        matches!(&args.args[2], FunctionArg::Named { name, arg: FunctionArgExpr::Expr(Expr::Value(value)), .. } if name.value == "mes\"sage" && value.value == SqlValue::SingleQuotedString("O'Reilly'); DROP TABLE events; --".into()))
    );
    Ok(())
}

#[test]
fn yaml_call_literals() -> TestResult {
    let fixture = Fixture::new(
        r#"name: literals
call:
  package: fixture
  revision: r1
  export: count
  parameters:
    maximum: 18446744073709551615
    minimum: -9223372036854775808
    decimal: 1.25
    absent: null
    text: "null"
    nested: {items: [1, true, null, "O'Reilly"]}
"#,
    )?;
    let definition = fixture.read()?;
    let values = Fixture::args(&definition)?
        .into_iter()
        .map(|arg| {
            let FunctionArg::Named {
                name,
                arg: FunctionArgExpr::Expr(value),
                ..
            } = arg
            else {
                return Err("call has an unexpected argument".into());
            };
            Ok((name.value, value))
        })
        .collect::<TestResult<BTreeMap<_, _>>>()?;
    assert_eq!(values["maximum"].to_string(), "18446744073709551615");
    assert_eq!(values["minimum"].to_string(), "-9223372036854775808");
    assert_eq!(values["decimal"].to_string(), "1.25");
    assert!(matches!(&values["absent"], Expr::Value(value) if value.value == SqlValue::Null));
    assert!(
        matches!(&values["text"], Expr::Value(value) if value.value == SqlValue::SingleQuotedString("null".into()))
    );
    let Expr::Dictionary(fields) = &values["nested"] else {
        return Err("nested parameter has no dictionary".into());
    };
    let field = fields.first().ok_or("nested parameter has no field")?;
    assert_eq!(field.key.value, "items");
    let Expr::Array(array) = field.value.as_ref() else {
        return Err("nested parameter has no array".into());
    };
    assert_eq!(array.elem.len(), 4);
    assert_eq!(array.elem[0].to_string(), "1");
    assert_eq!(array.elem[1].to_string(), "true");
    assert_eq!(array.elem[2].to_string(), "NULL");
    assert!(
        matches!(&array.elem[3], Expr::Value(value) if value.value == SqlValue::SingleQuotedString("O'Reilly".into()))
    );
    Ok(())
}

#[test]
fn yaml_literal_errors() -> TestResult {
    for value in [
        ".nan",
        ".inf",
        "-.inf",
        "1e999",
        "!!float .nan",
        "!!float 1.25",
        "!!float 18446744073709551616",
        "!unknown -9223372036854775809",
    ] {
        let fixture = Fixture::new(&format!(
            "name: rejected\ncall:\n  package: fixture\n  revision: r1\n  export: count\n  parameters: {{value: {value}}}\n"
        ))?;
        assert!(fixture.read().is_err(), "accepted {value}");
    }
    Ok(())
}

#[test]
fn yaml_input_queries() -> TestResult {
    for sql in [
        "SELECT 1; SELECT 2",
        "DELETE FROM events",
        "CREATE TABLE source (value BIGINT)",
        "SELECT FROM",
    ] {
        let fixture = Fixture::new(&format!(
            "name: rejected\ncall:\n  package: fixture\n  revision: r1\n  export: count\n  inputs:\n    source: {sql}\n"
        ))?;
        assert!(fixture.read().is_err(), "accepted {sql}");
    }
    let fixture = Fixture::new("name: missing\nsql: {file: absent.sql}")?;
    assert!(matches!(fixture.read(), Err(crate::Error::Io { .. })));
    let fixture = Fixture::new("name: ''\nsql: {file: absent.sql}")?;
    assert!(matches!(
        fixture.read(),
        Err(crate::Error::Invalid { field: "name", .. })
    ));
    Ok(())
}

#[test]
fn yaml_call_defaults() -> TestResult {
    let fixture =
        Fixture::new("name: defaults\ncall: {package: fixture, revision: r1, export: count}")?;
    let definition = fixture.read()?;
    assert_eq!(definition.description, "");
    assert!(definition.labels.is_empty());
    assert!(Fixture::args(&definition)?.is_empty());
    Ok(())
}

#[test]
fn yaml_integer_bounds() -> TestResult {
    for value in [
        "-9223372036854775809".to_owned(),
        "18446744073709551616".to_owned(),
        "9".repeat(200),
    ] {
        let fixture = Fixture::new(&format!(
            "name: rejected\ncall:\n  package: fixture\n  revision: r1\n  export: count\n  parameters: {{value: {value}}}\n"
        ))?;
        assert!(fixture.read().is_err(), "rounded {value}");
    }
    Ok(())
}

#[test]
fn yaml_literal_notation() -> TestResult {
    let fixture = Fixture::new(
        r#"name: notation
call:
  package: fixture
  revision: r1
  export: count
  parameters:
    text: "18446744073709551616"
    tagged: !!str 18446744073709551616
    decimal: 18446744073709551616.0
    exponential: 1e30
"#,
    )?;
    let definition = fixture.read()?;
    let args = Fixture::args(&definition)?;
    assert_eq!(args.len(), 4);
    for arg in args {
        let FunctionArg::Named {
            name,
            arg: FunctionArgExpr::Expr(value),
            ..
        } = arg
        else {
            return Err("call has an unexpected argument".into());
        };
        if ["text", "tagged"].contains(&name.value.as_str()) {
            assert!(
                matches!(value, Expr::Value(value) if value.value == SqlValue::SingleQuotedString("18446744073709551616".into()))
            );
        } else {
            assert!(
                matches!(value, Expr::Value(value) if matches!(value.value, SqlValue::Number(_, _)))
            );
        }
    }
    Ok(())
}

#[test]
fn native_call_quotes_metadata() -> TestResult {
    let image = PackageRefV1 {
        package_id: "fixture\".id".into(),
        revision: "r\"1".into(),
    };
    let definition = Definition {
        name: "native-call".into(),
        description: String::new(),
        labels: BTreeMap::new(),
        program: Program::call(&image, "co\"unt", "row's")?,
    };
    let query = Call::query(definition.program.source().inline()?)?;
    let SetExpr::Select(select) = *query.body else {
        return Err("native SELECT".into());
    };
    let TableFactor::Table { name, .. } = &select.from[0].relation else {
        return Err("native relation".into());
    };
    assert_eq!(
        name.0
            .iter()
            .map(|part| part.as_ident().map(|ident| ident.value.as_str()))
            .collect::<Option<Vec<_>>>(),
        Some(vec!["fixture\".id", "r\"1", "co\"unt"])
    );
    let args = Fixture::args(&definition)?;
    assert_eq!(args.len(), 1);
    assert!(matches!(&args[0],
        FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(value)))
            if value.value == SqlValue::SingleQuotedString("row's".into())));
    Ok(())
}
