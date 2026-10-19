use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use num_bigint::BigInt;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use serde_saphyr::granit_parser::{Event, Parser as YamlParser, ScalarStyle};
use snafu::ResultExt as _;
use sqlparser::ast::{
    Array, DictionaryField, Expr, FunctionArg, FunctionArgExpr, FunctionArgOperator, Ident,
    ObjectName, Query, Statement, TableFactor, Value as SqlValue,
};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

use crate::error::{InvalidSnafu, IoSnafu, SqlSnafu, YamlScanSnafu, YamlSnafu};
use crate::{Definition, Program, Result, Source};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct YamlDefinition {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default, deserialize_with = "non_null_map")]
    labels: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "present")]
    sql: Option<FileSource>,
    #[serde(default, deserialize_with = "present")]
    prql: Option<FileSource>,
    #[serde(default, deserialize_with = "present")]
    call: Option<Call>,
}

#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum FileSource {
    Text(String),
    File { file: PathBuf },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    package: String,
    revision: String,
    export: String,
    #[serde(default, deserialize_with = "non_null_map")]
    inputs: BTreeMap<String, FileSource>,
    #[serde(default, deserialize_with = "non_null_map")]
    parameters: BTreeMap<String, Value>,
    #[serde(default, deserialize_with = "present")]
    output: Option<String>,
}

fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

fn non_null_map<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, T>, D::Error> {
    Option::<BTreeMap<String, T>>::deserialize(deserializer)?
        .ok_or_else(|| serde::de::Error::custom("Expected a map"))
}

impl YamlDefinition {
    pub(crate) fn read(path: &Path) -> Result<Definition> {
        let yaml = std::fs::read_to_string(path).context(IoSnafu { path })?;
        Self::check_scalars(&yaml)?;
        let mut options = serde_saphyr::Options::default();
        options.budget = None;
        options.alias_limits = serde_saphyr::alias_limits! {
            max_total_replayed_events: usize::MAX,
            max_replay_stack_depth: usize::MAX,
            max_alias_expansions_per_anchor: usize::MAX,
        };
        options.strict_booleans = true;
        options.no_schema = true;
        options.duplicate_keys = serde_saphyr::DuplicateKeyPolicy::Error;
        options.merge_keys = serde_saphyr::MergeKeyPolicy::Error;
        let file: Self = serde_saphyr::from_str_with_options(&yaml, options).context(YamlSnafu)?;
        file.capture(path.parent().unwrap_or(Path::new(".")))
    }

    fn check_scalars(yaml: &str) -> Result<()> {
        let minimum = BigInt::from(i64::MIN);
        let maximum = BigInt::from(u64::MAX);
        for event in YamlParser::new_from_str(yaml) {
            let (event, _) = event.context(YamlScanSnafu)?;
            let Event::Scalar(value, style, _, tag) = event else {
                continue;
            };
            if tag.as_ref().is_some_and(|tag| !tag.is_yaml_core_schema()) {
                return InvalidSnafu { field: "YAML tag" }.fail();
            }
            if style != ScalarStyle::Plain
                || tag
                    .as_ref()
                    .is_some_and(|tag| !tag.is_yaml_core_schema_tag("int"))
            {
                continue;
            }
            let Ok(integer) = value.parse::<BigInt>() else {
                continue;
            };
            if integer < minimum || integer > maximum {
                return InvalidSnafu {
                    field: "integer literal",
                }
                .fail();
            }
        }
        Ok(())
    }

    fn capture(self, directory: &Path) -> Result<Definition> {
        if self.name.trim().is_empty() {
            return InvalidSnafu { field: "name" }.fail();
        }
        let program = match (self.sql, self.prql, self.call) {
            (Some(source), None, None) => Program::Sql {
                source: Source::Inline {
                    inline: source.capture(directory)?,
                },
            },
            (None, Some(source), None) => Program::Prql {
                source: Source::Inline {
                    inline: source.capture(directory)?,
                },
            },
            (None, None, Some(call)) => Program::Sql {
                source: Source::Inline {
                    inline: call.sql(directory)?,
                },
            },
            _ => return InvalidSnafu { field: "program" }.fail(),
        };
        Ok(Definition {
            name: self.name,
            description: self.description,
            labels: self.labels,
            program,
        })
    }
}

impl FileSource {
    fn capture(self, directory: &Path) -> Result<String> {
        let text = match self {
            Self::Text(text) => text,
            Self::File { file } => {
                if file.as_os_str().is_empty() {
                    return InvalidSnafu { field: "source" }.fail();
                }
                let path = directory.join(file);
                std::fs::read_to_string(&path).context(IoSnafu { path })?
            }
        };
        if text.trim().is_empty() {
            return InvalidSnafu { field: "source" }.fail();
        }
        Ok(text)
    }
}

impl Call {
    fn sql(self, directory: &Path) -> Result<String> {
        let name = ObjectName::from(vec![
            Self::ident(self.package)?,
            Self::ident(self.revision)?,
            Self::ident(self.export)?,
        ]);
        let mut args = Vec::new();
        if let Some(output) = self.output {
            if output.trim().is_empty() {
                return InvalidSnafu { field: "output" }.fail();
            }
            args.push(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(
                SqlValue::SingleQuotedString(output).into(),
            ))));
        }
        for (name, source) in self.inputs {
            args.push(FunctionArg::Named {
                name: Self::ident(name)?,
                arg: FunctionArgExpr::Expr(Expr::Subquery(Self::query(
                    &source.capture(directory)?,
                )?)),
                operator: FunctionArgOperator::RightArrow,
            });
        }
        for (name, value) in self.parameters {
            args.push(FunctionArg::Named {
                name: Self::ident(name)?,
                arg: FunctionArgExpr::Expr(Self::literal(value)),
                operator: FunctionArgOperator::RightArrow,
            });
        }
        let relation = TableFactor::Function {
            lateral: false,
            name,
            args,
            alias: None,
        };
        Ok(format!("SELECT * FROM {relation}"))
    }

    fn ident(value: String) -> Result<Ident> {
        if value.trim().is_empty() {
            return InvalidSnafu {
                field: "call identifier",
            }
            .fail();
        }
        Ok(Ident::with_quote('"', value))
    }

    fn query(sql: &str) -> Result<Box<Query>> {
        let mut statements = Parser::new(&GenericDialect)
            .with_recursion_limit(usize::MAX)
            .try_with_sql(sql)
            .and_then(|mut parser| parser.parse_statements())
            .context(SqlSnafu)?;
        if statements.len() != 1 {
            return InvalidSnafu { field: "input SQL" }.fail();
        }
        match statements.pop() {
            Some(Statement::Query(query)) => Ok(query),
            _ => InvalidSnafu { field: "input SQL" }.fail(),
        }
    }

    fn literal(value: Value) -> Expr {
        let value = match value {
            Value::Array(values) => {
                return Expr::Array(Array {
                    elem: values.into_iter().map(Self::literal).collect(),
                    named: true,
                });
            }
            Value::Object(fields) => {
                return Expr::Dictionary(
                    fields
                        .into_iter()
                        .map(|(name, value)| DictionaryField {
                            key: Ident::with_quote('"', name),
                            value: Box::new(Self::literal(value)),
                        })
                        .collect(),
                );
            }
            Value::Null => SqlValue::Null,
            Value::Bool(value) => SqlValue::Boolean(value),
            Value::Number(value) => SqlValue::Number(value.to_string(), false),
            Value::String(value) => SqlValue::SingleQuotedString(value),
        };
        Expr::Value(value.into())
    }
}

#[cfg(test)]
mod tests;
