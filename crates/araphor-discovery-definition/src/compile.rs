use snafu::ResultExt as _;

use crate::{error::PrqlSnafu, Program, Result};

impl Program {
    pub fn sql(&self) -> Result<Option<String>> {
        match self {
            Self::Sql { source } => Ok(Some(source.inline()?.to_owned())),
            Self::Prql { source } => {
                let options = prqlc::Options::default()
                    .with_target(prqlc::Target::Sql(Some(prqlc::sql::Dialect::Generic)))
                    .no_format()
                    .no_signature()
                    .with_display(prqlc::DisplayOptions::Plain);
                prqlc::compile(source.inline()?, &options)
                    .map(Some)
                    .context(PrqlSnafu)
            }
            Self::Package { .. } => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, Source};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn prql_program_forms() -> TestResult {
        for (source, fragments) in [
            ("from events", vec!["SELECT", "FROM events"]),
            (
                "from events | select {source_cursor, task_cookie}",
                vec!["source_cursor", "task_cookie", "FROM events"],
            ),
            (
                "from events | filter task_cookie > 0",
                vec!["FROM events", "WHERE", "task_cookie > 0"],
            ),
            (
                "from events | group {source_id} (aggregate {total = count this})",
                vec!["source_id", "COUNT(*)", "total", "GROUP BY"],
            ),
        ] {
            let program = Program::Prql {
                source: Source::Inline {
                    inline: source.into(),
                },
            };
            let Some(sql) = program.sql()? else {
                return Err("PRQL SQL is absent".into());
            };
            for fragment in fragments {
                assert!(sql.contains(fragment), "{sql}");
            }
            assert!(!sql.contains("--"));
        }
        Ok(())
    }

    #[test]
    fn prql_target_is_fixed() -> TestResult {
        let program = Program::Prql {
            source: Source::Inline {
                inline: "prql target:sql.mssql\nfrom events | take 2".into(),
            },
        };
        let Some(sql) = program.sql()? else {
            return Err("PRQL SQL is absent".into());
        };
        assert!(sql.contains("LIMIT 2"), "{sql}");
        assert!(!sql.contains("--"));
        Ok(())
    }

    #[test]
    fn prql_failure_is_structured() -> TestResult {
        let program = Program::Prql {
            source: Source::Inline {
                inline: "from".into(),
            },
        };
        let Err(error) = program.sql() else {
            return Err("invalid PRQL compiled".into());
        };
        assert!(matches!(error, Error::Prql { .. }));
        assert!(!error.to_string().contains('\u{001b}'));
        Ok(())
    }

    #[test]
    fn sql_source_is_retained() -> TestResult {
        let sql = "SELECT source_cursor\nFROM events WHERE task_cookie > 0\n";
        let program = Program::Sql {
            source: Source::Inline { inline: sql.into() },
        };
        assert_eq!(program.sql()?.as_deref(), Some(sql));
        Ok(())
    }
}
