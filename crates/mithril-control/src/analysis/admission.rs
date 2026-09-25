use std::collections::BTreeSet;
use std::ops::ControlFlow;

use sqlparser::ast::{
    Expr, FunctionArguments, ObjectName, Query, Select, SelectFlavor, SetExpr, Statement,
    TableFactor, Visit as _, Visitor,
};
use sqlparser::dialect::DuckDbDialect;
use sqlparser::parser::Parser;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SqlAdmissionError {
    TooLarge,
    Syntax,
    NotReadOnly,
    UnsupportedShape,
    UnknownRelation,
    UnknownFunction,
}

#[allow(dead_code, reason = "offline proof precedes the query owner")]
/// Checks read-only syntax and relation names. It does not bind columns or grant access.
pub(crate) fn inspect_read_only_shape(
    sql: &str,
    authorized_relations: &[&str],
) -> Result<BTreeSet<String>, SqlAdmissionError> {
    if sql.is_empty() || sql.len() > 16 * 1_024 {
        return Err(SqlAdmissionError::TooLarge);
    }
    let mut statements =
        Parser::parse_sql(&DuckDbDialect {}, sql).map_err(|_| SqlAdmissionError::Syntax)?;
    if statements.len() != 1 {
        return Err(SqlAdmissionError::NotReadOnly);
    }
    let Statement::Query(query) = statements.remove(0) else {
        return Err(SqlAdmissionError::NotReadOnly);
    };
    let mut guard = ReadOnlyGuard {
        authorized: authorized_relations
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect(),
        ctes: Vec::new(),
        dependencies: BTreeSet::new(),
    };
    match query.visit(&mut guard) {
        ControlFlow::Continue(()) => Ok(guard.dependencies),
        ControlFlow::Break(error) => Err(error),
    }
}

struct ReadOnlyGuard {
    authorized: BTreeSet<String>,
    ctes: Vec<BTreeSet<String>>,
    dependencies: BTreeSet<String>,
}

impl Visitor for ReadOnlyGuard {
    type Break = SqlAdmissionError;

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<Self::Break> {
        if matches!(statement, Statement::Query(_)) {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(SqlAdmissionError::NotReadOnly)
        }
    }

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        if !read_only_body(&query.body)
            || !query.locks.is_empty()
            || query.for_clause.is_some()
            || query.settings.is_some()
            || query.format_clause.is_some()
            || !query.pipe_operators.is_empty()
        {
            return ControlFlow::Break(SqlAdmissionError::NotReadOnly);
        }
        let mut ctes = BTreeSet::new();
        if let Some(with) = &query.with {
            if with.recursive {
                return ControlFlow::Break(SqlAdmissionError::UnsupportedShape);
            }
            for cte in &with.cte_tables {
                let name = cte.alias.name.value.to_ascii_lowercase();
                if self.authorized.contains(&name) {
                    return ControlFlow::Break(SqlAdmissionError::UnsupportedShape);
                }
                ctes.insert(name);
            }
        }
        self.ctes.push(ctes);
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.ctes.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        if select.into.is_some()
            || !select.optimizer_hints.is_empty()
            || select.select_modifiers.is_some()
            || select.top.is_some()
            || select.exclude.is_some()
            || !select.lateral_views.is_empty()
            || select.prewhere.is_some()
            || !select.connect_by.is_empty()
            || !select.cluster_by.is_empty()
            || !select.distribute_by.is_empty()
            || !select.sort_by.is_empty()
            || !select.named_window.is_empty()
            || select.qualify.is_some()
            || select.value_table_mode.is_some()
            || !matches!(select.flavor, SelectFlavor::Standard)
        {
            return ControlFlow::Break(SqlAdmissionError::UnsupportedShape);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, table: &TableFactor) -> ControlFlow<Self::Break> {
        match table {
            TableFactor::Table {
                name,
                args: None,
                with_hints,
                version: None,
                with_ordinality: false,
                partitions,
                json_path: None,
                sample: None,
                index_hints,
                ..
            } if with_hints.is_empty() && partitions.is_empty() && index_hints.is_empty() => {
                let Some(name) = simple_name(name) else {
                    return ControlFlow::Break(SqlAdmissionError::UnknownRelation);
                };
                if self.ctes.iter().rev().any(|scope| scope.contains(&name)) {
                    return ControlFlow::Continue(());
                }
                if !self.authorized.contains(&name) {
                    return ControlFlow::Break(SqlAdmissionError::UnknownRelation);
                }
                self.dependencies.insert(name);
                ControlFlow::Continue(())
            }
            TableFactor::Derived {
                lateral: false,
                sample: None,
                ..
            }
            | TableFactor::NestedJoin { .. } => ControlFlow::Continue(()),
            _ => ControlFlow::Break(SqlAdmissionError::UnsupportedShape),
        }
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        match expr {
            Expr::Identifier(_)
            | Expr::CompoundIdentifier(_)
            | Expr::IsFalse(_)
            | Expr::IsNotFalse(_)
            | Expr::IsTrue(_)
            | Expr::IsNotTrue(_)
            | Expr::IsNull(_)
            | Expr::IsNotNull(_)
            | Expr::IsUnknown(_)
            | Expr::IsNotUnknown(_)
            | Expr::IsDistinctFrom(_, _)
            | Expr::IsNotDistinctFrom(_, _)
            | Expr::InList { .. }
            | Expr::InSubquery { .. }
            | Expr::Between { .. }
            | Expr::BinaryOp { .. }
            | Expr::Like { .. }
            | Expr::ILike { .. }
            | Expr::UnaryOp { .. }
            | Expr::Cast { .. }
            | Expr::Nested(_)
            | Expr::Value(_)
            | Expr::TypedString(_)
            | Expr::Case { .. }
            | Expr::Exists { .. }
            | Expr::Subquery(_)
            | Expr::Tuple(_)
            | Expr::Interval(_)
            | Expr::Wildcard(_) => ControlFlow::Continue(()),
            Expr::Function(function) => {
                let Some(name) = simple_name(&function.name) else {
                    return ControlFlow::Break(SqlAdmissionError::UnknownFunction);
                };
                if function.uses_odbc_syntax
                    || !matches!(function.parameters, FunctionArguments::None)
                    || !function.within_group.is_empty()
                    || function.over.is_some()
                    || function.null_treatment.is_some()
                    || !matches!(
                        name.as_str(),
                        "count" | "sum" | "min" | "max" | "avg" | "coalesce" | "lower" | "upper"
                    )
                {
                    return ControlFlow::Break(SqlAdmissionError::UnknownFunction);
                }
                ControlFlow::Continue(())
            }
            _ => ControlFlow::Break(SqlAdmissionError::UnsupportedShape),
        }
    }
}

fn read_only_body(body: &SetExpr) -> bool {
    match body {
        SetExpr::Select(_) => true,
        SetExpr::Query(query) => read_only_body(&query.body),
        SetExpr::SetOperation { left, right, .. } => read_only_body(left) && read_only_body(right),
        _ => false,
    }
}

fn simple_name(name: &ObjectName) -> Option<String> {
    let [part] = name.0.as_slice() else {
        return None;
    };
    Some(part.as_ident()?.value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use duckdb::{Config, Connection};

    #[test]
    fn analysis_sql_admission_follows_ctes_aliases_and_joins() {
        let allowed = ["events", "coverage"];
        let sql = "WITH recent AS (SELECT e.operation FROM \"events\" e WHERE e.received_at >= ?)
                   SELECT r.operation, COUNT(*) FROM recent r LEFT JOIN coverage c ON c.operation = r.operation
                   WHERE r.operation IS NOT NULL GROUP BY r.operation";
        assert_eq!(
            inspect_read_only_shape(sql, &allowed),
            Ok(BTreeSet::from(["coverage".to_owned(), "events".to_owned()]))
        );
        assert_eq!(
            inspect_read_only_shape(
                "WITH recent AS (SELECT operation FROM coverage) SELECT * FROM recent",
                &allowed
            ),
            Ok(BTreeSet::from(["coverage".to_owned()]))
        );
        assert_eq!(
            inspect_read_only_shape(
                "WITH recent AS (SELECT operation FROM events) SELECT a.operation FROM recent a JOIN recent b ON a.operation = b.operation",
                &allowed
            ),
            Ok(BTreeSet::from(["events".to_owned()]))
        );
        assert_eq!(
            inspect_read_only_shape(
                "WITH events AS (SELECT operation FROM coverage) SELECT * FROM events",
                &allowed
            ),
            Err(SqlAdmissionError::UnsupportedShape)
        );
    }

    #[test]
    fn analysis_sql_admission_rejects_side_effects_and_external_access() {
        let allowed = ["events"];
        for sql in [
            "SELECT * FROM events; DELETE FROM events",
            "COPY events TO '/tmp/forbidden.csv'",
            "SELECT * INTO copy FROM events",
            "SELECT * FROM read_csv('/etc/passwd')",
            "SELECT read_text('/etc/passwd') FROM events",
            "SELECT * FROM main.events",
            "SELECT * FROM coverage",
        ] {
            assert!(inspect_read_only_shape(sql, &allowed).is_err(), "accepted {sql}");
        }
    }

    #[test]
    fn analysis_sql_authorized_schema_binds_before_evaluation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::default()
            .enable_external_access(false)?
            .enable_autoload_extension(false)?;
        let worker = Connection::open_in_memory_with_flags(config)?;
        worker.execute_batch(
            "CREATE TABLE events(id BIGINT, received_at TIMESTAMP, operation VARCHAR);
             CREATE TABLE coverage(operation VARCHAR);",
        )?;
        let allowed = ["events", "coverage"];
        for sql in [
            "SELECT id FROM events WHERE received_at >= TIMESTAMP '2026-01-01 00:00:00'",
            "WITH recent AS (SELECT operation FROM events) SELECT r.operation FROM recent r LEFT JOIN coverage c ON c.operation = r.operation",
            "SELECT id FROM events WHERE (operation IS NULL OR id = 3)",
            "SELECT \"operation\", COUNT(*) FROM \"events\" GROUP BY \"operation\"",
        ] {
            assert!(inspect_read_only_shape(sql, &allowed).is_ok(), "rejected {sql}");
            worker.prepare(sql)?;
        }
        for sql in [
            "SELECT secret FROM events",
            "SELECT id FROM events WHERE secret = 'x'",
            "SELECT id FROM events ORDER BY secret",
            "SELECT COUNT(secret) FROM events",
        ] {
            assert!(inspect_read_only_shape(sql, &allowed).is_ok(), "syntax rejected {sql}");
            assert!(worker.prepare(sql).is_err(), "bound hidden column in {sql}");
        }
        assert!(worker
            .prepare("SELECT * FROM read_csv('/etc/passwd')")
            .is_err());
        Ok(())
    }
}
