use super::*;

use araphor_discovery_definition::{Definition, Program, Source};
use datafusion::sql::parser::{DFParserBuilder, Statement};
use datafusion::sql::sqlparser::ast::{
    Expr, FunctionArg, FunctionArgExpr, FunctionArgOperator, Ident, ObjectName, Query, SelectItem,
    SetExpr, Statement as SqlStatement, TableFactor, Value,
};

impl Qualification {
    pub(super) fn definition(
        image: &PackageRefV1,
        fixture: &PackageFixtureV1,
        model: &sdk::Model,
    ) -> Result<Definition> {
        let output = model
            .outputs
            .first()
            .ok_or_else(|| Code::Invalid.error("fixture output"))?;
        let mut args = vec![FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(
            Value::SingleQuotedString(output.name.clone()).into(),
        )))];
        for (index, input) in fixture.inputs.iter().enumerate() {
            args.push(FunctionArg::Named {
                name: Ident::with_quote('"', &input.data.name),
                arg: FunctionArgExpr::Expr(Expr::Subquery(Self::selection(
                    &format!("__fixture_input_{index}"),
                    None,
                )?)),
                operator: FunctionArgOperator::RightArrow,
            });
        }
        for field in model.parameters.fields() {
            args.push(FunctionArg::Named {
                name: Ident::with_quote('"', field.name()),
                arg: FunctionArgExpr::Expr(Expr::Subquery(Self::selection(
                    "__fixture_parameters",
                    Some(field.name()),
                )?)),
                operator: FunctionArgOperator::RightArrow,
            });
        }
        let relation = TableFactor::Function {
            lateral: false,
            name: ObjectName::from(vec![
                Ident::with_quote('"', &image.package_id),
                Ident::with_quote('"', &image.revision),
                Ident::with_quote('"', &fixture.export),
            ]),
            args,
            alias: None,
        };
        Ok(Definition {
            name: format!("fixture:{}", fixture.name),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: format!("SELECT * FROM {relation}"),
                },
            },
        })
    }

    fn selection(table: &str, column: Option<&str>) -> Result<Box<Query>> {
        let mut statements = DFParserBuilder::new("SELECT * FROM __fixture")
            .build()
            .and_then(|mut parser| parser.parse_statements())
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let Some(Statement::Statement(statement)) = statements.pop_front() else {
            return Err(Code::Invalid.error("fixture native query").into());
        };
        let SqlStatement::Query(mut query) = *statement else {
            return Err(Code::Invalid.error("fixture native query").into());
        };
        let SetExpr::Select(select) = query.body.as_mut() else {
            return Err(Code::Invalid.error("fixture native query").into());
        };
        if let Some(column) = column {
            select.projection = vec![SelectItem::UnnamedExpr(Expr::Identifier(
                Ident::with_quote('"', column),
            ))];
        }
        let TableFactor::Table { name, .. } = &mut select.from[0].relation else {
            return Err(Code::Invalid.error("fixture native table").into());
        };
        *name = ObjectName::from(vec![Ident::with_quote('"', table)]);
        Ok(query)
    }
}
