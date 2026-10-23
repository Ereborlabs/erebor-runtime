use datafusion::sql::parser::{DFParserBuilder, Statement};
use snafu::ResultExt as _;

use crate::Result;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Parser {
    pub bytes: Option<usize>,
    pub depth: Option<usize>,
}

impl Parser {
    const STACK_BYTES: usize = 8 * 1024 * 1024;

    pub(crate) fn stack<T>(operation: impl FnOnce() -> T) -> T {
        // Native expressions and spans have no stack growth checkpoints.
        stacker::maybe_grow(Self::STACK_BYTES, Self::STACK_BYTES, operation)
    }

    pub fn parse(&self, sql: &str) -> Result<Statement> {
        if self.bytes.is_some_and(|maximum| sql.len() > maximum) {
            return Err(crate::InvalidSnafu { field: "SQL size" }.build());
        }
        Self::stack(|| {
            let mut statements = DFParserBuilder::new(sql)
                .with_recursion_limit(self.depth.unwrap_or(usize::MAX))
                .build()
                .and_then(|mut parser| parser.parse_statements())
                .context(crate::SqlSnafu)?;
            if statements.len() != 1 {
                return Err(crate::InvalidSnafu {
                    field: "SQL statement",
                }
                .build());
            }
            statements.pop_front().ok_or_else(|| {
                crate::InvalidSnafu {
                    field: "SQL statement",
                }
                .build()
            })
        })
    }
}
