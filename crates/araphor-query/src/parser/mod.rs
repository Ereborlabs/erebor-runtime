use datafusion::sql::parser::{DFParserBuilder, Statement};
use snafu::ResultExt as _;

use crate::Result;

pub struct Parser;

impl Parser {
    pub const SQL_BYTES: usize = 16 * 1024;
    pub const RECURSION_LIMIT: usize = 64;
    const STACK_BYTES: usize = 8 * 1024 * 1024;

    pub fn parse(sql: &str) -> Result<Statement> {
        if sql.is_empty() || sql.len() > Self::SQL_BYTES {
            return Err(crate::InvalidSnafu { field: "SQL size" }.build());
        }
        // Native nested expressions have no stack growth checkpoints.
        stacker::maybe_grow(Self::STACK_BYTES, Self::STACK_BYTES, || {
            let mut statements = DFParserBuilder::new(sql)
                .with_recursion_limit(Self::RECURSION_LIMIT)
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
