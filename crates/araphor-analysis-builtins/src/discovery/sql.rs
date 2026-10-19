pub const OBSERVED_EFFECTS_SQL: &str = include_str!("sql/observed_effects.sql");
pub const COVERAGE_RANGES_SQL: &str = include_str!("sql/coverage_ranges.sql");
pub const CONTEXT_BINDINGS_SQL: &str = include_str!("sql/context_bindings.sql");
pub const RECORDED_SNAPSHOT_SQL: &str = include_str!("sql/recorded_snapshot.sql");
pub const MERGE_SQL: &str = include_str!("sql/merge_snapshot.sql");
pub const QUALIFY_RANGES_SQL: &str = include_str!("sql/qualify_ranges.sql");
pub const VIEWS_SQL: &str = concat!(
    include_str!("sql/observed_effects.sql"),
    "\n",
    include_str!("sql/coverage_ranges.sql"),
    "\n",
    include_str!("sql/context_bindings.sql"),
);

impl super::Discovery {
    pub fn live_program(context_sql: &str, coverage_sql: &str) -> String {
        format!(
            include_str!("sql/live.sql"),
            context_sql = context_sql,
            coverage_sql = coverage_sql,
            recorded_sql = RECORDED_SNAPSHOT_SQL,
            qualify_sql = QUALIFY_RANGES_SQL,
            merge_sql = MERGE_SQL,
        )
    }
}
