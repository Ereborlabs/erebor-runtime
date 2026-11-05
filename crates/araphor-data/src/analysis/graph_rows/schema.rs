use super::*;

impl GraphRows {
    #[cfg(test)]
    pub(in crate::analysis) const SCHEMA: &str =
        crate::analysis::graph_rows::store::Relations::SCHEMA;

    pub(in crate::analysis) fn schema() -> String {
        crate::analysis::graph_rows::store::Relations::schema()
    }

    pub(in crate::analysis) fn validate_tables(writer: &Connection) -> Result<()> {
        crate::analysis::graph_rows::store::Relations::validate_tables(writer).map_err(Into::into)
    }
}
