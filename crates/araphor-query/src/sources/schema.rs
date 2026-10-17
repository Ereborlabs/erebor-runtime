use std::collections::BTreeMap;

use datafusion::arrow::datatypes::SchemaRef;

use super::SourceSnapshot;

impl SourceSnapshot {
    pub(crate) fn schemas() -> &'static BTreeMap<String, SchemaRef> {
        araphor_data::AnalysisStore::table_schemas()
    }
}
