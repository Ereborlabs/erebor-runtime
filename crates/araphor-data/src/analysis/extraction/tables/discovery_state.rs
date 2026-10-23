use super::*;
use crate::DiscoveryStateRowV1;

impl Capture<'_> {
    pub(in crate::analysis::extraction) fn discovery_state(
        &mut self,
        state: &DiscoveryStateRowV1,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        const NAMES: &[&str] = &[
            "tenant_id",
            "node_id",
            "node_boot_id",
            "label_epoch",
            "source_id",
            "source_epoch",
            "cpu_id",
            "contiguous_cursor",
            "retained_floor",
            "source_coverage_revision",
            "method_version",
            "processor_present",
            "processor_class",
            "start_cursor",
            "consumed_cursor",
            "resume_floor",
            "context_revision",
            "retired",
            "current_result_id",
            "result_commit_revision",
            "current_compatible",
            "notice_facts_revision",
            "notice_coverage_revision",
            "interval_id",
            "profile_revision",
            "facts_revision",
            "coverage_revision",
            "created_utc_ns",
            "updated_utc_ns",
            "sealed",
            "input_bytes",
            "incomplete",
            "gaps",
            "context_refs",
            "snapshot",
            "history",
        ];
        let schema = Arc::clone(&self.table("discovery_state", NAMES, budget)?.schema);
        budget.charge(schema.fields().len() * (size_of::<ArrayRef>() + 512))?;
        let batch = if schema.fields().is_empty() {
            RecordBatch::try_new_with_options(
                schema,
                Vec::new(),
                &sdk::arrow_array::RecordBatchOptions::new().with_row_count(Some(1)),
            )
            .map_err(arrow_error)?
        } else {
            serde_arrow::to_record_batch(schema.fields(), &[state]).map_err(|source| {
                crate::Error::DiscoveryContext {
                    source: Box::new(source),
                    location: snafu::location!(),
                }
            })?
        };
        self.table("discovery_state", NAMES, budget)?
            .append_native(batch, budget)
    }

    pub(super) fn discovery_state_fields() -> Vec<sdk::Field> {
        DiscoveryStateRowV1::schema()
            .fields()
            .iter()
            .map(|field| field.as_ref().clone())
            .collect()
    }
}
