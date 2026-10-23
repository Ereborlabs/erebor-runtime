use super::*;
use crate::AnalysisSourceReceiptV1;

pub(in crate::analysis::extraction) struct GraphState {
    pub class: Option<String>,
    pub start: Option<u64>,
    pub consumed: Option<u64>,
    pub resumed: Option<u64>,
    pub retired: Option<bool>,
    pub result: Option<String>,
}

impl Capture<'_> {
    table_row! {
        pub(in crate::analysis::extraction) fn graph_state(
            &mut self,
            receipt: &AnalysisSourceReceiptV1,
            state: &GraphState,
            budget: &mut ReadBudget<'_>,
        );
        schema graph_state_fields;
        row(self, "graph_state", budget);
        setup {
            let source = &receipt.identity;
            let source_key = source.key();
            budget.charge(source_key.capacity())?;
        }
        fields {
            tenant_id => Binary(false): Some(source.tenant_id.as_slice()),
            node_id => Utf8(false): Some(source.node_id.as_str()),
            node_boot_id => Binary(false): Some(source.node_boot_id.as_slice()),
            label_epoch => UInt64(false): Some(source.label_epoch),
            source_id => Binary(false): Some(source.source_id.as_slice()),
            source_epoch => UInt64(false): Some(source.source_epoch),
            source_key => Binary(false): Some(source_key.as_slice()),
            cpu_id => UInt32(false): Some(receipt.cpu_id),
            contiguous_cursor => UInt64(false): Some(receipt.contiguous_cursor),
            retained_floor => UInt64(false): Some(receipt.retained_floor),
            coverage_revision => UInt64(false): Some(receipt.coverage_revision),
            method_version => UInt64(false): Some(u64::from(crate::GRAPH_SCHEMA_VERSION)),
            processor_present => Boolean(false): Some(state.class.is_some()),
            processor_class => Utf8(true): state.class.as_deref(),
            start_cursor => UInt64(true): state.start,
            consumed_cursor => UInt64(true): state.consumed,
            resume_floor => UInt64(true): state.resumed,
            retired => Boolean(true): state.retired,
            current_result_id => Utf8(true): state.result.as_deref(),
        }
    }
}
