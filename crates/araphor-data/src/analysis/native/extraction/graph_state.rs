use super::*;
use crate::analysis::{
    extraction::tables::GraphState,
    native::{progress::Processor, records::Records},
};

impl NativeStore {
    pub(super) fn extract_graph_state(
        &self,
        view: &DataView,
        selection: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut Capture<'_>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if read.projected("graph_state").is_none() {
            return Ok(());
        }
        for identity in selection.sources.as_slice() {
            control.check()?;
            let Some(receipt) = view.source_receipt(identity)? else {
                continue;
            };
            let scope = crate::ProcessorScopeV1 {
                processor_id: crate::GRAPH_PROCESSOR.into(),
                method_version: u64::from(crate::GRAPH_SCHEMA_VERSION),
                identity: identity.clone(),
            };
            let processor = Processor::read(
                &scope,
                view.metadata_revision,
                |key| Records::read(key, &view.snapshot),
                &mut |bytes| output.charge(bytes),
            )?;
            let state = GraphState {
                class: processor.as_ref().map(|(_, state)| match state.class {
                    crate::ProcessorClassV1::Optional => "optional".into(),
                    crate::ProcessorClassV1::Required => "required".into(),
                }),
                start: processor.as_ref().map(|(_, state)| state.start),
                consumed: processor.as_ref().map(|(_, state)| state.consumed),
                resumed: processor.as_ref().map(|(_, state)| state.resumed),
                retired: processor
                    .as_ref()
                    .map(|(_, state)| state.retirement.is_some()),
                result: processor.and_then(|(_, state)| state.head.map(|head| head.result_id)),
            };
            capture.graph_state(&receipt, &state, &mut output.sink(control))?;
        }
        Ok(())
    }
}
