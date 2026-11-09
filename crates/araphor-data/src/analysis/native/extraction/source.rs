use super::{DataView, NativeStore};
use crate::{AnalysisExtractionV1, AnalysisReadControl, AnalysisSelectionV1, Result, Selection};

impl NativeStore {
    pub(super) fn select_sources(
        &self,
        view: &DataView,
        selection: &mut AnalysisSelectionV1,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if selection.sources.is_all() {
            let mut sources = Vec::new();
            for source in view.raw.sources.values() {
                control.check()?;
                let Some(receipt) = source.receipt.evidence() else {
                    continue;
                };
                let identity = &receipt.identity;
                if identity.tenant_id != selection.tenant_id
                    || !selection.nodes.is_empty() && !selection.nodes.contains(&identity.node_id)
                    || view.source_receipt(identity)?.is_none()
                {
                    continue;
                }
                if output
                    .limits
                    .keys
                    .is_some_and(|limit| selection.key_count() + sources.len() >= limit)
                {
                    return crate::AnalysisInputTooLargeSnafu {
                        resource: "selected input keys",
                    }
                    .fail();
                }
                output.charge(AnalysisExtractionV1::grow(
                    &mut sources,
                    output.input_bytes,
                    output.limits.input_bytes,
                )?)?;
                output.charge(identity.node_id.len())?;
                sources.push(identity.clone());
            }
            sources.sort();
            selection.sources = Selection::Exact(sources);
        } else if !selection.nodes.is_empty() {
            if let Some(sources) = selection.sources.exact_mut() {
                sources.retain(|identity| selection.nodes.contains(&identity.node_id));
            }
        }
        for identity in selection.sources.as_slice() {
            control.check()?;
            let added = AnalysisExtractionV1::grow(
                &mut output.sources,
                output.input_bytes,
                output.limits.input_bytes,
            )?;
            output.charge(added)?;
            let source = view.source_header(identity, &self.root, output, control)?;
            output.sources.push(source);
        }
        Ok(())
    }
}
