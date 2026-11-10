use super::*;

impl NativeStore {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn extract_source_manifest(
        &self,
        source: &SourceRead,
        read: &AnalysisTableRead<'_>,
        counts: (usize, usize),
        restricted: bool,
        output: &mut AnalysisExtractionV1,
        capture: &mut Capture<'_>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let mut manifest = source.manifest(&mut |bytes| output.charge(bytes))?;
        let references = if ["graph_revision", "context_refs"]
            .iter()
            .any(|field| read.projects_field("graph_manifest", field))
        {
            let (revision, references) =
                source.revision(self, control, &mut |bytes| output.charge(bytes))?;
            manifest.input_manifest = revision;
            references
        } else {
            Vec::new()
        };
        let reference = source.reference();
        let snapshot = manifest.snapshot();
        output.capture_graph(&reference.result_id, &snapshot, control)?;
        output.reference_result(
            &reference.result_id,
            reference.commit_revision,
            AnalysisReferenceOriginV1::Graph,
        )?;
        if read.projected("graph_manifest").is_none() {
            return Ok(());
        }
        let sensitivity = if restricted || source.restricted() != 0 {
            crate::ContextSensitivityV1::HostRestricted
        } else {
            crate::ContextSensitivityV1::Tenant
        };
        capture.graph(
            &reference.result_id,
            &snapshot,
            &BTreeMap::new(),
            counts.0,
            counts.1,
            reference.commit_revision,
            sensitivity,
            None,
            None,
            &references,
            (
                source.header.captured.commit_revision,
                source.header.coverage,
            ),
            source.expired(),
            Some(source.restricted()),
            &mut output.sink(control),
        )?;
        Ok(())
    }
}
