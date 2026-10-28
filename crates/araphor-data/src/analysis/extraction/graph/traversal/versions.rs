use super::*;

pub(super) struct TraversalVersion {
    pub(super) header: GraphHeader,
    pub(super) revision: u64,
    pub(super) sensitivity: crate::ContextSensitivityV1,
}

impl AnalysisStore {
    pub(super) fn traversal_versions(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<(Vec<String>, Vec<TraversalVersion>)> {
        let mut ids = Vec::new();
        let mut versions = Vec::new();
        GraphRows::visit_headers(
            snapshot,
            selection.tenant_id,
            selection.graphs.as_slice(),
            control,
            |id, mut header, revision, _| {
                let sensitivity =
                    self.traversal_scope(snapshot, selection, id, &mut header, control)?;
                if selection.permits_graph(&header.snapshot)
                    && (selection.binding_ids.is_empty()
                        || header.snapshot.findings.iter().all(|finding| {
                            !finding.effects.is_empty()
                                && finding.effects.iter().all(|effect| {
                                    effect.binding_id.is_some_and(|binding| {
                                        selection.binding_ids.contains(&binding)
                                    })
                                })
                        }))
                {
                    output.capture_graph(id, &header.snapshot, control)?;
                    let id = id.to_owned();
                    ids.push(id);
                    versions.push(TraversalVersion {
                        header,
                        revision,
                        sensitivity,
                    });
                }
                Ok(())
            },
        )?;
        Ok((ids, versions))
    }

    pub(super) fn traversal_scope(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        id: &str,
        header: &mut GraphHeader,
        control: &AnalysisReadControl,
    ) -> Result<crate::ContextSensitivityV1> {
        control.check()?;
        if !selection
            .sources
            .as_slice()
            .contains(&header.snapshot.scope.identity)
        {
            return crate::AnalysisReadDeniedSnafu.fail();
        }
        self.traversal_findings(snapshot, selection, id, header, control)?;
        self.graph_sensitivity(snapshot, &header.snapshot.input_manifest, control)
    }

    fn traversal_findings(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        id: &str,
        header: &mut GraphHeader,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if !selection.binding_ids.is_empty() {
            header.snapshot.findings =
                GraphRows::read_findings(snapshot, id, header, Some(control))?;
            if header.snapshot.findings.len() != header.finding_count {
                return self.reject("the traversal graph finding count differs");
            }
            header.snapshot.validate()?;
        }
        Ok(())
    }
}
