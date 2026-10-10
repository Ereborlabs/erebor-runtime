use super::*;

pub(super) struct TraversalVersion {
    pub(super) bytes: Vec<u8>,
    pub(super) revision: u64,
    pub(super) sensitivity: crate::ContextSensitivityV1,
    pub(super) buffer: usize,
}

impl AnalysisStore {
    pub(super) fn traversal_versions<T>(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        output: &mut AnalysisExtractionV1<T>,
        control: &AnalysisReadControl,
    ) -> Result<(Vec<String>, Vec<TraversalVersion>)> {
        let mut ids = Vec::new();
        let mut versions = Vec::new();
        let header_bytes = output.limits.input_bytes.saturating_sub(output.input_bytes) / 3;
        let header_bytes = header_bytes.min(
            output
                .limits
                .scan_bytes
                .saturating_sub(output.scanned_bytes),
        );
        GraphRows::visit_headers(
            snapshot,
            selection.tenant_id,
            &selection.graphs,
            header_bytes,
            control,
            |id, mut header, revision, bytes| {
                let buffer = header.snapshot_bytes.saturating_mul(2);
                self.traversal_memory(output, header_bytes.saturating_add(buffer))?;
                output.scan(bytes.len())?;
                let sensitivity =
                    self.traversal_scope(snapshot, selection, id, &mut header, output, control)?;
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
                    let id = id.to_owned();
                    output.charge(id.capacity().saturating_add(bytes.capacity()))?;
                    let added = AnalysisExtractionV1::<T>::grow(
                        &mut ids,
                        output.input_bytes,
                        output.limits.input_bytes,
                    )?;
                    output.charge(added)?;
                    let added = AnalysisExtractionV1::<T>::grow(
                        &mut versions,
                        output.input_bytes,
                        output.limits.input_bytes,
                    )?;
                    output.charge(added)?;
                    self.traversal_memory(output, header_bytes.saturating_add(buffer))?;
                    ids.push(id);
                    versions.push(TraversalVersion {
                        bytes,
                        revision,
                        sensitivity,
                        buffer,
                    });
                }
                Ok(())
            },
        )?;
        Ok((ids, versions))
    }

    pub(super) fn traversal_header<T>(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        id: &str,
        version: &TraversalVersion,
        output: &mut AnalysisExtractionV1<T>,
        control: &AnalysisReadControl,
    ) -> Result<GraphHeader> {
        control.check()?;
        self.traversal_memory(output, version.buffer)?;
        let mut header = GraphHeader::decode(&version.bytes)?;
        self.traversal_findings(snapshot, selection, id, &mut header, output, control)?;
        Ok(header)
    }

    pub(super) fn traversal_scope<T>(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        id: &str,
        header: &mut GraphHeader,
        output: &mut AnalysisExtractionV1<T>,
        control: &AnalysisReadControl,
    ) -> Result<crate::ContextSensitivityV1> {
        control.check()?;
        self.traversal_memory(output, header.snapshot_bytes.saturating_mul(2))?;
        if !selection
            .sources
            .as_slice()
            .contains(&header.snapshot.scope.identity)
        {
            return crate::QueryDeniedSnafu.fail();
        }
        self.traversal_findings(snapshot, selection, id, header, output, control)?;
        self.graph_sensitivity(snapshot, &header.snapshot.input_manifest, control)
    }

    fn traversal_findings<T>(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        id: &str,
        header: &mut GraphHeader,
        output: &mut AnalysisExtractionV1<T>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if !selection.binding_ids.is_empty() {
            output.scan(header.snapshot_bytes)?;
            header.snapshot.findings =
                GraphRows::read_findings(snapshot, id, header, Some(control))?;
            if header.snapshot.findings.len() != header.finding_count {
                return self.reject("the traversal graph finding count differs");
            }
            header.snapshot.validate()?;
        }
        Ok(())
    }

    pub(super) fn traversal_memory<T>(
        &self,
        output: &AnalysisExtractionV1<T>,
        bytes: usize,
    ) -> Result<()> {
        if output
            .input_bytes
            .checked_add(bytes)
            .is_none_or(|bytes| bytes > output.limits.input_bytes)
        {
            return AnalysisInputTooLargeSnafu {
                resource: "graph read buffers",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn traversal_work<T>(
        &self,
        snapshot: &Connection,
        ids: &[String],
        output: &mut AnalysisExtractionV1<T>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let values = std::iter::repeat_n("(?)", ids.len())
            .collect::<Vec<_>>()
            .join(", ");
        let query = format!(
            "WITH selected(result_id) AS (VALUES {values})
             SELECT coalesce(sum(octet_length(from_subject_id) + octet_length(to_subject_id)
                + octet_length(encode(edge_type)) + 32), 0)::UBIGINT
             FROM graph_relationships JOIN selected USING (result_id)"
        );
        let values = ids
            .iter()
            .map(|id| id as &dyn duckdb::ToSql)
            .collect::<Vec<_>>();
        control.check()?;
        let bytes: u64 = snapshot
            .query_row(&query, values.as_slice(), |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "bound native traversal work",
            })?;
        let bytes = usize::try_from(bytes).map_err(|_| {
            AnalysisInputTooLargeSnafu {
                resource: "graph traversal work bytes",
            }
            .build()
        })?;
        output.scan(bytes)?;
        Ok(())
    }
}
