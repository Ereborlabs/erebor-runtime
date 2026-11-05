use super::*;

impl AnalysisStore {
    pub(super) fn extract_definition_graph(
        &self,
        reader: &Connection,
        scope: &AnalysisSelectionV1,
        result: &str,
        revision: u64,
        grant: &crate::PackageGrantV1,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut tables::Capture<'_>,
        control: &AnalysisReadControl,
        owners: &mut crate::analysis::managed::OwnerRead<'_>,
    ) -> Result<()> {
        owners.check_reader(reader, scope.tenant_id)?;
        if grant.permitted_by(scope).is_err() {
            return Ok(());
        }
        let mut origins = BTreeMap::new();
        if read.projected("findings").is_some() {
            let rows = owners.finding_rows(
                &self.graph_engine,
                reader,
                scope.tenant_id,
                result,
                None,
                &mut |scan, bytes| {
                    control.check()?;
                    output.scan(scan)?;
                    output.charge(bytes)
                },
            )?;
            let mut seen = std::collections::BTreeSet::new();
            for row in rows {
                control.check()?;
                if !seen.insert(row.id()?.to_owned()) {
                    continue;
                }
                let origin = (row.origin.clone(), row.origin_revision);
                let allowed = match origins.get(&origin) {
                    Some(allowed) => *allowed,
                    None => {
                        output.charge(
                            origin.0.capacity() + 8 * std::mem::size_of::<(String, u64, bool)>(),
                        )?;
                        let allowed = owners
                            .producer(&origin.0, origin.1, &mut |scan, bytes| {
                                output.scan(scan)?;
                                output.charge(bytes)
                            })?
                            .grant()
                            .permitted_by(scope)
                            .is_ok();
                        origins.insert(origin, allowed);
                        allowed
                    }
                };
                if !allowed {
                    continue;
                }
                let member = row.decode(&mut |scan, bytes| {
                    output.scan(scan)?;
                    output.charge(bytes)
                })?;
                if !capture.native_finding(
                    result,
                    revision,
                    row.restricted,
                    None,
                    &member.value,
                    row.value,
                    &mut output.sink(control),
                )? {
                    return Ok(());
                }
            }
        }
        if read.projected("graph_manifest").is_none() {
            return Ok(());
        }
        let mut query = reader.prepare_cached(
            "SELECT pin.writer_id,layer.revision,publication.previous_result_id,coalesce(origin.restricted,false)
             FROM managed_graph_publications publication LEFT JOIN managed_graph_publication_layers pin USING(result_id)
             LEFT JOIN graph_layers layer USING(layer_id,writer_id)
             LEFT JOIN managed_graph_results origin USING(layer_id,writer_id)
             WHERE publication.result_id=?"
        ).context(AnalysisDatabaseSnafu { operation:"prepare Definition Graph view" })?;
        let pins = query
            .query_map(params![result], |row| {
                Ok((
                    row.get::<_, Option<u64>>(0)?,
                    row.get::<_, Option<u64>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read Definition Graph view",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode Definition Graph view",
            })?;
        let previous = pins
            .first()
            .and_then(|(_, _, previous, _)| previous.clone());
        let restricted = pins.iter().any(|(_, _, _, restricted)| *restricted);
        let heads = pins
            .into_iter()
            .filter_map(|(writer, revision, _, _)| writer.zip(revision))
            .collect::<BTreeMap<_, _>>();
        let members = self.graph_engine.view(&heads, || {
            control.check().map_err(araphor_graph::Error::backend)
        })?;
        let mut nodes = std::collections::BTreeSet::new();
        let mut edges = std::collections::BTreeSet::new();
        let mut producers = std::collections::BTreeSet::new();
        for member in members {
            output.charge(member.key.len() + 12 * std::mem::size_of::<(u64, Vec<u8>)>())?;
            match member.kind {
                araphor_graph::EntityKind::Node => {
                    nodes.insert((member.relation, member.key.to_vec()));
                }
                araphor_graph::EntityKind::Edge => {
                    edges.insert((member.relation, member.key.to_vec()));
                }
            }
            producers.insert((member.writer, member.revision));
        }
        for (writer, revision) in producers {
            let origin:(String,u64) = reader.query_row(
                "SELECT result_id,revision FROM managed_graph_results WHERE writer_id=? AND revision=?",
                params![writer,revision],|row| Ok((row.get(0)?,row.get(1)?)))
                .context(AnalysisDatabaseSnafu { operation:"read Definition Graph producer" })?;
            let allowed = match origins.get(&origin) {
                Some(allowed) => *allowed,
                None => {
                    output.charge(origin.0.capacity() + 128)?;
                    let allowed = owners
                        .producer(&origin.0, origin.1, &mut |scan, bytes| {
                            output.scan(scan)?;
                            output.charge(bytes)
                        })?
                        .grant()
                        .permitted_by(scope)
                        .is_ok();
                    origins.insert(origin, allowed);
                    allowed
                }
            };
            if !allowed {
                return Ok(());
            }
        }
        let (nodes, edges) = (nodes.len() as u64, edges.len() as u64);
        output.reference_result(result, revision, AnalysisReferenceOriginV1::Graph)?;
        capture.definition_manifest(
            scope.tenant_id,
            result,
            revision,
            (nodes, edges),
            previous.as_deref(),
            restricted,
            &mut output.sink(control),
        )?;
        Ok(())
    }

    pub(super) fn extract_native_graph(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        result: &str,
        header: &GraphHeader,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut tables::Capture<'_>,
        control: &AnalysisReadControl,
    ) -> Result<bool> {
        if !selection.binding_ids.is_empty()
            || ["snapshot", "metadata", "graph_revision", "context_refs"]
                .iter()
                .any(|field| read.projects_field("graph_manifest", field))
            || [
                "graph_subjects",
                "relationships",
                "graph_branches",
                "policy_observations",
                "correlation_packages",
            ]
            .iter()
            .any(|table| read.projected(table).is_some())
        {
            return Ok(false);
        }
        if read.projected("findings").is_some_and(|indices| {
            let schemas = Self::table_schemas();
            let schema = &schemas["findings"];
            indices.iter().any(|index| {
                !matches!(
                    schema.field(*index).name().as_str(),
                    "tenant_id"
                        | "source_key"
                        | "graph_result_id"
                        | "commit_revision"
                        | "graph_sensitivity"
                        | "finding_value_id"
                        | "state"
                        | "severity"
                        | "sensitivity"
                        | "finding_id"
                        | "package_id"
                        | "package_version"
                        | "window_start_utc_ns"
                        | "window_end_utc_ns"
                        | "required_action"
                )
            })
        }) {
            return Ok(false);
        }
        let revision: u64 = snapshot.query_row(
            "SELECT revision FROM managed_source_publications WHERE result_id=? AND tenant_id=?",
            params![result,selection.tenant_id.as_slice()],|row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation:"read native graph extraction cut" })?;
        let source = &header.snapshot.scope.identity;
        if !selection.sources.as_slice().contains(source) {
            return Ok(true);
        }
        if read.projected("findings").is_some() {
            let catalog =
                crate::analysis::managed::graph::projection::DomainProjection::load_scope(
                    snapshot,
                    None,
                    Some(selection.tenant_id.as_slice()),
                    &mut |scan, bytes| {
                        output.scan(scan)?;
                        output.charge(bytes)
                    },
                )?;
            let mut seen = std::collections::BTreeSet::new();
            for row in catalog.read_findings(
                self,
                snapshot,
                selection.tenant_id,
                result,
                None,
                &mut |scan, bytes| {
                    control.check()?;
                    output.scan(scan)?;
                    output.charge(bytes)
                },
            )? {
                if !seen.insert(row.id()?.to_owned()) {
                    continue;
                }
                let member = row.decode(&mut |scan, bytes| {
                    control.check()?;
                    output.scan(scan)?;
                    output.charge(bytes)
                })?;
                if !capture.native_finding(
                    result,
                    revision,
                    header.restricted_count.is_some_and(|count| count > 0) || row.restricted,
                    Some(&source.key()),
                    &member.value,
                    row.value,
                    &mut output.sink(control),
                )? {
                    return Ok(true);
                }
            }
        }
        let sensitivity = self.graph_sensitivity(snapshot, header, control)?;
        output.capture_graph(result, &header.snapshot, control)?;
        output.reference_result(result, revision, AnalysisReferenceOriginV1::Graph)?;
        capture.graph(
            result,
            &header.snapshot,
            &BTreeMap::new(),
            header.subject_count,
            header.edge_count,
            revision,
            sensitivity,
            None,
            None,
            &[],
            header.notice,
            header.expired,
            header.restricted_count,
            &mut output.sink(control),
        )?;
        Ok(true)
    }
}
