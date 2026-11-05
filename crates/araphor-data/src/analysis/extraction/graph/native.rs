use super::*;
use std::sync::Arc;

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
        use sdk::arrow_array::{Array as _, BooleanArray, StringArray, StructArray, UInt64Array};
        owners.check_reader(reader, scope.tenant_id)?;
        if grant.permitted_by(scope).is_err() {
            return Ok(());
        }
        let mut origins = BTreeMap::new();
        if read.projected("findings").is_some() {
            if let Some(findings) =
                owners.finding_sql(reader, scope.tenant_id, &mut |scan, bytes| {
                    output.scan(scan)?;
                    output.charge(bytes)
                })?
            {
                let mut query = reader.prepare(&format!(
                    "SELECT member.finding_value_id,member.properties,member.origin_result_id,
                        member.origin_revision,member.restricted
                     FROM ({findings}) member WHERE member.result_id=? AND member.tenant_id=?
                     QUALIFY row_number() OVER(PARTITION BY member.properties.value.finding_id
                        ORDER BY member.relation_id,member.properties_ref,member.writer_id,member.owner_ref)=1"
                )).context(AnalysisDatabaseSnafu { operation: "prepare Definition findings" })?;
                for batch in query
                    .query_arrow(params![result, scope.tenant_id.as_slice()])
                    .context(AnalysisDatabaseSnafu {
                        operation: "read Definition findings",
                    })?
                {
                    control.check()?;
                    let bytes = batch.get_array_memory_size();
                    output.scan(bytes)?;
                    output.charge(bytes.checked_mul(12).ok_or_else(|| {
                        self.state_error("the Definition finding size is invalid")
                    })?)?;
                    let ids = batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<UInt64Array>()
                        .ok_or_else(|| {
                            self.state_error("the Definition finding value is absent")
                        })?;
                    let properties = batch
                        .column(1)
                        .as_any()
                        .downcast_ref::<StructArray>()
                        .ok_or_else(|| self.state_error("the Definition finding is absent"))?;
                    let producers = batch
                        .column(2)
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .ok_or_else(|| {
                            self.state_error("the Definition finding origin is absent")
                        })?;
                    let revisions = batch
                        .column(3)
                        .as_any()
                        .downcast_ref::<UInt64Array>()
                        .ok_or_else(|| self.state_error("the Definition finding cut is absent"))?;
                    let restricted = batch
                        .column(4)
                        .as_any()
                        .downcast_ref::<BooleanArray>()
                        .ok_or_else(|| {
                            self.state_error("the Definition finding disclosure is absent")
                        })?;
                    if batch.columns().iter().any(|array| array.null_count() != 0) {
                        return self.reject("the Definition finding has a null authority field");
                    }
                    let port = araphor_analysis_types::FindingMember::port();
                    let native = sdk::RecordBatch::try_new(
                        Arc::new(sdk::Schema::new(properties.fields().clone())),
                        properties.columns().to_vec(),
                    )
                    .context(crate::PackageArrowSnafu)?;
                    let data = sdk::Dataset {
                        name: port.name,
                        batches: vec![sdk::Dataset::normalize_batch(native, Arc::new(port.schema))
                            .context(crate::AnalysisContractSnafu)?],
                    };
                    for (row, member) in araphor_analysis_types::FindingMember::decode(&data)
                        .context(crate::AnalysisContractSnafu)?
                        .into_iter()
                        .enumerate()
                    {
                        let origin = (producers.value(row).to_owned(), revisions.value(row));
                        let allowed = match origins.get(&origin) {
                            Some(allowed) => *allowed,
                            None => {
                                output.charge(
                                    origin.0.capacity()
                                        + 8 * std::mem::size_of::<(String, u64, bool)>(),
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
                        if !capture.definition_finding(
                            result,
                            revision,
                            restricted.value(row),
                            &member.value,
                            ids.value(row),
                            &mut output.sink(control),
                        )? {
                            return Ok(());
                        }
                    }
                }
            }
        }
        if read.projected("graph_manifest").is_none() {
            return Ok(());
        }
        let mut query = reader.prepare(
            "SELECT DISTINCT origin.result_id,origin.revision,octet_length(encode(origin.result_id))
             FROM managed_graph_publication_layers pin
             JOIN graph_layers layer USING(layer_id,writer_id)
             JOIN graph_members member ON member.writer_id=pin.writer_id AND member.valid_from<=layer.revision
                AND (member.valid_to IS NULL OR member.valid_to>layer.revision)
             JOIN managed_graph_results origin ON origin.writer_id=member.writer_id AND origin.revision=member.valid_from
             WHERE pin.result_id=?"
        ).context(AnalysisDatabaseSnafu { operation: "prepare Definition Graph producers" })?;
        let mut rows = query
            .query(params![result])
            .context(AnalysisDatabaseSnafu {
                operation: "read Definition Graph producers",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Definition Graph producers",
        })? {
            control.check()?;
            let bytes: usize = row.get(2).context(AnalysisDatabaseSnafu {
                operation: "bound Definition Graph producer",
            })?;
            output.charge(
                bytes
                    .checked_mul(4)
                    .and_then(|bytes| bytes.checked_add(128))
                    .ok_or_else(|| {
                        self.state_error("the Definition Graph producer size is invalid")
                    })?,
            )?;
            let origin: (String, u64) =
                (|| -> duckdb::Result<_> { Ok((row.get(0)?, row.get(1)?)) })().context(
                    AnalysisDatabaseSnafu {
                        operation: "decode Definition Graph producer",
                    },
                )?;
            let allowed = match origins.get(&origin) {
                Some(allowed) => *allowed,
                None => {
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
        let (nodes,edges,previous,restricted): (u64,u64,Option<String>,bool) = reader.query_row(
            "WITH members AS (
                SELECT DISTINCT member.relation_id,member.entity_key,member.entity_kind
                FROM managed_graph_publication_layers pin JOIN graph_layers layer USING(layer_id,writer_id)
                JOIN graph_members member ON member.writer_id=pin.writer_id AND member.valid_from<=layer.revision
                    AND (member.valid_to IS NULL OR member.valid_to>layer.revision) WHERE pin.result_id=?
             ) SELECT (SELECT count(*) FROM members WHERE entity_kind=0),
                (SELECT count(*) FROM members WHERE entity_kind=1),
                (SELECT previous_result_id FROM managed_graph_publications WHERE result_id=?),
                EXISTS(SELECT 1 FROM managed_graph_publication_layers pin JOIN managed_graph_results result USING(writer_id,layer_id)
                    WHERE pin.result_id=? AND result.restricted)",
            params![result,result,result],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).context(AnalysisDatabaseSnafu { operation: "read Definition Graph summary" })?;
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

    fn native_finding_field(name: &str) -> Option<String> {
        let expression = match name {
            "tenant_id" => "member.tenant_id",
            "source_key" => "source.stream_key",
            "graph_result_id" => "member.result_id",
            "commit_revision" => "member.revision",
            "graph_sensitivity" => "CASE WHEN member.restricted OR source.restricted_count>0 THEN 'host_restricted' ELSE 'tenant' END",
            "finding_value_id" => "member.finding_value_id",
            "state" => "CASE upper(member.properties.value.state) WHEN 'PROVISIONAL' THEN 'provisional' WHEN 'CONFIRMED' THEN 'confirmed' WHEN 'SUPERSEDED' THEN 'superseded' WHEN 'RETRACTED' THEN 'retracted' WHEN 'COVERAGE_INSUFFICIENT' THEN 'coverage_insufficient' END",
            "severity" => "CASE upper(member.properties.value.severity) WHEN 'INFO' THEN 'info' WHEN 'WARNING' THEN 'warning' WHEN 'HIGH' THEN 'high' WHEN 'CRITICAL' THEN 'critical' END",
            "sensitivity" => "CASE upper(member.properties.value.sensitivity) WHEN 'PUBLIC' THEN 'public' WHEN 'TENANT' THEN 'tenant' WHEN 'HOSTRESTRICTED' THEN 'host_restricted' END",
            "finding_id" | "package_id" | "package_version" | "window_start_utc_ns" | "window_end_utc_ns" | "required_action" => {
                return Some(format!("member.properties.value.{name} AS {name}"));
            }
            _ => return None,
        };
        Some(format!("{expression} AS {name}"))
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
        let columns = read.projected("findings").map(|indices| {
            let schema = Self::table_schemas().get("findings")?;
            indices
                .iter()
                .map(|index| Self::native_finding_field(schema.field(*index).name()))
                .collect::<Option<Vec<_>>>()
        });
        if columns.as_ref().is_some_and(Option::is_none) {
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
        if let Some(Some(mut columns)) = columns {
            if let Some(findings) = Self::native_findings_sql(snapshot)? {
                columns.push("member.tenant_id AS __native_tenant".into());
                columns.push("member.properties.value.finding_id AS __native_id".into());
                let query = format!(
                    "SELECT {} FROM ({findings}) member
                     JOIN managed_source_publications source ON source.result_id=member.result_id
                        AND source.tenant_id=member.tenant_id AND source.revision=member.revision
                     WHERE member.result_id=? AND member.tenant_id=?
                     QUALIFY row_number() OVER(PARTITION BY member.properties.value.finding_id
                        ORDER BY member.relation_id,member.properties_ref,member.writer_id,member.owner_ref)=1",
                    columns.join(","),
                );
                let mut statement = snapshot.prepare(&query).context(AnalysisDatabaseSnafu {
                    operation: "prepare native finding projection",
                })?;
                let batches = statement
                    .query_arrow(params![result, selection.tenant_id.as_slice()])
                    .context(AnalysisDatabaseSnafu {
                        operation: "read native finding projection",
                    })?;
                for batch in batches {
                    control.check()?;
                    output.scan(batch.get_array_memory_size())?;
                    if !capture.native_findings(
                        batch,
                        result,
                        revision,
                        &mut output.sink(control),
                    )? {
                        return Ok(true);
                    }
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
