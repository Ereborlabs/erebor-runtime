use super::*;
use crate::{AnalysisSourceSnapshotV1, CoverageInterval, CoverageReport};
use prost::Message as _;

impl Capture<'_> {
    pub(super) fn metadata(
        &mut self,
        extraction: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        for (relation, available) in [
            ("behaviors", extraction.discovery_enabled),
            ("findings", extraction.graph_enabled),
            ("relationships", extraction.graph_enabled),
            ("graph_subjects", extraction.graph_enabled),
            ("graph_branches", extraction.graph_enabled),
            ("correlation_packages", extraction.graph_enabled),
            ("policy_observations", extraction.graph_enabled),
            ("graph_manifest", extraction.graph_enabled),
            ("notifications", extraction.notification_enabled),
        ] {
            if self.read.relations.contains(relation) && !available {
                return Err(crate::Error::AnalysisUnavailable {
                    relation,
                    location: snafu::location!(),
                });
            }
        }
        let sources = std::mem::take(&mut extraction.sources);
        let traversal = extraction
            .graph_traversal()
            .map(|receipt| (receipt.max_hops, receipt.hop_boundary));
        let mut budget = extraction.sink(control);
        if self.read.relations.contains("coverage") {
            for source in &sources {
                budget.check()?;
                let report = if let Some(bytes) = &source.coverage_report {
                    if bytes.is_empty() || bytes.len() > crate::MAX_EVIDENCE_GRPC_MESSAGE_BYTES {
                        return Err(invalid("the coverage report size is invalid"));
                    }
                    budget.charge(bytes.len().checked_mul(128).ok_or_else(overflow)?)?;
                    let report = CoverageReport::decode(bytes.as_slice()).map_err(|source| {
                        crate::Error::EvidenceDecode {
                            source,
                            frame_bytes: bytes.len(),
                            location: snafu::location!(),
                        }
                    })?;
                    if report.source_id.as_slice() != source.receipt.identity.source_id
                        || report.source_epoch != source.receipt.identity.source_epoch
                        || report.cpu_id != source.receipt.cpu_id
                        || report.revision != source.receipt.coverage_revision
                        || report.revision == 0
                    {
                        return Err(invalid(
                            "the coverage report differs from its captured source receipt",
                        ));
                    }
                    Some(report)
                } else {
                    if source.receipt.coverage_revision != 0 {
                        return Err(invalid("the captured coverage revision has no report"));
                    }
                    None
                };
                self.coverage(
                    source,
                    "receipt",
                    if report.is_some() {
                        "reported"
                    } else {
                        "unknown"
                    },
                    None,
                    None,
                    &mut budget,
                )?;
                for (kind, gaps) in [
                    ("expired", &source.expired),
                    ("recovery", &source.recovery),
                    ("pending", &source.pending),
                ] {
                    for gap in gaps {
                        self.coverage(source, kind, kind, Some(gap), None, &mut budget)?;
                    }
                }
                if let Some(report) = report {
                    for interval in &report.intervals {
                        self.coverage(
                            source,
                            "interval",
                            &interval.state,
                            None,
                            Some(interval),
                            &mut budget,
                        )?;
                    }
                }
            }
        }
        if self.read.columns.contains_key("trace_recipes") {
            for recipe in [TraceRecipeV1::SyscallErrors, TraceRecipeV1::FailedOpens] {
                budget.charge(crate::MAX_TRACE_SOURCE_BYTES + 8192)?;
                let manifest = recipe.manifest()?;
                table_row!(self,"trace_recipes",&mut budget;
                    recipe=>Utf8:Some(match recipe {TraceRecipeV1::SyscallErrors=>"syscall_errors",TraceRecipeV1::FailedOpens=>"failed_opens"}),
                    version=>UInt32:Some(manifest.version),
                    source=>Binary:Some(&manifest.source.bytes),
                    source_sha256=>Binary:Some(&manifest.source.sha256),
                    parameter=>Utf8:Some(&manifest.parameter),
                    attribution=>Utf8:Some(&manifest.attribution),
                    sensitivity=>Utf8:Some(&manifest.sensitivity),
                    hook=>Utf8:Some(&manifest.hook),
                    measurement_keys=>Json:Some(&manifest.measurement_keys),
                    unit=>Utf8:Some(&manifest.unit),
                    cumulative=>Boolean:Some(manifest.cumulative),
                    atomic_snapshot=>Boolean:Some(manifest.atomic_snapshot),
                    maximum_probes=>UInt32:Some(u32::from(manifest.maximum_probes)),
                    maximum_map_keys=>UInt32:Some(manifest.maximum_map_keys),
                    return_code_semantics=>Utf8:Some(&manifest.return_code_semantics),
                    capability_status=>Utf8:Some("requires_node_capability"),
                    example=>Utf8:Some(match recipe {TraceRecipeV1::SyscallErrors=>"SELECT syscall_id, errno, count FROM trace_measurements",TraceRecipeV1::FailedOpens=>"SELECT errno, count FROM trace_measurements"}),
                )?;
            }
        }
        if let (Some((max_hops, boundary)), Some(table)) =
            (traversal, self.tables.get_mut("graph_manifest"))
        {
            table.traversal(max_hops, boundary, &mut budget)?;
        }
        extraction.sources = sources;
        Ok(())
    }

    fn coverage(
        &mut self,
        source: &AnalysisSourceSnapshotV1,
        row_kind: &str,
        state: &str,
        gap: Option<&AnalysisGapV1>,
        interval: Option<&CoverageInterval>,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        let receipt = &source.receipt;
        let identity = &receipt.identity;
        let opening = interval.and_then(|value| value.opening_counters.as_ref());
        let closing = interval.and_then(|value| value.closing_counters.as_ref());
        table_row!(self,"coverage",budget;
            tenant_id=>Binary:Some(&identity.tenant_id),
            node_id=>Utf8:Some(&identity.node_id),
            node_boot_id=>Binary:Some(&identity.node_boot_id),
            label_epoch=>UInt64:Some(identity.label_epoch),
            source_id=>Binary:Some(&identity.source_id),
            source_epoch=>UInt64:Some(identity.source_epoch),
            cpu_id=>UInt32:Some(receipt.cpu_id),
            contiguous_cursor=>UInt64:Some(receipt.contiguous_cursor),
            coverage_revision=>UInt64:Some(receipt.coverage_revision),
            retained_floor=>UInt64:Some(receipt.retained_floor),
            kind=>Utf8:Some(row_kind),
            state=>Utf8:Some(state),
            first_cursor=>UInt64:gap.map(|value|value.first_cursor),
            last_cursor=>UInt64:gap.map(|value|value.last_cursor),
            commit_revision=>UInt64:gap.map(|value|value.commit_revision),
            interval_id=>Binary:interval.map(|value|value.interval_id.as_slice()),
            interval_source_epoch=>UInt64:interval.map(|value|value.source_epoch),
            interval_revision=>UInt64:interval.map(|value|value.revision),
            first_sequence=>UInt64:interval.map(|value|value.first_sequence),
            last_sequence=>UInt64:interval.and_then(|value|value.last_sequence),
            current=>Boolean:interval.map(|value|value.current),
            gap_reasons=>Utf8:if let Some(interval)=interval {budget.charge(interval.gap_reasons.iter().map(String::len).sum::<usize>()+interval.gap_reasons.len())?;Some(interval.gap_reasons.join(","))} else {None},
            opening_attempted=>UInt64:opening.map(|value|value.attempted),
            opening_suppressed=>UInt64:opening.map(|value|value.suppressed),
            opening_requested=>UInt64:opening.map(|value|value.requested),
            opening_emitted=>UInt64:opening.map(|value|value.emitted),
            opening_lost=>UInt64:opening.map(|value|value.lost),
            opening_classifier_miss_count=>UInt64:opening.map(|value|value.classifier_miss_count),
            opening_unresolved=>UInt64:opening.map(|value|value.unresolved),
            opening_next_sequence=>UInt64:opening.map(|value|value.next_sequence),
            closing_attempted=>UInt64:closing.map(|value|value.attempted),
            closing_suppressed=>UInt64:closing.map(|value|value.suppressed),
            closing_requested=>UInt64:closing.map(|value|value.requested),
            closing_emitted=>UInt64:closing.map(|value|value.emitted),
            closing_lost=>UInt64:closing.map(|value|value.lost),
            closing_classifier_miss_count=>UInt64:closing.map(|value|value.classifier_miss_count),
            closing_unresolved=>UInt64:closing.map(|value|value.unresolved),
            closing_next_sequence=>UInt64:closing.map(|value|value.next_sequence),
        )
    }
}
