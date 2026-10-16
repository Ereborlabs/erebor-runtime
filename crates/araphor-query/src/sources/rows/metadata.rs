use araphor_data::{
    AnalysisExtractionV1, AnalysisGapV1, AnalysisReadControl, AnalysisSourceSnapshotV1,
    CoverageInterval, CoverageReport, ProjectionSink, TraceRecipeV1,
};
use datafusion::common::ScalarValue;
use prost::Message as _;

use super::{ArrowBatch, Capture};

impl Capture<'_> {
    pub(super) fn metadata(
        &mut self,
        extraction: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> araphor_data::Result<()> {
        let enabled = (
            extraction.discovery_enabled,
            extraction.graph_enabled,
            extraction.notification_enabled,
        );
        for (relation, available) in [
            ("behaviors", enabled.0),
            ("findings", enabled.1),
            ("relationships", enabled.1),
            ("graph_subjects", enabled.1),
            ("graph_branches", enabled.1),
            ("correlation_packages", enabled.1),
            ("policy_observations", enabled.1),
            ("graph_manifest", enabled.1),
            ("notifications", enabled.2),
        ] {
            if self.sources.contains(relation) && !available {
                return Err(araphor_data::Error::AnalysisUnavailable {
                    relation,
                    location: snafu::location!(),
                });
            }
        }
        let sources = std::mem::take(&mut extraction.sources);
        let traversal = extraction
            .graph_traversal()
            .map(|receipt| (receipt.max_hops, receipt.hop_boundary));
        let mut sink = extraction.sink(control);
        if self.sources.contains("coverage") {
            for source in &sources {
                sink.check()?;
                let report = if let Some(bytes) = &source.coverage_report {
                    if bytes.is_empty()
                        || bytes.len() > araphor_data::MAX_EVIDENCE_GRPC_MESSAGE_BYTES
                    {
                        return Err(ArrowBatch::invalid("the coverage report size is invalid"));
                    }
                    sink.charge(
                        bytes
                            .len()
                            .checked_mul(128)
                            .ok_or_else(ArrowBatch::overflow)?,
                    )?;
                    let report = CoverageReport::decode(bytes.as_slice()).map_err(|source| {
                        araphor_data::Error::EvidenceDecode {
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
                        return Err(ArrowBatch::invalid(
                            "the coverage report differs from its captured source receipt",
                        ));
                    }
                    Some(report)
                } else {
                    if source.receipt.coverage_revision != 0 {
                        return Err(ArrowBatch::invalid(
                            "the captured coverage revision has no report",
                        ));
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
                    &mut sink,
                )?;
                for (kind, gaps) in [
                    ("expired", &source.expired),
                    ("recovery", &source.recovery),
                    ("pending", &source.pending),
                ] {
                    for gap in gaps {
                        self.coverage(source, kind, kind, Some(gap), None, &mut sink)?;
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
                            &mut sink,
                        )?;
                    }
                }
            }
        }
        if self.requested.contains_key("catalog") {
            for (relation, schema) in super::super::SourceSnapshot::schemas() {
                let readiness = if relation == "behaviors" {
                    if enabled.0 {
                        "enabled"
                    } else {
                        "disabled"
                    }
                } else if matches!(
                    relation.as_str(),
                    "findings"
                        | "relationships"
                        | "graph_subjects"
                        | "graph_branches"
                        | "correlation_packages"
                        | "policy_observations"
                        | "graph_manifest"
                ) {
                    if enabled.1 {
                        "enabled"
                    } else {
                        "disabled"
                    }
                } else if relation == "notifications" {
                    if enabled.2 {
                        "enabled"
                    } else {
                        "disabled"
                    }
                } else {
                    "available"
                };
                for (ordinal, field) in schema.fields().iter().enumerate() {
                    sink.check()?;
                    self.append("catalog", &mut sink, |name, _kind, sink| {
                        Ok(match name {
                            "relation" => Self::text(Some(&relation), sink)?,
                            "ordinal" => ScalarValue::UInt32(Some(
                                u32::try_from(ordinal).map_err(|_| ArrowBatch::overflow())?,
                            )),
                            "column_name" => Self::text(Some(field.name()), sink)?,
                            "data_type" => {
                                sink.charge(128)?;
                                Self::text(Some(&field.data_type().to_string()), sink)?
                            }
                            "units" => Self::text(
                                Some(
                                    field
                                        .metadata()
                                        .get("araphor.units")
                                        .map_or("", String::as_str),
                                ),
                                sink,
                            )?,
                            "nullable" => ScalarValue::Boolean(Some(field.is_nullable())),
                            "null_meaning" => Self::text(
                                Some(
                                    field
                                        .metadata()
                                        .get("araphor.null_meaning")
                                        .map_or("", String::as_str),
                                ),
                                sink,
                            )?,
                            "join_keys" => Self::text(
                                Some(
                                    field
                                        .metadata()
                                        .get("araphor.join_keys")
                                        .map_or("", String::as_str),
                                ),
                                sink,
                            )?,
                            "owner" => Self::text(
                                Some(
                                    field
                                        .metadata()
                                        .get("araphor.owner")
                                        .map_or("araphor-data.AnalysisStore", String::as_str),
                                ),
                                sink,
                            )?,
                            "readiness" => Self::text(Some(readiness), sink)?,
                            "description" => Self::text(
                                Some(
                                    field
                                        .metadata()
                                        .get("araphor.description")
                                        .map_or("", String::as_str),
                                ),
                                sink,
                            )?,
                            _ => {
                                return Err(ArrowBatch::invalid(
                                    "the native source field has no adapter",
                                ));
                            }
                        })
                    })?;
                }
            }
        }
        if self.requested.contains_key("trace_recipes") {
            for recipe in [TraceRecipeV1::SyscallErrors, TraceRecipeV1::FailedOpens] {
                sink.charge(araphor_data::MAX_TRACE_SOURCE_BYTES + 8192)?;
                let manifest = recipe.manifest()?;
                self.append("trace_recipes", &mut sink, |name, _kind, sink| {
                    Ok(match name {
                        "recipe" => Self::text(
                            Some(match recipe {
                                TraceRecipeV1::SyscallErrors => "syscall_errors",
                                TraceRecipeV1::FailedOpens => "failed_opens",
                            }),
                            sink,
                        )?,
                        "version" => ScalarValue::UInt32(Some(manifest.version)),
                        "source" => Self::binary(Some(&manifest.source.bytes), sink)?,
                        "source_sha256" => Self::binary(Some(&manifest.source.sha256), sink)?,
                        "parameter" => Self::text(Some(&manifest.parameter), sink)?,
                        "attribution" => Self::text(Some(&manifest.attribution), sink)?,
                        "sensitivity" => Self::text(Some(&manifest.sensitivity), sink)?,
                        "hook" => Self::text(Some(&manifest.hook), sink)?,
                        "measurement_keys" => Self::json(&manifest.measurement_keys, sink)?,
                        "unit" => Self::text(Some(&manifest.unit), sink)?,
                        "cumulative" => ScalarValue::Boolean(Some(manifest.cumulative)),
                        "atomic_snapshot" => ScalarValue::Boolean(Some(manifest.atomic_snapshot)),
                        "maximum_probes" => {
                            ScalarValue::UInt32(Some(u32::from(manifest.maximum_probes)))
                        }
                        "maximum_map_keys" => ScalarValue::UInt32(Some(manifest.maximum_map_keys)),
                        "return_code_semantics" => {
                            Self::text(Some(&manifest.return_code_semantics), sink)?
                        }
                        "capability_status" => Self::text(Some("requires_node_capability"), sink)?,
                        "example" => Self::text(
                            Some(match recipe {
                                TraceRecipeV1::SyscallErrors => {
                                    "SELECT syscall_id, errno, count FROM trace_measurements"
                                }
                                TraceRecipeV1::FailedOpens => {
                                    "SELECT errno, count FROM trace_measurements"
                                }
                            }),
                            sink,
                        )?,
                        _ => {
                            return Err(ArrowBatch::invalid(
                                "the native source field has no adapter",
                            ));
                        }
                    })
                })?;
            }
        }
        if let (Some((max_hops, boundary)), Some(table)) =
            (traversal, self.tables.get_mut("graph_manifest"))
        {
            table.finish(&mut sink)?;
            table.traversal(max_hops, boundary, &mut sink)?;
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
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<bool> {
        let receipt = &source.receipt;
        let identity = &receipt.identity;
        let opening = interval.and_then(|interval| interval.opening_counters.as_ref());
        let closing = interval.and_then(|interval| interval.closing_counters.as_ref());
        self.append("coverage", sink, |name, kind, sink| {
            Ok(match name {
                "tenant_id" => Self::binary(Some(&identity.tenant_id), sink)?,
                "node_id" => Self::text(Some(&identity.node_id), sink)?,
                "node_boot_id" => Self::binary(Some(&identity.node_boot_id), sink)?,
                "label_epoch" => ScalarValue::UInt64(Some(identity.label_epoch)),
                "source_id" => Self::binary(Some(&identity.source_id), sink)?,
                "source_epoch" => ScalarValue::UInt64(Some(identity.source_epoch)),
                "cpu_id" => ScalarValue::UInt32(Some(receipt.cpu_id)),
                "contiguous_cursor" => ScalarValue::UInt64(Some(receipt.contiguous_cursor)),
                "coverage_revision" => ScalarValue::UInt64(Some(receipt.coverage_revision)),
                "retained_floor" => ScalarValue::UInt64(Some(receipt.retained_floor)),
                "kind" => Self::text(Some(row_kind), sink)?,
                "state" => Self::text(Some(state), sink)?,
                "first_cursor" => ScalarValue::UInt64(gap.map(|gap| gap.first_cursor)),
                "last_cursor" => ScalarValue::UInt64(gap.map(|gap| gap.last_cursor)),
                "commit_revision" => ScalarValue::UInt64(gap.map(|gap| gap.commit_revision)),
                "interval_id" => {
                    Self::binary(interval.map(|value| value.interval_id.as_slice()), sink)?
                }
                "interval_source_epoch" => {
                    ScalarValue::UInt64(interval.map(|value| value.source_epoch))
                }
                "interval_revision" => ScalarValue::UInt64(interval.map(|value| value.revision)),
                "first_sequence" => ScalarValue::UInt64(interval.map(|value| value.first_sequence)),
                "last_sequence" => {
                    ScalarValue::UInt64(interval.and_then(|value| value.last_sequence))
                }
                "current" => ScalarValue::Boolean(interval.map(|value| value.current)),
                "gap_reasons" => {
                    if let Some(interval) = interval {
                        sink.charge(
                            interval.gap_reasons.iter().map(String::len).sum::<usize>()
                                + interval.gap_reasons.len(),
                        )?;
                        Self::text(Some(&interval.gap_reasons.join(",")), sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "opening_attempted" => ScalarValue::UInt64(opening.map(|value| value.attempted)),
                "opening_suppressed" => ScalarValue::UInt64(opening.map(|value| value.suppressed)),
                "opening_requested" => ScalarValue::UInt64(opening.map(|value| value.requested)),
                "opening_emitted" => ScalarValue::UInt64(opening.map(|value| value.emitted)),
                "opening_lost" => ScalarValue::UInt64(opening.map(|value| value.lost)),
                "opening_classifier_miss_count" => {
                    ScalarValue::UInt64(opening.map(|value| value.classifier_miss_count))
                }
                "opening_unresolved" => ScalarValue::UInt64(opening.map(|value| value.unresolved)),
                "opening_next_sequence" => {
                    ScalarValue::UInt64(opening.map(|value| value.next_sequence))
                }
                "closing_attempted" => ScalarValue::UInt64(closing.map(|value| value.attempted)),
                "closing_suppressed" => ScalarValue::UInt64(closing.map(|value| value.suppressed)),
                "closing_requested" => ScalarValue::UInt64(closing.map(|value| value.requested)),
                "closing_emitted" => ScalarValue::UInt64(closing.map(|value| value.emitted)),
                "closing_lost" => ScalarValue::UInt64(closing.map(|value| value.lost)),
                "closing_classifier_miss_count" => {
                    ScalarValue::UInt64(closing.map(|value| value.classifier_miss_count))
                }
                "closing_unresolved" => ScalarValue::UInt64(closing.map(|value| value.unresolved)),
                "closing_next_sequence" => {
                    ScalarValue::UInt64(closing.map(|value| value.next_sequence))
                }
                _ => {
                    return Err(ArrowBatch::invalid(
                        "the native source field has no adapter",
                    ));
                }
            })
        })
    }
}
