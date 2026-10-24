use super::*;
use crate::{AnalysisSourceReceiptV1, CoverageInterval, CoverageReport};
use prost::Message as _;

impl Capture<'_> {
    pub(in crate::analysis) fn coverage_report(
        bytes: &[u8],
        receipt: &crate::AnalysisSourceReceiptV1,
        budget: &mut ReadBudget<'_>,
    ) -> Result<CoverageReport> {
        if bytes.is_empty() {
            return Err(invalid("the coverage report size is invalid"));
        }
        budget.charge(bytes.len().checked_mul(128).ok_or_else(overflow)?)?;
        let report =
            CoverageReport::decode(bytes).map_err(|source| crate::Error::EvidenceDecode {
                source,
                frame_bytes: bytes.len(),
                location: snafu::location!(),
            })?;
        if report.source_id.as_slice() != receipt.identity.source_id
            || report.source_epoch != receipt.identity.source_epoch
            || report.cpu_id != receipt.cpu_id
            || report.revision != receipt.coverage_revision
            || report.revision == 0
        {
            return Err(invalid(
                "the coverage report differs from its captured source receipt",
            ));
        }
        Ok(report)
    }

    pub(super) fn metadata(
        &mut self,
        extraction: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        for (relation, available) in [
            ("behaviors", extraction.discovery_enabled),
            ("relationships", extraction.graph_enabled),
            ("graph_subjects", extraction.graph_enabled),
            ("graph_branches", extraction.graph_enabled),
            ("correlation_packages", extraction.graph_enabled),
            ("policy_observations", extraction.graph_enabled),
            ("graph_manifest", extraction.graph_enabled),
            ("graph_state", extraction.graph_enabled),
            ("notifications", extraction.notification_enabled),
        ] {
            if self.read.requests.contains_key(relation) && !available {
                return Err(crate::Error::AnalysisUnavailable {
                    relation,
                    location: snafu::location!(),
                });
            }
        }
        let enabled = (
            extraction.discovery_enabled,
            extraction.graph_enabled,
            extraction.notification_enabled,
        );
        let sources = std::mem::take(&mut extraction.sources);
        let traversal = extraction
            .graph_traversal()
            .map(|receipt| (receipt.max_hops, receipt.hop_boundary));
        let mut budget = extraction.sink(control);
        if self.read.requests.contains_key("coverage") {
            for source in &sources {
                budget.check()?;
                let report = if let Some(bytes) = &source.coverage_report {
                    let report = Self::coverage_report(bytes, &source.receipt, &mut budget)?;
                    Some(report)
                } else {
                    if source.receipt.coverage_revision != 0 {
                        return Err(invalid("the captured coverage revision has no report"));
                    }
                    None
                };
                self.coverage(
                    "coverage",
                    &source.receipt,
                    (
                        "receipt",
                        if report.is_some() {
                            "reported"
                        } else {
                            "unknown"
                        },
                    ),
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
                        self.coverage(
                            "coverage",
                            &source.receipt,
                            (kind, kind),
                            Some(gap),
                            None,
                            &mut budget,
                        )?;
                    }
                }
                if let Some(report) = report {
                    for interval in &report.intervals {
                        self.coverage(
                            "coverage",
                            &source.receipt,
                            ("interval", &interval.state),
                            None,
                            Some(interval),
                            &mut budget,
                        )?;
                    }
                }
            }
        }
        if self.read.projected("trace_recipes").is_some() {
            for recipe in [TraceRecipeV1::SyscallErrors, TraceRecipeV1::FailedOpens] {
                budget.charge(recipe.source_bytes().len() + 8192)?;
                let manifest = recipe.manifest()?;
                self.recipe_row(recipe, &manifest, &mut budget)?;
            }
        }
        if let (Some((max_hops, boundary)), Some(table)) =
            (traversal, self.tables.get_mut("graph_manifest"))
        {
            table.traversal(max_hops, boundary, &mut budget)?;
        }
        if self.read.projected("catalog").is_some() {
            for (relation, schema) in Self::schemas() {
                for (ordinal, field) in schema.fields().iter().enumerate() {
                    self.catalog_size(relation, ordinal, field, enabled, &mut budget)?;
                }
            }
            self.tables
                .get_mut("catalog")
                .ok_or_else(|| invalid("the catalog builder is absent"))?
                .reserve(&mut budget)?;
            for (relation, schema) in Self::schemas() {
                for (ordinal, field) in schema.fields().iter().enumerate() {
                    self.catalog_row(relation, ordinal, field, enabled, &mut budget)?;
                }
            }
        }
        extraction.sources = sources;
        Ok(())
    }

    table_row! {
        pub(super) fn catalog_row(
            &mut self,
            relation: &str,
            ordinal: usize,
            field: &sdk::Field,
            enabled: (bool, bool, bool),
            budget: &mut ReadBudget<'_>,
        );
        schema catalog_fields;
        measure catalog_size;
        row(self, "catalog", budget);
        setup {
            let metadata = field.metadata();
        }
        fields {
            relation => Utf8(false):Some(relation),
            ordinal => UInt32(false):Some(u32::try_from(ordinal).map_err(|_|overflow())?),
            column_name => Utf8(false):Some(field.name()),
            data_type => Display(false):Some(field.data_type()),
            units => Utf8(false):Some(metadata.get("araphor.units").map_or("",String::as_str)),
            nullable => Boolean(false):Some(field.is_nullable()),
            null_meaning => Utf8(false):Some(metadata.get("araphor.null_meaning").map_or("",String::as_str)),
            join_keys => Utf8(false):Some(metadata.get("araphor.join_keys").map_or("",String::as_str)),
            owner => Utf8(false):Some(metadata.get("araphor.owner").map_or("araphor-data.AnalysisStore",String::as_str)),
            readiness => Utf8(false):Some(match relation {
                "behaviors"=>if enabled.0 {"enabled"} else {"disabled"},
                "relationships"|"graph_subjects"|"graph_branches"|"correlation_packages"|"policy_observations"|"graph_manifest"=>if enabled.1 {"enabled"} else {"disabled"},
                "notifications"=>if enabled.2 {"enabled"} else {"disabled"},
                _=>"available",
            }),
            description => Utf8(false):Some(metadata.get("araphor.description").map_or("",String::as_str)),
        }
    }

    table_row! {
        pub(in crate::analysis::extraction) fn coverage(
            &mut self,
            relation: &str,
            receipt: &AnalysisSourceReceiptV1,
            classification: (&str, &str),
            gap: Option<&AnalysisGapV1>,
            interval: Option<&CoverageInterval>,
            budget: &mut ReadBudget<'_>,
        );
        schema coverage_fields;
        row(self, relation, budget);
        setup {
            let (row_kind, state) = classification;
            let identity = &receipt.identity;
            let opening = interval.and_then(|value| value.opening_counters.as_ref());
            let closing = interval.and_then(|value| value.closing_counters.as_ref());
        }
        fields {
            tenant_id => Binary(false):Some(&identity.tenant_id),
            node_id => Utf8(false):Some(&identity.node_id),
            node_boot_id => Binary(false):Some(&identity.node_boot_id),
            label_epoch => UInt64(false):Some(identity.label_epoch),
            source_id => Binary(false):Some(&identity.source_id),
            source_epoch => UInt64(false):Some(identity.source_epoch),
            cpu_id => UInt32(false):Some(receipt.cpu_id),
            contiguous_cursor => UInt64(false):Some(receipt.contiguous_cursor),
            coverage_revision => UInt64(false):Some(receipt.coverage_revision),
            retained_floor => UInt64(false):Some(receipt.retained_floor),
            kind => Utf8(false):Some(row_kind),
            state => Utf8(false):Some(state),
            first_cursor => UInt64(true):gap.map(|value|value.first_cursor),
            last_cursor => UInt64(true):gap.map(|value|value.last_cursor),
            commit_revision => UInt64(true):gap.map(|value|value.commit_revision),
            interval_id => Binary(true):interval.map(|value|value.interval_id.as_slice()),
            interval_source_epoch => UInt64(true):interval.map(|value|value.source_epoch),
            interval_revision => UInt64(true):interval.map(|value|value.revision),
            first_sequence => UInt64(true):interval.map(|value|value.first_sequence),
            last_sequence => UInt64(true):interval.and_then(|value|value.last_sequence),
            current => Boolean(true):interval.map(|value|value.current),
            gap_reasons => Utf8(true):if let Some(interval)=interval {budget.charge(interval.gap_reasons.iter().map(String::len).sum::<usize>()+interval.gap_reasons.len())?;Some(interval.gap_reasons.join(","))} else {None},
            opening_attempted => UInt64(true):opening.map(|value|value.attempted),
            opening_suppressed => UInt64(true):opening.map(|value|value.suppressed),
            opening_requested => UInt64(true):opening.map(|value|value.requested),
            opening_emitted => UInt64(true):opening.map(|value|value.emitted),
            opening_lost => UInt64(true):opening.map(|value|value.lost),
            opening_classifier_miss_count => UInt64(true):opening.map(|value|value.classifier_miss_count),
            opening_unresolved => UInt64(true):opening.map(|value|value.unresolved),
            opening_next_sequence => UInt64(true):opening.map(|value|value.next_sequence),
            closing_attempted => UInt64(true):closing.map(|value|value.attempted),
            closing_suppressed => UInt64(true):closing.map(|value|value.suppressed),
            closing_requested => UInt64(true):closing.map(|value|value.requested),
            closing_emitted => UInt64(true):closing.map(|value|value.emitted),
            closing_lost => UInt64(true):closing.map(|value|value.lost),
            closing_classifier_miss_count => UInt64(true):closing.map(|value|value.classifier_miss_count),
            closing_unresolved => UInt64(true):closing.map(|value|value.unresolved),
            closing_next_sequence => UInt64(true):closing.map(|value|value.next_sequence),
        }
    }

    table_row! {
        fn recipe_row(
            &mut self,
            recipe: TraceRecipeV1,
            manifest: &crate::TraceRecipeManifestV1,
            budget: &mut ReadBudget<'_>,
        );
        schema recipe_fields;
        row(self, "trace_recipes", budget);
        setup {
        }
        fields {
            recipe => Utf8(false):Some(match recipe {TraceRecipeV1::SyscallErrors=>"syscall_errors",TraceRecipeV1::FailedOpens=>"failed_opens"}),
            version => UInt32(false):Some(manifest.version),
            source => Binary(false):Some(&manifest.source.bytes),
            source_sha256 => Binary(false):Some(&manifest.source.sha256),
            parameter => Utf8(false):Some(&manifest.parameter),
            attribution => Utf8(false):Some(&manifest.attribution),
            sensitivity => Utf8(false):Some(&manifest.sensitivity),
            hook => Utf8(false):Some(&manifest.hook),
            measurement_keys => Json(false):Some(&manifest.measurement_keys),
            unit => Utf8(false):Some(&manifest.unit),
            cumulative => Boolean(false):Some(manifest.cumulative),
            atomic_snapshot => Boolean(false):Some(manifest.atomic_snapshot),
            maximum_probes => UInt32(false):Some(u32::from(manifest.maximum_probes)),
            return_code_semantics => Utf8(false):Some(&manifest.return_code_semantics),
            capability_status => Utf8(false):Some("requires_node_capability"),
            example => Utf8(false):Some(match recipe {TraceRecipeV1::SyscallErrors=>"SELECT syscall_id, errno, count FROM trace_measurements",TraceRecipeV1::FailedOpens=>"SELECT errno, count FROM trace_measurements"}),
        }
    }
}
