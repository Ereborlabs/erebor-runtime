use super::*;
use datafusion::physical_plan::metrics::MetricBuilder;

impl SourceSnapshot {
    pub(super) fn record_work<'a>(
        &self,
        read: usize,
        name: &str,
        image: Option<SourceImage>,
        rows: usize,
        witnesses: impl Iterator<Item = &'a araphor_data::AnalysisWitnessV1>,
    ) {
        let mut bounds = None::<(u64, u64)>;
        if name == "events" {
            for witness in witnesses {
                bounds = Some(
                    bounds.map_or((witness.cursor, witness.cursor), |(first, last)| {
                        (first.min(witness.cursor), last.max(witness.cursor))
                    }),
                );
            }
        }
        let known = bounds.is_some();
        let (first, last) = bounds.unwrap_or_default();
        MetricBuilder::new(&self.work)
            .with_new_label("read_id", read.to_string())
            .with_new_label("source_name", name.to_owned())
            .with_new_label(
                "image",
                image.map_or_else(|| "Snapshot".into(), |image| format!("{image:?}")),
            )
            .with_new_label("bounds_known", known.to_string())
            .with_new_label("first_cursor", first.to_string())
            .with_new_label("last_cursor", last.to_string())
            .global_counter("source_rows")
            .add(rows);
    }

    pub(crate) fn report_work(&self) {
        if self.reported.swap(true, Ordering::Relaxed) {
            return;
        }
        let Ok(snapshot) = self.snapshot() else {
            return;
        };
        let instance = snapshot
            .managed()
            .map(|managed| &managed.instance().spec.id)
            .or_else(|| {
                self.reference
                    .get()
                    .map(|reference| &reference.instance().spec.id)
            });
        let instance = instance.map_or("", String::as_str);
        let metrics = self.work.clone_inner();
        let mut rows = 0usize;
        let mut reads = 0usize;
        for metric in metrics.iter() {
            if metric.value().name() != "source_rows" {
                continue;
            }
            let label = |name| {
                metric
                    .labels()
                    .iter()
                    .find(|label| label.name() == name)
                    .map_or("", |label| label.value())
            };
            let count = metric.value().as_usize();
            rows = rows.saturating_add(count);
            reads = reads.saturating_add(1);
            erebor_telemetry::debug!(
                stage = "source",
                instance_id = instance,
                cut_revision = snapshot.page.extraction.meta.commit_revision,
                source_name = label("source_name"),
                read_id = label("read_id"),
                image = label("image"),
                bounds_known = label("bounds_known"),
                rows = count,
                first_cursor = label("first_cursor"),
                last_cursor = label("last_cursor"),
                "Native source read completed"
            );
        }
        erebor_telemetry::debug!(
            stage = "source_done",
            instance_id = instance,
            cut_revision = snapshot.page.extraction.meta.commit_revision,
            rows,
            read_count = reads,
            "Native source execution completed"
        );
    }
}
