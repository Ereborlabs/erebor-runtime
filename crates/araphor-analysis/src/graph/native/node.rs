use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use araphor_analysis_builtins::graph::Unit;
use araphor_analysis_sdk as sdk;
use araphor_data::{ManagedDestination, ManagedSourceRead, PackageErrorCodeV1 as Code};
use araphor_query::execution::Session;
use araphor_query::sources::{PortRead, PortSource, SourceImage, SourceSnapshot};
use datafusion::arrow::array::{
    Array, BinaryArray, BooleanArray, StringArray, UInt32Array, UInt64Array,
};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::Result;
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{LogicalPlan, LogicalPlanBuilder};
use futures_util::future::BoxFuture;
use futures_util::FutureExt as _;

use super::Projection;

#[derive(Clone, Copy, Debug)]
pub(super) enum MetadataPort {
    Capture,
    Control,
    Window,
    Status,
    Prefix,
}

impl MetadataPort {
    pub(super) async fn plan(
        self,
        session: &Session,
        header: LogicalPlan,
    ) -> araphor_query::Result<LogicalPlan> {
        let name = match self {
            Self::Capture => "graph_capture",
            Self::Control => "graph_control",
            Self::Window => "window",
            Self::Status => "graph_status",
            Self::Prefix => "graph_prefix",
        };
        let driver = LogicalPlanBuilder::empty(true)
            .build()
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let node = araphor_query::sources::SourcePort::new(
            session,
            name.into(),
            self.schema(),
            driver,
            header,
            Arc::new(self),
        )
        .await?;
        node.plan()
    }

    pub(super) fn schema(self) -> SchemaRef {
        use sdk::{DataType, Field, Schema};
        Arc::new(match self {
            Self::Capture => {
                Schema::new(vec![Field::new("resume_window", DataType::Boolean, false)])
            }
            Self::Control => Schema::new(vec![
                Field::new("source_key", DataType::Binary, false),
                Field::new("first_cursor", DataType::UInt64, false),
                Field::new("last_cursor", DataType::UInt64, false),
                Field::new("base_result_id", DataType::Utf8, true),
                Field::new("base_commit_revision", DataType::UInt64, true),
                Field::new("witness_deadline_utc_ns", DataType::UInt64, false),
                Field::new("window_ns", DataType::UInt64, false),
                Field::new("restricted_count", DataType::UInt64, true),
                Field::new("tenant_id", DataType::Binary, false),
                Field::new("node_id", DataType::Utf8, false),
                Field::new("node_boot_id", DataType::Binary, false),
                Field::new("label_epoch", DataType::UInt64, false),
                Field::new("source_id", DataType::Binary, false),
                Field::new("source_epoch", DataType::UInt64, false),
                Field::new("consumed_cursor", DataType::UInt64, true),
                Field::new("retained_floor", DataType::UInt64, true),
                Field::new("contiguous_cursor", DataType::UInt64, true),
                Field::new("coverage_revision", DataType::UInt64, true),
                Field::new("notice_context_revision", DataType::UInt64, true),
                Field::new("notice_coverage_revision", DataType::UInt64, true),
                Field::new("expired", DataType::Boolean, false),
            ]),
            Self::Window => Unit::window_port().schema,
            Self::Status => Schema::new(vec![
                Field::new("restricted", DataType::Boolean, false),
                Field::new("zero_crossing", DataType::Boolean, false),
                Field::new("append_only", DataType::Boolean, false),
            ]),
            Self::Prefix => Schema::new(vec![
                Field::new("available", DataType::Boolean, false),
                Field::new("tenant_id", DataType::Binary, false),
                Field::new("node_id", DataType::Utf8, false),
                Field::new("node_boot_id", DataType::Binary, false),
                Field::new("label_epoch", DataType::UInt64, false),
                Field::new("source_id", DataType::Binary, false),
                Field::new("source_epoch", DataType::UInt64, false),
                Field::new("cpu_id", DataType::UInt32, false),
                Field::new("coverage_interval_id", DataType::Binary, false),
                Field::new("kernel_sequence", DataType::UInt64, false),
                Field::new("temporal_coverage", DataType::UInt32, false),
            ]),
        })
    }

    fn scalar(batches: &[sdk::RecordBatch]) -> Result<()> {
        if batches
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>()
            != 1
            || batches.iter().any(|batch| batch.num_columns() != 0)
        {
            return Err(Projection::invalid("Graph scalar driver"));
        }
        Ok(())
    }
}

impl PortSource for MetadataPort {
    fn reusable(&self) -> bool {
        true
    }
    fn snapshot_bound(&self) -> bool {
        true
    }
    fn after_is_current(&self) -> bool {
        matches!(self, Self::Control)
    }
    fn key_columns(&self) -> &[(usize, usize)] {
        &[]
    }

    fn header(&self, image: SourceImage, header: &LogicalPlan) -> Result<Option<LogicalPlan>> {
        if matches!(self, Self::Control | Self::Status) && image == SourceImage::Before {
            LogicalPlanBuilder::empty(true).build().map(Some)
        } else if matches!(self, Self::Status) && image == SourceImage::After {
            Ok(Some(header.clone()))
        } else {
            Ok(None)
        }
    }

    fn read<'a>(
        &'a self,
        image: Option<SourceImage>,
        driver: Vec<sdk::RecordBatch>,
        header: Vec<sdk::RecordBatch>,
        source: Arc<SourceSnapshot>,
        context: Arc<TaskContext>,
    ) -> BoxFuture<'a, Result<PortRead>> {
        async move {
            Self::scalar(&driver)?;
            if matches!(self, Self::Status) {
                return Projection::read_status(image, driver, header, source, context).await;
            }
            let memory = source
                .memory()
                .prepare_input(source.extraction_limits().input_bytes)?;
            let mut limits = source.extraction_limits();
            if memory.size() != 0
                || source.memory().input_capacity().is_some()
                || limits.input_bytes != usize::MAX
            {
                limits.input_bytes = memory.size();
            }
            let kind = *self;
            let callback = Arc::clone(&context);
            let operation =
                move |source: &Arc<SourceSnapshot>, control: &araphor_data::AnalysisReadControl| {
                    (|| -> Result<_> {
                        let input = match kind {
                            Self::Capture => {
                                Self::scalar(&header)?;
                                let (resume, revision, instance, generation, cut) = source.with_capture(|_, capture, _| {
                                    let frame = capture
                                        .source()
                                        .ok_or_else(|| Code::Invalid.error("Graph source frame"))?;
                                    let parent = match frame.read() {
                                        ManagedSourceRead::Initial => 0,
                                        ManagedSourceRead::Changes(parent) => {
                                            parent.result.commit_revision
                                        }
                                    };
                                    Ok((
                                        !capture.rebuild()
                                            && matches!(
                                                frame.read(),
                                                ManagedSourceRead::Changes(_)
                                            ),
                                        format!(
                                            "{}:{}:{}:{parent}",
                                            capture.instance().generation,
                                            capture.revision(),
                                            capture.time_utc_ns(),
                                        ),
                                        capture.instance().spec.id.clone(),
                                        capture.instance().generation,
                                        capture.revision(),
                                    ))
                                })?;
                                erebor_telemetry::debug!(
                                    stage = "source_capture_flags", instance_id = %instance,
                                    generation, cut_revision = cut, image = ?image,
                                    resume_window = resume, "Native source capture flags"
                                );
                                sdk::Input {
                                    data: sdk::Dataset {
                                        name: "graph_capture".into(),
                                        batches: vec![sdk::RecordBatch::try_new(
                                            kind.schema(),
                                            vec![Arc::new(BooleanArray::from(vec![resume]))],
                                        )
                                        .map_err(Projection::external)?],
                                    },
                                    revision: sdk::Revision {
                                        owner: "araphor-analysis.GraphCapture".into(),
                                        id: revision,
                                        window: None,
                                    },
                                    coverage: sdk::Coverage {
                                        state: sdk::CoverageState::Complete,
                                        limits: Vec::new(),
                                    },
                                }
                            }
                            Self::Control => {
                                let before = image == Some(SourceImage::Before);
                                let mut selected = None;
                                if before {
                                    Self::scalar(&header)?;
                                } else {
                                    for batch in &header {
                                        for row in 0..batch.num_rows() {
                                            if selected.is_some() {
                                                return Err(Projection::invalid(
                                                    "Graph control has multiple windows",
                                                ));
                                            }
                                            let ids = Projection::column::<StringArray>(
                                                batch,
                                                "base_result_id",
                                            )?;
                                            let revisions = Projection::column::<UInt64Array>(
                                                batch,
                                                "base_commit_revision",
                                            )?;
                                            let keys = Projection::column::<BinaryArray>(
                                                batch,
                                                "source_key",
                                            )?;
                                            let first = Projection::column::<UInt64Array>(
                                                batch,
                                                "first_cursor",
                                            )?;
                                            let last = Projection::column::<UInt64Array>(
                                                batch,
                                                "last_cursor",
                                            )?;
                                            if ids.is_null(row) != revisions.is_null(row)
                                                || keys.is_null(row)
                                                || first.is_null(row)
                                                || last.is_null(row)
                                            {
                                                return Err(Projection::invalid(
                                                    "Graph control base",
                                                ));
                                            }
                                            let base = (!ids.is_null(row)).then(|| {
                                                araphor_data::analysis::PackageResultRefV1 {
                                                    result_id: ids.value(row).into(),
                                                    commit_revision: revisions.value(row),
                                                }
                                            });
                                            selected = Some((
                                                keys.value(row).to_vec(),
                                                first.value(row),
                                                last.value(row),
                                                base,
                                            ));
                                        }
                                    }
                                }
                                let (identity, saved, metadata, revision) =
                                    source.with_capture(|store, capture, reference| {
                                        let ManagedDestination::Graph { source, .. } =
                                            &capture.instance().spec.destination
                                        else {
                                            return Err(
                                                Code::Invalid.error("Graph control destination")
                                            );
                                        };
                                        let base = if before {
                                            Some(
                                                reference
                                                    .and_then(|reference| reference.receipt())
                                                    .and_then(|receipt| receipt.graph.as_ref())
                                                    .ok_or_else(|| {
                                                        Code::Incomplete
                                                            .error("Graph before owning result")
                                                    })?
                                                    .clone(),
                                            )
                                        } else {
                                            selected
                                                .as_ref()
                                                .and_then(|(_, _, _, base)| base.clone())
                                        };
                                        let metadata = base
                                            .as_ref()
                                            .map(|base| {
                                                store
                                                    .graph_frozen_facts(
                                                        capture,
                                                        reference,
                                                        base,
                                                        &BTreeSet::new(),
                                                        limits,
                                                        control,
                                                    )
                                                    .map(|(summary, _, _)| summary)
                                            })
                                            .transpose()?;
                                        let revision = format!(
                                            "{}:{}:{}:{}",
                                            capture.instance().generation,
                                            capture.revision(),
                                            capture.time_utc_ns(),
                                            base.as_ref().map_or(0, |base| base.commit_revision),
                                        );
                                        Ok((source.clone(), base, metadata, revision))
                                    })?;
                                let selected = if before {
                                    let metadata = &metadata
                                        .as_ref()
                                        .ok_or_else(|| Projection::invalid("Graph before header"))?
                                        .manifest;
                                    Some((
                                        identity.key(),
                                        metadata.first_cursor,
                                        metadata.last_cursor,
                                        saved.clone(),
                                    ))
                                } else {
                                    selected
                                };
                                let mut rows = Vec::new();
                                if let Some((key, first, last, base)) = selected {
                                    if key != identity.key()
                                        || first == 0
                                        || last < first
                                        || base.as_ref().is_some_and(|base| {
                                            base.result_id.is_empty() || base.commit_revision == 0
                                        })
                                        || metadata.as_ref().is_some_and(|summary| {
                                            let metadata = &summary.manifest;
                                            metadata.scope.identity != identity
                                        })
                                    {
                                        return Err(Projection::invalid("Graph selected window"));
                                    }
                                    let deadline = metadata
                                        .as_ref()
                                        .filter(|summary| summary.manifest.first_cursor == first)
                                        .map(|summary| summary.manifest.witness_deadline_utc_ns)
                                        .or_else(|| {
                                            source
                                                .time_utc_ns()
                                                .checked_add(araphor_data::GRAPH_WITNESS_TTL_NS)
                                        })
                                        .ok_or_else(|| {
                                            Projection::invalid("Graph window deadline")
                                        })?;
                                    let expired = if before {
                                        metadata
                                            .as_ref()
                                            .ok_or_else(|| {
                                                Projection::invalid("Graph before lifecycle")
                                            })?
                                            .expired
                                    } else {
                                        source.with_capture(|_, capture, _| {
                                            capture
                                                .source()
                                                .ok_or_else(|| {
                                                    Code::Incomplete.error("Graph lifecycle source")
                                                })?
                                                .expired_window(
                                                    &identity,
                                                    first,
                                                    deadline,
                                                    capture.time_utc_ns(),
                                                )
                                        })?
                                    };
                                    rows.push((key, first, last, base, deadline, expired));
                                }
                                let batches =
                                    if let Some((key, first, last, base, deadline, expired)) =
                                        rows.first()
                                    {
                                        let progress = if before {
                                            None
                                        } else {
                                            let (consumed, floor, accepted) =
                                                Projection::progress(&header, &identity)?;
                                            Some((
                                                consumed,
                                                floor,
                                                accepted,
                                                Projection::coverage_revision(&header, &identity)?,
                                            ))
                                        };
                                        let count = metadata
                                            .as_ref()
                                            .filter(|summary| {
                                                summary.manifest.first_cursor == *first
                                            })
                                            .and_then(|summary| summary.restricted_count);
                                        let notices = if before {
                                            (
                                                metadata.as_ref().map(|summary| {
                                                    summary.manifest.context_notice_revision
                                                }),
                                                None,
                                            )
                                        } else {
                                            let batch = header
                                                .iter()
                                                .find(|batch| batch.num_rows() != 0)
                                                .ok_or_else(|| {
                                                    Projection::invalid("Graph control notice row")
                                                })?;
                                            let bound = Projection::column::<UInt64Array>(
                                                batch,
                                                "notice_base_revision",
                                            )?;
                                            if base.as_ref().is_some_and(|base| {
                                                bound.is_null(0)
                                                    || bound.value(0) != base.commit_revision
                                            }) {
                                                return Err(Projection::invalid(
                                                    "Graph control notice base",
                                                ));
                                            }
                                            let contexts = Projection::column::<UInt64Array>(
                                                batch,
                                                "notice_context_revision",
                                            )?;
                                            let coverage = Projection::column::<UInt64Array>(
                                                batch,
                                                "notice_coverage_revision",
                                            )?;
                                            if contexts.is_null(0) || coverage.is_null(0) {
                                                return Err(Projection::invalid(
                                                    "Graph control notice",
                                                ));
                                            }
                                            (Some(contexts.value(0)), Some(coverage.value(0)))
                                        };
                                        let (instance, generation, cut, resume) = source.with_capture(|_, capture, _| {
                                            Ok((capture.instance().spec.id.clone(), capture.instance().generation, capture.revision(),
                                                !capture.rebuild() && capture.source().is_some_and(|frame|
                                                    matches!(frame.read(), ManagedSourceRead::Changes(_)))))
                                        })?;
                                        erebor_telemetry::debug!(
                                            stage = "source_window", instance_id = %instance, generation, cut_revision = cut,
                                            image = ?image, first_cursor = *first, last_cursor = *last,
                                            base_revision = base.as_ref().map_or(0, |base| base.commit_revision),
                                            base_first = metadata.as_ref().map_or(0, |summary| summary.manifest.first_cursor),
                                            base_last = metadata.as_ref().map_or(0, |summary| summary.manifest.last_cursor),
                                            consumed_cursor = progress.map_or(0, |value| value.0),
                                            retained_floor = progress.map_or(0, |value| value.1),
                                            contiguous_cursor = progress.map_or(0, |value| value.2),
                                            resume_window = resume, expired = *expired,
                                            "Source window selected"
                                        );
                                        Projection::begin(
                                            source,
                                            &callback,
                                            &identity,
                                            *first,
                                            *last,
                                            *deadline,
                                            base.as_ref(),
                                            metadata.as_ref(),
                                            *expired,
                                            progress,
                                            &memory,
                                        )?;
                                        vec![sdk::RecordBatch::try_new(
                                            kind.schema(),
                                            vec![
                                                Arc::new(BinaryArray::from_vec(vec![
                                                    key.as_slice()
                                                ])),
                                                Arc::new(UInt64Array::from(vec![*first])),
                                                Arc::new(UInt64Array::from(vec![*last])),
                                                Arc::new(StringArray::from(vec![base
                                                    .as_ref()
                                                    .map(|base| base.result_id.as_str())])),
                                                Arc::new(UInt64Array::from(vec![base
                                                    .as_ref()
                                                    .map(|base| base.commit_revision)])),
                                                Arc::new(UInt64Array::from(vec![*deadline])),
                                                Arc::new(UInt64Array::from(vec![
                                                    araphor_data::GRAPH_WINDOW_NS,
                                                ])),
                                                Arc::new(UInt64Array::from(vec![count])),
                                                Arc::new(BinaryArray::from_vec(vec![identity
                                                    .tenant_id
                                                    .as_slice()])),
                                                Arc::new(StringArray::from(vec![identity
                                                    .node_id
                                                    .as_str()])),
                                                Arc::new(BinaryArray::from_vec(vec![identity
                                                    .node_boot_id
                                                    .as_slice()])),
                                                Arc::new(UInt64Array::from(vec![
                                                    identity.label_epoch,
                                                ])),
                                                Arc::new(BinaryArray::from_vec(vec![identity
                                                    .source_id
                                                    .as_slice()])),
                                                Arc::new(UInt64Array::from(vec![
                                                    identity.source_epoch,
                                                ])),
                                                Arc::new(UInt64Array::from(vec![
                                                    progress.map(|value| value.0)
                                                ])),
                                                Arc::new(UInt64Array::from(vec![
                                                    progress.map(|value| value.1)
                                                ])),
                                                Arc::new(UInt64Array::from(vec![
                                                    progress.map(|value| value.2)
                                                ])),
                                                Arc::new(UInt64Array::from(vec![
                                                    progress.map(|value| value.3)
                                                ])),
                                                Arc::new(UInt64Array::from(vec![notices.0])),
                                                Arc::new(UInt64Array::from(vec![notices.1])),
                                                Arc::new(BooleanArray::from(vec![*expired])),
                                            ],
                                        )
                                        .map_err(Projection::external)?]
                                    } else {
                                        vec![sdk::RecordBatch::new_empty(kind.schema())]
                                    };
                                drop(metadata);
                                sdk::Input {
                                    data: sdk::Dataset {
                                        name: "graph_control".into(),
                                        batches,
                                    },
                                    revision: sdk::Revision {
                                        owner: "araphor-analysis.GraphControl".into(),
                                        id: revision,
                                        window: None,
                                    },
                                    coverage: sdk::Coverage {
                                        state: sdk::CoverageState::Complete,
                                        limits: Vec::new(),
                                    },
                                }
                            }
                            Self::Window => {
                                let mut selected = None;
                                for batch in &header {
                                    for row in 0..batch.num_rows() {
                                        if selected.is_some() {
                                            return Err(Projection::invalid(
                                                "Graph window has multiple rows",
                                            ));
                                        }
                                        selected = Some((
                                            Projection::column::<BinaryArray>(batch, "source_key")?
                                                .value(row)
                                                .to_vec(),
                                            Projection::column::<UInt64Array>(
                                                batch,
                                                "first_cursor",
                                            )?
                                            .value(row),
                                            Projection::column::<UInt64Array>(
                                                batch,
                                                "witness_deadline_utc_ns",
                                            )?
                                            .value(row),
                                            Projection::column::<BooleanArray>(batch, "expired")?
                                                .value(row),
                                        ));
                                    }
                                }
                                let (key, first, deadline, expired) = selected
                                    .ok_or_else(|| Projection::invalid("Graph window is absent"))?;
                                let generation = source.with_capture(|_, capture, _| {
                                    Ok(capture.instance().generation)
                                })?;
                                let revision = format!(
                                    "{generation}:{first}:{deadline}:{expired}:{}:{}",
                                    araphor_data::GRAPH_WINDOW_NS,
                                    araphor_data::GRAPH_SCHEMA_VERSION,
                                );
                                sdk::Input {
                                    data: Unit::window_data(&key, first, deadline, expired)
                                        .map_err(Projection::external)?,
                                    revision: sdk::Revision {
                                        owner: "araphor-analysis.GraphWindow".into(),
                                        id: revision,
                                        window: None,
                                    },
                                    coverage: sdk::Coverage {
                                        state: sdk::CoverageState::Complete,
                                        limits: Vec::new(),
                                    },
                                }
                            }
                            Self::Prefix => {
                                let run = super::GraphRun::from_context(
                                    &callback,
                                    &callback
                                        .session_config()
                                        .get_extension::<super::GraphRun>()
                                        .and_then(|run| run.projection.upgrade())
                                        .ok_or_else(|| {
                                            Projection::invalid("Graph prefix projection")
                                        })?,
                                )?;
                                let (identity, base, first, last, deadline) = {
                                    let capture = run
                                        .captured
                                        .lock()
                                        .unwrap_or_else(|error| error.into_inner());
                                    let capture = capture.as_ref().ok_or_else(|| {
                                        Projection::invalid("Graph prefix header")
                                    })?;
                                    (
                                        capture.metadata.scope.identity.clone(),
                                        capture.base.clone(),
                                        capture.metadata.first_cursor,
                                        capture.metadata.last_cursor,
                                        capture.metadata.witness_deadline_utc_ns,
                                    )
                                };
                                let proof = base
                                    .as_ref()
                                    .map(|base| {
                                        source.with_capture(|_, capture, _| {
                                            Ok(capture.graph_input(base).cloned())
                                        })
                                    })
                                    .transpose()?
                                    .flatten()
                                    .filter(|proof| proof.scope(&identity, first, last));
                                let mut rows = proof
                                    .as_ref()
                                    .map(|proof| proof.boundaries().collect::<Vec<_>>())
                                    .unwrap_or_default();
                                let eligible = run.projection.upgrade().is_some_and(|owner| {
                                    owner.append_stable && owner.facts.local_observations()
                                });
                                let available = eligible
                                    && deadline > source.time_utc_ns()
                                    && proof.is_some()
                                    && !rows.is_empty();
                                if rows.is_empty() {
                                    rows.push((0, identity.source_id, 0));
                                }
                                let len = rows.len();
                                let input = sdk::Input {
                                    data: sdk::Dataset {
                                        name: "graph_prefix".into(),
                                        batches: vec![sdk::RecordBatch::try_new(
                                            kind.schema(),
                                            vec![
                                                Arc::new(BooleanArray::from(vec![available; len])),
                                                Arc::new(BinaryArray::from_iter_values(
                                                    std::iter::repeat_n(
                                                        identity.tenant_id.as_slice(),
                                                        len,
                                                    ),
                                                )),
                                                Arc::new(StringArray::from_iter_values(
                                                    std::iter::repeat_n(
                                                        identity.node_id.as_str(),
                                                        len,
                                                    ),
                                                )),
                                                Arc::new(BinaryArray::from_iter_values(
                                                    std::iter::repeat_n(
                                                        identity.node_boot_id.as_slice(),
                                                        len,
                                                    ),
                                                )),
                                                Arc::new(UInt64Array::from(vec![
                                                    identity
                                                        .label_epoch;
                                                    len
                                                ])),
                                                Arc::new(BinaryArray::from_iter_values(
                                                    std::iter::repeat_n(
                                                        identity.source_id.as_slice(),
                                                        len,
                                                    ),
                                                )),
                                                Arc::new(UInt64Array::from(vec![
                                                    identity
                                                        .source_epoch;
                                                    len
                                                ])),
                                                Arc::new(UInt32Array::from_iter_values(
                                                    rows.iter().map(|row| row.0),
                                                )),
                                                Arc::new(BinaryArray::from_iter_values(
                                                    rows.iter().map(|row| row.1),
                                                )),
                                                Arc::new(UInt64Array::from_iter_values(
                                                    rows.iter().map(|row| row.2),
                                                )),
                                                Arc::new(UInt32Array::from(vec![1; len])),
                                            ],
                                        )
                                        .map_err(Projection::external)?],
                                    },
                                    revision: sdk::Revision {
                                        owner: "araphor-graph.InputProof".into(),
                                        id: format!(
                                            "{}:{}:{}",
                                            source.with_capture(|_, capture, _| Ok(
                                                capture.revision()
                                            ))?,
                                            first,
                                            last
                                        ),
                                        window: None,
                                    },
                                    coverage: sdk::Coverage {
                                        state: sdk::CoverageState::Complete,
                                        limits: Vec::new(),
                                    },
                                };
                                input
                            }
                            Self::Status => {
                                return Err(Projection::invalid("Graph status dispatch"))
                            }
                        };
                        drop(driver);
                        drop(header);
                        for batch in &input.data.batches {
                            source.memory().retain_input(batch, &memory)?;
                        }
                        memory.try_resize(input.metadata_bytes())?;
                        Ok((input, memory))
                    })()
                    .map_err(|source| araphor_query::Error::Sql { source })
                };
            if matches!(kind, Self::Capture | Self::Window | Self::Prefix) {
                source.inline(&context, operation)
            } else {
                source.blocking(&context, (), operation).await
            }
        }
        .map(|result| result.map(Into::into))
        .boxed()
    }
}

pub(super) struct Port {
    pub(super) owner: Arc<Projection>,
    pub(super) index: usize,
}

impl fmt::Debug for Port {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphPort")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl PortSource for Port {
    fn reusable(&self) -> bool {
        true
    }
    fn snapshot_bound(&self) -> bool {
        true
    }
    fn key_columns(&self) -> &[(usize, usize)] {
        if self.index >= 2 {
            &[]
        } else {
            &[(0, 0)]
        }
    }

    fn driver(&self, image: SourceImage, driver: &LogicalPlan) -> Result<Option<LogicalPlan>> {
        if self.index >= 2 && image == SourceImage::After {
            Ok(Some(driver.clone()))
        } else {
            Ok(None)
        }
    }

    fn header_required(&self, driver: &[sdk::RecordBatch]) -> Result<bool> {
        if self.index != 3 {
            return Ok(true);
        }
        match driver.iter().map(sdk::RecordBatch::num_rows).sum::<usize>() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Projection::invalid("source selection control rows")),
        }
    }

    fn read<'a>(
        &'a self,
        image: Option<SourceImage>,
        driver: Vec<sdk::RecordBatch>,
        header: Vec<sdk::RecordBatch>,
        source: Arc<SourceSnapshot>,
        context: Arc<TaskContext>,
    ) -> BoxFuture<'a, Result<PortRead>> {
        if self.index == 3 {
            async move {
                if !self.header_required(&driver)? {
                    return source.inline(&context, |source, _| {
                        let memory = source
                            .memory()
                            .reserve_input(0)
                            .map_err(|source| araphor_query::Error::Sql { source })?;
                        Ok((
                            sdk::Input {
                                data: sdk::Dataset {
                                    name: "__source_selection".into(),
                                    batches: vec![sdk::RecordBatch::new_empty(Arc::new(
                                        sdk::Schema::empty(),
                                    ))],
                                },
                                revision: sdk::Revision {
                                    owner: "araphor-analysis.SourceSelection".into(),
                                    id: "empty".into(),
                                    window: None,
                                },
                                coverage: sdk::Coverage {
                                    state: sdk::CoverageState::Complete,
                                    limits: Vec::new(),
                                },
                            },
                            memory,
                        )
                            .into())
                    });
                }
                let status = header
                    .iter()
                    .find(|batch| batch.num_rows() != 0)
                    .ok_or_else(|| Projection::invalid("source selection status"))?
                    .slice(0, 1);
                self.owner
                    .read_bound(3, image, header, vec![status], source, context)
                    .await
            }
            .boxed()
        } else {
            self.owner
                .read_bound(self.index, image, driver, header, source, context)
        }
    }
}
