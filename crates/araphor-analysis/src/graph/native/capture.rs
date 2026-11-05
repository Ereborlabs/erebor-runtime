use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::sync::{Arc, Weak};

use araphor_analysis_builtins::graph::{Fact, Observation, Unit};
use araphor_analysis_sdk as sdk;
use araphor_data::{
    analysis::{GraphManifest, GraphSourceSummary, PackageResultRefV1},
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, ContextSensitivityV1,
    DiscoveryCoverageStateV1, DiscoveryCoverageV1, DiscoveryRecordIdV1, DiscoveryRecordV1,
    EvidenceIntakeIdentityV1, GraphCoverageKeyV1, GraphReplayInputV1, GraphRevisionV1,
    ProcessorScopeV1, StorePositionV1,
};
use araphor_query::sources::{PortRead, SourceImage, SourceSnapshot};
use datafusion::arrow::array::{
    Array, BinaryArray, BooleanArray, StringArray, StructArray, UInt64Array,
};
use datafusion::common::Result;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;
use futures_util::future::BoxFuture;
use futures_util::FutureExt as _;

use super::{Capture, GraphPublication, GraphRun, Projection};
use crate::Graph;

impl Projection {
    pub(super) fn begin(
        source: &Arc<SourceSnapshot>,
        context: &TaskContext,
        identity: &EvidenceIntakeIdentityV1,
        first: u64,
        last: u64,
        deadline: u64,
        base: Option<&PackageResultRefV1>,
        summary: Option<&GraphSourceSummary>,
        expired: bool,
        progress: Option<(u64, u64, u64, u64)>,
        memory: &MemoryReservation,
    ) -> Result<()> {
        let run = context
            .session_config()
            .get_extension::<GraphRun>()
            .ok_or_else(|| Self::invalid("graph execution context"))?;
        let owner = run
            .projection
            .upgrade()
            .ok_or_else(|| Self::invalid("graph execution projection"))?;
        if owner.tenant != identity.tenant_id {
            return Err(Self::invalid("graph capture tenant"));
        }
        if summary.is_some_and(|summary| {
            summary.manifest.scope.identity != *identity
                || summary.manifest.first_cursor != first
                    && (!summary.expired || first <= summary.manifest.last_cursor)
        }) {
            return Err(Self::invalid("Graph parent window"));
        }
        let parent = base;
        let summary = summary.filter(|summary| summary.manifest.first_cursor == first);
        let base = parent.filter(|_| summary.is_some());
        let mut capture = run
            .captured
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(current) = capture.as_ref() {
            if !Weak::ptr_eq(&current.source, &Arc::downgrade(source))
                || current.metadata.scope.identity != *identity
                || current.metadata.first_cursor != first
                || current.metadata.last_cursor != last
                || current.metadata.witness_deadline_utc_ns != deadline
                || current.base.as_ref() != base
                || current.base_last != summary.map(|summary| summary.manifest.last_cursor)
                || current.parent.as_ref() != parent
                || current.expired != expired
                || current.base_count != summary.and_then(|summary| summary.restricted_count)
                || current.progress != progress
                || summary.is_some_and(|summary| {
                    let summary = &summary.manifest;
                    current.metadata.schema_version != summary.schema_version
                        || current.metadata.scope != summary.scope
                        || current.metadata.input_manifest.coverage
                            != summary.input_manifest.coverage
                        || current.metadata.missing_ranges != summary.missing_ranges
                        || current.metadata.context_notice_revision
                            != summary.context_notice_revision
                })
            {
                return Err(Self::invalid("conflicting Graph capture header"));
            }
            return Ok(());
        }
        let mut metadata = summary
            .map(|summary| summary.manifest.clone())
            .unwrap_or_else(|| GraphManifest {
                schema_version: araphor_data::GRAPH_SCHEMA_VERSION,
                scope: ProcessorScopeV1 {
                    processor_id: araphor_data::GRAPH_PROCESSOR.into(),
                    method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
                    identity: identity.clone(),
                },
                first_cursor: first,
                last_cursor: last,
                input_manifest: GraphRevisionV1 {
                    evidence: Vec::new(),
                    coverage: Vec::new(),
                    context: Vec::new(),
                    missing_ranges: Vec::new(),
                },
                facts: Vec::new(),
                packages: Vec::new(),
                missing_ranges: Vec::new(),
                input_positions: Vec::new(),
                previous_result_id: None,
                context_notice_revision: 0,
                witness_deadline_utc_ns: deadline,
            });
        if metadata.scope.identity != *identity
            || metadata.first_cursor != first
            || metadata.last_cursor > last
            || first == 0
            || last < first
        {
            return Err(Self::invalid("Graph native base window"));
        }
        metadata.last_cursor = last;
        metadata.previous_result_id = parent.map(|base| base.result_id.clone());
        metadata.witness_deadline_utc_ns = deadline;
        metadata.packages = Vec::new();
        if !metadata.input_manifest.evidence.is_empty()
            || !metadata.input_manifest.context.is_empty()
            || !metadata.facts.is_empty()
            || !metadata.input_positions.is_empty()
        {
            return Err(Self::invalid("Graph header contains unloaded rows"));
        }
        if progress.is_some_and(|(_, floor, _, _)| floor > 0) && base.is_none() {
            metadata
                .missing_ranges
                .push((1, progress.map_or(0, |value| value.1)));
            metadata.missing_ranges.sort();
            metadata.missing_ranges.dedup();
        }
        let mut value = Capture {
            source: Arc::downgrade(source),
            metadata,
            parent: parent.cloned(),
            base: base.cloned(),
            base_last: summary.map(|summary| summary.manifest.last_cursor),
            expired,
            base_count: summary.and_then(|summary| summary.restricted_count),
            restricted: None,
            append: None,
            progress,
            records: BTreeMap::new(),
            facts: BTreeMap::new(),
            proofs: BTreeMap::new(),
            coverage: BTreeMap::new(),
            coverage_keys: BTreeSet::new(),
            removed: BTreeSet::new(),
            _memory: Vec::new(),
        };
        value.retain(memory)?;
        *capture = Some(value);
        Ok(())
    }

    pub(super) fn read_bound<'a>(
        self: &'a Arc<Self>,
        index: usize,
        image: Option<SourceImage>,
        driver: Vec<sdk::RecordBatch>,
        header: Vec<sdk::RecordBatch>,
        source: Arc<SourceSnapshot>,
        context: Arc<TaskContext>,
    ) -> BoxFuture<'a, Result<PortRead>> {
        async move {
            if matches!(image, Some(SourceImage::Inserted | SourceImage::Removed)) {
                return datafusion::common::not_impl_err!("composite Graph delta image");
            }
            let memory = source
                .memory()
                .prepare_input(source.extraction_limits().input_bytes)?;
            let owner = Arc::clone(self);
            let callback = Arc::clone(&context);
            source
                .blocking(&context, (), move |source, control| {
                    (|| -> Result<_> {
                        let run = GraphRun::from_context(&callback, &owner)?;
                        let (identity, base, parent, expired, missing, window) = {
                            let capture = run
                                .captured
                                .lock()
                                .unwrap_or_else(|error| error.into_inner());
                            let capture = capture
                                .as_ref()
                                .ok_or_else(|| Self::invalid("Graph input header"))?;
                            if !Weak::ptr_eq(&capture.source, &Arc::downgrade(source)) {
                                return Err(Self::invalid(
                                    "Graph input belongs to another capture",
                                ));
                            }
                            (
                                capture.metadata.scope.identity.clone(),
                                capture.base.clone(),
                                capture.parent.clone(),
                                capture.expired,
                                capture.metadata.missing_ranges.clone(),
                                (
                                    capture.metadata.first_cursor,
                                    capture.metadata.last_cursor,
                                    capture.metadata.witness_deadline_utc_ns,
                                ),
                            )
                        };
                        let (mut input, incoming, mut proofs, mut removed) =
                            Self::decode_rows(&driver, &identity)?;
                        input.missing_ranges = missing;
                        let mut keys = input
                            .records
                            .iter()
                            .map(|record| record.id.clone())
                            .chain(removed.iter().cloned())
                            .collect::<BTreeSet<_>>();
                        let mut limits = source.extraction_limits();
                        Self::read_limit(source, &memory, &mut limits);
                        let historical =
                            source.with_capture(|_, _, reference| Ok(reference.is_some()))?;
                        let frozen = base
                            .as_ref()
                            .map(|base| {
                                source.with_capture(|store, capture, reference| {
                                    if historical {
                                        store
                                            .graph_frozen_facts(
                                                capture, reference, base, &keys, limits, control,
                                            )
                                            .map(|(summary, contexts, proofs)| {
                                                (summary, contexts, proofs, None)
                                            })
                                    } else {
                                        store
                                            .graph_frozen_source(
                                                capture, reference, base, &keys, limits, control,
                                            )
                                            .map(|(summary, history)| {
                                                (summary, Vec::new(), Vec::new(), Some(history))
                                            })
                                    }
                                })
                            })
                            .transpose()?;
                        let mut references = BTreeMap::new();
                        let mut facts = BTreeMap::new();
                        let history = frozen
                            .as_ref()
                            .and_then(|(_, _, _, history)| history.as_ref().map(Arc::clone));
                        if let Some((_, contexts, parents, history)) = &frozen {
                            for (value, reference) in contexts
                                .iter()
                                .chain(history.iter().flat_map(|history| history.contexts()))
                                .cloned()
                            {
                                let fact = araphor_data::GraphFactV1::try_from(&value)
                                    .map_err(Self::external)?;
                                if input
                                    .records
                                    .binary_search_by(|record| record.id.cmp(&fact.record_id))
                                    .is_ok()
                                {
                                    references.insert(value.key.clone(), reference);
                                    facts.insert(value.key.clone(), value);
                                }
                            }
                            proofs.extend(
                                parents
                                    .iter()
                                    .map(|(record, reference)| (record, reference))
                                    .chain(history.iter().flat_map(|history| history.proofs()))
                                    .map(|(record, reference)| (record.clone(), reference.clone()))
                                    .filter(|(record, _)| {
                                        input
                                            .records
                                            .binary_search_by(|row| row.id.cmp(record))
                                            .is_ok()
                                    }),
                            );
                        }
                        for value in incoming {
                            if facts.get(&value.key).is_some_and(|old| old != &value) {
                                return Err(Self::invalid("conflicting Graph fact value"));
                            }
                            facts.insert(value.key.clone(), value);
                        }
                        proofs.sort_by(|left, right| {
                            (&left.0, &left.1.key, left.1.commit_revision).cmp(&(
                                &right.0,
                                &right.1.key,
                                right.1.commit_revision,
                            ))
                        });
                        if proofs.windows(2).any(|pair| {
                            pair[0].0 == pair[1].0
                                && pair[0].1.key == pair[1].1.key
                                && pair[0].1 != pair[1].1
                        }) {
                            return Err(Self::invalid("conflicting Graph input proof"));
                        }
                        proofs.dedup();
                        input.facts = facts.into_values().collect();
                        let derived = if historical || image == Some(SourceImage::Before) {
                            None
                        } else {
                            let bytes = araphor_data::ManagedSourceFrame::derived_bytes(
                                &input,
                                &references,
                                &proofs,
                            )
                            .and_then(|bytes| {
                                history.as_ref().map_or(Some(bytes), |history| {
                                    bytes.checked_add(history.allocated_bytes()?)
                                })
                            })
                            .ok_or_else(|| Self::invalid("derived source memory"))?;
                            let peak = bytes
                                .checked_mul(3)
                                .ok_or_else(|| Self::invalid("derived source memory"))?;
                            if memory.size() < peak {
                                memory.try_grow(peak - memory.size())?;
                            }
                            let lease = Arc::new(memory.split(bytes));
                            source
                                .with_capture(|_, capture, _| {
                                    capture
                                        .source()
                                        .ok_or_else(|| {
                                            araphor_data::PackageErrorCodeV1::Invalid
                                                .error("derived source frame")
                                        })?
                                        .seal_derived(&input, &references, &proofs, history, lease)
                                })
                                .map(Some)?
                        };
                        if index >= 2 && !historical && image != Some(SourceImage::Before) {
                            if header.iter().map(sdk::RecordBatch::num_rows).sum::<usize>() != 1 {
                                return Err(Self::invalid("native source selection status"));
                            }
                            let status = header
                                .iter()
                                .find(|batch| batch.num_rows() != 0)
                                .ok_or_else(|| Self::invalid("native source selection status"))?;
                            let append =
                                Self::column::<BooleanArray>(status, "append_only")?.value(0);
                            let eligible = owner.append_stable && owner.facts.local_observations();
                            source.with_capture(|_, capture, reference| {
                                let frame = capture.source().ok_or_else(|| {
                                    araphor_data::PackageErrorCodeV1::Invalid
                                        .error("native source selection frame")
                                })?;
                                let bytes = araphor_data::ManagedSourceFrame::selection_bytes(
                                    &input,
                                    base.as_ref()
                                        .and_then(|base| capture.graph_input(base))
                                        .map(Arc::as_ref),
                                )
                                .ok_or_else(|| {
                                    araphor_data::PackageErrorCodeV1::Limit
                                        .error("native source selection memory")
                                })?;
                                let peak = bytes.checked_mul(3).ok_or_else(|| {
                                    araphor_data::PackageErrorCodeV1::Limit
                                        .error("native source selection memory")
                                })?;
                                if memory.size() < peak {
                                    memory.try_grow(peak - memory.size()).map_err(|_| {
                                        araphor_data::PackageErrorCodeV1::Limit
                                            .error("native source selection memory")
                                    })?;
                                }
                                let lease = memory.split(bytes);
                                frame.select_graph_input(
                                    capture,
                                    reference,
                                    &input,
                                    derived.as_ref().ok_or_else(|| {
                                        araphor_data::PackageErrorCodeV1::Incomplete
                                            .error("native source selection handle")
                                    })?,
                                    parent.as_ref(),
                                    window,
                                    (
                                        append,
                                        eligible,
                                        frame.expired_window(
                                            &identity,
                                            window.0,
                                            window.2,
                                            capture.time_utc_ns(),
                                        )?,
                                    ),
                                    Arc::new(lease),
                                )?;
                                Ok(())
                            })?;
                            if let Some(base) =
                                base.as_ref().filter(|_| index == 2 && !append && !expired)
                            {
                                let prior = source.with_capture(|store, capture, reference| {
                                    store.graph_record_keys(
                                        capture, reference, base, limits, control,
                                    )
                                })?;
                                for record in prior {
                                    if input
                                        .records
                                        .binary_search_by(|row| row.id.cmp(&record))
                                        .is_err()
                                    {
                                        removed.insert(record.clone());
                                    }
                                    keys.insert(record);
                                }
                            }
                        }
                        Graph::validate_local(&input).map_err(Self::external)?;
                        input
                            .manifest()
                            .validate(input.source.tenant_id)
                            .map_err(Self::external)?;
                        let observations =
                            Graph::qualify_records(&input).map_err(Self::external)?;
                        let revision = sdk::Revision {
                            owner: araphor_data::GRAPH_PROCESSOR.into(),
                            id: source.with_capture(|_, capture, _| {
                                Ok(format!(
                                    "{}:{}:{}:{}:{index}",
                                    capture.instance().generation,
                                    capture.revision(),
                                    capture.time_utc_ns(),
                                    base.as_ref().map_or(0, |base| base.commit_revision),
                                ))
                            })?,
                            window: observations
                                .iter()
                                .map(|row| row.ingested_utc_ns)
                                .min()
                                .zip(observations.iter().map(|row| row.ingested_utc_ns).max())
                                .map(|(start_utc_ns, end_utc_ns)| sdk::SourceWindow {
                                    source: identity.exact_key(),
                                    start_utc_ns,
                                    end_utc_ns,
                                }),
                        };
                        let coverage = Self::input_coverage(&input, &observations);
                        let data = match index {
                            0 => Observation::encode(&observations).map_err(Self::external)?,
                            1 => {
                                let facts = input
                                    .facts
                                    .iter()
                                    .map(|context| {
                                        let fact = araphor_data::GraphFactV1::try_from(context)
                                            .map_err(Self::external)?;
                                        let record = input
                                            .records
                                            .binary_search_by(|row| row.id.cmp(&fact.record_id))
                                            .ok()
                                            .and_then(|row| u32::try_from(row).ok())
                                            .ok_or_else(|| {
                                                Self::invalid("Graph fact source row")
                                            })?;
                                        Ok(Fact {
                                            record,
                                            key: context.key.clone(),
                                            sensitivity: context.sensitivity,
                                            value: fact.value,
                                        })
                                    })
                                    .collect::<Result<Vec<_>>>()?;
                                Fact::encode_source(&facts, &observations)
                                    .map_err(Self::external)?
                            }
                            2 => Unit::encode_affected(&keys.iter().cloned().collect::<Vec<_>>())
                                .map_err(Self::external)?,
                            3 => sdk::Dataset {
                                name: "__source_selection".into(),
                                batches: vec![sdk::RecordBatch::try_new_with_options(
                                    Arc::new(sdk::Schema::empty()),
                                    Vec::new(),
                                    &sdk::arrow_array::RecordBatchOptions::new()
                                        .with_row_count(Some(1)),
                                )
                                .map_err(Self::external)?],
                            },
                            _ => return Err(Self::invalid("Graph source port")),
                        };
                        let local = input;
                        let input = sdk::Input {
                            data,
                            revision,
                            coverage,
                        };
                        let rows = local.records.len();
                        let contexts = local.facts.len();
                        let first = local
                            .records
                            .iter()
                            .map(|row| row.id.durable_cursor)
                            .min()
                            .unwrap_or(0);
                        let last = local
                            .records
                            .iter()
                            .map(|row| row.id.durable_cursor)
                            .max()
                            .unwrap_or(0);
                        let affected = if index >= 2 { keys.len() } else { 0 };
                        drop(observations);
                        run.retain_input(
                            local,
                            references,
                            proofs,
                            if index == 2 { Some(removed) } else { None },
                            &memory,
                        )?;
                        drop(driver);
                        drop(header);
                        for batch in &input.data.batches {
                            source.memory().retain_input(batch, &memory)?;
                        }
                        memory.try_resize(input.metadata_bytes())?;
                        control.check().map_err(Self::external)?;
                        Self::report_input(
                            source,
                            match index {
                                0 => "records",
                                1 => "facts",
                                _ => "affected",
                            },
                            image,
                            rows,
                            contexts,
                            affected,
                            first,
                            last,
                        )?;
                        Ok(PortRead {
                            input,
                            memory,
                            derived,
                        })
                    })()
                    .map_err(|source| araphor_query::Error::Sql { source })
                })
                .await
        }
        .boxed()
    }

    pub(super) fn read_status<'a>(
        image: Option<SourceImage>,
        driver: Vec<sdk::RecordBatch>,
        header: Vec<sdk::RecordBatch>,
        source: Arc<SourceSnapshot>,
        context: Arc<TaskContext>,
    ) -> BoxFuture<'a, Result<(sdk::Input, MemoryReservation)>> {
        async move {
            let memory = source
                .memory()
                .prepare_input(source.extraction_limits().input_bytes)?;
            let callback = Arc::clone(&context);
            source
                .blocking(&context, (), move |source, control| {
                    (|| -> Result<_> {
                        let run = callback
                            .session_config()
                            .get_extension::<GraphRun>()
                            .ok_or_else(|| Self::invalid("Graph status context"))?;
                        let owner = run
                            .projection
                            .upgrade()
                            .ok_or_else(|| Self::invalid("Graph status projection"))?;
                        GraphRun::from_context(&callback, &owner)?;
                        let mut limits = source.extraction_limits();
                        Self::read_limit(source, &memory, &mut limits);
                        let before = image == Some(SourceImage::Before);
                        if before {
                            let (base, summary) =
                                source.with_capture(|store, capture, reference| {
                                    let base = reference
                                        .and_then(|reference| reference.receipt())
                                        .and_then(|receipt| receipt.graph.as_ref())
                                        .ok_or_else(|| {
                                            araphor_data::PackageErrorCodeV1::Incomplete
                                                .error("Graph before owning result")
                                        })?;
                                    store
                                        .graph_frozen_facts(
                                            capture,
                                            reference,
                                            base,
                                            &BTreeSet::new(),
                                            limits,
                                            control,
                                        )
                                        .map(|(summary, _, _)| (base.clone(), summary))
                                })?;
                            Self::begin(
                                source,
                                &callback,
                                &summary.manifest.scope.identity,
                                summary.manifest.first_cursor,
                                summary.manifest.last_cursor,
                                summary.manifest.witness_deadline_utc_ns,
                                Some(&base),
                                Some(&summary),
                                summary.expired,
                                None,
                                &memory,
                            )?;
                        }
                        let (identity, base, base_count, expired, missing) = {
                            let capture = run
                                .captured
                                .lock()
                                .unwrap_or_else(|error| error.into_inner());
                            let capture = capture
                                .as_ref()
                                .ok_or_else(|| Self::invalid("Graph status header"))?;
                            (
                                capture.metadata.scope.identity.clone(),
                                capture.base.clone(),
                                capture.base_count,
                                capture.expired,
                                capture.metadata.missing_ranges.clone(),
                            )
                        };
                        let (count, crossing, rows, contexts, first, last, append) = if before
                            || expired
                        {
                            (
                                base_count
                                    .ok_or_else(|| Self::invalid("Graph before native count"))?,
                                false,
                                0,
                                0,
                                0,
                                0,
                                false,
                            )
                        } else {
                            let (mut input, incoming, mut proofs, removed) =
                                Self::decode_rows(&header, &identity)?;
                            input.missing_ranges = missing;
                            let keys = input
                                .records
                                .iter()
                                .map(|record| record.id.clone())
                                .chain(removed.iter().cloned())
                                .collect::<BTreeSet<_>>();
                            let frozen = base
                                .as_ref()
                                .map(|base| {
                                    source.with_capture(|store, capture, reference| {
                                        store.graph_frozen_facts(
                                            capture, reference, base, &keys, limits, control,
                                        )
                                    })
                                })
                                .transpose()?;
                            let mut old = BTreeMap::new();
                            let mut facts = BTreeMap::new();
                            let mut references = BTreeMap::new();
                            if let Some((_, frozen, frozen_proofs)) = frozen {
                                for (value, reference) in frozen {
                                    old.insert(value.key.clone(), value.sensitivity);
                                    let fact = araphor_data::GraphFactV1::try_from(&value)
                                        .map_err(Self::external)?;
                                    if input
                                        .records
                                        .binary_search_by(|record| record.id.cmp(&fact.record_id))
                                        .is_ok()
                                    {
                                        references.insert(value.key.clone(), reference);
                                        facts.insert(value.key.clone(), value);
                                    }
                                }
                                proofs.extend(
                                    frozen_proofs
                                        .into_iter()
                                        .filter(|(record, _)| !removed.contains(record)),
                                );
                            }
                            for value in incoming {
                                if facts.get(&value.key).is_some_and(|old| old != &value) {
                                    return Err(Self::invalid("conflicting Graph status fact"));
                                }
                                facts.insert(value.key.clone(), value);
                            }
                            let old_count = u64::try_from(
                                old.values()
                                    .filter(|value| **value == ContextSensitivityV1::HostRestricted)
                                    .count(),
                            )
                            .map_err(Self::external)?;
                            let new_count = u64::try_from(
                                facts
                                    .values()
                                    .filter(|value| {
                                        value.sensitivity == ContextSensitivityV1::HostRestricted
                                    })
                                    .count(),
                            )
                            .map_err(Self::external)?;
                            let resume = header
                                .iter()
                                .find(|batch| batch.num_rows() != 0)
                                .ok_or_else(|| Self::invalid("Graph status control row"))
                                .and_then(|batch| {
                                    Ok(Self::column::<BooleanArray>(batch, "resume_window")?
                                        .value(0))
                                })?;
                            let prefix = header
                                .iter()
                                .find(|batch| batch.num_rows() != 0)
                                .and_then(|batch| batch.column_by_name("prefix_complete"))
                                .and_then(|array| array.as_any().downcast_ref::<BooleanArray>())
                                .is_some_and(|array| !array.is_null(0) && array.value(0));
                            let count = match base_count.filter(|_| resume && prefix) {
                                Some(base) => base
                                    .checked_sub(old_count)
                                    .and_then(|value| value.checked_add(new_count))
                                    .ok_or_else(|| Self::invalid("Graph restricted count"))?,
                                None => new_count,
                            };
                            let crossing = base_count.is_some_and(|old| (old == 0) != (count == 0));
                            let parent = source.with_capture(|_, capture, _| {
                                Ok(capture.source().and_then(|frame| frame.read().after()))
                            })?;
                            let append = prefix
                                && owner.append_stable
                                && owner.facts.local_observations()
                                && !crossing
                                && removed.is_empty()
                                && input.missing_ranges.is_empty()
                                && parent.is_some_and(|parent| {
                                    input
                                        .input_positions
                                        .iter()
                                        .all(|(_, position)| *position > parent)
                                });
                            input.facts = facts.into_values().collect();
                            let input = Graph::from_parts(input, count != 0)
                                .map_err(Self::external)?
                                .input
                                .into_owned();
                            let rows = input.records.len();
                            let contexts = input.facts.len();
                            let first = input
                                .records
                                .iter()
                                .map(|row| row.id.durable_cursor)
                                .min()
                                .unwrap_or(0);
                            let last = input
                                .records
                                .iter()
                                .map(|row| row.id.durable_cursor)
                                .max()
                                .unwrap_or(0);
                            run.retain_input(input, references, proofs, None, &memory)?;
                            (count, crossing, rows, contexts, first, last, append)
                        };
                        {
                            let mut capture = run
                                .captured
                                .lock()
                                .unwrap_or_else(|error| error.into_inner());
                            let capture = capture
                                .as_mut()
                                .ok_or_else(|| Self::invalid("Graph status capture"))?;
                            if capture.restricted.is_some_and(|old| old != count) {
                                return Err(Self::invalid("conflicting Graph status"));
                            }
                            capture.restricted = Some(count);
                            if capture.append.is_some_and(|saved| saved != append) {
                                return Err(Self::invalid("conflicting Graph append proof"));
                            }
                            capture.append = Some(append);
                            capture.retain(&memory)?;
                        }
                        let input = sdk::Input {
                            data: sdk::Dataset {
                                name: "graph_status".into(),
                                batches: vec![sdk::RecordBatch::try_new(
                                    super::node::MetadataPort::Status.schema(),
                                    vec![
                                        Arc::new(BooleanArray::from(vec![count != 0])),
                                        Arc::new(BooleanArray::from(vec![crossing])),
                                        Arc::new(BooleanArray::from(vec![append])),
                                    ],
                                )
                                .map_err(Self::external)?],
                            },
                            revision: sdk::Revision {
                                owner: "araphor-analysis.GraphStatus".into(),
                                id: source.with_capture(|_, capture, _| {
                                    Ok(format!(
                                        "{}:{}:{}:{}",
                                        capture.instance().generation,
                                        capture.revision(),
                                        capture.time_utc_ns(),
                                        base.as_ref().map_or(0, |base| base.commit_revision),
                                    ))
                                })?,
                                window: None,
                            },
                            coverage: sdk::Coverage {
                                state: sdk::CoverageState::Complete,
                                limits: Vec::new(),
                            },
                        };
                        drop(driver);
                        drop(header);
                        for batch in &input.data.batches {
                            source.memory().retain_input(batch, &memory)?;
                        }
                        memory.try_resize(input.metadata_bytes())?;
                        Self::report_input(
                            source, "status", image, rows, contexts, 0, first, last,
                        )?;
                        Ok((input, memory))
                    })()
                    .map_err(|source| araphor_query::Error::Sql { source })
                })
                .await
        }
        .boxed()
    }

    fn report_input(
        source: &SourceSnapshot,
        role: &'static str,
        image: Option<SourceImage>,
        rows: usize,
        contexts: usize,
        affected: usize,
        first: u64,
        last: u64,
    ) -> Result<()> {
        let (instance, cut) = source.with_capture(|_, capture, _| {
            Ok((capture.instance().spec.id.clone(), capture.revision()))
        })?;
        let image = match image {
            Some(SourceImage::Before) => "before",
            Some(SourceImage::Inserted) => "inserted",
            Some(SourceImage::Removed) => "removed",
            _ => "after",
        };
        erebor_telemetry::debug!(
            stage = "graph_input", instance_id = %instance, cut_revision = cut,
            role, image, rows = rows as u64, affected_roots = affected as u64,
            support_rows = rows as u64, first_cursor = first, last_cursor = last,
            "Native Graph input completed"
        );
        erebor_telemetry::debug!(
            stage = "context", instance_id = %instance, cut_revision = cut,
            role, image, rows = contexts as u64,
            "Native Graph contexts qualified"
        );
        Ok(())
    }

    pub(super) fn read_limit(
        source: &SourceSnapshot,
        memory: &MemoryReservation,
        limits: &mut araphor_data::AnalysisExtractLimits,
    ) {
        if memory.size() != 0
            || source.memory().input_capacity().is_some()
            || limits.input_bytes != usize::MAX
        {
            limits.input_bytes = memory.size();
        }
    }

    pub(super) fn decode_rows(
        batches: &[sdk::RecordBatch],
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<(
        GraphReplayInputV1,
        Vec<AnalysisContextVersionV1>,
        Vec<(DiscoveryRecordIdV1, AnalysisContextRefV1)>,
        BTreeSet<DiscoveryRecordIdV1>,
    )> {
        let mut records = BTreeMap::new();
        let mut positions = BTreeMap::new();
        let mut contexts = BTreeMap::new();
        let mut proofs = BTreeMap::new();
        let mut coverage = BTreeMap::new();
        let mut coverage_keys = BTreeSet::new();
        let mut removed = BTreeSet::new();
        let mut payloads =
            BTreeMap::<DiscoveryRecordIdV1, (&StructArray, &StructArray, usize)>::new();
        for batch in batches {
            let record_values = datafusion::arrow::compute::cast(
                Self::column::<StructArray>(batch, "record")?,
                Unit::affected_port().schema.field(0).data_type(),
            )
            .map_err(Self::external)?;
            let ids = record_values
                .as_any()
                .downcast_ref::<StructArray>()
                .ok_or_else(|| Self::invalid("Graph record key"))?;
            let events = Self::column::<StructArray>(batch, "event")?;
            let resolved = Self::column::<StructArray>(batch, "resolved")?;
            let mut end = 0;
            while end < batch.num_rows() {
                let start = end;
                end += 1;
                if ids.is_null(start) {
                    continue;
                }
                let present = !events.is_null(start);
                if present == resolved.is_null(start) {
                    return Err(Self::invalid(if present {
                        "Graph resolved event"
                    } else {
                        "Graph removed record"
                    }));
                }
                while end < batch.num_rows()
                    && !ids.is_null(end)
                    && events.is_null(end) != present
                    && resolved.is_null(end) != present
                {
                    end += 1;
                }
                let length = end - start;
                let key = sdk::RecordBatch::try_new(
                    Arc::new(Unit::affected_port().schema),
                    vec![Arc::new(ids.slice(start, length))],
                )
                .map_err(Self::external)?;
                let keys = Unit::decode_affected(&sdk::Dataset {
                    name: Unit::affected_port().name,
                    batches: vec![key],
                })
                .map_err(Self::external)?;
                if keys.len() != length {
                    return Err(Self::invalid("Graph record key"));
                }
                let event = present.then(|| sdk::RecordBatch::from(events.slice(start, length)));
                let mut values = if present {
                    let values = sdk::RecordBatch::from(resolved.slice(start, length));
                    let values = GraphPublication::decode_resolved(&values)?;
                    if values.len() != length {
                        return Err(Self::invalid("Graph resolved row"));
                    }
                    values
                } else {
                    Vec::new()
                }
                .into_iter();
                for (offset, record) in keys.into_iter().enumerate() {
                    let row = start + offset;
                    if record.stream != *identity {
                        return Err(Self::invalid("Graph record source"));
                    }
                    let Some(event) = &event else {
                        if records.contains_key(&record) || !removed.insert(record) {
                            return Err(Self::invalid("Graph removed record"));
                        }
                        continue;
                    };
                    if removed.contains(&record) {
                        return Err(Self::invalid("Graph resolved event"));
                    }
                    let (value, position) = GraphPublication::decode_event(&record, event, offset)?;
                    if records.get(&record).is_some_and(|old| old != &value)
                        || positions.get(&record).is_some_and(|old| old != &position)
                        || payloads.get(&record).is_some_and(|(event, facts, index)| {
                            StructArray::slice(event, *index, 1)
                                != StructArray::slice(events, row, 1)
                                || StructArray::slice(facts, *index, 1)
                                    != StructArray::slice(resolved, row, 1)
                        })
                    {
                        return Err(Self::invalid("conflicting Graph driver record"));
                    }
                    records.entry(record.clone()).or_insert(value);
                    positions.entry(record.clone()).or_insert(position);
                    payloads
                        .entry(record.clone())
                        .or_insert((events, resolved, row));
                    let (decoded, incoming, references) = values
                        .next()
                        .ok_or_else(|| Self::invalid("Graph resolved row"))?;
                    if decoded != record {
                        return Err(Self::invalid("Graph resolver record binding"));
                    }
                    for value in incoming {
                        if contexts.get(&value.key).is_some_and(|old| old != &value) {
                            return Err(Self::invalid("Graph resolved fact conflict"));
                        }
                        contexts.insert(value.key.clone(), value);
                    }
                    for reference in references {
                        let key = (record.clone(), reference.key.clone());
                        if proofs.get(&key).is_some_and(|old| old != &reference) {
                            return Err(Self::invalid("Graph record proof conflict"));
                        }
                        proofs.insert(key, reference);
                    }
                    let name = if batch.column_by_name("record_coverage_revision").is_some() {
                        "record_coverage_revision"
                    } else {
                        "coverage_revision"
                    };
                    let revision = Self::column::<UInt64Array>(batch, name)?;
                    let interval = Self::column::<UInt64Array>(batch, "interval_revision")?;
                    let ids = Self::column::<BinaryArray>(batch, "coverage_interval_id")?;
                    let state =
                        match Self::column::<StringArray>(batch, "coverage_state")?.value(row) {
                            "HEALTHY" => DiscoveryCoverageStateV1::Healthy,
                            "CLOSED" => DiscoveryCoverageStateV1::Closed,
                            "GAPPED" => DiscoveryCoverageStateV1::Gapped,
                            "UNKNOWN" => DiscoveryCoverageStateV1::Unknown,
                            _ => return Err(Self::invalid("Graph coverage state")),
                        };
                    let reasons =
                        Self::column::<StringArray>(batch, "coverage_reasons")?.value(row);
                    let mut reasons = reasons
                        .split(',')
                        .filter(|reason| !reason.is_empty())
                        .map(str::to_owned)
                        .collect::<Vec<_>>();
                    reasons.sort();
                    reasons.dedup();
                    let interval_id = ids
                        .value(row)
                        .try_into()
                        .map_err(|_| Self::invalid("Graph coverage interval"))?;
                    let range = DiscoveryCoverageV1 {
                        stream: identity.clone(),
                        cpu_id: record.cpu_id,
                        first_cursor: record.durable_cursor,
                        last_cursor: record.durable_cursor,
                        expected_records: 1,
                        coverage_revision: revision.value(row),
                        coverage_interval_id: interval_id,
                        state,
                        gap_reasons: reasons.clone(),
                    };
                    if !interval.is_null(row) {
                        coverage_keys.insert(GraphCoverageKeyV1 {
                            source: identity.clone(),
                            cpu_id: record.cpu_id,
                            report_revision: revision.value(row),
                            interval_id,
                            interval_revision: interval.value(row),
                            state,
                            gap_reasons: reasons,
                        });
                    }
                    let key = (
                        record,
                        revision.value(row),
                        (!interval.is_null(row)).then(|| interval.value(row)),
                    );
                    if coverage.insert(key, range).is_some() {
                        return Err(Self::invalid("duplicate Graph coverage qualification"));
                    }
                }
            }
        }
        Ok((
            GraphReplayInputV1 {
                source: identity.clone(),
                records: records.into_values().collect(),
                input_positions: positions.into_iter().collect(),
                coverage: coverage.into_values().collect(),
                coverage_keys: coverage_keys.into_iter().collect(),
                facts: Vec::new(),
                missing_ranges: Vec::new(),
            },
            contexts.into_values().collect(),
            proofs
                .into_iter()
                .map(|((record, _), proof)| (record, proof))
                .collect(),
            removed,
        ))
    }

    fn input_coverage(input: &GraphReplayInputV1, observations: &[Observation]) -> sdk::Coverage {
        let state = if !input.missing_ranges.is_empty()
            || input
                .coverage
                .iter()
                .any(|range| range.state == DiscoveryCoverageStateV1::Gapped)
        {
            sdk::CoverageState::Gapped
        } else if observations.iter().any(|row| {
            row.proof_quality.temporal_coverage != araphor_data::TemporalCoverageV1::Complete
        }) {
            sdk::CoverageState::Unknown
        } else {
            sdk::CoverageState::Complete
        };
        sdk::Coverage {
            state,
            limits: if state == sdk::CoverageState::Complete {
                Vec::new()
            } else {
                vec!["SOURCE_COVERAGE_INSUFFICIENT".into()]
            },
        }
    }
    pub(super) fn progress(
        batches: &[sdk::RecordBatch],
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<(u64, u64, u64)> {
        let mut found = None;
        for batch in batches {
            for row in 0..batch.num_rows() {
                if Self::identity(batch, row)? != *source {
                    continue;
                }
                let retired = Self::column::<BooleanArray>(batch, "retired")?;
                let class = Self::column::<StringArray>(batch, "processor_class")?;
                let consumed = Self::column::<UInt64Array>(batch, "consumed_cursor")?;
                if retired.is_null(row)
                    || retired.value(row)
                    || class.is_null(row)
                    || class.value(row) != "required"
                    || consumed.is_null(row)
                    || found.is_some()
                {
                    return Err(Self::invalid("required graph progress"));
                }
                let resumed = Self::column::<UInt64Array>(batch, "resume_floor")?;
                if resumed.is_null(row) || resumed.value(row) > consumed.value(row) {
                    return Err(Self::invalid("graph resume gap"));
                }
                found = Some((
                    consumed.value(row),
                    Self::column::<UInt64Array>(batch, "retained_floor")?.value(row),
                    Self::column::<UInt64Array>(batch, "contiguous_cursor")?.value(row),
                ));
            }
        }
        found.ok_or_else(|| Self::invalid("graph source registration"))
    }

    pub(super) fn coverage_revision(
        batches: &[sdk::RecordBatch],
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<u64> {
        for batch in batches {
            for row in 0..batch.num_rows() {
                if Self::identity(batch, row)? == *source {
                    return Ok(Self::column::<UInt64Array>(batch, "coverage_revision")?.value(row));
                }
            }
        }
        Err(Self::invalid("graph source receipt"))
    }

    pub(super) fn identity(
        batch: &sdk::RecordBatch,
        row: usize,
    ) -> Result<EvidenceIntakeIdentityV1> {
        Ok(EvidenceIntakeIdentityV1 {
            tenant_id: Self::column::<BinaryArray>(batch, "tenant_id")?
                .value(row)
                .try_into()
                .map_err(|_| Self::invalid("graph tenant"))?,
            node_id: Self::column::<StringArray>(batch, "node_id")?
                .value(row)
                .into(),
            node_boot_id: Self::column::<BinaryArray>(batch, "node_boot_id")?
                .value(row)
                .try_into()
                .map_err(|_| Self::invalid("graph boot"))?,
            label_epoch: Self::column::<UInt64Array>(batch, "label_epoch")?.value(row),
            source_id: Self::column::<BinaryArray>(batch, "source_id")?
                .value(row)
                .try_into()
                .map_err(|_| Self::invalid("graph source"))?,
            source_epoch: Self::column::<UInt64Array>(batch, "source_epoch")?.value(row),
        })
    }

    pub(super) fn value<T: serde::de::DeserializeOwned>(
        batch: &sdk::RecordBatch,
        name: &str,
        row: usize,
    ) -> Result<T> {
        #[derive(serde::Deserialize)]
        struct Cell<T> {
            value: T,
        }
        let column = batch
            .column_by_name(name)
            .ok_or_else(|| Self::invalid("graph native column"))?
            .slice(row, 1);
        let schema = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
            "value",
            column.data_type().clone(),
            true,
        )]));
        let batch = sdk::RecordBatch::try_new(schema, vec![column]).map_err(Self::external)?;
        let mut values: Vec<Cell<T>> =
            serde_arrow::from_record_batch(&batch).map_err(Self::external)?;
        values
            .pop()
            .map(|value| value.value)
            .ok_or_else(|| Self::invalid("graph native value"))
    }

    pub(super) fn column<'a, T: Array + 'static>(
        batch: &'a sdk::RecordBatch,
        name: &str,
    ) -> Result<&'a T> {
        batch
            .column_by_name(name)
            .and_then(|column| column.as_any().downcast_ref())
            .ok_or_else(|| Self::invalid("graph native column"))
    }
}

#[cfg(test)]
mod tests;

impl GraphRun {
    fn retain_input(
        &self,
        input: GraphReplayInputV1,
        references: BTreeMap<AnalysisContextKeyV1, AnalysisContextRefV1>,
        proofs: Vec<(DiscoveryRecordIdV1, AnalysisContextRefV1)>,
        removed: Option<BTreeSet<DiscoveryRecordIdV1>>,
        memory: &MemoryReservation,
    ) -> Result<()> {
        let mut capture = self
            .captured
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let result = capture
            .as_mut()
            .ok_or_else(|| Projection::invalid("Graph input capture"))
            .and_then(|capture| {
                capture.absorb(input, references, proofs, removed)?;
                capture.retain(memory)
            });
        if result.is_err() {
            capture.take();
        }
        result
    }
}

impl Capture {
    fn absorb(
        &mut self,
        input: GraphReplayInputV1,
        references: BTreeMap<AnalysisContextKeyV1, AnalysisContextRefV1>,
        proofs: Vec<(DiscoveryRecordIdV1, AnalysisContextRefV1)>,
        removed: Option<BTreeSet<DiscoveryRecordIdV1>>,
    ) -> Result<()> {
        if input.source != self.metadata.scope.identity {
            return Err(Projection::invalid("Graph local basis source"));
        }
        let positions = input
            .input_positions
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        for record in input.records {
            if !(self.metadata.first_cursor..=self.metadata.last_cursor)
                .contains(&record.id.durable_cursor)
            {
                return Err(Projection::invalid("Graph local basis window"));
            }
            let position = *positions
                .get(&record.id)
                .ok_or_else(|| Projection::invalid("Graph local basis position"))?;
            if self
                .records
                .get(&record.id)
                .is_some_and(|old| old.0 != record || old.1 != position)
            {
                return Err(Projection::invalid("conflicting Graph local record"));
            }
            if removed.is_some() && self.removed.contains(&record.id) {
                return Err(Projection::invalid("conflicting Graph target presence"));
            }
            self.records
                .entry(record.id.clone())
                .or_insert((record, position));
        }
        for value in input.facts {
            let reference = references.get(&value.key).cloned();
            if let Some((old, bound)) = self.facts.get_mut(&value.key) {
                if old != &value
                    || bound
                        .as_ref()
                        .zip(reference.as_ref())
                        .is_some_and(|(left, right)| left != right)
                {
                    return Err(Projection::invalid("conflicting Graph local fact"));
                }
                if bound.is_none() {
                    *bound = reference;
                }
            } else {
                self.facts.insert(value.key.clone(), (value, reference));
            }
        }
        for (record, proof) in proofs {
            let key = (record, proof.key.clone());
            if self.proofs.get(&key).is_some_and(|old| old != &proof) {
                return Err(Projection::invalid("conflicting Graph local proof"));
            }
            self.proofs.insert(key, proof);
        }
        let mut intervals = BTreeMap::new();
        for key in self.coverage_keys.iter().chain(&input.coverage_keys) {
            let identity = (key.cpu_id, key.report_revision, key.interval_id);
            if intervals
                .insert(identity, key.interval_revision)
                .is_some_and(|old| old != key.interval_revision)
            {
                return Err(Projection::invalid("conflicting Graph interval proof"));
            }
        }
        for range in input.coverage {
            let id = DiscoveryRecordIdV1 {
                stream: range.stream.clone(),
                cpu_id: range.cpu_id,
                durable_cursor: range.first_cursor,
            };
            let interval = intervals
                .get(&(
                    range.cpu_id,
                    range.coverage_revision,
                    range.coverage_interval_id,
                ))
                .copied();
            let key = (id, range.coverage_revision, interval);
            if self.coverage.get(&key).is_some_and(|old| old != &range) {
                return Err(Projection::invalid("conflicting Graph local coverage"));
            }
            self.coverage.entry(key).or_insert(range);
        }
        self.coverage_keys.extend(input.coverage_keys);
        if let Some(removed) = removed {
            for id in removed {
                if id.stream != self.metadata.scope.identity || self.records.contains_key(&id) {
                    return Err(Projection::invalid("conflicting Graph removed target"));
                }
                self.removed.insert(id);
            }
        }
        Ok(())
    }

    fn retain(&mut self, memory: &MemoryReservation) -> Result<()> {
        let used = self
            ._memory
            .iter()
            .try_fold(0usize, |bytes, memory| bytes.checked_add(memory.size()))
            .ok_or_else(|| Projection::invalid("Graph capture memory"))?;
        let bytes = self
            .allocated_bytes()
            .ok_or_else(|| Projection::invalid("Graph capture memory"))?;
        if bytes <= used {
            return Ok(());
        }
        self._memory.try_reserve(1).map_err(Projection::external)?;
        let bytes = self
            .allocated_bytes()
            .ok_or_else(|| Projection::invalid("Graph capture memory"))?;
        if let Some(added) = bytes.checked_sub(used).filter(|added| *added != 0) {
            if memory.size() < added {
                memory.try_grow(added - memory.size())?;
            }
            self._memory.push(memory.split(added));
        }
        Ok(())
    }

    fn key_bytes(key: &AnalysisContextKeyV1) -> Option<usize> {
        key.owner_id
            .capacity()
            .checked_add(key.entity_key.capacity())?
            .checked_add(key.lifetime_key.capacity())
    }

    fn allocated_bytes(&self) -> Option<usize> {
        let strings = |values: &Vec<String>| {
            values.iter().try_fold(
                values.capacity().checked_mul(size_of::<String>())?,
                |bytes, value| bytes.checked_add(value.capacity()),
            )
        };
        let mut bytes = size_of::<Self>().checked_add(
            self._memory
                .capacity()
                .checked_mul(size_of::<MemoryReservation>())?,
        )?;
        bytes = bytes.checked_add(
            self.base
                .as_ref()
                .map_or(0, |base| base.result_id.capacity()),
        )?;
        bytes = bytes.checked_add(
            self.parent
                .as_ref()
                .map_or(0, |parent| parent.result_id.capacity()),
        )?;
        bytes = bytes
            .checked_add(self.metadata.scope.identity.node_id.capacity())?
            .checked_add(self.metadata.scope.processor_id.capacity())?
            .checked_add(
                self.metadata
                    .previous_result_id
                    .as_ref()
                    .map_or(0, String::capacity),
            )?
            .checked_add(
                self.metadata
                    .missing_ranges
                    .capacity()
                    .checked_mul(size_of::<(u64, u64)>())?,
            )?;
        bytes = self.metadata.input_manifest.coverage.iter().try_fold(
            bytes.checked_add(
                self.metadata
                    .input_manifest
                    .coverage
                    .capacity()
                    .checked_mul(size_of::<GraphCoverageKeyV1>())?,
            )?,
            |bytes, key| {
                bytes
                    .checked_add(key.source.node_id.capacity())?
                    .checked_add(strings(&key.gap_reasons)?)
            },
        )?;
        bytes = bytes.checked_add(
            self.metadata
                .input_manifest
                .missing_ranges
                .capacity()
                .checked_mul(size_of::<(u64, u64)>())?,
        )?;
        bytes = self
            .records
            .iter()
            .try_fold(bytes, |bytes, (id, (record, _))| {
                bytes
                    .checked_add(size_of::<(
                        DiscoveryRecordIdV1,
                        (DiscoveryRecordV1, StorePositionV1),
                    )>())?
                    .checked_add(id.allocated_bytes())?
                    .checked_add(record.id.allocated_bytes())?
                    .checked_add(record.wire_record.capacity())
            })?;
        bytes = self
            .facts
            .iter()
            .try_fold(bytes, |bytes, (key, (value, reference))| {
                bytes
                    .checked_add(size_of::<(
                        AnalysisContextKeyV1,
                        (AnalysisContextVersionV1, Option<AnalysisContextRefV1>),
                    )>())?
                    .checked_add(Self::key_bytes(key)?)?
                    .checked_add(Self::key_bytes(&value.key)?)?
                    .checked_add(value.body.capacity())?
                    .checked_add(
                        reference
                            .as_ref()
                            .map_or(Some(0), |reference| Self::key_bytes(&reference.key))?,
                    )
            })?;
        bytes = self
            .proofs
            .iter()
            .try_fold(bytes, |bytes, ((id, key), reference)| {
                bytes
                    .checked_add(size_of::<(
                        (DiscoveryRecordIdV1, AnalysisContextKeyV1),
                        AnalysisContextRefV1,
                    )>())?
                    .checked_add(id.allocated_bytes())?
                    .checked_add(Self::key_bytes(key)?)?
                    .checked_add(Self::key_bytes(&reference.key)?)
            })?;
        bytes = self
            .coverage
            .iter()
            .try_fold(bytes, |bytes, ((id, _, _), range)| {
                bytes
                    .checked_add(size_of::<(
                        (DiscoveryRecordIdV1, u64, Option<u64>),
                        DiscoveryCoverageV1,
                    )>())?
                    .checked_add(id.allocated_bytes())?
                    .checked_add(range.stream.node_id.capacity())?
                    .checked_add(strings(&range.gap_reasons)?)
            })?;
        bytes = self.coverage_keys.iter().try_fold(bytes, |bytes, key| {
            bytes
                .checked_add(size_of::<GraphCoverageKeyV1>())?
                .checked_add(key.source.node_id.capacity())?
                .checked_add(strings(&key.gap_reasons)?)
        })?;
        self.removed.iter().try_fold(bytes, |bytes, id| {
            bytes
                .checked_add(size_of::<DiscoveryRecordIdV1>())?
                .checked_add(id.allocated_bytes())
        })
    }

    pub(super) fn take_input(
        &mut self,
    ) -> (
        GraphReplayInputV1,
        BTreeMap<AnalysisContextKeyV1, AnalysisContextRefV1>,
    ) {
        let mut records = Vec::with_capacity(self.records.len());
        let mut positions = Vec::with_capacity(self.records.len());
        for (id, (record, position)) in std::mem::take(&mut self.records) {
            records.push(record);
            positions.push((id, position));
        }
        let mut facts = Vec::with_capacity(self.facts.len());
        let mut references = BTreeMap::new();
        for (key, (value, reference)) in std::mem::take(&mut self.facts) {
            facts.push(value);
            if let Some(reference) = reference {
                references.insert(key, reference);
            }
        }
        (
            GraphReplayInputV1 {
                source: self.metadata.scope.identity.clone(),
                records,
                input_positions: positions,
                coverage: std::mem::take(&mut self.coverage).into_values().collect(),
                coverage_keys: std::mem::take(&mut self.coverage_keys)
                    .into_iter()
                    .collect(),
                facts,
                missing_ranges: self.metadata.missing_ranges.clone(),
            },
            references,
        )
    }
}
