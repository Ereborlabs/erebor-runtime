use std::collections::{BTreeMap, BTreeSet};

use duckdb::{params, OptionalExt as _, Transaction};
use snafu::ResultExt as _;

use super::{
    AnalysisContextRefV1, AnalysisResultCommitV1, AnalysisResultReceiptV1, AnalysisStore,
    MAX_WITNESS_AGE_NS,
};
use crate::analysis::context::VerifiedPackages;
use crate::analysis::graph::{GraphCommit, GraphManifest, GraphRequestMeta};
use crate::analysis::graph_rows::{CanonicalGraph, GraphRows, GraphWrite};
use crate::analysis::PackageResultRefV1;
use crate::{
    AnalysisConflictSnafu, AnalysisDatabaseSnafu, AnalysisReadControl, GraphFactV1,
    ManagedDestination, ManagedGraphOperation, ManagedReceipt, PackageErrorCodeV1 as Code, Result,
};

#[cfg(any(test, feature = "test-fixtures"))]
use crate::GraphSnapshotV1;

struct GraphResultWrite {
    evidence_count: Option<usize>,
    receipt: AnalysisResultReceiptV1,
    reference: PackageResultRefV1,
    relations: Vec<&'static str>,
    changed: bool,
    work: (u64, u64, u64),
    metadata_rows: (u64, u64),
    pin_rows: u64,
    root_cursors: BTreeMap<u64, (u64, u64)>,
}

impl AnalysisStore {
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn commit_graph(
        &self,
        input: &AnalysisResultCommitV1,
        advance: bool,
        check: impl FnMut() -> Result<()>,
    ) -> Result<AnalysisResultReceiptV1> {
        let snapshot: GraphSnapshotV1 =
            serde_json::from_slice(&input.body).context(crate::GraphEncodingSnafu)?;
        let prepared = CanonicalGraph::new(snapshot)?;
        let mut input = input.clone();
        input.body.clear();
        self.commit_graph_snapshot(input, prepared, &[], &[], &[], advance, check)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The direct Graph fixture carries exact captured inputs."
    )]
    pub fn commit_graph_snapshot(
        &self,
        input: AnalysisResultCommitV1,
        prepared: CanonicalGraph,
        contexts: &[crate::AnalysisContextVersionV1],
        proofs: &[AnalysisContextRefV1],
        sources: &[(String, u64)],
        advance: bool,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<AnalysisResultReceiptV1> {
        let snapshot = prepared.into_snapshot();
        let metadata = GraphManifest::from_snapshot(&snapshot);
        self.check_graph_commit(&input, &metadata, advance)?;
        let mut writer = self.maintenance_writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin direct Graph publication",
            })?;
        let revision = Self::read_meta_from(&transaction, &self.root)?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the Graph revision is exhausted"))?;
        let write = self.graph_result_rows(
            &transaction,
            &input,
            &metadata,
            contexts,
            proofs,
            sources,
            advance,
            false,
            revision,
            metadata.context_notice_revision,
            GraphWrite::Direct(&snapshot),
            None,
            None,
            None,
        )?;
        let changed = !write.relations.is_empty();
        if changed {
            self.check_revision_limits(&transaction, input.scope.identity.tenant_id)?;
            if write.changed {
                self.check_witnesses(
                    &transaction,
                    input.scope.identity.tenant_id,
                    input.created_utc_ns,
                )?;
            }
            Self::record_revision(&transaction, revision, &write.relations)?;
            #[cfg(any(test, feature = "test-fixtures"))]
            self.crash_at("result.before");
        }
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(crate::AnalysisCommitStage::BeforeResultCommit)?;
        check()?;
        if !write.changed {
            self.commit_metadata(transaction, "commit unchanged Graph notice")?;
            if changed {
                self.revision.send_replace(revision);
            }
            return Ok(write.receipt);
        }
        self.commit_metadata(transaction, "commit direct Graph publication")?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.crash_at("result.after");
        self.revision.send_replace(revision);
        Ok(write.receipt)
    }

    pub fn commit_managed_graph(
        &self,
        prepared: crate::PreparedManagedCommit<'_>,
        packet: Option<GraphCommit>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<(ManagedReceipt, Option<AnalysisResultReceiptV1>)> {
        let managed = prepared.input();
        let spec = &managed.attempt.instance().spec;
        let ManagedDestination::Graph {
            source,
            operation: ManagedGraphOperation::Evaluate,
            ..
        } = &spec.destination
        else {
            return Err(Code::Invalid.error("managed source publication destination"));
        };
        let selection = managed
            .attempt
            .source_frame()
            .map(|frame| frame.input_selection())
            .transpose()?
            .flatten();
        if packet.is_some() != selection.is_some() {
            return Err(Code::Incomplete.error("managed source selection receipt"));
        }
        let mut source_receipt = None;
        let mut source_work = (0u64, 0u64);
        let mut graph_work = (0u64, 0u64, 0u64);
        let mut coverage = 0u64;
        let mut previous = String::new();
        let (receipt,pins) = self.commit_managed_projection(
            prepared,
            |transaction, revision, publication, _, _, work, prepared_source| {
                graph_work = work;
                let Some(mut prepared_source) = prepared_source else {
                    return Ok((Vec::new(),None,Default::default(),None));
                };
                let roots=std::mem::take(&mut prepared_source.roots);
                coverage=prepared_source.coverage;
                let (published, metadata) = super::super::managed::SourcePublication::publish(
                    transaction, managed, publication, revision, prepared_source)?;
                let selection=selection.as_ref().ok_or_else(|| Code::Incomplete.error("managed source selection receipt"))?;
                source_work = metadata;
                previous = selection.base.as_ref().map_or_else(String::new,|base| base.result_id.clone());
                let advanced = transaction.execute(
                    "INSERT INTO processor_versions
                     SELECT processor_id,method_version,tenant_id,stream_key,class,
                        greatest(consumed_cursor,?),resume_floor,?,?,start_cursor,
                        greatest(required_floor,?),retired,retirement_id,retirement_reason,
                        retirement_cursor,retirement_revision,?,?
                     FROM processor_progress WHERE processor_id=? AND method_version=? AND tenant_id=? AND stream_key=?",
                    params![published.last,coverage,managed.attempt.captured_revision(),published.last,
                        published.reference.result_id,revision,crate::GRAPH_PROCESSOR,
                        crate::GRAPH_SCHEMA_VERSION,source.tenant_id.as_slice(),source.key()],
                ).context(AnalysisDatabaseSnafu { operation:"advance native source publication" })?;
                if advanced != 1 { return Err(Code::Conflict.error("native source processor head")); }
                source_receipt = Some(AnalysisResultReceiptV1 { commit_revision:revision,consumed_cursor:published.last });
                Ok((vec!["managed_source_publications","managed_source_members","managed_source_gaps","processor_versions"],
                    Some(published.reference),roots,selection.prefix.clone()))
            },
            check,
        )?;
        let inserted = u128::from(graph_work.1) + u128::from(source_work.0);
        let closed = u128::from(graph_work.2) + u128::from(source_work.1);
        erebor_telemetry::debug!(stage="graph_commit",instance_id=%spec.id,
            cut_revision=managed.attempt.captured_revision(),publication_revision=receipt.commit_revision,
            coverage_revision=coverage,
            graph_revision=receipt.graph.as_ref().map_or(0,|graph|graph.commit_revision),
            prior_graph_result_id=%previous,
            graph_result_id=%receipt.graph.as_ref().map_or("",|graph|graph.result_id.as_str()),
            staged_support_rows=graph_work.0,inserted_rows=inserted,closed_rows=closed,
            metadata_inserted_rows=source_work.0,metadata_closed_rows=source_work.1,
            detector_inserted_rows=graph_work.1,detector_closed_rows=graph_work.2,
            pin_rows=pins,"Graph commit completed");
        Ok((receipt, source_receipt))
    }

    pub(super) fn check_graph_commit(
        &self,
        input: &AnalysisResultCommitV1,
        metadata: &GraphManifest,
        advance: bool,
    ) -> Result<()> {
        metadata.validate()?;
        let latest_witness = input
            .created_utc_ns
            .checked_add(MAX_WITNESS_AGE_NS)
            .ok_or_else(|| self.state_error("the Graph witness deadline is exhausted"))?;
        let expected: Vec<_> = metadata
            .input_manifest
            .evidence
            .iter()
            .filter(|id| {
                !metadata
                    .missing_ranges
                    .iter()
                    .any(|(first, last)| (*first..=*last).contains(&id.durable_cursor))
            })
            .map(|id| {
                (
                    crate::AnalysisStreamIdentityV1::Evidence(id.stream.clone()),
                    id.durable_cursor,
                )
            })
            .collect();
        let actual: Vec<_> = input
            .witnesses
            .iter()
            .map(|witness| (witness.identity.clone(), witness.cursor))
            .collect();
        if input.scope.processor_id != crate::GRAPH_PROCESSOR
            || !input.body.is_empty()
            || metadata.scope != input.scope
            || expected != actual
            || input.witnesses.iter().any(|witness| {
                witness.expires_utc_ns != metadata.witness_deadline_utc_ns
                    || witness.expires_utc_ns < input.created_utc_ns
                    || witness.expires_utc_ns > latest_witness
            })
            || (advance && metadata.last_cursor != input.consumed_cursor)
            || (!advance && input.expected_cursor != input.consumed_cursor)
        {
            return self.reject("the Graph input, witnesses, or progress differ");
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The Graph writer receives one captured transaction boundary."
    )]
    fn graph_result_rows(
        &self,
        transaction: &Transaction<'_>,
        input: &AnalysisResultCommitV1,
        metadata: &GraphManifest,
        contexts: &[crate::AnalysisContextVersionV1],
        proofs: &[AnalysisContextRefV1],
        sources: &[(String, u64)],
        advance: bool,
        captured_prefix: bool,
        revision: u64,
        notice: u64,
        graph_write: GraphWrite<'_>,
        resolved_witnesses: Option<(&[crate::AnalysisWitnessV1], &[u64])>,
        validated_contexts: Option<&[AnalysisContextRefV1]>,
        verified: Option<&mut VerifiedPackages>,
    ) -> Result<GraphResultWrite> {
        let started = std::time::Instant::now();
        let mut own_verified = VerifiedPackages::default();
        let verified = verified.unwrap_or(&mut own_verified);
        if !input.scope.valid()
            || input.result_id.is_empty()
            || input.created_utc_ns == 0
            || input.consumed_cursor < input.expected_cursor
            || contexts.windows(2).any(|pair| pair[0].key >= pair[1].key)
            || proofs.windows(2).any(|pair| pair[0].key >= pair[1].key)
            || sources.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || sources.iter().any(|(source, _)| source.is_empty())
            || input
                .context_refs
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || input.context_refs.iter().any(|reference| {
                !reference.key.valid()
                    || reference.key.tenant_id != input.scope.identity.tenant_id
                    || reference.commit_revision == 0
            })
        {
            return self.reject("the Graph publication input is invalid");
        }
        let tenant = input.scope.identity.tenant_id;
        if contexts
            .iter()
            .any(|context| !context.valid() || context.key.tenant_id != tenant)
            || proofs
                .iter()
                .any(|proof| !proof.key.valid() || proof.key.tenant_id != tenant)
        {
            return self.reject("the Graph publication context is invalid");
        }
        let key = input.scope.identity.key();
        let managed = matches!(graph_write, GraphWrite::Managed { .. });
        let inherited = if managed {
            let reset = match &graph_write {
                GraphWrite::Managed { commit, .. } => {
                    commit.attempt.request().rebuild || commit.attempt.switches_version()
                }
                _ => false,
            };
            GraphRows::reset_proofs(transaction, &self.root, metadata, reset)?
        } else {
            Vec::new()
        };
        let record_proofs = match &graph_write {
            GraphWrite::Managed { record_proofs, .. } => *record_proofs,
            _ => &[],
        };
        if managed
            && proofs.iter().any(|proof| {
                metadata
                    .input_manifest
                    .context
                    .binary_search(&proof.key)
                    .is_ok()
                    || record_proofs
                        .iter()
                        .any(|(_, reference)| reference.key == proof.key)
            })
        {
            return self.reject("the global Graph proofs contain record refs");
        }
        let mut global_proofs = proofs
            .iter()
            .filter(|reference| {
                metadata
                    .input_manifest
                    .context
                    .binary_search(&reference.key)
                    .is_err()
            })
            .cloned()
            .collect::<Vec<_>>();
        global_proofs.extend(inherited);
        global_proofs.sort_by(|left, right| left.key.cmp(&right.key));
        global_proofs.dedup();
        let mut expected_keys: BTreeSet<_> = metadata.input_manifest.context.iter().collect();
        for context in contexts {
            if context.package_provenance()?.is_some() {
                expected_keys.insert(&context.key);
            } else {
                let fact = GraphFactV1::try_from(context)?;
                if !expected_keys.contains(&context.key) || !metadata.facts.contains(&fact) {
                    return self.reject("the Graph fact differs from its captured input");
                }
            }
        }
        expected_keys.extend(proofs.iter().map(|proof| &proof.key));
        expected_keys.extend(global_proofs.iter().map(|proof| &proof.key));
        expected_keys.extend(record_proofs.iter().map(|(_, proof)| &proof.key));
        let mut context_write = None;
        let context_started = std::time::Instant::now();
        let inserted = self.context_rows(
            transaction,
            contexts,
            false,
            None,
            &mut context_write,
            verified,
        )?;
        let context_written = std::time::Instant::now();
        let verified_contexts = inserted
            .iter()
            .map(|reference| (reference.key.clone(), reference.commit_revision))
            .collect::<BTreeMap<_, _>>();
        let mut references = input.context_refs.clone();
        references.extend(inserted);
        references.extend_from_slice(proofs);
        references.extend_from_slice(&global_proofs);
        references.extend(record_proofs.iter().map(|(_, proof)| proof.clone()));
        references.sort_by(|left, right| left.key.cmp(&right.key));
        if references
            .windows(2)
            .any(|pair| pair[0].key == pair[1].key && pair[0] != pair[1])
        {
            return AnalysisConflictSnafu.fail();
        }
        references.dedup();
        if !expected_keys
            .iter()
            .copied()
            .eq(references.iter().map(|reference| &reference.key))
        {
            return self.reject("the Graph contexts differ from their captured input");
        }
        let context_revision = references
            .iter()
            .map(|reference| reference.commit_revision)
            .max()
            .unwrap_or(0);
        let request_meta = GraphRequestMeta {
            scope: input.scope.clone(),
            expected_cursor: input.expected_cursor,
            consumed_cursor: input.consumed_cursor,
            coverage_revision: input.coverage_revision,
            captured_context_revision: input.context_revision,
            result_id: input.result_id.clone(),
            created_utc_ns: input.created_utc_ns,
            witnesses: if managed {
                Vec::new()
            } else {
                input.witnesses.clone()
            },
            captured_context_refs: if managed {
                Vec::new()
            } else {
                input.context_refs.clone()
            },
            context_refs: if managed {
                Vec::new()
            } else {
                references.clone()
            },
            sources: sources.to_vec(),
            advance,
            captured_prefix,
        }
        .encode()?;
        let existing: Option<(Vec<u8>, u64)> = transaction
            .query_row(
                "SELECT request_meta, commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
                params![tenant.as_slice(), input.result_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph result identity",
            })?;
        if existing
            .as_ref()
            .is_some_and(|(stored, _)| stored != &request_meta)
        {
            return AnalysisConflictSnafu.fail();
        }
        for reference in &references {
            if verified_contexts.get(&reference.key) == Some(&reference.commit_revision) {
                continue;
            }
            if validated_contexts.is_some_and(|verified| verified.contains(reference)) {
                continue;
            }
            let Some((_, retained)) =
                self.read_context_verified_from(transaction, &self.root, &reference.key, verified)?
            else {
                return self.reject("the Graph context version is absent");
            };
            if retained != reference.commit_revision {
                return self.reject("the Graph context version differs");
            }
        }
        if let Some((_, previous_revision)) = existing {
            if let GraphWrite::Direct(snapshot) = graph_write {
                let Some(header) = GraphRows::read_header(transaction, tenant, &input.result_id)?
                else {
                    return AnalysisConflictSnafu.fail();
                };
                if GraphRows::read(transaction, &input.result_id, &header)? != *snapshot {
                    return AnalysisConflictSnafu.fail();
                }
            } else {
                return AnalysisConflictSnafu.fail();
            }
            return Ok(GraphResultWrite {
                evidence_count: None,
                receipt: AnalysisResultReceiptV1 {
                    commit_revision: previous_revision,
                    consumed_cursor: input.consumed_cursor,
                },
                reference: PackageResultRefV1 {
                    result_id: input.result_id.clone(),
                    commit_revision: previous_revision,
                },
                relations: Vec::new(),
                changed: false,
                work: (0, 0, 0),
                metadata_rows: (0, 0),
                pin_rows: 0,
                root_cursors: Default::default(),
            });
        }
        if input.context_revision
            != input
                .context_refs
                .iter()
                .map(|reference| reference.commit_revision)
                .max()
                .unwrap_or(0)
        {
            return self.reject("the Graph captured context revision differs");
        }
        let progress: Option<(u64, u64, bool)> = transaction
            .query_row(
                "SELECT consumed_cursor, resume_floor, retired FROM processor_progress WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![crate::GRAPH_PROCESSOR, input.scope.method_version, tenant.as_slice(), key.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph progress",
            })?;
        if !progress.is_some_and(|(consumed, resumed, retired)| {
            !retired && consumed.max(resumed) == input.expected_cursor
        }) {
            return AnalysisConflictSnafu.fail();
        }
        let (receipt, _) =
            Self::read_receipt_from(transaction, &self.root, &input.scope.identity, &key)?
                .ok_or_else(|| self.state_error("the Graph source is absent"))?;
        if input.consumed_cursor > receipt.contiguous_cursor
            || input.coverage_revision > receipt.coverage_revision
        {
            return self.reject("the Graph result exceeds accepted source progress");
        }
        let available = self
            .raw
            .lock()
            .map_err(|_| self.state_error("the raw owner lock is poisoned"))?
            .record_count(
                &key,
                input.expected_cursor.saturating_add(1),
                input.consumed_cursor,
                revision.saturating_sub(1),
            );
        if available != input.consumed_cursor - input.expected_cursor {
            return self.reject("the Graph result skips unavailable source input");
        }
        if sources.iter().any(|(_, captured)| *captured >= revision)
            || (!captured_prefix
                && !Self::package_sources_current(
                    transaction,
                    sources,
                    &AnalysisReadControl::default(),
                )?)
        {
            return AnalysisConflictSnafu.fail();
        }
        let witness_segments = if let Some((witnesses, segments)) = resolved_witnesses {
            if witnesses.len() != segments.len() {
                return self.reject("the Graph witness segments differ");
            }
            let mut by_witness = BTreeMap::new();
            for (witness, segment) in witnesses.iter().zip(segments) {
                if by_witness
                    .insert((&witness.identity, witness.cursor), *segment)
                    .is_some()
                {
                    return self.reject("the Graph witness is duplicated");
                }
            }
            input
                .witnesses
                .iter()
                .map(|witness| {
                    by_witness
                        .get(&(&witness.identity, witness.cursor))
                        .copied()
                        .ok_or_else(|| self.state_error("the Graph witness is absent"))
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            self.resolve_witnesses(&input.witnesses, revision.saturating_sub(1))?
        };
        let head: Option<String> = transaction
            .query_row(
                "SELECT result_id FROM analysis_results WHERE tenant_id = ? AND processor_id = ? AND method_version = ? AND stream_key = ? AND first_cursor = ? ORDER BY commit_revision DESC LIMIT 1",
                params![tenant.as_slice(), crate::GRAPH_PROCESSOR, input.scope.method_version, key.as_slice(), metadata.first_cursor],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph window head",
            })?;
        if head.as_deref() != metadata.previous_result_id.as_deref() {
            return AnalysisConflictSnafu.fail();
        }
        if let (GraphWrite::Direct(snapshot), Some(prior_id)) =
            (&graph_write, metadata.previous_result_id.as_deref())
        {
            if !advance {
                let header = GraphRows::read_header(transaction, tenant, prior_id)?
                    .ok_or_else(|| Code::Missing.error("prior Graph result"))?;
                let retained = GraphRows::read(transaction, prior_id, &header)?;
                let (saved_meta, prior_revision): (Vec<u8>, u64) = transaction
                    .query_row(
                        "SELECT request_meta, commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND processor_id = ?",
                        params![tenant.as_slice(), prior_id, crate::GRAPH_PROCESSOR],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read prior Graph attribution",
                    })?;
                let saved = GraphRequestMeta::decode(&saved_meta)?;
                if retained.last_cursor == snapshot.last_cursor
                    && retained.input_manifest == snapshot.input_manifest
                    && retained.graph == snapshot.graph
                    && retained.findings == snapshot.findings
                    && retained.packages == snapshot.packages
                    && retained.input_positions == snapshot.input_positions
                    && retained.witness_deadline_utc_ns > input.created_utc_ns
                    && saved.context_refs == references
                {
                    if context_write.is_some() {
                        return Err(Code::Invalid.error("unchanged Graph context versions"));
                    }
                    let changed = self.notice_rows(
                        transaction,
                        &input.scope,
                        &PackageResultRefV1 {
                            result_id: prior_id.to_owned(),
                            commit_revision: prior_revision,
                        },
                        notice,
                        input.coverage_revision,
                        Some(revision),
                    )?;
                    return Ok(GraphResultWrite {
                        evidence_count: None,
                        receipt: AnalysisResultReceiptV1 {
                            commit_revision: prior_revision,
                            consumed_cursor: input.consumed_cursor,
                        },
                        reference: PackageResultRefV1 {
                            result_id: prior_id.to_owned(),
                            commit_revision: prior_revision,
                        },
                        relations: changed
                            .map_or_else(Vec::new, |_| vec!["result_notices", "analysis_results"]),
                        changed: false,
                        work: (0, 0, 0),
                        metadata_rows: (0, 0),
                        pin_rows: 0,
                        root_cursors: Default::default(),
                    });
                }
            }
        }
        let stage_started = std::time::Instant::now();
        let mut staged = match &graph_write {
            GraphWrite::Managed { .. } => Some(GraphRows::stage_managed(
                self,
                transaction,
                metadata,
                &graph_write,
                &global_proofs,
                verified,
            )?),
            GraphWrite::Direct(_) | GraphWrite::Expiry(_) => None,
        };
        let staged_at = std::time::Instant::now();
        let resolved = staged
            .as_ref()
            .map(|changes| {
                let mut metadata = metadata.clone();
                changes.resolve_metadata(&mut metadata)?;
                Ok::<_, crate::Error>(metadata)
            })
            .transpose()?;
        let metadata = resolved.as_ref().unwrap_or(metadata);
        if let (Some(changes), Some(prior_id)) =
            (staged.as_mut(), metadata.previous_result_id.as_deref())
        {
            if !advance && metadata.witness_deadline_utc_ns > input.created_utc_ns {
                let prior_revision: u64 = transaction
                    .query_row(
                        "SELECT commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND processor_id = ?",
                        params![tenant.as_slice(), prior_id, crate::GRAPH_PROCESSOR],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read prior Graph result revision",
                    })?;
                let prior = PackageResultRefV1 {
                    result_id: prior_id.to_owned(),
                    commit_revision: prior_revision,
                };
                if GraphRows::unchanged(transaction, &prior, metadata, changes)? {
                    let changed = self.notice_rows(
                        transaction,
                        &input.scope,
                        &prior,
                        notice,
                        input.coverage_revision,
                        Some(revision),
                    )?;
                    let mut relations = vec![
                        "analysis_results",
                        "graph_producer_scopes",
                        "graph_producer_versions",
                        "graph_producer_members",
                    ];
                    if changed.is_some() {
                        relations.push("result_notices");
                    }
                    return Ok(GraphResultWrite {
                        evidence_count: changes
                            .previous
                            .as_ref()
                            .map(|header| header.evidence_count),
                        receipt: AnalysisResultReceiptV1 {
                            commit_revision: prior.commit_revision,
                            consumed_cursor: input.consumed_cursor,
                        },
                        reference: prior,
                        relations,
                        changed: true,
                        work: changes.work,
                        metadata_rows: (0, 0),
                        pin_rows: 0,
                        root_cursors: std::mem::take(&mut changes.root_cursors),
                    });
                }
            }
        }
        transaction
            .execute(
                "INSERT INTO analysis_results (result_id, tenant_id, processor_id, body, request_meta, commit_revision, stream_key, method_version, interval_id, facts_revision, coverage_revision, first_cursor) VALUES (?, ?, ?, ?::BLOB, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    input.result_id,
                    tenant.as_slice(),
                    crate::GRAPH_PROCESSOR,
                    Vec::<u8>::new(),
                    request_meta,
                    revision,
                    key.as_slice(),
                    input.scope.method_version,
                    metadata.first_cursor.to_string(),
                    notice,
                    input.coverage_revision,
                    metadata.first_cursor,
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert Graph result",
            })?;
        let reference = PackageResultRefV1 {
            result_id: input.result_id.clone(),
            commit_revision: revision,
        };
        let managed_producers = match &graph_write {
            GraphWrite::Managed { producers, .. } => Some(
                producers
                    .iter()
                    .map(|(_, reference)| reference.clone())
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        };
        let root_cursors = staged
            .as_mut()
            .map(|changes| std::mem::take(&mut changes.root_cursors))
            .unwrap_or_default();
        let publish_started = std::time::Instant::now();
        let (body, work, metadata_rows, evidence_count) = match staged {
            Some(changes) => {
                let (body, work, rows, count) =
                    GraphRows::publish(transaction, &reference, metadata, changes)?;
                (body, work, rows, Some(count))
            }
            None => {
                let (body, work, rows) =
                    GraphRows::commit(transaction, &reference, metadata, graph_write)?;
                (body, work, rows, None)
            }
        };
        let published = std::time::Instant::now();
        if let Some(producers) = managed_producers.as_deref() {
            Self::insert_managed_edges(transaction, tenant, &input.result_id, producers)?;
        }
        transaction
            .execute(
                "UPDATE analysis_results SET body = ? WHERE tenant_id = ? AND result_id = ?",
                params![body, tenant.as_slice(), input.result_id],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "store Graph result header",
            })?;
        let references_started = std::time::Instant::now();
        let pin_rows = Self::insert_references(
            transaction,
            &input.result_id,
            &input.witnesses,
            &witness_segments,
            &references,
        )?;
        let referenced = std::time::Instant::now();
        if advance {
            transaction
                .execute(
                    "INSERT INTO processor_versions
                     SELECT processor_id, method_version, tenant_id, stream_key, class,
                        ?, resume_floor, ?, ?, start_cursor, ?, retired, retirement_id,
                        retirement_reason, retirement_cursor, retirement_revision, ?, ?
                     FROM processor_progress
                     WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                    params![
                        input.consumed_cursor,
                        input.coverage_revision,
                        context_revision,
                        input.consumed_cursor,
                        input.result_id,
                        revision,
                        crate::GRAPH_PROCESSOR,
                        input.scope.method_version,
                        tenant.as_slice(),
                        key.as_slice(),
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "advance Graph progress",
                })?;
        }
        let mut relations = vec![
            "analysis_results",
            "graph_producer_scopes",
            "graph_producer_versions",
            "graph_producer_members",
            "graph_result_producers",
            "graph_subjects",
            "graph_relationships",
            "graph_findings",
        ];
        if managed_producers.is_some() {
            relations.push("managed_edges");
        }
        if advance {
            relations.push("processor_progress");
        }
        if context_write.is_some() {
            relations.push("context_versions");
        }
        if !references.is_empty() {
            relations.push("context_refs");
        }
        if !input.witnesses.is_empty() {
            relations.push("evidence_refs");
        }
        erebor_telemetry::debug!(
            stage = "graph_rows_timing",
            publication_revision = revision,
            validate_s = context_started.duration_since(started).as_secs_f64(),
            contexts_s = context_written
                .duration_since(context_started)
                .as_secs_f64(),
            prepare_s = stage_started.duration_since(context_written).as_secs_f64(),
            stage_s = staged_at.duration_since(stage_started).as_secs_f64(),
            result_s = publish_started.duration_since(staged_at).as_secs_f64(),
            publish_s = published.duration_since(publish_started).as_secs_f64(),
            edges_s = references_started.duration_since(published).as_secs_f64(),
            references_s = referenced.duration_since(references_started).as_secs_f64(),
            completion_s = referenced.elapsed().as_secs_f64(),
            "Graph publication row work completed"
        );
        Ok(GraphResultWrite {
            evidence_count,
            receipt: AnalysisResultReceiptV1 {
                commit_revision: revision,
                consumed_cursor: input.consumed_cursor,
            },
            reference,
            relations,
            changed: true,
            work,
            metadata_rows,
            pin_rows,
            root_cursors,
        })
    }
}
