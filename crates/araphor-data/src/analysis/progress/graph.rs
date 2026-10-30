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
    AnalysisConflictSnafu, AnalysisDatabaseSnafu, AnalysisReadControl, GraphFactV1, ManagedCommit,
    ManagedDestination, ManagedGraphOperation, ManagedReceipt, PackageErrorCodeV1 as Code, Result,
};

#[cfg(any(test, feature = "test-fixtures"))]
use crate::GraphSnapshotV1;

struct GraphResultWrite {
    receipt: AnalysisResultReceiptV1,
    reference: PackageResultRefV1,
    relations: Vec<&'static str>,
    changed: bool,
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
        if write.changed {
            self.check_revision_limits(&transaction, input.scope.identity.tenant_id)?;
            self.check_witnesses(
                &transaction,
                input.scope.identity.tenant_id,
                input.created_utc_ns,
            )?;
            Self::record_revision(&transaction, revision, &write.relations)?;
            #[cfg(any(test, feature = "test-fixtures"))]
            self.crash_at("result.before");
        }
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(crate::AnalysisCommitStage::BeforeResultCommit)?;
        check()?;
        if !write.changed {
            self.commit_metadata(transaction, "commit unchanged Graph notice")?;
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
        managed: &ManagedCommit<'_>,
        packet: Option<GraphCommit>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<(ManagedReceipt, Option<AnalysisResultReceiptV1>)> {
        let spec = &managed.attempt.instance().spec;
        let ManagedDestination::Graph {
            source,
            calls,
            operation,
            ..
        } = &spec.destination
        else {
            return Err(Code::Invalid.error("managed Graph destination"));
        };
        let Some(packet) = packet else {
            if !managed.returns.is_empty()
                || managed
                    .selected
                    .batches
                    .iter()
                    .any(|batch| batch.num_rows() != 0)
            {
                return Err(Code::Invalid.error("managed Graph empty result"));
            }
            return self
                .commit_managed_projection(managed, |_, _, _, _, _| Ok((Vec::new(), None)), check)
                .map(|receipt| (receipt, None));
        };
        if packet.request.scope.identity != *source
            || packet.request.created_utc_ns != managed.attempt.request().time_utc_ns
            || calls
                .iter()
                .copied()
                .ne(managed.returns.iter().map(|returned| returned.call))
            || packet.expire != (*operation == ManagedGraphOperation::Expire)
        {
            return Err(Code::Invalid.error("managed Graph capture"));
        }
        self.check_graph_commit(&packet.request, &packet.metadata, packet.advance)?;
        if packet.expire && (packet.advance || !packet.request.witnesses.is_empty()) {
            return Err(Code::Invalid.error("managed Graph expiry"));
        }
        let mut graph_receipt = None;
        let receipt = self.commit_managed_projection(
            managed,
            |transaction, revision, publication, witnesses, verified| {
                let producers: Vec<_> = publication
                    .results
                    .iter()
                    .map(|(call, result)| (*call, result.clone()))
                    .collect();
                let previous = packet
                    .metadata
                    .previous_result_id
                    .as_deref()
                    .map(|id| {
                        transaction
                            .query_row(
                                "SELECT commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND processor_id = ?",
                                params![source.tenant_id.as_slice(), id, crate::GRAPH_PROCESSOR],
                                |row| row.get::<_, u64>(0),
                            )
                            .optional()
                            .context(AnalysisDatabaseSnafu {
                                operation: "read previous Graph result",
                            })?
                            .map(|commit_revision| PackageResultRefV1 {
                                result_id: id.to_owned(),
                                commit_revision,
                            })
                            .ok_or_else(|| Code::Missing.error("previous Graph result"))
                    })
                    .transpose()?;
                let graph_write = if packet.expire {
                    GraphWrite::Expiry(previous.as_ref().ok_or_else(|| {
                        Code::Invalid.error("managed Graph expiry base")
                    })?)
                } else {
                    GraphWrite::Managed {
                        commit: managed,
                        producers: &producers,
                    }
                };
                let notice = if managed.attempt.follows_graph() {
                    managed.attempt.captured_revision()
                } else {
                    revision
                };
                let write = self.graph_result_rows(
                    transaction,
                    &packet.request,
                    &packet.metadata,
                    &packet.contexts,
                    &packet.proofs,
                    &packet.sources,
                    packet.advance,
                    managed.attempt.follows_graph(),
                    revision,
                    notice,
                    graph_write,
                    Some(witnesses),
                    Some(managed.attempt.contexts()),
                    Some(verified),
                )?;
                graph_receipt = Some(write.receipt);
                Ok((write.relations, Some(write.reference)))
            },
            check,
        )?;
        Ok((receipt, graph_receipt))
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
        let mut context_write = None;
        let inserted = self.context_rows(transaction, contexts, false, None, &mut context_write)?;
        let verified_contexts = inserted
            .iter()
            .map(|reference| (reference.key.clone(), reference.commit_revision))
            .collect::<BTreeMap<_, _>>();
        let mut references = input.context_refs.clone();
        references.extend(inserted);
        references.extend_from_slice(proofs);
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
            witnesses: input.witnesses.clone(),
            captured_context_refs: input.context_refs.clone(),
            context_refs: references.clone(),
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
        let receipt =
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
                    self.notice_rows(
                        transaction,
                        &input.scope,
                        prior_id,
                        prior_revision,
                        notice,
                        input.coverage_revision,
                    )?;
                    return Ok(GraphResultWrite {
                        receipt: AnalysisResultReceiptV1 {
                            commit_revision: prior_revision,
                            consumed_cursor: input.consumed_cursor,
                        },
                        reference: PackageResultRefV1 {
                            result_id: prior_id.to_owned(),
                            commit_revision: prior_revision,
                        },
                        relations: Vec::new(),
                        changed: false,
                    });
                }
            }
        }
        let staged = match &graph_write {
            GraphWrite::Managed { commit, producers } => Some(GraphRows::stage_managed(
                self,
                transaction,
                metadata,
                commit,
                producers,
                verified,
            )?),
            GraphWrite::Direct(_) | GraphWrite::Expiry(_) => None,
        };
        if let (Some(changes), Some(prior_id)) =
            (staged.as_ref(), metadata.previous_result_id.as_deref())
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
                if GraphRows::unchanged(transaction, &prior, metadata, &references, changes)? {
                    self.notice_rows(
                        transaction,
                        &input.scope,
                        &prior.result_id,
                        prior.commit_revision,
                        notice,
                        input.coverage_revision,
                    )?;
                    return Ok(GraphResultWrite {
                        receipt: AnalysisResultReceiptV1 {
                            commit_revision: prior.commit_revision,
                            consumed_cursor: input.consumed_cursor,
                        },
                        reference: prior,
                        relations: vec![
                            "analysis_results",
                            "graph_producer_scopes",
                            "graph_producer_versions",
                            "graph_producer_members",
                        ],
                        changed: true,
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
        let body = match staged {
            Some(changes) => GraphRows::publish(transaction, &reference, metadata, changes)?,
            None => GraphRows::commit(transaction, &reference, metadata, graph_write)?,
        };
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
        Self::insert_references(
            transaction,
            &input.result_id,
            &input.witnesses,
            &witness_segments,
            &references,
        )?;
        if advance {
            transaction
                .execute(
                    "UPDATE processor_progress SET consumed_cursor = ?, coverage_revision = ?, context_revision = ?, required_floor = ?, result_id = ? WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                    params![
                        input.consumed_cursor,
                        input.coverage_revision,
                        context_revision,
                        input.consumed_cursor,
                        input.result_id,
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
        Ok(GraphResultWrite {
            receipt: AnalysisResultReceiptV1 {
                commit_revision: revision,
                consumed_cursor: input.consumed_cursor,
            },
            reference,
            relations,
            changed: true,
        })
    }
}
