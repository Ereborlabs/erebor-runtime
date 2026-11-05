use super::*;

impl InputInterest {
    pub(super) fn head(
        &self,
        store: &AnalysisStore,
        control: &AnalysisReadControl,
        memory: &managed::PreparedMemory<'_>,
    ) -> Result<(AnalysisStoreMetaV1, StorePositionV1)> {
        let (coordinator, mut reader) = store.coordinated_reader(control)?;
        control.run(&mut reader, |connection| {
            let meta = AnalysisStore::read_meta_from(connection, &store.root)?;
            drop(coordinator);
            let mut position = StorePositionV1 { commit_revision: 0, ordinal: 0 };
            let mut metadata = |revision: u64| {
                if revision != 0 {
                    position = position.max(StorePositionV1 {
                        commit_revision: revision, ordinal: u32::MAX,
                    });
                }
            };
            {
                let raw = store.raw.until(control)?;
                for (key, source) in &raw.sources {
                    control.check()?;
                    let tenant = match &source.receipt {
                        raw::RawReceipt::Evidence(receipt) => receipt.identity.tenant_id,
                        raw::RawReceipt::Diagnostic(receipt) => receipt.identity.tenant_id,
                    };
                    if tenant != self.selection.tenant_id { continue; }
                    let bytes = match &source.receipt {
                        raw::RawReceipt::Evidence(receipt) => receipt.identity.node_id.len(),
                        raw::RawReceipt::Diagnostic(receipt) => receipt.identity.node_id.len(),
                    };
                    let _row = memory.reserve(bytes + 4 * size_of::<AnalysisStreamIdentityV1>())?;
                    let identity = match &source.receipt {
                        raw::RawReceipt::Evidence(receipt) => AnalysisStreamIdentityV1::Evidence(receipt.identity.clone()),
                        raw::RawReceipt::Diagnostic(receipt) => AnalysisStreamIdentityV1::Diagnostic(receipt.identity.clone()),
                    };
                    if identity.tenant() != self.selection.tenant_id { continue; }
                    if self.matches(&InputChange::Removal { identity: &identity, range: None }) {
                        metadata(self.removal_head(connection, &identity, meta.commit_revision)?);
                    }
                    if self.matches(&InputChange::Raw { identity: &identity, range: None }) {
                        let revision = match &identity {
                            AnalysisStreamIdentityV1::Evidence(_) => connection.query_row(
                                "SELECT COALESCE(MAX(commit_revision),0) FROM (
                                    SELECT commit_revision FROM source_versions WHERE tenant_id=? AND stream_key=?
                                    UNION ALL SELECT commit_revision FROM coverage WHERE tenant_id=? AND stream_key=?
                                 ) WHERE commit_revision<=?",
                                params![identity.tenant().as_slice(),key,identity.tenant().as_slice(),key,meta.commit_revision],
                                |row| row.get::<_,u64>(0),
                            ),
                            AnalysisStreamIdentityV1::Diagnostic(_) => connection.query_row(
                                "SELECT COALESCE(MAX(version_revision),0) FROM trace_versions
                                 WHERE tenant_id=? AND stream_key=? AND version_revision<=?",
                                params![identity.tenant().as_slice(),key,meta.commit_revision],
                                |row| row.get::<_,u64>(0),
                            ),
                        }.context(AnalysisDatabaseSnafu { operation: "read source input head" })?;
                        metadata(revision);
                    }
                    let AnalysisStreamIdentityV1::Evidence(source) = identity else { continue; };
                    for (processor, version) in [(crate::GRAPH_PROCESSOR, u64::from(crate::GRAPH_SCHEMA_VERSION)),
                        ("discovery", u64::from(crate::DISCOVERY_SCHEMA_VERSION))] {
                        let scope = ProcessorScopeV1 { identity: source.clone(), processor_id: processor.into(), method_version: version };
                        if !self.matches(&InputChange::Processor(&scope)) { continue; }
                        let revision = connection.query_row(
                            "SELECT COALESCE(MAX(commit_revision),0) FROM (
                                SELECT commit_revision FROM processor_versions WHERE tenant_id=? AND stream_key=?
                                    AND processor_id=? AND method_version=?
                                UNION ALL SELECT commit_revision FROM processor_gaps WHERE tenant_id=? AND stream_key=?
                                    AND processor_id=? AND method_version=?
                             ) WHERE commit_revision<=?",
                            params![source.tenant_id.as_slice(),key,processor,version,
                                source.tenant_id.as_slice(),key,processor,version,meta.commit_revision],
                            |row| row.get::<_,u64>(0),
                        ).context(AnalysisDatabaseSnafu { operation: "read processor input head" })?;
                        metadata(revision);
                    }
                }
            }
            metadata(self.context_head(connection, meta.commit_revision, control, memory)?);
            metadata(self.result_head(store, connection, meta.commit_revision, control, memory)?);
            metadata(self.trace_head(connection, meta.commit_revision, control, memory, &store.root)?);
            drop(metadata);
            let raw = store.raw.until(control)?;
            for (&revision, entry) in raw.entries.range(..=meta.commit_revision).rev() {
                control.check()?;
                if revision < position.commit_revision { break; }
                for span in &entry.commit.spans {
                    if !self.matches(&InputChange::Raw { identity: &entry.identity,
                        range: Some((span.first,span.last,entry.commit.intake)) }) { continue; }
                    let last = match &entry.identity {
                        AnalysisStreamIdentityV1::Evidence(_) if !self.has(&["coverage", "discovery_state", "graph_state"]) => {
                            let Some((_, upper)) = self.selection.cursor_range() else { continue; };
                            span.last.min(upper)
                        }
                        _ => span.last,
                    };
                    position = position.max(StorePositionV1 { commit_revision: revision,
                        ordinal: span.ordinal+(last-span.first) as u32 });
                }
            }
            Ok((meta, position))
        })
    }

    fn context_head(
        &self,
        reader: &duckdb::Connection,
        cut: u64,
        control: &AnalysisReadControl,
        memory: &managed::PreparedMemory<'_>,
    ) -> Result<u64> {
        if !self.has(&[
            "context",
            "context_versions",
            "targets",
            "compiled_policies",
            "notification_routes",
            "notifications",
        ]) {
            return Ok(0);
        }
        let mut query = reader
            .prepare(
                "SELECT owner_id,entity_key,lifetime_key,owner_revision,MAX(commit_revision),
                octet_length(encode(owner_id))+octet_length(entity_key)+octet_length(lifetime_key)
             FROM context_versions WHERE tenant_id=? AND commit_revision<=?
             GROUP BY owner_id,entity_key,lifetime_key,owner_revision",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare context input heads",
            })?;
        let mut rows = query
            .query(params![self.selection.tenant_id.as_slice(), cut])
            .context(AnalysisDatabaseSnafu {
                operation: "read context input heads",
            })?;
        let mut head = 0;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance context input head",
        })? {
            control.check()?;
            let bytes: usize = row.get(5).context(AnalysisDatabaseSnafu {
                operation: "read context head size",
            })?;
            let _row = memory.reserve(bytes + 4 * size_of::<AnalysisContextKeyV1>())?;
            let (key, revision) = (|| -> duckdb::Result<_> {
                Ok((
                    AnalysisContextKeyV1 {
                        tenant_id: self.selection.tenant_id,
                        owner_id: row.get(0)?,
                        entity_key: row.get(1)?,
                        lifetime_key: row.get(2)?,
                        owner_revision: row.get(3)?,
                    },
                    row.get::<_, u64>(4)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode context input head",
            })?;
            if self.matches(&InputChange::Context(&key)) {
                head = head.max(revision);
            }
        }
        Ok(head)
    }

    fn result_head(
        &self,
        store: &AnalysisStore,
        reader: &duckdb::Connection,
        cut: u64,
        control: &AnalysisReadControl,
        memory: &managed::PreparedMemory<'_>,
    ) -> Result<u64> {
        if !self.has(&[
            "behaviors",
            "discovery_state",
            "findings",
            "relationships",
            "graph_subjects",
            "graph_branches",
            "correlation_packages",
            "policy_observations",
            "graph_manifest",
            "graph_coverage",
            "notifications",
        ]) {
            return Ok(0);
        }
        let mut query = reader.prepare(
            "WITH results AS (
                SELECT result_id,stream_key,processor_id,method_version,commit_revision FROM analysis_results WHERE tenant_id=?
                UNION ALL SELECT publication.result_id,NULL,?,NULL,publication.revision
                    FROM managed_graph_publications publication JOIN managed_graphs graph USING(graph_id) WHERE graph.tenant_id=?
             ) SELECT r.result_id,r.stream_key,r.processor_id,r.method_version,
                r.commit_revision,
                octet_length(encode(r.result_id))+COALESCE(octet_length(r.stream_key),0)+octet_length(encode(r.processor_id)),COALESCE(MAX(n.commit_revision),0)
             FROM results r LEFT JOIN result_notices n ON n.result_id=r.result_id AND n.tenant_id=? AND n.commit_revision<=?
             WHERE r.commit_revision<=? GROUP BY r.result_id,r.stream_key,r.processor_id,r.method_version,r.commit_revision",
        ).context(AnalysisDatabaseSnafu { operation: "prepare result input heads" })?;
        let mut rows = query
            .query(params![
                self.selection.tenant_id.as_slice(),
                crate::GRAPH_PROCESSOR,
                self.selection.tenant_id.as_slice(),
                self.selection.tenant_id.as_slice(),
                cut,
                cut
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "read result input heads",
            })?;
        let mut head = 0;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance result input head",
        })? {
            control.check()?;
            let bytes: usize = row.get(5).context(AnalysisDatabaseSnafu {
                operation: "read result head size",
            })?;
            let _row = memory.reserve(bytes + 8 * size_of::<String>())?;
            let (id, key, processor, version, revision) = (|| -> duckdb::Result<_> {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<u64>>(3)?,
                    row.get::<_, u64>(4)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode result input head",
            })?;
            let notice: u64 = row.get(6).context(AnalysisDatabaseSnafu {
                operation: "read result notice head",
            })?;
            let revision = if processor == crate::DISCOVERY_PROCESSOR || self.graph_notices() {
                revision.max(notice)
            } else {
                revision
            };
            if processor == crate::GRAPH_PROCESSOR {
                if self.graph_matches(store, reader, &id, key.as_deref(), control)? {
                    head = head.max(revision);
                }
            } else if processor == crate::DISCOVERY_PROCESSOR {
                let Some(key) = key else {
                    continue;
                };
                let raw = store.raw.until(control)?;
                let Some(source) = raw
                    .sources
                    .get(&key)
                    .and_then(|source| source.receipt.evidence())
                else {
                    continue;
                };
                let scope = ProcessorScopeV1 {
                    identity: source.identity.clone(),
                    processor_id: processor,
                    method_version: version.unwrap_or(0),
                };
                if self.matches(&InputChange::Profile {
                    scope: &scope,
                    result: &id,
                }) {
                    head = head.max(revision);
                }
            }
        }
        Ok(head)
    }

    fn graph_matches(
        &self,
        store: &AnalysisStore,
        reader: &duckdb::Connection,
        id: &str,
        key: Option<&[u8]>,
        control: &AnalysisReadControl,
    ) -> Result<bool> {
        if store
            .managed_results
            .graph_publication(reader, self.selection.tenant_id, id)?
            .is_some()
        {
            return Ok(store.managed_results.publication_matches(
                self.selection.tenant_id,
                id,
                |witnesses| {
                    self.matches(&InputChange::Graph {
                        tenant: self.selection.tenant_id,
                        result: id,
                        source: None,
                        witnesses,
                    })
                },
            ));
        }
        let Some(key) = key else {
            return Ok(false);
        };
        let raw = store.raw.until(control)?;
        let Some(source) = raw
            .sources
            .get(key)
            .and_then(|source| source.receipt.evidence())
        else {
            return Ok(false);
        };
        Ok(self.matches(&InputChange::Graph {
            tenant: self.selection.tenant_id,
            result: id,
            source: Some(&source.identity),
            witnesses: &[],
        }))
    }

    fn trace_head(
        &self,
        reader: &duckdb::Connection,
        cut: u64,
        control: &AnalysisReadControl,
        memory: &managed::PreparedMemory<'_>,
        root: &std::path::Path,
    ) -> Result<u64> {
        if !self.has(&["traces"]) {
            return Ok(0);
        }
        let mut query = reader.prepare(
            "SELECT request_id,bindings,revision,octet_length(encode(bindings)) FROM traces WHERE tenant_id=? AND revision<=?",
        ).context(AnalysisDatabaseSnafu { operation: "prepare trace input heads" })?;
        let mut rows = query
            .query(params![self.selection.tenant_id.as_slice(), cut])
            .context(AnalysisDatabaseSnafu {
                operation: "read trace input heads",
            })?;
        let mut head = 0;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance trace input head",
        })? {
            control.check()?;
            let bytes: usize = row.get(3).context(AnalysisDatabaseSnafu {
                operation: "read trace head size",
            })?;
            let _row = memory.reserve(bytes.saturating_mul(4) + 8 * size_of::<TraceBindingV1>())?;
            let (request, bindings, revision) = (|| -> duckdb::Result<_> {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode trace input head",
            })?;
            let request: [u8; 16] = request
                .try_into()
                .map_err(|_| crate::PackageErrorCodeV1::Invalid.error("trace input request"))?;
            let bindings: Vec<TraceBindingV1> =
                serde_json::from_str(&bindings).context(crate::JsonSnafu { path: root })?;
            if self.matches(&InputChange::Trace {
                tenant: self.selection.tenant_id,
                request,
                bindings: &bindings,
            }) {
                head = head.max(revision);
            }
        }
        Ok(head)
    }

    fn removal_head(
        &self,
        reader: &duckdb::Connection,
        identity: &AnalysisStreamIdentityV1,
        cut: u64,
    ) -> Result<u64> {
        let rows_only = matches!(identity, AnalysisStreamIdentityV1::Evidence(_))
            && !self.has(&["coverage", "discovery_state", "graph_state"]);
        let (first, last) = self.selection.cursor_range().unwrap_or((1, 0));
        let (start, end) = self.selection.time_range().unwrap_or((1, 0));
        reader.query_row(
            "SELECT COALESCE(MAX(commit_revision),0) FROM (
                SELECT commit_revision FROM expired_ranges WHERE tenant_id=? AND stream_key=?
                    AND (NOT ? OR (first_cursor<=? AND last_cursor>=? AND received_utc_ns BETWEEN ? AND ?))
                UNION ALL SELECT commit_revision FROM recovery_gaps WHERE tenant_id=? AND stream_key=?
                    AND (NOT ? OR (first_cursor<=? AND last_cursor>=?))
             ) WHERE commit_revision<=?",
            params![identity.tenant().as_slice(), identity.key(), rows_only, last, first, start, end,
                identity.tenant().as_slice(), identity.key(), rows_only, last, first, cut],
            |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "read removed input head" })
    }
}
