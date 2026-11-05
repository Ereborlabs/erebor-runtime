use super::*;
use crate::{NotificationFindingRefV1, PackageErrorCodeV1 as Code};

#[derive(Default)]
pub(in crate::analysis::extraction) struct NativeNotifications {
    headers: BTreeMap<String, Header>,
    heads: BTreeMap<String, (String, u64)>,
    members: BTreeMap<String, BTreeMap<String, Member>>,
}

struct Member {
    value: u64,
    allowed: bool,
}

struct Header {
    revision: u64,
    allowed: bool,
    definition: bool,
}

pub(in crate::analysis::extraction) struct Resolved<'a> {
    pub(in crate::analysis::extraction) allowed: bool,
    pub(in crate::analysis::extraction) revision: u64,
    pub(in crate::analysis::extraction) value: Option<u64>,
    pub(in crate::analysis::extraction) current: Option<(&'a str, u64)>,
}

impl NativeNotifications {
    pub(in crate::analysis::extraction) fn read(
        store: &AnalysisStore,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
        states: &[NotificationState],
        capture: &tables::Capture<'_>,
        current: bool,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
        owners: &mut crate::analysis::managed::OwnerRead<'_>,
    ) -> Result<Self> {
        owners.check_reader(snapshot, selection.tenant_id)?;
        if !selection.binding_ids.is_empty() {
            return Ok(Self::default());
        }
        let mut wanted = Vec::new();
        for state in states {
            control.check()?;
            if let Some(reference) = &state.obligation.finding {
                if !capture.needs_manifest(&reference.result_id) {
                    output.sink(control).grow(&mut wanted)?;
                    wanted.push((reference.result_id.as_str(), reference.finding_id.as_str()));
                }
            }
        }
        wanted.sort_unstable();
        wanted.dedup();
        if wanted.is_empty() {
            return Ok(Self::default());
        }
        snapshot
            .execute_batch(
                "CREATE TEMP TABLE native_notice_wanted(result_id VARCHAR,finding_id VARCHAR)",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "create notification scalar requests",
            })?;
        let result = Self::capture(
            store, snapshot, selection, scope, &wanted, current, output, control, owners,
        );
        let cleanup = snapshot
            .execute_batch(
                "DROP TABLE IF EXISTS native_notice_heads; DROP TABLE native_notice_wanted",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "release notification scalar requests",
            });
        let result = result?;
        cleanup?;
        Ok(result)
    }

    fn capture(
        store: &AnalysisStore,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
        wanted: &[(&str, &str)],
        current: bool,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
        owners: &mut crate::analysis::managed::OwnerRead<'_>,
    ) -> Result<Self> {
        {
            let mut append =
                snapshot
                    .appender("native_notice_wanted")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open notification scalar requests",
                    })?;
            for (result, finding) in wanted {
                control.check()?;
                append
                    .append_row(params![result, finding])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append notification scalar request",
                    })?;
            }
            append.flush().context(AnalysisDatabaseSnafu {
                operation: "flush notification scalar requests",
            })?;
        }
        let started = std::time::Instant::now();
        let findings =
            owners.finding_catalog(snapshot, selection.tenant_id, &mut |scan, bytes| {
                control.check()?;
                output.scan(scan)?;
                output.charge(bytes)
            })?;
        let catalog = std::time::Instant::now();
        output.charge(wanted.len().saturating_mul(4 * size_of::<&str>()))?;
        let ids = wanted.iter().map(|(_, id)| *id).collect::<Vec<_>>();
        let mut result = Self::default();
        if current {
            result.heads = AnalysisStore::finding_heads_on(
                store,
                snapshot,
                selection.tenant_id,
                Some(&ids),
                &findings,
                &mut |scan, bytes| {
                    control.check()?;
                    output.scan(scan)?;
                    output.charge(bytes)
                },
            )?;
            result
                .heads
                .retain(|id, _| wanted.iter().any(|(_, wanted)| id == wanted));
        }
        snapshot.execute_batch("CREATE TEMP TABLE native_notice_heads(finding_id VARCHAR,result_id VARCHAR,revision UBIGINT)")
            .context(AnalysisDatabaseSnafu { operation:"create notification scalar heads" })?;
        {
            let mut append =
                snapshot
                    .appender("native_notice_heads")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open notification scalar heads",
                    })?;
            for (id, (owner, revision)) in &result.heads {
                append
                    .append_row(params![id, owner, revision])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append notification scalar head",
                    })?;
            }
            append.flush().context(AnalysisDatabaseSnafu {
                operation: "flush notification scalar heads",
            })?;
        }
        let heads = std::time::Instant::now();
        result.read_headers(snapshot, selection, scope, owners, output, control)?;
        let headers = std::time::Instant::now();
        result.read_members(
            store, snapshot, selection, scope, wanted, &findings, owners, output, control,
        )?;
        control.check()?;
        erebor_telemetry::debug!(
            stage = "notification_capture_timing",
            rows = wanted.len(),
            header_count = result.headers.len(),
            current,
            catalog_s = catalog.duration_since(started).as_secs_f64(),
            heads_s = heads.duration_since(catalog).as_secs_f64(),
            headers_s = headers.duration_since(heads).as_secs_f64(),
            members_s = headers.elapsed().as_secs_f64(),
            elapsed_s = started.elapsed().as_secs_f64(),
            "Native notification scalar capture completed"
        );
        Ok(result)
    }

    fn read_headers(
        &mut self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
        owners: &mut crate::analysis::managed::OwnerRead<'_>,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let mut query = snapshot.prepare(&format!(
            "WITH wanted AS (SELECT result_id FROM native_notice_wanted UNION SELECT result_id FROM native_notice_heads)
             SELECT wanted.result_id,raw.result_id IS NOT NULL,publication.revision,publication.stream_key,
                publication.first_cursor,publication.last_cursor,source.identity_json,
                coalesce(graph.result_id IS NULL OR (graph.revision=publication.revision
                    AND owner.tenant_id=publication.tenant_id AND owner.instance_id=publication.instance_id),false),
                octet_length(encode(wanted.result_id))+coalesce(octet_length(publication.stream_key),0)
                    +coalesce(octet_length(encode(source.identity_json)),0)
             FROM wanted LEFT JOIN managed_source_publications raw ON raw.result_id=wanted.result_id
             LEFT JOIN ({}) publication ON publication.result_id=wanted.result_id AND publication.tenant_id=?
             LEFT JOIN source_receipts source ON source.stream_key=publication.stream_key AND source.tenant_id=publication.tenant_id
             LEFT JOIN managed_graph_publications graph ON graph.result_id=publication.result_id
             LEFT JOIN managed_graphs owner ON owner.graph_id=graph.graph_id", AnalysisStore::SOURCE_OWNER
        )).context(AnalysisDatabaseSnafu { operation: "prepare notification publication owners" })?;
        let mut rows = query
            .query(params![selection.tenant_id.as_slice()])
            .context(AnalysisDatabaseSnafu {
                operation: "read notification publication owners",
            })?;
        let mut sources = BTreeMap::<Vec<u8>, bool>::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance notification publication owners",
        })? {
            Self::charge(
                row.get(8).context(AnalysisDatabaseSnafu {
                    operation: "bound notification publication owner",
                })?,
                12 * (size_of::<(String, Header)>()
                    + size_of::<(Vec<u8>, bool)>()
                    + size_of::<EvidenceIntakeIdentityV1>()),
                output,
                control,
            )?;
            let present: bool = row.get(1).context(AnalysisDatabaseSnafu {
                operation: "read notification publication presence",
            })?;
            if !present {
                let id: String = row.get(0).context(AnalysisDatabaseSnafu {
                    operation: "read Definition notification owner",
                })?;
                if let Some(owner) =
                    owners.publication(snapshot, selection.tenant_id, &id, &mut |scan, bytes| {
                        output.scan(scan)?;
                        output.charge(bytes)
                    })?
                {
                    if self
                        .headers
                        .insert(
                            id,
                            Header {
                                revision: owner.revision(),
                                allowed: owner.grant().permitted_by(scope).is_ok(),
                                definition: true,
                            },
                        )
                        .is_some()
                    {
                        return Err(Code::Invalid.error("notification duplicate Definition owner"));
                    }
                }
                continue;
            }
            let (id, revision, stream, first, last, identity, valid): (
                String,
                Option<u64>,
                Option<Vec<u8>>,
                Option<u64>,
                Option<u64>,
                Option<String>,
                bool,
            ) = (|| -> duckdb::Result<_> {
                Ok((
                    row.get(0)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode notification publication owner",
            })?;
            let (Some(revision), Some(stream), Some(first), Some(last), Some(identity)) =
                (revision, stream, first, last, identity)
            else {
                return Err(Code::Denied.error("notification native publication owner"));
            };
            if revision == 0 || first == 0 || last < first || !valid {
                return Err(Code::Denied.error("notification native publication owner"));
            }
            let allowed = match sources.get(&stream) {
                Some(allowed) => *allowed,
                None => {
                    let source: EvidenceIntakeIdentityV1 = serde_json::from_str(&identity)
                        .map_err(|_| Code::Invalid.error("notification native source identity"))?;
                    if !source.valid()
                        || source.tenant_id != selection.tenant_id
                        || source.key() != stream
                    {
                        return Err(Code::Denied.error("notification native source identity"));
                    }
                    let allowed = selection.sources.as_slice().contains(&source);
                    sources.insert(stream, allowed);
                    allowed
                }
            };
            if self
                .headers
                .insert(
                    id,
                    Header {
                        revision,
                        allowed,
                        definition: false,
                    },
                )
                .is_some()
            {
                return Err(Code::Invalid.error("notification duplicate publication owner"));
            }
        }
        Ok(())
    }

    fn read_members(
        &mut self,
        store: &AnalysisStore,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
        wanted: &[(&str, &str)],
        findings: &crate::analysis::managed::graph::projection::DomainProjection,
        owners: &mut crate::analysis::managed::OwnerRead<'_>,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let mut requests = BTreeMap::<String, BTreeMap<String, Vec<u8>>>::new();
        for (result, id) in wanted.iter().copied().chain(
            self.heads
                .iter()
                .map(|(id, (result, _))| (result.as_str(), id.as_str())),
        ) {
            control.check()?;
            output.charge(
                result.len()
                    + id.len()
                    + id.len().saturating_add(16)
                    + 12 * size_of::<(String, Vec<u8>)>(),
            )?;
            let key = araphor_analysis_types::DomainRelations::key(&id)
                .context(crate::AnalysisContractSnafu)?;
            requests
                .entry(result.into())
                .or_default()
                .insert(id.into(), key);
        }
        let mut origins = BTreeMap::new();
        for (result, ids) in requests {
            let keys = ids.into_values().collect::<Vec<_>>();
            let rows = findings.read_findings(
                store,
                snapshot,
                selection.tenant_id,
                &result,
                Some(&keys),
                &mut |scan, bytes| {
                    control.check()?;
                    output.scan(scan)?;
                    output.charge(bytes)
                },
            )?;
            let mut seen = std::collections::BTreeSet::new();
            for row in rows {
                let id = row.id()?;
                if !seen.insert(id.to_owned()) {
                    continue;
                }
                Self::charge(
                    result.len() + id.len() + row.origin.len(),
                    12 * (size_of::<(String, BTreeMap<String, Member>)>()
                        + size_of::<(String, Member)>()),
                    output,
                    control,
                )?;
                let mut allowed = self
                    .headers
                    .get(&result)
                    .is_some_and(|header| header.allowed);
                if allowed
                    && self
                        .headers
                        .get(&result)
                        .is_some_and(|header| header.definition)
                {
                    let origin = (row.origin.clone(), row.origin_revision);
                    allowed = match origins.get(&origin) {
                        Some(allowed) => *allowed,
                        None => {
                            output.charge(
                                origin.0.capacity() + 8 * size_of::<(String, u64, bool)>(),
                            )?;
                            let producer =
                                owners.producer(&origin.0, origin.1, &mut |scan, bytes| {
                                    output.scan(scan)?;
                                    output.charge(bytes)
                                })?;
                            let allowed = producer.grant().permitted_by(scope).is_ok();
                            origins.insert(origin, allowed);
                            allowed
                        }
                    };
                }
                if row.value == 0
                    || self
                        .members
                        .entry(result.clone())
                        .or_default()
                        .insert(
                            id.into(),
                            Member {
                                value: row.value,
                                allowed,
                            },
                        )
                        .is_some()
                {
                    return Err(Code::Invalid.error("notification finding scalar identity"));
                }
            }
        }
        Ok(())
    }

    pub(in crate::analysis::extraction) fn resolve<'a>(
        &'a self,
        store: &AnalysisStore,
        reference: &NotificationFindingRefV1,
        selection: &AnalysisSelectionV1,
        current: bool,
    ) -> Result<Option<Resolved<'a>>> {
        let Some(header) = self.headers.get(&reference.result_id) else {
            return Ok(None);
        };
        let member = self
            .members
            .get(&reference.result_id)
            .and_then(|members| members.get(&reference.finding_id));
        let mut resolved = Resolved {
            allowed: header.allowed && member.is_none_or(|member| member.allowed),
            revision: header.revision,
            value: member.map(|member| member.value),
            current: None,
        };
        if current && member.is_some() && resolved.allowed {
            if let Some((id, revision)) = self.heads.get(&reference.finding_id) {
                let Some(header) = self.headers.get(id) else {
                    return Ok(None);
                };
                if header.revision != *revision {
                    return Err(Code::Conflict.error("notification current publication revision"));
                }
                if header.allowed
                    && (selection.graphs.is_empty() || selection.graphs.as_slice().contains(id))
                {
                    let member = self
                        .members
                        .get(id)
                        .and_then(|members| members.get(&reference.finding_id))
                        .ok_or_else(|| {
                            store.state_error("the current notification finding is absent")
                        })?;
                    if member.allowed {
                        resolved.current = Some((id, *revision));
                    }
                }
            }
        }
        Ok(Some(resolved))
    }

    fn charge(
        bytes: usize,
        metadata: usize,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        control.check()?;
        output.scan(bytes)?;
        let bytes = bytes
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(metadata))
            .ok_or_else(|| Code::Limit.error("notification scalar capture memory"))?;
        output.charge(bytes)
    }
}
