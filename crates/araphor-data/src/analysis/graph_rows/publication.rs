use super::*;
use crate::{AnalysisContextRefV1, ManagedDestination};

pub(in crate::analysis) struct ProducerChanges {
    cuts: Vec<(String, u64, u64)>,
    previous: Option<GraphManifest>,
    full_check: bool,
    touched: BTreeSet<(u8, Vec<u8>)>,
    states: BTreeMap<(String, u64), GraphPackageStateV1>,
}

impl ProducerChanges {
    pub(in crate::analysis) fn resolve_metadata(&self, metadata: &mut GraphManifest) -> Result<()> {
        for ((id, version), state) in &self.states {
            let mut matches = metadata
                .packages
                .iter_mut()
                .filter(|package| &package.package_id == id && package.package_version == *version);
            let package = matches
                .next()
                .ok_or_else(|| GraphRows::invalid("graph unit package metadata"))?;
            if matches.next().is_some() {
                return Err(GraphRows::invalid("graph unit package metadata"));
            }
            package.state = state.clone();
        }
        Ok(())
    }
}

impl GraphRows {
    pub(in crate::analysis) fn stage_managed(
        store: &super::super::AnalysisStore,
        writer: &Connection,
        metadata: &GraphManifest,
        commit: &ManagedCommit<'_>,
        producers: &[(u64, PackageResultRefV1)],
        verified: &mut super::super::context::VerifiedPackages,
    ) -> Result<ProducerChanges> {
        metadata.validate()?;
        let source = Self::source_id(writer, &metadata.scope.identity)?;
        let spec = &commit.attempt.instance().spec;
        let ManagedDestination::Graph {
            calls,
            source: declared,
            ..
        } = &spec.destination
        else {
            return Err(Self::invalid("graph managed destination"));
        };
        if declared != &metadata.scope.identity
            || producers.len() != calls.len()
            || producers
                .iter()
                .map(|(call, _)| call)
                .collect::<BTreeSet<_>>()
                .len()
                != calls.len()
        {
            return Err(Self::invalid("graph managed producer set"));
        }
        let previous = metadata
            .previous_result_id
            .as_deref()
            .map(|id| {
                Self::read_metadata_control(writer, metadata.scope.identity.tenant_id, id, None)?
                    .map(|header| GraphManifest::from_snapshot(&header.snapshot))
                    .ok_or_else(|| Self::invalid("graph producer previous result"))
            })
            .transpose()?;
        let mut cuts = Vec::new();
        let mut touched = BTreeSet::new();
        let mut states = BTreeMap::new();
        let mut full_check = previous.is_none()
            || commit.attempt.request().rebuild
            || commit.attempt.switches_version();
        for (call, reference) in producers {
            if !calls.contains(call) {
                return Err(Self::invalid("graph managed call"));
            }
            let descriptor = super::super::AnalysisStore::managed_contract(
                writer,
                spec.tenant,
                &spec.manifest.calls[call],
            )?;
            let model = descriptor
                .exports
                .iter()
                .find(|model| model.name == spec.manifest.calls[call].export)
                .ok_or_else(|| Self::invalid("graph producer export"))?;
            let unit_contract = Detector::supports_units(model);
            if !unit_contract {
                continue;
            }
            let returned = commit
                .returns
                .iter()
                .find(|returned| returned.call == *call)
                .ok_or_else(|| Self::invalid("graph managed return"))?;
            let prior = commit.attempt.prior_result(*call);
            let rebuild = commit.attempt.request().rebuild || commit.attempt.switches_version();
            if unit_contract {
                store.verify_package_revision(
                    writer,
                    spec.tenant,
                    &spec.manifest.calls[call].package,
                    verified,
                )?;
                let changes = returned
                    .changes
                    .ok_or_else(|| Self::invalid("graph unit input base"))?;
                let reset = model
                    .change_inputs
                    .as_ref()
                    .ok_or_else(|| Self::invalid("graph unit change contract"))?
                    .is_reset(returned.evaluation)
                    .context(crate::AnalysisContractSnafu)?;
                if returned.retained.is_some()
                    || reset != changes.base.is_none()
                    || (!reset && changes.base.as_ref() != prior)
                    || (rebuild && !reset)
                {
                    return Err(Self::invalid("graph unit input base"));
                }
                let storage_prior = prior.filter(|_| !rebuild);
                let scope = if let Some(prior) = storage_prior {
                    Self::call_scope(writer, spec, *call, prior)?
                } else {
                    Self::new_scope(
                        writer,
                        metadata,
                        source,
                        0,
                        Some(super::history::ProducerPin {
                            instance: &spec.id,
                            call: *call,
                            declaration: &spec.manifest.calls[call],
                        }),
                        reference.commit_revision,
                    )?
                };
                Self::version(
                    writer,
                    &reference.result_id,
                    scope,
                    reference.commit_revision,
                    storage_prior.map(|prior| prior.result_id.as_str()),
                )?;
                let effects = Self::apply_units(
                    writer,
                    &store.root,
                    scope,
                    reference.commit_revision,
                    metadata,
                    returned,
                    &spec.manifest.calls[call],
                )?;
                touched.extend(effects.touched);
                let package = metadata
                    .packages
                    .iter()
                    .find(|package| {
                        package.package_id == spec.manifest.calls[call].package.package_id
                    })
                    .ok_or_else(|| Self::invalid("graph unit package metadata"))?;
                if states
                    .insert(
                        (package.package_id.clone(), package.package_version),
                        effects.state.clone(),
                    )
                    .is_some_and(|prior| prior != effects.state)
                {
                    return Err(Self::invalid("graph unit package state conflict"));
                }
                full_check |= reset || storage_prior.is_none();
                cuts.push((
                    reference.result_id.clone(),
                    scope,
                    reference.commit_revision,
                ));
                continue;
            }
        }
        if cuts.is_empty() {
            return Err(Self::invalid("graph producer is absent"));
        }
        if let Some(prior) = metadata.previous_result_id.as_deref() {
            let mut statement=writer.prepare("SELECT v.scope_id FROM graph_result_producers b JOIN graph_producer_versions v ON v.result_id=b.producer_result_id JOIN graph_producer_scopes s USING(scope_id) WHERE b.result_id=? AND s.producer_kind=0").context(AnalysisDatabaseSnafu {operation:"prepare previous producer scopes"})?;
            let scopes = statement
                .query_map(params![prior], |row| row.get::<_, u64>(0))
                .context(AnalysisDatabaseSnafu {
                    operation: "read previous producer scopes",
                })?
                .collect::<duckdb::Result<BTreeSet<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode previous producer scopes",
                })?;
            full_check |= scopes != cuts.iter().map(|(_, scope, _)| *scope).collect();
        }
        Ok(ProducerChanges {
            cuts,
            previous,
            full_check,
            touched,
            states,
        })
    }

    pub(in crate::analysis) fn unchanged(
        writer: &Connection,
        prior: &PackageResultRefV1,
        metadata: &GraphManifest,
        refs: &[AnalysisContextRefV1],
        changes: &ProducerChanges,
    ) -> Result<bool> {
        let Some(previous) = changes.previous.as_ref() else {
            return Ok(false);
        };
        if metadata.previous_result_id.as_deref() != Some(&prior.result_id) {
            return Err(Self::invalid("graph unchanged base"));
        }
        let mut expected = metadata.clone();
        expected.previous_result_id = previous.previous_result_id.clone();
        expected.context_notice_revision = previous.context_notice_revision;
        if expected != *previous {
            return Ok(false);
        }
        let saved:Option<(u64,Vec<u8>)>=writer.query_row("SELECT commit_revision,request_meta FROM analysis_results WHERE result_id=? AND tenant_id=? AND processor_id=?",params![prior.result_id,metadata.scope.identity.tenant_id.as_slice(),crate::GRAPH_PROCESSOR],|row|Ok((row.get(0)?,row.get(1)?))).optional().context(AnalysisDatabaseSnafu {operation:"read unchanged Graph references"})?;
        let Some((revision, body)) = saved else {
            return Err(Self::invalid("graph unchanged result"));
        };
        if revision != prior.commit_revision {
            return Err(Self::invalid("graph unchanged revision"));
        }
        let stored = super::super::graph::GraphRequestMeta::decode(&body)?;
        if stored.context_refs != refs {
            return Ok(false);
        }
        Self::stage_cuts(writer, changes)?;
        Self::stage_keys(writer, changes)?;
        let changed:bool=writer.query_row(
            "WITH old_cuts AS (
                SELECT v.scope_id,v.commit_revision,v.result_id FROM graph_result_producers b
                JOIN graph_producer_versions v ON v.result_id=b.producer_result_id
                JOIN graph_producer_scopes s USING(scope_id)
                WHERE b.result_id=? AND s.producer_kind=0
             ), touched AS (
                SELECT member_kind,member_key FROM graph_stage_touched
             ), before AS (
                SELECT DISTINCT m.member_kind,m.member_key,m.value_ref FROM graph_producer_members m
                JOIN old_cuts old USING(scope_id) LEFT JOIN touched t ON t.member_kind=m.member_kind AND t.member_key=m.member_key
                WHERE m.member_kind IN (2,3,4,6) AND (? OR t.member_key IS NOT NULL) AND m.valid_from<=old.commit_revision AND (m.valid_to IS NULL OR m.valid_to>old.commit_revision)
             ), after AS (
                SELECT DISTINCT m.member_kind,m.member_key,m.value_ref FROM graph_producer_members m
                JOIN graph_stage_cuts c USING(scope_id) LEFT JOIN touched t ON t.member_kind=m.member_kind AND t.member_key=m.member_key
                WHERE m.member_kind IN (2,3,4,6) AND (? OR t.member_key IS NOT NULL) AND m.valid_from<=c.commit_revision AND (m.valid_to IS NULL OR m.valid_to>c.commit_revision)
             ) SELECT EXISTS((SELECT * FROM before EXCEPT SELECT * FROM after)
                UNION ALL (SELECT * FROM after EXCEPT SELECT * FROM before))",
            params![prior.result_id,changes.full_check,changes.full_check],|row|row.get(0),
        ).context(AnalysisDatabaseSnafu {operation:"compare affected Graph values"})?;
        writer
            .execute_batch("DROP TABLE graph_stage_cuts; DROP TABLE graph_stage_touched")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph producer stage",
            })?;
        Ok(!changed)
    }

    pub(in crate::analysis) fn publish(
        writer: &Connection,
        result: &PackageResultRefV1,
        metadata: &GraphManifest,
        changes: ProducerChanges,
    ) -> Result<Vec<u8>> {
        let source = Self::source_id(writer, &metadata.scope.identity)?;
        let previous = metadata
            .previous_result_id
            .as_deref()
            .map(|id| {
                writer
                    .query_row(
                        "SELECT metadata_result_id FROM graph_versions WHERE result_id=?",
                        params![id],
                        |row| row.get::<_, String>(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read Graph metadata base",
                    })
            })
            .transpose()?;
        let (scope, previous) = Self::publication_scope(
            writer,
            metadata,
            source,
            2,
            previous.as_deref(),
            result.commit_revision,
        )?;
        let metadata_id = format!("{}:metadata", result.result_id);
        Self::version(
            writer,
            &metadata_id,
            scope,
            result.commit_revision,
            previous.as_deref(),
        )?;
        Self::write_metadata(writer, scope, source, result.commit_revision, metadata)?;
        writer
            .execute(
                "INSERT INTO graph_versions VALUES(?,?,?,true,false)",
                params![result.result_id, result.commit_revision, metadata_id],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert public Graph version",
            })?;
        Self::bind_result(writer, &result.result_id, &metadata_id)?;
        for (producer, _, _) in &changes.cuts {
            Self::bind_result(writer, &result.result_id, producer)?;
        }
        Self::stage_keys(writer, &changes)?;
        let (subjects, edges, findings) = Self::result_counts(
            writer,
            &result.result_id,
            metadata.previous_result_id.as_deref(),
            result.commit_revision,
            changes.full_check,
        )?;
        writer
            .execute_batch("DROP TABLE graph_stage_touched")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph touched keys",
            })?;
        GraphHeader::encode(
            metadata,
            (subjects as usize, edges as usize, findings as usize, 0),
        )
    }

    fn stage_keys(writer: &Connection, changes: &ProducerChanges) -> Result<()> {
        writer.execute_batch("CREATE TEMP TABLE graph_stage_touched(member_kind UTINYINT,member_key BLOB,PRIMARY KEY(member_kind,member_key))").context(AnalysisDatabaseSnafu {operation:"create Graph touched keys"})?;
        let mut appender =
            writer
                .appender("graph_stage_touched")
                .context(AnalysisDatabaseSnafu {
                    operation: "open Graph touched keys",
                })?;
        for (kind, key) in &changes.touched {
            appender
                .append_row(params![kind, key])
                .context(AnalysisDatabaseSnafu {
                    operation: "append Graph touched key",
                })?;
        }
        appender.flush().context(AnalysisDatabaseSnafu {
            operation: "flush Graph touched keys",
        })?;
        Ok(())
    }

    fn stage_cuts(writer: &Connection, changes: &ProducerChanges) -> Result<()> {
        writer.execute_batch("CREATE TEMP TABLE graph_stage_cuts(result_id VARCHAR,scope_id UBIGINT,commit_revision UBIGINT)").context(AnalysisDatabaseSnafu {operation:"create Graph producer stage"})?;
        let mut appender = writer
            .appender("graph_stage_cuts")
            .context(AnalysisDatabaseSnafu {
                operation: "open Graph producer stage",
            })?;
        for (result, scope, revision) in &changes.cuts {
            appender
                .append_row(params![result, scope, revision])
                .context(AnalysisDatabaseSnafu {
                    operation: "append Graph producer stage",
                })?;
        }
        appender.flush().context(AnalysisDatabaseSnafu {
            operation: "flush Graph producer stage",
        })?;
        Ok(())
    }
}
