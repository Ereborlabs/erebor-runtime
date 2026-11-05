use super::*;
use crate::{AnalysisContextRefV1, ManagedDestination};

pub(in crate::analysis) use crate::analysis::graph_rows::store::ProducerChanges;

impl GraphRows {
    pub(in crate::analysis) fn reset_proofs(
        writer: &Connection,
        root: &std::path::Path,
        metadata: &GraphManifest,
        reset: bool,
    ) -> Result<Vec<AnalysisContextRefV1>> {
        let Some(id) = metadata.previous_result_id.as_deref() else {
            return Ok(Vec::new());
        };
        let restricted: Option<u64> = writer
            .query_row(
                "SELECT v.restricted_count FROM graph_versions g JOIN graph_producer_versions v
             ON v.result_id=g.metadata_result_id WHERE g.result_id=?",
                params![id],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read reset Graph provenance layout",
            })?;
        if restricted.is_some() && !reset {
            return Ok(Vec::new());
        }
        if restricted.is_some() {
            let header = Self::read_summary(writer, metadata.scope.identity.tenant_id, id, None)?
                .ok_or_else(|| Self::invalid("graph reset provenance"))?;
            if header.snapshot.scope != metadata.scope {
                return Err(Self::invalid("graph reset provenance scope"));
            }
            let mut statement=writer.prepare(
                "SELECT c.tenant_id,c.owner_id,c.entity_key,c.lifetime_key,c.owner_revision,
                    c.commit_revision,m.valid_from,g.result_id,p.ref_id,
                    m.anchor_record_id IS NULL AND m.anchor_fact IS NULL AND m.reason_code IS NULL AND m.ordinal=0
                 FROM graph_versions base JOIN graph_producer_versions v ON v.result_id=base.metadata_result_id
                 JOIN graph_producer_members m ON m.scope_id=v.scope_id AND m.unit_ref=0 AND m.member_kind=10
                    AND m.valid_from<=v.commit_revision AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision)
                 LEFT JOIN context_versions c ON c.version_key=m.member_key AND c.commit_revision=m.value_ref
                 LEFT JOIN graph_producer_versions opened ON opened.scope_id=m.scope_id AND opened.commit_revision=m.valid_from
                 LEFT JOIN graph_versions g ON g.metadata_result_id=opened.result_id
                 LEFT JOIN context_refs p ON p.ref_id=g.result_id AND p.tenant_id=c.tenant_id
                    AND p.owner_id=c.owner_id AND p.entity_key=c.entity_key
                    AND p.lifetime_key=c.lifetime_key AND p.owner_revision=c.owner_revision
                 WHERE base.result_id=?"
            ).context(AnalysisDatabaseSnafu {operation:"prepare reset Graph global refs"})?;
            let mut rows = statement
                .query(params![id])
                .context(AnalysisDatabaseSnafu {
                    operation: "read reset Graph global refs",
                })?;
            let mut proofs = Vec::new();
            let mut cuts = BTreeMap::new();
            let mut seen = BTreeSet::new();
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance reset Graph global refs",
            })? {
                let key = crate::AnalysisContextKeyV1 {
                    tenant_id: Self::column::<Vec<u8>>(row, 0)?
                        .try_into()
                        .map_err(|_| Self::invalid("graph reset proof tenant"))?,
                    owner_id: Self::column(row, 1)?,
                    entity_key: Self::column(row, 2)?,
                    lifetime_key: Self::column(row, 3)?,
                    owner_revision: Self::column(row, 4)?,
                };
                let revision: u64 = Self::column(row, 5)?;
                let opening: u64 = Self::column(row, 6)?;
                let owner: String = Self::column(row, 7)?;
                let captured = if let Some(cut) = cuts.get(&(owner.clone(), opening)) {
                    *cut
                } else {
                    let cut = super::super::AnalysisStore::graph_capture_cut(
                        writer,
                        key.tenant_id,
                        &PackageResultRefV1 {
                            result_id: owner.clone(),
                            commit_revision: opening,
                        },
                        None,
                        None,
                    )?;
                    cuts.insert((owner, opening), cut);
                    cut
                };
                if !key.valid()
                    || key.tenant_id != metadata.scope.identity.tenant_id
                    || revision == 0
                    || revision > captured
                    || Self::column::<Option<String>>(row, 8)?.is_none()
                    || !Self::column::<bool>(row, 9)?
                    || !seen.insert(key.clone())
                {
                    return Err(Self::invalid("graph reset global proof"));
                }
                let (context, committed) =
                    super::super::AnalysisStore::read_context_from(writer, root, &key)?
                        .ok_or_else(|| Self::invalid("graph reset context"))?;
                if committed != revision {
                    return Err(Self::invalid("graph reset context revision"));
                }
                if context.package_provenance()?.is_none() {
                    proofs.push(AnalysisContextRefV1 {
                        key,
                        commit_revision: revision,
                    });
                }
            }
            return Ok(proofs);
        }
        let header =
            Self::read_metadata_control(writer, metadata.scope.identity.tenant_id, id, None)?
                .ok_or_else(|| Self::invalid("graph reset provenance"))?;
        let facts = header
            .snapshot
            .graph
            .facts
            .iter()
            .map(Self::encode_value)
            .collect::<Result<BTreeSet<_>>>()?;
        let body: Vec<u8> = writer
            .query_row(
                "SELECT request_meta FROM analysis_results WHERE tenant_id=? AND result_id=?",
                params![metadata.scope.identity.tenant_id.as_slice(), id],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read reset Graph provenance",
            })?;
        let request = super::super::graph::GraphRequestMeta::decode(&body)?;
        let mut proofs = Vec::new();
        for reference in request.context_refs {
            let (context, revision) =
                super::super::AnalysisStore::read_context_from(writer, root, &reference.key)?
                    .ok_or_else(|| Self::invalid("graph reset context"))?;
            if revision != reference.commit_revision {
                return Err(Self::invalid("graph reset context revision"));
            }
            if context.package_provenance()?.is_some() {
                continue;
            }
            let is_fact = match crate::GraphFactV1::try_from(&context) {
                Ok(fact) => facts.contains(&Self::encode_value(&fact)?),
                Err(_) => false,
            };
            if header
                .snapshot
                .input_manifest
                .context
                .binary_search(&reference.key)
                .is_err()
                || !is_fact
            {
                proofs.push(reference);
            }
        }
        Ok(proofs)
    }

    fn metadata_prior(
        writer: &Connection,
        scope: u64,
        replacements: &[crate::analysis::graph_rows::store::Replacement],
    ) -> Result<BTreeMap<u64, BTreeSet<(u8, Vec<u8>, u64)>>> {
        let units = replacements
            .iter()
            .filter_map(|replacement| replacement.unit)
            .collect::<BTreeSet<_>>();
        if units.is_empty() {
            return Ok(BTreeMap::new());
        }
        writer
            .execute_batch("CREATE TEMP TABLE graph_metadata_units(unit_ref UBIGINT PRIMARY KEY)")
            .context(AnalysisDatabaseSnafu {
                operation: "stage touched Graph metadata units",
            })?;
        let result = (|| -> Result<BTreeMap<u64, BTreeSet<(u8, Vec<u8>, u64)>>> {
            {
                let mut appender =
                    writer
                        .appender("graph_metadata_units")
                        .context(AnalysisDatabaseSnafu {
                            operation: "open touched Graph metadata units",
                        })?;
                for unit in units {
                    appender
                        .append_row(params![unit])
                        .context(AnalysisDatabaseSnafu {
                            operation: "append touched Graph metadata unit",
                        })?;
                }
                appender.flush().context(AnalysisDatabaseSnafu {
                    operation: "flush touched Graph metadata units",
                })?;
            }
            let mut statement = writer
                .prepare(
                    "SELECT m.unit_ref,m.member_kind,m.member_key,m.value_ref,
                    m.anchor_record_id,m.anchor_fact,m.reason_code,m.ordinal
                 FROM graph_metadata_units u JOIN graph_producer_members m USING(unit_ref)
                 WHERE m.scope_id=? AND m.valid_to IS NULL",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare touched Graph metadata",
                })?;
            let mut rows = statement
                .query(params![scope])
                .context(AnalysisDatabaseSnafu {
                    operation: "read touched Graph metadata",
                })?;
            let mut previous = BTreeMap::<u64, BTreeSet<_>>::new();
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance touched Graph metadata",
            })? {
                let unit: u64 = Self::column(row, 0)?;
                let kind: u8 = Self::column(row, 1)?;
                let key: Vec<u8> = Self::column(row, 2)?;
                if !matches!(kind, 0 | 1 | 7 | 10)
                    || Self::column::<Option<u64>>(row, 4)?
                        != if kind == 10 { Some(unit) } else { None }
                    || Self::column::<Option<Vec<u8>>>(row, 5)?.is_some()
                    || Self::column::<Option<String>>(row, 6)?.is_some()
                    || Self::column::<u32>(row, 7)? != 0
                    || !previous.entry(unit).or_default().insert((
                        kind,
                        key,
                        Self::column::<u64>(row, 3)?,
                    ))
                {
                    return Err(Self::invalid("graph metadata member"));
                }
            }
            Ok(previous)
        })();
        let cleanup = writer
            .execute_batch("DROP TABLE graph_metadata_units")
            .context(AnalysisDatabaseSnafu {
                operation: "release touched Graph metadata units",
            });
        let previous = result?;
        cleanup?;
        Ok(previous)
    }

    fn metadata_diff(
        writer: &Connection,
        scope: u64,
        replacements: &[crate::analysis::graph_rows::store::Replacement],
        reset: bool,
        prior: u64,
    ) -> Result<(bool, u64, BTreeSet<(u8, Vec<u8>, u64)>)> {
        let mut changed = reset;
        let mut before = BTreeSet::new();
        let mut after = BTreeSet::new();
        let mut removed_members = BTreeSet::new();
        let previous = if reset {
            BTreeMap::new()
        } else {
            Self::metadata_prior(writer, scope, replacements)?
        };
        let empty = BTreeSet::new();
        for replacement in replacements {
            let desired = replacement
                .members
                .iter()
                .map(|member| (member.kind, member.key.clone(), member.value))
                .collect::<BTreeSet<_>>();
            if desired.len() != replacement.members.len() {
                return Err(Self::invalid("graph duplicate metadata member"));
            }
            for (kind, key, _) in &desired {
                if *kind == 7 {
                    after.insert(key.clone());
                }
            }
            if reset {
                continue;
            }
            let Some(unit) = replacement.unit else {
                for (kind, key, value) in desired {
                    if kind != 10 {
                        return Err(Self::invalid("graph global proof kind"));
                    }
                    let old:Option<(u64,bool)>=writer.query_row(
                        "SELECT value_ref,anchor_record_id IS NULL AND anchor_fact IS NULL
                            AND reason_code IS NULL AND ordinal=0 FROM graph_producer_members WHERE scope_id=? AND unit_ref=0
                         AND member_kind=10 AND member_key=? AND valid_to IS NULL",
                        params![scope,key],|row|Ok((row.get(0)?,row.get(1)?)),
                    ).optional().context(AnalysisDatabaseSnafu { operation:"compare global Graph proof" })?;
                    if old.is_some_and(|(old, shape)| old != value || !shape) {
                        return Err(Self::invalid("graph global proof revision"));
                    }
                    changed |= old.is_none();
                }
                continue;
            };
            let old = previous.get(&unit).unwrap_or(&empty);
            before.extend(
                old.iter()
                    .filter(|(kind, _, _)| *kind == 7)
                    .map(|(_, key, _)| key.clone()),
            );
            removed_members.extend(
                old.difference(&desired)
                    .filter(|(kind, _, _)| matches!(*kind, 0 | 7))
                    .cloned(),
            );
            changed |= old != &desired;
        }
        let mut restricted = writer
            .prepare("SELECT sensitivity FROM context_versions WHERE version_key=?")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph metadata sensitivity",
            })?;
        let mut count = |keys: BTreeSet<Vec<u8>>| -> Result<u64> {
            let mut count = 0;
            for key in keys {
                let sensitivity: String = restricted
                    .query_row(params![key], |row| row.get(0))
                    .context(AnalysisDatabaseSnafu {
                        operation: "read Graph metadata sensitivity",
                    })?;
                let sensitivity = crate::ContextSensitivityV1::try_from(sensitivity.as_str())
                    .map_err(|_| Self::invalid("graph metadata sensitivity"))?;
                count += u64::from(sensitivity == crate::ContextSensitivityV1::HostRestricted);
            }
            Ok(count)
        };
        let removed = count(before)?;
        let added = count(after)?;
        let count = if reset { 0 } else { prior }
            .checked_sub(removed)
            .and_then(|count| count.checked_add(added))
            .ok_or_else(|| Self::invalid("graph metadata sensitivity count"))?;
        Ok((changed, count, removed_members))
    }

    pub(in crate::analysis) fn stage_managed(
        store: &super::super::AnalysisStore,
        writer: &Connection,
        metadata: &GraphManifest,
        input: &GraphWrite<'_>,
        proofs: &[AnalysisContextRefV1],
        verified: &mut super::super::context::VerifiedPackages,
    ) -> Result<ProducerChanges> {
        let started = std::time::Instant::now();
        let GraphWrite::Managed {
            commit,
            producers,
            removed,
            record_proofs,
        } = input
        else {
            return Err(Self::invalid("graph managed producer stage"));
        };
        let (commit, producers, removed, record_proofs) =
            (*commit, *producers, *removed, *record_proofs);
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
                Self::read_summary(writer, metadata.scope.identity.tenant_id, id, None)?
                    .ok_or_else(|| Self::invalid("graph producer previous result"))
            })
            .transpose()?;
        if previous.as_ref().is_some_and(|previous| {
            metadata.scope != previous.snapshot.scope
                || metadata.witness_deadline_utc_ns > previous.snapshot.witness_deadline_utc_ns
        }) || metadata.input_positions.len() != metadata.input_manifest.evidence.len()
            || metadata
                .input_positions
                .iter()
                .map(|(record, _)| record)
                .ne(metadata.input_manifest.evidence.iter())
            || metadata
                .input_positions
                .iter()
                .map(|(_, position)| position)
                .collect::<BTreeSet<_>>()
                .len()
                != metadata.input_positions.len()
            || proofs
                .iter()
                .any(|proof| proof.commit_revision > commit.attempt.captured_revision())
        {
            return Err(Self::invalid("graph delta metadata basis"));
        }
        if removed.windows(2).any(|pair| pair[0] >= pair[1])
            || removed.iter().any(|record| {
                record.stream != metadata.scope.identity
                    || metadata
                        .input_manifest
                        .evidence
                        .binary_search(record)
                        .is_ok()
            })
        {
            return Err(Self::invalid("graph metadata removals"));
        }
        let revision = producers
            .first()
            .ok_or_else(|| Self::invalid("graph producer is absent"))?
            .1
            .commit_revision;
        let captured = commit.attempt.captured_revision();
        if captured == 0 || captured >= revision {
            return Err(Self::invalid("graph producer captured cut"));
        }
        let prior_meta = metadata.previous_result_id.as_deref().map(|id| {
            writer.query_row(
                "SELECT v.result_id,v.restricted_count,g.commit_revision FROM graph_versions g
                 JOIN graph_producer_versions v ON v.result_id=g.metadata_result_id WHERE g.result_id=?",
                params![id],|row|Ok((row.get::<_,String>(0)?,row.get::<_,Option<u64>>(1)?,row.get::<_,u64>(2)?)),
            ).context(AnalysisDatabaseSnafu { operation:"read Graph metadata frontier" })
        }).transpose()?;
        if prior_meta
            .as_ref()
            .is_some_and(|(_, _, revision)| *revision > captured)
        {
            return Err(Self::invalid("graph metadata future base"));
        }
        let (metadata_scope, metadata_base) = Self::publication_scope(
            writer,
            metadata,
            source,
            2,
            prior_meta.as_ref().map(|(id, _, _)| id.as_str()),
            revision,
        )?;
        let latest:Option<String>=writer.query_row(
            "SELECT result_id FROM graph_producer_versions WHERE scope_id=? ORDER BY commit_revision DESC LIMIT 1",
            params![metadata_scope],|row|row.get(0),
        ).optional().context(AnalysisDatabaseSnafu {operation:"check Graph metadata base"})?;
        if latest != metadata_base {
            return Err(Self::invalid("graph metadata stale base"));
        }
        let metadata_reset = prior_meta
            .as_ref()
            .is_none_or(|(_, count, _)| count.is_none())
            || commit.attempt.request().rebuild
            || commit.attempt.switches_version();
        let canonical = Self::canonical_contexts(writer, &store.root, metadata)?;
        let (mut metadata_members, staged, mut records, positions) =
            Self::metadata_members(writer, metadata, Some((removed, &canonical)))?;
        let mut work = (staged, 0u64, 0u64);
        let mut root_cursors = BTreeMap::new();
        let by_record = metadata_members
            .iter()
            .enumerate()
            .filter_map(|(index, replacement)| {
                replacement
                    .members
                    .iter()
                    .find(|member| member.kind == 0)
                    .map(|member| (member.key.clone(), index))
            })
            .collect::<BTreeMap<_, _>>();
        let mut seen = BTreeMap::new();
        for (record, proof) in record_proofs {
            let index = *by_record
                .get(&Self::member_key(record)?)
                .ok_or_else(|| Self::invalid("graph record proof owner"))?;
            if proof.key.tenant_id != metadata.scope.identity.tenant_id
                || !proof.key.valid()
                || proof.commit_revision == 0
                || proof.commit_revision > commit.attempt.captured_revision()
                || seen
                    .insert((record, &proof.key), proof.commit_revision)
                    .is_some_and(|revision| revision != proof.commit_revision)
            {
                return Err(Self::invalid("graph record proof ref"));
            }
            let replacement = &mut metadata_members[index];
            let key = super::super::context::version_key(&proof.key)?;
            if !replacement
                .members
                .iter()
                .any(|member| member.kind == 10 && member.key == key)
            {
                replacement
                    .members
                    .push(crate::analysis::graph_rows::store::Member {
                        kind: 10,
                        key,
                        value: proof.commit_revision,
                        record: replacement.unit,
                        fact: None,
                        reason: None,
                        ordinal: 0,
                    });
            }
        }
        if !proofs.is_empty() {
            metadata_members.push(crate::analysis::graph_rows::store::Replacement {
                unit: None,
                members: proofs
                    .iter()
                    .map(|proof| {
                        Ok(crate::analysis::graph_rows::store::Member {
                            kind: 10,
                            key: super::super::context::version_key(&proof.key)?,
                            value: proof.commit_revision,
                            record: None,
                            fact: None,
                            reason: None,
                            ordinal: 0,
                        })
                    })
                    .collect::<Result<_>>()?,
            });
        }
        let (metadata_changed, restricted, metadata_removed) = Self::metadata_diff(
            writer,
            metadata_scope,
            &metadata_members,
            metadata_reset,
            prior_meta
                .as_ref()
                .and_then(|(_, count, _)| *count)
                .unwrap_or(0),
        )?;
        let mut cuts = Vec::new();
        let mut touched = BTreeSet::new();
        let mut states = BTreeMap::new();
        let mut unit_calls = Vec::new();
        let mut full_check = metadata_reset;
        let metadata_at = std::time::Instant::now();
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
            let unit_contract = araphor_analysis_builtins::graph::Detector::supports_units(model);
            if !unit_contract {
                return Err(Self::invalid("graph producer contract"));
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
                if reset != changes.base.is_none()
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
                        }),
                        reference.commit_revision,
                    )?
                };
                crate::analysis::graph_rows::store::Relations::producer_version(
                    writer,
                    &reference.result_id,
                    scope,
                    reference.commit_revision,
                    storage_prior.map(|prior| prior.result_id.as_str()),
                    Some(crate::analysis::graph_rows::store::VersionPin {
                        package: &spec.manifest.calls[call].package.package_id,
                        revision: &spec.manifest.calls[call].package.revision,
                        image: &spec.manifest.calls[call].image.digest,
                    }),
                )?;
                writer
                    .execute(
                        "UPDATE graph_producer_versions SET captured_revision=? WHERE result_id=?",
                        params![captured, reference.result_id],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "store Graph call captured cut",
                    })?;
                unit_calls.push((scope, returned, &spec.manifest.calls[call], *call));
                full_check |= reset || storage_prior.is_none();
                cuts.push((
                    reference.result_id.clone(),
                    scope,
                    reference.commit_revision,
                ));
                continue;
            }
        }
        let versions_at = std::time::Instant::now();
        let inputs = unit_calls
            .iter()
            .map(|(scope, returned, pin, _)| (*scope, *returned, *pin))
            .collect::<Vec<_>>();
        let mut effects = Self::apply_units(
            writer,
            revision,
            metadata,
            &inputs,
            restricted != 0,
            &mut records,
            &positions,
            &canonical,
        )?;
        for (scope, _, pin, call) in unit_calls {
            let effect = effects
                .remove(&scope)
                .ok_or_else(|| Self::invalid("graph producer work"))?;
            root_cursors.insert(call, effect.root_cursors);
            touched.extend(effect.touched);
            work.0 = work.0.saturating_add(effect.work.0);
            work.1 = work.1.saturating_add(effect.work.1);
            work.2 = work.2.saturating_add(effect.work.2);
            let package = metadata
                .packages
                .iter()
                .find(|package| package.package_id == pin.package.package_id)
                .ok_or_else(|| Self::invalid("graph unit package metadata"))?;
            if states
                .insert(
                    (package.package_id.clone(), package.package_version),
                    effect.state.clone(),
                )
                .is_some_and(|prior| prior != effect.state)
            {
                return Err(Self::invalid("graph unit package state conflict"));
            }
        }
        let applied = std::time::Instant::now();
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
        let completed = std::time::Instant::now();
        erebor_telemetry::debug!(
            stage = "graph_stage_timing", instance_id = %spec.id,
            cut_revision = captured, publication_revision = revision,
            metadata_s = metadata_at.duration_since(started).as_secs_f64(),
            versions_s = versions_at.duration_since(metadata_at).as_secs_f64(),
            units_s = applied.duration_since(versions_at).as_secs_f64(),
            completion_s = completed.duration_since(applied).as_secs_f64(),
            elapsed_s = completed.duration_since(started).as_secs_f64(),
            "Graph contribution stage completed"
        );
        Ok(ProducerChanges {
            diff: None,
            cuts,
            previous,
            metadata_scope,
            metadata_base,
            metadata_members,
            metadata_reset,
            metadata_changed,
            metadata_removed,
            restricted,
            captured,
            full_check,
            touched,
            states,
            work,
            root_cursors,
        })
    }

    pub(in crate::analysis) fn unchanged(
        writer: &Connection,
        prior: &PackageResultRefV1,
        metadata: &GraphManifest,
        changes: &mut ProducerChanges,
    ) -> Result<bool> {
        crate::analysis::graph_rows::store::Relations::new(writer)
            .unchanged(&prior.result_id, metadata, changes)
            .map_err(Into::into)
    }

    pub(in crate::analysis) fn publish(
        writer: &Connection,
        result: &PackageResultRefV1,
        metadata: &GraphManifest,
        changes: ProducerChanges,
    ) -> Result<(Vec<u8>, (u64, u64, u64), (u64, u64), usize)> {
        crate::analysis::graph_rows::store::Relations::new(writer)
            .apply(&result.result_id, result.commit_revision, metadata, changes)
            .map_err(Into::into)
    }
}
