use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::super::AnalysisStore;
use crate::{AnalysisDatabaseSnafu, Result};

impl AnalysisStore {
    pub(in crate::analysis) const MANAGED_SCHEMA: &'static str = "
        CREATE SEQUENCE managed_graphs_seq;
        CREATE SEQUENCE managed_graph_writers_seq;
        CREATE SEQUENCE managed_graph_relations_seq;
        CREATE SEQUENCE managed_graph_layers_seq;
        CREATE TABLE managed_graphs (
            graph_id UBIGINT PRIMARY KEY, tenant_id BLOB NOT NULL, instance_id VARCHAR NOT NULL,
            UNIQUE(tenant_id,instance_id)
        );
        CREATE TABLE managed_graph_writers (
            writer_id UBIGINT PRIMARY KEY, graph_id UBIGINT NOT NULL, call_id UBIGINT NOT NULL,
            UNIQUE(graph_id,call_id)
        );
        CREATE TABLE managed_graph_relations (
            relation_id UBIGINT PRIMARY KEY, graph_id UBIGINT NOT NULL,
            relation_name VARCHAR NOT NULL, contract BLOB NOT NULL,
            UNIQUE(graph_id,relation_name)
        );
        CREATE TABLE managed_graph_results (
            writer_id UBIGINT NOT NULL, layer_id UBIGINT NOT NULL UNIQUE,
            revision UBIGINT NOT NULL, result_id VARCHAR NOT NULL UNIQUE,
            restricted BOOLEAN NOT NULL,
            PRIMARY KEY(writer_id,revision)
        );
        CREATE TABLE managed_graph_reads (
            result_id VARCHAR NOT NULL, writer_id UBIGINT NOT NULL,
            revision UBIGINT NOT NULL, producer_id VARCHAR NOT NULL,
            PRIMARY KEY(result_id,writer_id,revision)
        );
        CREATE TABLE managed_graph_row_reads (
            result_id VARCHAR NOT NULL, relation_id UBIGINT NOT NULL, writer_id UBIGINT NOT NULL,
            owner_key BLOB NOT NULL, entity_key BLOB NOT NULL, revision UBIGINT NOT NULL,
            PRIMARY KEY(result_id,relation_id,writer_id,owner_key,entity_key,revision)
        );
        CREATE TABLE managed_graph_publications (
            result_id VARCHAR PRIMARY KEY, graph_id UBIGINT NOT NULL,
            revision UBIGINT NOT NULL, previous_result_id VARCHAR,
            UNIQUE(graph_id,revision)
        );
        CREATE TABLE managed_graph_publication_layers (
            result_id VARCHAR NOT NULL, writer_id UBIGINT NOT NULL, layer_id UBIGINT NOT NULL,
            PRIMARY KEY(result_id,writer_id)
        );
        CREATE TABLE managed_graph_finding_values (
            relation_id UBIGINT NOT NULL, properties_ref UBIGINT NOT NULL,
            canonical_relation_id UBIGINT NOT NULL, canonical_properties_ref UBIGINT NOT NULL,
            PRIMARY KEY(relation_id,properties_ref)
        );
        CREATE TABLE managed_source_reads (
            result_id VARCHAR NOT NULL, producer_id VARCHAR NOT NULL, revision UBIGINT NOT NULL,
            PRIMARY KEY(result_id,producer_id)
        );
        CREATE TABLE managed_source_proofs (
            result_id VARCHAR NOT NULL, record_key BLOB NOT NULL,
            version_key BLOB NOT NULL, revision UBIGINT NOT NULL,
            stream_key BLOB NOT NULL, cpu_id UINTEGER NOT NULL, source_cursor UBIGINT NOT NULL,
            PRIMARY KEY(result_id,record_key,version_key)
        );
        CREATE TABLE managed_context_imports (
            result_id VARCHAR NOT NULL, version_key BLOB NOT NULL, revision UBIGINT NOT NULL,
            PRIMARY KEY(result_id,version_key)
        );
        CREATE TABLE managed_source_publications (
            result_id VARCHAR PRIMARY KEY, tenant_id BLOB NOT NULL, instance_id VARCHAR NOT NULL,
            stream_key BLOB NOT NULL, revision UBIGINT NOT NULL,
            attempt_id VARCHAR NOT NULL, generation UBIGINT NOT NULL,
            previous_result_id VARCHAR, captured_revision UBIGINT NOT NULL, captured_ordinal UINTEGER NOT NULL,
            first_cursor UBIGINT NOT NULL, last_cursor UBIGINT NOT NULL,
            witness_deadline UBIGINT NOT NULL, coverage_revision UBIGINT NOT NULL,
            context_notice UBIGINT NOT NULL, record_count UBIGINT NOT NULL, restricted_count UBIGINT NOT NULL,
            subject_count UBIGINT NOT NULL, relationship_count UBIGINT NOT NULL, finding_count UBIGINT NOT NULL,
            expired BOOLEAN NOT NULL,
            UNIQUE(tenant_id,instance_id,stream_key,revision)
        );
        CREATE TABLE managed_source_coverage (
            result_id VARCHAR NOT NULL, ordinal UBIGINT NOT NULL, cpu_id UINTEGER NOT NULL, report_revision UBIGINT NOT NULL,
            interval_id BLOB NOT NULL, interval_revision UBIGINT NOT NULL, state UTINYINT NOT NULL,
            PRIMARY KEY(result_id,ordinal)
        );
        CREATE TABLE managed_source_reasons (
            result_id VARCHAR NOT NULL, ordinal UBIGINT NOT NULL, reason VARCHAR NOT NULL,
            PRIMARY KEY(result_id,ordinal,reason)
        );
        CREATE TABLE managed_source_members (
            tenant_id BLOB NOT NULL, instance_id VARCHAR NOT NULL, stream_key BLOB NOT NULL,
            record_key BLOB NOT NULL, cpu_id UINTEGER NOT NULL, source_cursor UBIGINT NOT NULL,
            position_revision UBIGINT NOT NULL, position_ordinal UINTEGER NOT NULL,
            origin_result_id VARCHAR NOT NULL, restricted UBIGINT NOT NULL,
            valid_from UBIGINT NOT NULL, valid_to UBIGINT,
            PRIMARY KEY(tenant_id,instance_id,stream_key,record_key,valid_from)
        );
        CREATE TABLE managed_source_gaps (
            result_id VARCHAR NOT NULL, first_cursor UBIGINT NOT NULL, last_cursor UBIGINT NOT NULL,
            PRIMARY KEY(result_id,first_cursor,last_cursor)
        );
        CREATE TABLE managed_versions (
            tenant_id BLOB NOT NULL, instance_id VARCHAR NOT NULL,
            generation UBIGINT NOT NULL, spec BLOB NOT NULL, scope BLOB NOT NULL,
            PRIMARY KEY (tenant_id, instance_id, generation)
        );
        CREATE TABLE managed_instances (
            tenant_id BLOB NOT NULL, instance_id VARCHAR NOT NULL,
            authority BLOB NOT NULL,
            generation UBIGINT NOT NULL, progress UBIGINT NOT NULL,
            running BOOLEAN NOT NULL, removed BOOLEAN NOT NULL, lifecycle UBIGINT NOT NULL, failure BLOB,
            PRIMARY KEY (tenant_id, instance_id)
        );
        CREATE TABLE managed_calls (
            tenant_id BLOB NOT NULL, instance_id VARCHAR NOT NULL, call_id UBIGINT NOT NULL,
            state_revision UBIGINT NOT NULL, result_id VARCHAR,
            PRIMARY KEY (tenant_id, instance_id, call_id)
        );
        CREATE TABLE managed_attempts (
            tenant_id BLOB NOT NULL, instance_id VARCHAR NOT NULL, attempt_id VARCHAR NOT NULL,
            generation UBIGINT NOT NULL, contract BLOB NOT NULL, completed UBIGINT NOT NULL,
            PRIMARY KEY (tenant_id, instance_id, attempt_id)
        );
        CREATE INDEX managed_completion ON managed_attempts (tenant_id, instance_id, generation, completed);
        CREATE TABLE managed_edges (
            tenant_id BLOB NOT NULL, result_id VARCHAR NOT NULL, dependency_id VARCHAR NOT NULL,
            commit_revision UBIGINT NOT NULL,
            PRIMARY KEY (result_id, dependency_id)
        );";

    pub(in crate::analysis) fn validate_managed(reader: &Connection, root: &Path) -> Result<()> {
        Self::validate_graph_calls(reader)?;
        let orphan: bool = reader.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_source_proofs pin
             LEFT JOIN analysis_results result USING(result_id)
             WHERE result.result_id IS NULL OR result.processor_id NOT IN ('managed-package-v1','managed-definition-v1'))",
            [], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "check source record proof owners" })?;
        if orphan {
            return Self::reject_path(root, "the source record proof owner is absent");
        }
        let meta = Self::read_meta_from(reader, &root.join("analysis.duckdb"))?;
        let mut progress = std::collections::BTreeMap::new();
        let mut heads = std::collections::BTreeMap::new();
        let mut failures = std::collections::BTreeMap::new();
        let mut graph_admissions = std::collections::BTreeMap::new();
        let head: u64 = reader
            .query_row("SELECT commit_revision FROM store_meta", [], |row| {
                row.get(0)
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read managed recovery revision",
            })?;
        let mut versions = reader
            .prepare("SELECT tenant_id, instance_id, generation FROM managed_versions")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare managed version recovery",
            })?;
        let versions = versions
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read managed version recovery",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode managed version recovery",
            })?;
        for (tenant, id, generation) in versions {
            let tenant = tenant
                .try_into()
                .map_err(|_| crate::PackageErrorCodeV1::Invalid.error("managed version tenant"))?;
            if generation == 0 || generation > head {
                return Self::reject_path(root, "the managed version revision is invalid");
            }
            let spec = Self::managed_version_from(reader, tenant, &id, generation)?;
            Self::check_managed_images(reader, &spec)?;
            Self::managed_scope_from(reader, tenant, &id, generation)?;
            for call in spec.manifest.calls.values() {
                let package = Self::managed_contract(reader, tenant, call)?;
                let model = package
                    .exports
                    .iter()
                    .find(|model| model.name == call.export)
                    .ok_or_else(|| {
                        crate::PackageErrorCodeV1::Missing.error("managed version export")
                    })?;
                if model.graph.is_some() {
                    graph_admissions
                        .entry((tenant, id.clone()))
                        .and_modify(|cut: &mut u64| *cut = (*cut).min(generation))
                        .or_insert(generation);
                    break;
                }
            }
        }
        let mut statement = reader
            .prepare("SELECT tenant_id, instance_id FROM managed_instances")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare managed recovery",
            })?;
        let keys = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read managed recovery",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode managed recovery",
            })?;
        for (tenant, id) in keys {
            let tenant: [u8; 16] = tenant
                .try_into()
                .map_err(|_| crate::PackageErrorCodeV1::Invalid.error("managed recovery tenant"))?;
            let instance = Self::managed_instance_from(reader, tenant, &id)?.ok_or_else(|| {
                crate::PackageErrorCodeV1::Missing.error("managed recovery instance")
            })?;
            instance.validate()?;
            if Self::managed_scope_from(reader, tenant, &id, instance.generation)?
                != instance.grant.selection
            {
                return Self::reject_path(root, "the managed authority scope differs");
            }
            if instance.generation == 0
                || instance.generation > head
                || instance.progress > head
                || instance.lifecycle < instance.generation
                || instance.lifecycle > head
                || (instance.lifecycle == instance.generation && instance.running)
            {
                return Self::reject_path(root, "the managed generation is invalid");
            }
            Self::check_managed_images(reader, &instance.spec)?;
            failures.insert(
                (tenant, id.clone()),
                Self::validate_managed_failure(reader, &instance)?,
            );
            progress.insert((tenant, id.clone()), (instance.progress, 0_u64));
            let mut calls = reader.prepare("SELECT call_id, state_revision, result_id FROM managed_calls WHERE tenant_id = ? AND instance_id = ? ORDER BY call_id")
                .context(AnalysisDatabaseSnafu { operation: "prepare recovered managed calls" })?;
            let rows = calls
                .query_map(params![tenant.as_slice(), id], |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read recovered managed calls",
                })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode recovered managed calls",
                })?;
            if rows
                .iter()
                .map(|row| row.0)
                .collect::<std::collections::BTreeSet<_>>()
                != instance.spec.manifest.calls.keys().copied().collect()
            {
                return Self::reject_path(root, "the managed call manifest differs");
            }
            for (call, revision, result) in rows {
                let saved = result.as_ref().map(|id| super::super::PackageResultRefV1 {
                    result_id: id.clone(),
                    commit_revision: revision,
                });
                heads.insert(
                    (tenant, id.clone(), call),
                    (saved, None::<super::super::PackageResultRefV1>),
                );
                if let Some(id) = result {
                    let (record, saved) = Self::managed_meta_from(reader, tenant, &id)?;
                    let (_, owner) = Self::managed_call_owner(reader, tenant, &id, saved, &record)?;
                    if revision != saved
                        || record.instance != instance.spec.id
                        || record.call != call
                        || instance.spec.manifest.calls.get(&call)
                            != owner.manifest.calls.get(&call)
                    {
                        return Self::reject_path(root, "the managed call state differs");
                    }
                } else if revision != 0 {
                    return Self::reject_path(root, "the managed empty state has a revision");
                }
            }
        }
        let invalid: bool = reader.query_row("SELECT EXISTS (
            SELECT 1 FROM managed_calls c LEFT JOIN managed_instances i USING (tenant_id, instance_id)
                WHERE i.instance_id IS NULL
            UNION ALL SELECT 1 FROM managed_attempts a LEFT JOIN managed_instances i USING (tenant_id, instance_id)
                WHERE i.instance_id IS NULL
            UNION ALL SELECT 1 FROM managed_source_reads e LEFT JOIN analysis_results r ON e.result_id=r.result_id
                LEFT JOIN analysis_results d ON e.producer_id=d.result_id
                WHERE r.result_id IS NULL OR d.result_id IS NULL OR r.tenant_id<>d.tenant_id OR e.revision<>d.commit_revision OR e.revision>=r.commit_revision
            UNION ALL SELECT 1 FROM managed_context_imports i LEFT JOIN analysis_results r USING(result_id)
                LEFT JOIN context_versions c USING(version_key)
                LEFT JOIN graph_fact_records f USING(version_key)
                WHERE r.result_id IS NULL OR c.version_key IS NULL OR f.version_key IS NULL OR c.tenant_id<>r.tenant_id OR c.commit_revision<>i.revision OR i.revision>r.commit_revision
            UNION ALL SELECT 1 FROM managed_edges e LEFT JOIN analysis_results r ON e.result_id = r.result_id AND e.tenant_id = r.tenant_id
                LEFT JOIN analysis_results d ON e.dependency_id = d.result_id AND e.tenant_id = d.tenant_id
                WHERE r.result_id IS NULL OR d.result_id IS NULL OR e.commit_revision <> d.commit_revision
        )", [], |row| row.get(0)).context(AnalysisDatabaseSnafu { operation: "validate managed references" })?;
        if invalid {
            return Self::reject_path(root, "the managed references are invalid");
        }
        let mut statement = reader
            .prepare("SELECT tenant_id, instance_id, attempt_id, completed FROM managed_attempts")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare recovered attempts",
            })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read recovered attempts",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode recovered attempts",
            })?;
        for (tenant, instance, id, completed) in rows {
            let tenant = tenant
                .try_into()
                .map_err(|_| crate::PackageErrorCodeV1::Invalid.error("managed attempt tenant"))?;
            let attempt =
                Self::managed_attempt_from(reader, tenant, &instance, &id)?.ok_or_else(|| {
                    crate::PackageErrorCodeV1::Missing.error("managed recovery attempt")
                })?;
            let owner = Self::managed_instance_from(reader, tenant, &instance)?
                .ok_or_else(|| crate::PackageErrorCodeV1::Missing.error("managed attempt owner"))?;
            if attempt.receipt.is_some() && attempt.terminal.is_some()
                || completed
                    != attempt
                        .receipt
                        .as_ref()
                        .map(|receipt| receipt.commit_revision)
                        .or_else(|| attempt.terminal.as_ref().map(|terminal| terminal.revision))
                        .unwrap_or(0)
                || attempt
                    .request
                    .frontier
                    .as_ref()
                    .is_some_and(|frontier| frontier.cursor.is_empty() || frontier.pending)
                || attempt
                    .receipt
                    .as_ref()
                    .is_some_and(|receipt| !receipt.matches_frontier(&attempt.request.frontier))
            {
                return Self::reject_path(root, "the managed frontier receipt differs");
            }
            let capture = &attempt.capture;
            let program =
                Self::managed_version_from(reader, tenant, &instance, capture.generation)?;
            let previous =
                Self::managed_version_from(reader, tenant, &instance, capture.expected_generation)?;
            capture.grant.validate()?;
            capture.check_follow_mode(&program)?;
            if capture.store != meta.store_uuid
                || capture.schema != meta.schema_version
                || capture.recovery == 0
                || capture.recovery > meta.recovery_epoch
                || capture.generation > capture.revision
                || capture.grant.selection
                    != Self::managed_scope_from(reader, tenant, &instance, capture.generation)?
                || (capture.lifecycle == owner.lifecycle && capture.grant != owner.grant)
                || capture.lifecycle < capture.expected_generation
                || capture.lifecycle > owner.lifecycle
                || capture.lifecycle > capture.revision
                || (capture.lifecycle == capture.expected_generation && capture.running)
                || (capture.lifecycle == owner.lifecycle && capture.running != owner.running)
                || capture.progress > capture.completed
                || capture.completed > capture.revision
                || capture.prior.keys().ne(program.manifest.calls.keys())
                || attempt.request.id.is_empty()
                || attempt.request.time_utc_ns == 0
                || i64::try_from(attempt.request.time_utc_ns).is_err()
                || attempt.request.rebuild != capture.rebuild
                || attempt.request.time_utc_ns != capture.time_utc_ns
                || capture
                    .sources
                    .windows(2)
                    .any(|pair| pair[0].0 >= pair[1].0)
                || capture
                    .sources
                    .iter()
                    .any(|(name, revision)| name.is_empty() || *revision > capture.revision)
                || capture
                    .dependencies
                    .windows(2)
                    .any(|pair| pair[0].result_id >= pair[1].result_id)
                || capture.dependencies.iter().any(|reference| {
                    reference.commit_revision == 0 || reference.commit_revision > capture.revision
                })
                || capture
                    .contexts
                    .windows(2)
                    .any(|pair| pair[0].key >= pair[1].key)
                || capture.contexts.iter().any(|reference| {
                    !reference.key.valid()
                        || reference.key.tenant_id != tenant
                        || reference.commit_revision == 0
                        || reference.commit_revision > capture.revision
                })
                || capture.witnesses.windows(2).any(|pair| {
                    (&pair[0].identity, pair[0].cursor) >= (&pair[1].identity, pair[1].cursor)
                })
                || capture.witnesses.iter().any(|witness| {
                    !witness.identity.valid()
                        || witness.identity.tenant() != tenant
                        || witness.cursor == 0
                        || witness.expires_utc_ns < attempt.request.time_utc_ns
                })
            {
                return Self::reject_path(root, "the managed captured contract is invalid");
            }
            Self::check_managed_progress(reader, capture)?;
            for (call, prior) in &capture.prior {
                if let Some(reference) = prior {
                    let (record, revision) =
                        Self::managed_meta_from(reader, tenant, &reference.result_id)?;
                    let (_, owner) = Self::managed_call_owner(
                        reader,
                        tenant,
                        &reference.result_id,
                        revision,
                        &record,
                    )?;
                    if record.call != *call
                        || !program.same_call(&previous, *call)
                        || record.instance != instance
                        || program.manifest.calls.get(call) != owner.manifest.calls.get(call)
                        || revision != reference.commit_revision
                        || revision > capture.progress
                    {
                        return Self::reject_path(root, "the captured prior reference differs");
                    }
                }
            }
            let prior_completed: u64 = reader.query_row(
                "SELECT COALESCE(MAX(completed), 0) FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND generation = ? AND completed <= ?",
                params![tenant.as_slice(), instance, capture.expected_generation, capture.revision], |row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation: "validate captured managed completion" })?;
            if capture.completed != prior_completed {
                return Self::reject_path(root, "the captured managed completion is invalid");
            }
            if attempt.registered == 0
                || attempt.registered > head
                || attempt.capture.revision >= attempt.registered
            {
                return Self::reject_path(root, "the managed attempt revision is invalid");
            }
            if let Some(terminal) = &attempt.terminal {
                if matches!(terminal.exit, super::ManagedExit::Failed(_))
                    && capture.generation == owner.generation
                    && capture.expected_generation == capture.generation
                    && capture.progress == owner.progress
                    && (capture.lifecycle == owner.lifecycle
                        || terminal.suspended && terminal.revision == owner.lifecycle)
                    && failures
                        .get(&(tenant, instance.clone()))
                        .and_then(Option::as_ref)
                        .is_none_or(|failure| failure.revision < terminal.revision)
                {
                    return Self::reject_path(root, "the managed failure status is absent");
                }
                if terminal.instance != instance
                    || terminal.attempt != id
                    || terminal.revision <= attempt.registered
                    || terminal.revision > head
                    || terminal.suspended
                        && (terminal.exit
                            != super::ManagedExit::Failed(crate::PackageErrorCodeV1::Denied)
                            || !capture.running
                            || owner.lifecycle < terminal.revision
                            || (owner.lifecycle == terminal.revision && owner.running))
                {
                    return Self::reject_path(root, "the managed terminal state is invalid");
                }
            }
            if let Some(receipt) = &attempt.receipt {
                if capture.generation == owner.generation {
                    if let Some((_, expected)) = progress.get_mut(&(tenant, instance.clone())) {
                        *expected = (*expected).max(receipt.commit_revision);
                    }
                }
                if receipt.commit_revision == owner.progress && !owner.removed {
                    if capture.generation != owner.generation {
                        return Self::reject_path(
                            root,
                            "the current managed program differs from its progress",
                        );
                    }
                    for call in owner.spec.manifest.calls.keys() {
                        let expected = heads
                            .get_mut(&(tenant, instance.clone(), *call))
                            .ok_or_else(|| {
                                crate::PackageErrorCodeV1::Missing.error("managed current head")
                            })?;
                        expected.1 = receipt
                            .results
                            .get(call)
                            .cloned()
                            .or_else(|| capture.prior.get(call).cloned().flatten());
                    }
                }
                if receipt.instance != instance
                    || receipt.attempt != id
                    || receipt.commit_revision <= attempt.registered
                    || receipt.commit_revision > head
                {
                    return Self::reject_path(root, "the managed receipt is invalid");
                }
                let (step, revision) =
                    Self::managed_step_header(reader, tenant, &receipt.selected.result_id)?;
                if receipt.selected.commit_revision != receipt.commit_revision
                    || revision != receipt.commit_revision
                    || step.instance != instance
                    || step.attempt != id
                {
                    return Self::reject_path(root, "the managed selected relation differs");
                }
                Self::validate_selected_header(
                    reader,
                    tenant,
                    &receipt.selected.result_id,
                    &step,
                    revision,
                )?;
                if graph_admissions
                    .get(&(tenant, instance.clone()))
                    .is_some_and(|cut| revision > *cut)
                {
                    let (published, required): (bool, bool) = reader
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM managed_graph_publications publication
                         JOIN managed_graphs graph USING(graph_id)
                         WHERE publication.result_id=? AND publication.revision=?
                             AND graph.tenant_id=? AND graph.instance_id=?),
                         EXISTS(SELECT 1 FROM managed_graph_results result
                             JOIN graph_writers writer USING(writer_id)
                             JOIN managed_graphs graph USING(graph_id)
                             WHERE graph.tenant_id=? AND graph.instance_id=? AND result.revision=?)
                         OR EXISTS(SELECT 1 FROM managed_source_publications source
                             WHERE source.result_id=? AND source.tenant_id=?
                                 AND source.instance_id=? AND source.revision=?)",
                            params![
                                receipt.selected.result_id,
                                revision,
                                tenant.as_slice(),
                                instance,
                                tenant.as_slice(),
                                instance,
                                revision,
                                receipt.selected.result_id,
                                tenant.as_slice(),
                                instance,
                                revision
                            ],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .context(AnalysisDatabaseSnafu {
                            operation: "check selected Graph publication",
                        })?;
                    if required && !published {
                        return Self::reject_path(
                            root,
                            "the selected Graph publication is missing",
                        );
                    }
                }
            }
        }
        if progress
            .values()
            .any(|(actual, expected)| actual != expected)
            || heads.values().any(|(actual, expected)| actual != expected)
        {
            return Self::reject_path(root, "the managed heads differ from completed attempts");
        }
        crate::analysis::graph_rows::GraphRows::validate_history(reader, root)?;
        let mut statement = reader.prepare("SELECT tenant_id, result_id, processor_id, commit_revision FROM analysis_results WHERE processor_id IN ('managed-package-v1', 'managed-definition-v1')")
            .context(AnalysisDatabaseSnafu { operation: "prepare complete managed recovery" })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read complete managed recovery",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode complete managed recovery",
            })?;
        for (tenant, id, processor, revision) in rows {
            let tenant = tenant
                .try_into()
                .map_err(|_| crate::PackageErrorCodeV1::Invalid.error("managed result tenant"))?;
            if processor == "managed-package-v1" {
                let (record, checkpoint, saved) = Self::managed_state_from(reader, tenant, &id)?;
                if saved != revision {
                    return Self::reject_path(root, "the managed result revision differs");
                }
                let (descriptor, _attempt, evaluated) =
                    Self::validate_managed_header(reader, tenant, &id, &record, saved)?;
                let declaration = &evaluated.manifest.calls[&record.call];
                let model = descriptor
                    .exports
                    .iter()
                    .find(|model| model.name == declaration.export)
                    .ok_or_else(|| {
                        crate::PackageErrorCodeV1::Missing.error("managed recovery model")
                    })?;
                let checkpoint = checkpoint
                    .as_ref()
                    .map(|state| {
                        state
                            .decode_model(model)
                            .context(crate::AnalysisContractSnafu)
                    })
                    .transpose()?;
                model
                    .validate_checkpoint(checkpoint.as_ref(), true)
                    .context(crate::AnalysisContractSnafu)?;
            } else {
                let (step, saved) = Self::managed_step_header(reader, tenant, &id)?;
                if saved != revision {
                    return Self::reject_path(root, "the managed selected revision differs");
                }
                Self::validate_selected_header(reader, tenant, &id, &step, revision)?;
            }
        }
        Ok(())
    }
}
