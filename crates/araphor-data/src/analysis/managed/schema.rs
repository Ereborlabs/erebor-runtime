use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::super::AnalysisStore;
use crate::{AnalysisDatabaseSnafu, Result};

impl AnalysisStore {
    pub(in crate::analysis) const MANAGED_SCHEMA: &'static str = "
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
        );
        CREATE TABLE managed_arrow (
            result_id VARCHAR NOT NULL, role VARCHAR NOT NULL, slot UBIGINT NOT NULL, ipc BLOB NOT NULL,
            PRIMARY KEY (result_id, role, slot)
        );";

    pub(in crate::analysis) fn validate_managed(reader: &Connection, root: &Path) -> Result<()> {
        let meta = Self::read_meta_from(reader, &root.join("analysis.duckdb"))?;
        let mut progress = std::collections::BTreeMap::new();
        let mut heads = std::collections::BTreeMap::new();
        let mut failures = std::collections::BTreeMap::new();
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
                    let (record, _, saved) = Self::managed_record_from(reader, tenant, &id)?;
                    if revision != saved
                        || record.instance != instance.spec.id
                        || record.call != call
                        || instance.spec.manifest.calls.get(&call) != Some(&record.declaration)
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
            UNION ALL SELECT 1 FROM managed_edges e LEFT JOIN analysis_results r ON e.result_id = r.result_id AND e.tenant_id = r.tenant_id
                LEFT JOIN analysis_results d ON e.dependency_id = d.result_id AND e.tenant_id = d.tenant_id
                WHERE r.result_id IS NULL OR d.result_id IS NULL OR e.commit_revision <> d.commit_revision
            UNION ALL SELECT 1 FROM managed_arrow a LEFT JOIN analysis_results r USING (result_id)
                WHERE r.result_id IS NULL OR r.processor_id NOT IN ('managed-package-v1', 'managed-definition-v1')
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
            for (call, prior) in &capture.prior {
                if let Some(reference) = prior {
                    let (record, _, revision) =
                        Self::managed_record_from(reader, tenant, &reference.result_id)?;
                    if record.call != *call
                        || !program.same_call(&previous, *call)
                        || record.instance != instance
                        || program.manifest.calls.get(call) != Some(&record.declaration)
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
                let (step, selected, revision) =
                    Self::managed_step_from(reader, tenant, &receipt.selected.result_id)?;
                if receipt.selected.commit_revision != receipt.commit_revision
                    || revision != receipt.commit_revision
                    || step.instance != instance
                    || step.attempt != id
                {
                    return Self::reject_path(root, "the managed selected relation differs");
                }
                let (_, schema) = Self::validate_selected_header(
                    reader,
                    tenant,
                    &receipt.selected.result_id,
                    &step,
                    revision,
                )?;
                Self::decode_selected_record(&selected, &schema, step.rows)?;
            }
        }
        if progress
            .values()
            .any(|(actual, expected)| actual != expected)
            || heads.values().any(|(actual, expected)| actual != expected)
        {
            return Self::reject_path(root, "the managed heads differ from completed attempts");
        }
        crate::analysis::graph_rows::GraphCallRows::validate(reader, root)?;
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
                let (record, output, saved) = Self::managed_record_from(reader, tenant, &id)?;
                Self::validate_managed_record(reader, tenant, &id, &record, &output, saved)?;
                let mut owner = Self::managed_instance_from(reader, tenant, &record.instance)?
                    .ok_or_else(|| {
                        crate::PackageErrorCodeV1::Missing.error("managed evaluation owner")
                    })?;
                let attempt =
                    Self::managed_attempt_from(reader, tenant, &record.instance, &record.attempt)?
                        .ok_or_else(|| {
                            crate::PackageErrorCodeV1::Missing.error("managed evaluation attempt")
                        })?;
                let evaluated = Self::managed_version_from(
                    reader,
                    tenant,
                    &record.instance,
                    attempt.capture.generation,
                )?;
                owner.spec = evaluated.clone();
                owner.generation = attempt.capture.generation;
                owner.grant = attempt.capture.grant.clone();
                let control = crate::AnalysisReadControl::default();
                let evaluation =
                    Self::saved_evaluation_from(reader, &owner, &id, &control)?.decode(&control)?;
                let descriptor = Self::managed_contract(reader, tenant, &record.declaration)?;
                let native = matches!(&evaluated.destination,
                    super::ManagedDestination::Graph { calls, .. } if calls.contains(&record.call))
                    && descriptor
                        .exports
                        .iter()
                        .find(|model| model.name == record.declaration.export)
                        .is_some_and(araphor_analysis_builtins::graph::Detector::supports);
                let base: Option<Option<String>> = reader
                    .query_row(
                        "SELECT base_result_id FROM graph_call_versions WHERE result_id = ?",
                        params![id],
                        |row| row.get(0),
                    )
                    .optional()
                    .context(AnalysisDatabaseSnafu {
                        operation: "validate Graph call result binding",
                    })?;
                if native {
                    let base = base.ok_or_else(|| {
                        crate::PackageErrorCodeV1::Missing.error("Graph call native version")
                    })?;
                    let expected = attempt
                        .capture
                        .prior
                        .get(&record.call)
                        .and_then(Option::as_ref)
                        .map(|reference| reference.result_id.as_str());
                    if base.as_deref() != expected {
                        return Self::reject_path(root, "the Graph call base result differs");
                    }
                    crate::analysis::graph_rows::GraphCallRows::load(
                        reader,
                        &evaluated,
                        record.call,
                        &id,
                        revision,
                        &evaluation,
                        &control,
                    )?;
                } else if base.is_some() {
                    return Self::reject_path(root, "a generic call has a native Graph version");
                }
            } else {
                let (step, packet, _) = Self::managed_step_from(reader, tenant, &id)?;
                let (_, schema) =
                    Self::validate_selected_header(reader, tenant, &id, &step, revision)?;
                Self::decode_selected_record(&packet, &schema, step.rows)?;
            }
        }
        Ok(())
    }
}
