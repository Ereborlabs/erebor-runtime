use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_graph::ReadOrigin;
use duckdb::{Connection, OptionalExt as _, params};
use snafu::ResultExt as _;

use super::{ManagedBudget, ManagedGraphCall};
use crate::analysis::PackageResultRefV1;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisStore, PackageErrorCodeV1 as Code,
    PackageGrantV1, Result,
};

pub(super) struct GraphAuthority {
    attempt: Arc<super::ManagedAttempt>,
    call: u64,
    authority: Vec<u8>,
    heads: BTreeSet<u64>,
    origins: BTreeMap<ReadOrigin, OriginAuthority>,
    pub(super) view: araphor_graph::GraphReadView,
    leases: Vec<Arc<dyn Any + Send + Sync>>,
    _memory: Box<dyn Any + Send + Sync>,
}

struct OriginAuthority {
    reference: PackageResultRefV1,
    grant: PackageGrantV1,
}

impl GraphAuthority {
    pub(super) fn bind(
        call: &ManagedGraphCall,
        store: &AnalysisStore,
        reader: &Connection,
        control: &AnalysisReadControl,
        budget: &dyn ManagedBudget,
    ) -> Result<Self> {
        control.check()?;
        store.check_managed_claim(&call.attempt)?;
        call.attempt.1.grant.remaining()?;
        let capture = &call.attempt.0.capture;
        let (bytes, authority_bytes): (u64,u64) = reader.query_row(
            "SELECT octet_length(a.contract)+octet_length(candidate.spec)
                +octet_length(current.spec)+octet_length(i.authority),octet_length(i.authority)
             FROM managed_attempts a JOIN managed_versions candidate USING(tenant_id,instance_id,generation)
             JOIN managed_instances i USING(tenant_id,instance_id)
             JOIN managed_versions current ON current.tenant_id=i.tenant_id
                AND current.instance_id=i.instance_id AND current.generation=i.generation
             WHERE a.tenant_id=? AND a.instance_id=? AND a.attempt_id=?",
            params![capture.tenant.as_slice(),capture.instance,call.attempt.request().id],
            |row| Ok((row.get(0)?,row.get(1)?)),
        ).context(AnalysisDatabaseSnafu { operation: "bound Graph authority validation" })?;
        let bytes = usize::try_from(bytes)
            .ok()
            .and_then(|bytes| bytes.checked_mul(12))
            .ok_or_else(|| Code::Limit.error("Graph authority validation memory"))?;
        let _scratch = budget.reserve(bytes)?;
        let authority_bytes = usize::try_from(authority_bytes)
            .map_err(|_| Code::Limit.error("Graph authority memory"))?;
        let memory = budget.reserve(
            size_of::<Self>()
                .saturating_add(authority_bytes)
                .saturating_add(
                    capture
                        .prior
                        .len()
                        .saturating_mul(size_of::<u64>() + 6 * size_of::<usize>()),
                ),
        )?;
        let saved = AnalysisStore::managed_attempt_from(
            reader,
            capture.tenant,
            &capture.instance,
            &call.attempt.request().id,
        )?
        .ok_or_else(|| Code::Missing.error("Graph registered attempt"))?;
        if saved.request != call.attempt.0.request
            || saved.capture != *capture
            || saved.receipt.is_some()
            || saved.terminal.is_some()
        {
            return Err(Code::Conflict.error("Graph current attempt"));
        }
        let current =
            AnalysisStore::managed_instance_from(reader, capture.tenant, &capture.instance)?
                .ok_or_else(|| Code::Missing.error("managed capture instance"))?;
        let heads = capture
            .prior
            .keys()
            .filter(|id| call.attempt.1.spec.same_call(&current.spec, **id))
            .copied()
            .collect();
        let authority: Vec<u8> = reader
            .query_row(
                "SELECT authority FROM managed_instances WHERE tenant_id=? AND instance_id=?",
                params![capture.tenant.as_slice(), capture.instance],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "retain Graph authority identity",
            })?;
        if authority.capacity() > authority_bytes {
            return Err(Code::Limit.error("Graph authority memory"));
        }
        let _scratch = budget.reserve(call.relations.len().saturating_mul(size_of::<u64>()))?;
        let relations = call.relations.values().copied().collect::<Vec<_>>();
        let mut leases = Vec::new();
        let view = store.graph_engine.read_view(
            reader,
            call.graph,
            call.attempt.captured_revision(),
            &relations,
            || control.check().map_err(araphor_graph::Error::backend),
            |bytes| {
                let lease = budget
                    .reserve(bytes)
                    .map_err(araphor_graph::Error::backend)?;
                leases.push(Arc::from(lease));
                Ok(())
            },
        )?;
        Ok(Self {
            attempt: Arc::clone(&call.attempt),
            call: call.call,
            authority,
            heads,
            origins: BTreeMap::new(),
            leases,
            view,
            _memory: memory,
        })
    }

    pub(super) fn check(
        &self,
        call: &ManagedGraphCall,
        store: &AnalysisStore,
        reader: &Connection,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let started = std::time::Instant::now();
        self.check_call(call)?;
        control.check()?;
        store.check_managed_claim(&call.attempt)?;
        call.attempt.1.grant.remaining()?;
        let capture = &call.attempt.0.capture;
        let pending: Option<(u64, u64)> = reader
            .query_row(
                "SELECT generation,completed FROM managed_attempts
             WHERE tenant_id=? AND instance_id=? AND attempt_id=?",
                params![
                    capture.tenant.as_slice(),
                    capture.instance,
                    call.attempt.request().id
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "check Graph pending attempt",
            })?;
        if pending != Some((capture.generation, 0)) {
            return Err(Code::Conflict.error("Graph current attempt"));
        }
        let (authority,generation,progress,running,removed,lifecycle): (bool,u64,u64,bool,bool,u64) = reader.query_row(
            "SELECT authority=?,generation,progress,running,removed,lifecycle FROM managed_instances
             WHERE tenant_id=? AND instance_id=?",
            params![self.authority,capture.tenant.as_slice(),capture.instance],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        ).context(AnalysisDatabaseSnafu { operation: "check Graph live instance" })?;
        let meta = AnalysisStore::read_meta_from(reader, &store.root.join("analysis.duckdb"))?;
        if meta.store_uuid != capture.store
            || meta.schema_version != capture.schema
            || meta.recovery_epoch != capture.recovery
            || meta.commit_revision < capture.revision
            || generation != capture.expected_generation
            || !authority
            || lifecycle != capture.lifecycle
            || running != capture.running
            || removed
            || progress != capture.progress
            || AnalysisStore::managed_completed_from(
                reader,
                capture.tenant,
                &capture.instance,
                capture.expected_generation,
            )? != capture.completed
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        let live_at = std::time::Instant::now();
        for id in &self.heads {
            let (revision, result): (u64, Option<String>) = reader
                .query_row(
                    "SELECT state_revision,result_id FROM managed_calls
                 WHERE tenant_id=? AND instance_id=? AND call_id=?",
                    params![capture.tenant.as_slice(), capture.instance, id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "check Graph captured call head",
                })?;
            if capture.prior[id]
                .as_ref()
                .map(|prior| (prior.commit_revision, Some(prior.result_id.as_str())))
                .unwrap_or((0, None))
                != (revision, result.as_deref())
            {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        let heads_at = std::time::Instant::now();
        if !capture.follows_graph(&call.attempt.1.spec)
            && !AnalysisStore::package_sources_current(reader, &capture.sources, control)?
        {
            return if AnalysisStore::check_trace_reads_from(
                reader,
                capture.tenant,
                &capture.traces,
                control,
            )
            .is_ok()
            {
                crate::AnalysisSourceChangedSnafu.fail()
            } else {
                crate::AnalysisConflictSnafu.fail()
            };
        }
        AnalysisStore::check_trace_reads_from(reader, capture.tenant, &capture.traces, control)?;
        let sources_at = std::time::Instant::now();
        let mut packages = Default::default();
        for reference in &capture.contexts {
            if store
                .read_context_verified_from(reader, &store.root, &reference.key, &mut packages)?
                .is_none_or(|(_, revision)| revision != reference.commit_revision)
            {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        let contexts_at = std::time::Instant::now();
        for reference in &capture.dependencies {
            if !store.managed_current(
                reader,
                &call.attempt.1.spec,
                &reference.result_id,
                reference.commit_revision,
                call.attempt.request().time_utc_ns,
                control,
            )? {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        let dependencies_at = std::time::Instant::now();
        if capture.witnesses.iter().any(|witness| {
            witness.identity.tenant() != capture.tenant
                || witness.cursor == 0
                || witness.expires_utc_ns <= call.attempt.request().time_utc_ns
        }) {
            return Err(Code::Incomplete.error("managed witness lifetime"));
        }
        control.check()?;
        erebor_telemetry::debug!(
            stage = "graph_authority_timing",
            instance_id = %capture.instance,
            cut_revision = capture.revision,
            call_id = call.call,
            heads = self.heads.len(),
            contexts = capture.contexts.len(),
            dependencies = capture.dependencies.len(),
            live_s = live_at.duration_since(started).as_secs_f64(),
            heads_s = heads_at.duration_since(live_at).as_secs_f64(),
            sources_s = sources_at.duration_since(heads_at).as_secs_f64(),
            contexts_s = contexts_at.duration_since(sources_at).as_secs_f64(),
            dependencies_s = dependencies_at.duration_since(contexts_at).as_secs_f64(),
            tail_s = dependencies_at.elapsed().as_secs_f64(),
            elapsed_s = started.elapsed().as_secs_f64(),
            "Graph invocation authority validation completed"
        );
        Ok(())
    }

    pub(super) fn check_snapshot(
        &self,
        call: &ManagedGraphCall,
        store: &AnalysisStore,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        self.check_call(call)?;
        control.check()?;
        store.check_managed_claim(&call.attempt)?;
        call.attempt.1.grant.remaining()?;
        Ok(())
    }

    pub(super) fn origin(
        &mut self,
        call: &ManagedGraphCall,
        store: &AnalysisStore,
        origin: ReadOrigin,
        control: &AnalysisReadControl,
        reserve: &mut dyn FnMut(usize) -> Result<Arc<dyn Any + Send + Sync>>,
    ) -> Result<PackageResultRefV1> {
        self.check_snapshot(call, store, control)?;
        if origin.revision > call.attempt.captured_revision() {
            return Err(Code::Denied.error("Graph origin cut"));
        }
        if let Some(saved) = self.origins.get(&origin) {
            saved.grant.permitted_by(&call.attempt.1.grant.selection)?;
            return Ok(saved.reference.clone());
        }
        let saved = store
            .managed_results
            .graph_origin(call.attempt.1.spec.tenant, origin.writer, origin.revision)?
            .ok_or_else(|| Code::Missing.error("Graph result origin"))?;
        if saved.graph != call.graph {
            return Err(Code::Denied.error("Graph result authority"));
        }
        let reference = PackageResultRefV1 {
            result_id: saved.result.clone(),
            commit_revision: origin.revision,
        };
        let producer = store.managed_results.producer(
            call.attempt.1.spec.tenant,
            &reference.result_id,
            reference.commit_revision,
        )?;
        producer
            .grant()
            .permitted_by(&call.attempt.1.grant.selection)?;
        if producer.record.instance != call.attempt.1.spec.id || producer.record.call != saved.call
        {
            return Err(Code::Denied.error("Graph result authority"));
        }
        let grant = producer.grant();
        let bytes = size_of::<(ReadOrigin, OriginAuthority)>()
            .saturating_add(16 * size_of::<usize>())
            .saturating_add(reference.result_id.capacity())
            .saturating_add(grant.principal.capacity())
            .saturating_add(grant.authorization_id.as_ref().map_or(0, String::capacity))
            .saturating_add(grant.selection.allocation_bytes());
        let lease = reserve(bytes)?;
        self.origins.insert(
            origin,
            OriginAuthority {
                reference: reference.clone(),
                grant: grant.clone(),
            },
        );
        self.leases.push(lease);
        Ok(reference)
    }

    fn check_call(&self, call: &ManagedGraphCall) -> Result<()> {
        if !Arc::ptr_eq(&self.attempt, &call.attempt) || self.call != call.call {
            return Err(Code::Denied.error("Graph invocation authority"));
        }
        Ok(())
    }
}
