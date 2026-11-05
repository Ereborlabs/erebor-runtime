use duckdb::{Connection, params};
use snafu::ResultExt as _;

use super::budget::PreparedMemory;
use super::commit::Packet;
use super::graph::PreparedGraph;
use super::model::{Attempt, ManagedCommit, Step};
use super::source::{SourceEvidence, import::PreparedDerived, publication::PreparedSource};
use crate::analysis::context::VerifiedPackages;
use crate::{AnalysisStore, PackageErrorCodeV1 as Code, Result};

pub struct PreparedManagedCommit<'a> {
    pub(super) input: &'a ManagedCommit<'a>,
    pub(super) evidence: SourceEvidence,
    pub(super) packets: Vec<Packet>,
    pub(super) step: Option<Step>,
    pub(super) derived: PreparedDerived,
    pub(super) graph: Option<PreparedGraph>,
    pub(super) source: Option<PreparedSource>,
    pub(super) verified: VerifiedPackages,
    pub(super) contracts: Vec<crate::analysis::PackageRevisionV1>,
    pub(super) started: std::time::Instant,
    pub(super) prepared: std::time::Instant,
    pub(super) memory: PreparedMemory<'a>,
}

impl<'a> PreparedManagedCommit<'a> {
    pub fn input(&self) -> &'a ManagedCommit<'a> {
        self.input
    }
}

impl AnalysisStore {
    pub fn prepare_managed<'a>(
        &self,
        input: &'a ManagedCommit<'a>,
    ) -> Result<PreparedManagedCommit<'a>> {
        let started = std::time::Instant::now();
        let mut memory = PreparedMemory::new(input.control, input.budget)?;
        let capture = &input.attempt.0.capture;
        let evidence = match &input.attempt.5 {
            Some(source) => source.freeze_evidence(
                capture,
                input.attempt.request().witness_expiry,
                &mut memory,
            )?,
            None => {
                memory.charge(SourceEvidence::metadata_bytes(
                    capture.witnesses.iter(),
                    capture.contexts.iter(),
                )?)?;
                SourceEvidence {
                    witnesses: capture.witnesses.clone(),
                    contexts: capture.contexts.clone(),
                }
            }
        };
        let frozen = std::time::Instant::now();
        let mut reader = self.frozen_reader(input.control)?;
        let ready = std::time::Instant::now();
        input.control.run(&mut reader,|connection| {
            Self::charge_packets(input,&evidence,&mut memory)?;
            let charged=std::time::Instant::now();
            let attempt=self.check_managed_state(connection,input)?;
            let state=std::time::Instant::now();
            let mut contracts=Vec::new();
            let mut seen=std::collections::BTreeSet::new();
            for returned in input.returns {
                let declaration=input.attempt.1.spec.manifest.calls.get(&returned.call)
                    .ok_or_else(|| Code::Invalid.error("managed returned calls"))?;
                if !seen.insert(&declaration.package) { continue; }
                let bytes:usize=connection.query_row(
                    "SELECT octet_length(descriptor)+octet_length(artifact)+length(dependencies)*8 FROM package_revisions
                        WHERE tenant_id=? AND package_id=? AND revision=?",
                    params![input.attempt.1.spec.tenant.as_slice(),declaration.package.package_id,declaration.package.revision],|row| row.get(0))
                    .context(crate::AnalysisDatabaseSnafu { operation:"read prepared package size" })?;
                memory.charge(bytes.checked_add(16*std::mem::size_of::<crate::analysis::PackageRevisionV1>())
                    .and_then(|bytes| bytes.checked_mul(4)).ok_or_else(|| Code::Limit.error("prepared package memory"))?)?;
                contracts.push(Self::package_from(connection,input.attempt.1.spec.tenant,&declaration.package.package_id,&declaration.package.revision)?
                    .ok_or_else(|| Code::Missing.error("managed prepared package"))?);
            }
            let contracted=std::time::Instant::now();
            let mut verified=self.check_managed_capture(connection,&attempt.capture,input.now_utc_ns,
                (&evidence.witnesses,&evidence.contexts),input.attempt.4.as_ref()
                    .map(|owner| owner.packages(input.attempt.instance(),&attempt.capture)).unwrap_or_default())?;
            let captured=std::time::Instant::now();
            let (packets,step)=self.prepare_packets(connection,&attempt,input,&evidence)?;
            let packet_at=std::time::Instant::now();
            let snapshot=Self::read_meta_from(connection,&self.root)?.commit_revision;
            let derived=self.prepare_derived(connection,input,snapshot,&mut verified,&mut memory)?;
            let derived_at=std::time::Instant::now();
            let source=input.attempt.5.as_ref().map(|frame| frame.input_selection()).transpose()?.flatten()
                .as_ref().map(|selection| super::SourcePublication::prepare(connection,input,selection,&mut memory)).transpose()?;
            let source_at=std::time::Instant::now();
            let graph=self.prepare_graph_journals(&contracts,input,&evidence,&derived,&mut memory)?;
            memory.check()?;
            let prepared=std::time::Instant::now();
            erebor_telemetry::debug!(stage="managed_prepare_timing",instance_id=%input.attempt.1.spec.id,
                cut_revision=input.attempt.captured_revision(),elapsed_s=prepared.duration_since(started).as_secs_f64(),
                evidence_s=frozen.duration_since(started).as_secs_f64(),reader_s=ready.duration_since(frozen).as_secs_f64(),
                charge_s=charged.duration_since(ready).as_secs_f64(),state_s=state.duration_since(charged).as_secs_f64(),
                contracts_s=contracted.duration_since(state).as_secs_f64(),capture_s=captured.duration_since(contracted).as_secs_f64(),
                packets_s=packet_at.duration_since(captured).as_secs_f64(),derived_s=derived_at.duration_since(packet_at).as_secs_f64(),
                source_s=source_at.duration_since(derived_at).as_secs_f64(),graph_s=prepared.duration_since(source_at).as_secs_f64(),
                retained_bytes=memory.bytes(),peak_bytes=memory.peak(),"Managed change preparation completed");
            Ok(PreparedManagedCommit { input,evidence,packets,step:Some(step),derived,graph,source,verified,contracts,started,prepared,memory })
        })
    }

    pub(super) fn check_managed_state(
        &self,
        connection: &Connection,
        input: &ManagedCommit<'_>,
    ) -> Result<Attempt> {
        input.control.check()?;
        input.attempt.1.grant.remaining()?;
        if input.now_utc_ns < input.attempt.request().time_utc_ns {
            return Err(Code::Invalid.error("managed publication time"));
        }
        if !input.completed && input.attempt.request().frontier.is_none() {
            return Err(Code::Invalid.error("managed pending frontier"));
        }
        self.check_managed_claim(input.attempt)?;
        let supplied = &input.attempt.0;
        let spec = &input.attempt.1.spec;
        let attempt =
            Self::managed_attempt_from(connection, spec.tenant, &spec.id, &supplied.request.id)?
                .ok_or_else(|| Code::Missing.error("managed attempt"))?;
        if supplied.request != attempt.request
            || supplied.capture != attempt.capture
            || supplied.registered != attempt.registered
            || attempt.receipt.is_some()
            || attempt.terminal.is_some()
            || Self::managed_version_from(
                connection,
                spec.tenant,
                &spec.id,
                attempt.capture.generation,
            )? != *spec
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        Ok(attempt)
    }

    fn charge_packets(
        input: &ManagedCommit<'_>,
        evidence: &SourceEvidence,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<()> {
        let spec = &input.attempt.1.spec;
        let mut bytes = spec
            .allocation_bytes()
            .and_then(|bytes| bytes.checked_mul(8))
            .ok_or_else(|| Code::Limit.error("managed packet memory"))?;
        let shared =
            SourceEvidence::metadata_bytes(evidence.witnesses.iter(), evidence.contexts.iter())?;
        bytes = input
            .returns
            .len()
            .checked_add(4)
            .and_then(|count| shared.checked_mul(count))
            .and_then(|shared| bytes.checked_add(shared))
            .ok_or_else(|| Code::Limit.error("managed packet memory"))?;
        for returned in input.returns {
            let evaluation = returned.evaluation;
            let mut extra = evaluation.context.id.capacity();
            for value in &evaluation.inputs {
                extra = extra
                    .checked_add(value.revision.owner.capacity())
                    .and_then(|bytes| bytes.checked_add(value.revision.id.capacity()))
                    .and_then(|bytes| {
                        bytes.checked_add(
                            value
                                .revision
                                .window
                                .as_ref()
                                .map_or(0, |window| window.source.capacity()),
                        )
                    })
                    .and_then(|bytes| bytes.checked_add(value.coverage.metadata_bytes()))
                    .ok_or_else(|| Code::Limit.error("managed packet memory"))?;
            }
            if let Some(state) = &returned.output.checkpoint {
                for data in &state.datasets {
                    extra = extra
                        .checked_add(
                            data.batches
                                .iter()
                                .try_fold(data.name.capacity(), |bytes, batch| {
                                    bytes.checked_add(batch.get_array_memory_size())
                                })
                                .unwrap_or(usize::MAX),
                        )
                        .ok_or_else(|| Code::Limit.error("managed checkpoint memory"))?;
                }
            }
            bytes = bytes
                .checked_add(
                    extra
                        .checked_mul(8)
                        .ok_or_else(|| Code::Limit.error("managed packet memory"))?,
                )
                .ok_or_else(|| Code::Limit.error("managed packet memory"))?;
        }
        memory.charge(bytes)
    }
}
