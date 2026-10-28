use duckdb::{params, OptionalExt as _};
use snafu::ResultExt as _;

use super::{
    AnalysisResultCommitV1, AnalysisResultReceiptV1, AnalysisStore, ProgressWrite, ResultHead,
    MAX_RESULT_BYTES,
};
use crate::{
    DiscoveryEncodingSnafu, DiscoveryProfileV1, ManagedCommit, ManagedDestination, ManagedReceipt,
    PackageErrorCodeV1 as Code, Result,
};

mod replay;

pub use replay::DiscoveryProducer;

pub struct PreparedProfile {
    profile: DiscoveryProfileV1,
    body: Vec<u8>,
    contexts: Vec<crate::AnalysisContextVersionV1>,
}

pub struct ProfileCommit {
    pub request: AnalysisResultCommitV1,
    pub profile: PreparedProfile,
    pub previous: Option<super::super::PackageResultRefV1>,
    pub head: Option<super::super::PackageResultRefV1>,
    pub notice: Option<(u64, u64)>,
}

impl PreparedProfile {
    pub fn new(profile: DiscoveryProfileV1) -> Result<Self> {
        profile.validate()?;
        let body = Self::encode(&profile)?;
        Ok(Self {
            profile,
            body,
            contexts: Vec::new(),
        })
    }

    pub fn captured(
        profile: DiscoveryProfileV1,
        contexts: Vec<crate::AnalysisContextVersionV1>,
    ) -> Result<Self> {
        profile.validate()?;
        if contexts.is_empty() {
            return Self::new(profile);
        }
        Ok(Self {
            profile,
            body: Vec::new(),
            contexts,
        })
    }

    pub(super) fn encode(profile: &DiscoveryProfileV1) -> Result<Vec<u8>> {
        let mut output = araphor_analysis_sdk::wire::BoundedBuffer::new(MAX_RESULT_BYTES as u64);
        if let Err(source) = serde_json::to_writer(&mut output, &profile) {
            if source.io_error_kind() == Some(std::io::ErrorKind::FileTooLarge) {
                return crate::DiscoveryInvalidSnafu {
                    field: "profile bytes",
                }
                .fail();
            }
            return Err(source).context(DiscoveryEncodingSnafu);
        }
        Ok(output.finish())
    }
}

impl AnalysisStore {
    pub fn commit_managed_profile(
        &self,
        managed: &ManagedCommit<'_>,
        packet: Option<ProfileCommit>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<(ManagedReceipt, Option<AnalysisResultReceiptV1>)> {
        let ManagedDestination::DiscoveryProfile {
            source,
            call,
            output,
        } = &managed.attempt.instance().spec.destination
        else {
            return Err(Code::Invalid.error("managed profile destination"));
        };
        let returned = managed
            .returns
            .iter()
            .find(|returned| returned.call == *call)
            .ok_or_else(|| Code::Invalid.error("managed profile call"))?;
        let data = returned
            .output
            .datasets
            .iter()
            .find(|data| data.name == *output)
            .ok_or_else(|| Code::Invalid.error("managed profile dataset"))?;
        if packet.as_ref().is_some_and(|packet| {
            packet.request.scope.identity != *source
                || packet.request.created_utc_ns != managed.attempt.request().time_utc_ns
        }) {
            return Err(Code::Invalid.error("managed profile capture"));
        }
        let mut profile_receipt = None;
        let receipt = self.commit_managed_projection(
            managed,
            |transaction, _, publication| {
                let declaration = &managed.attempt.instance().spec.manifest.calls[call];
                let descriptor =
                    Self::managed_contract(transaction, source.tenant_id, declaration)?;
                let model = descriptor
                    .exports
                    .iter()
                    .find(|model| model.name == declaration.export)
                    .ok_or_else(|| Code::Invalid.error("managed profile export"))?;
                let port = model
                    .outputs
                    .iter()
                    .find(|port| port.name == *output)
                    .ok_or_else(|| Code::Invalid.error("managed profile output"))?;
                if data
                    .batches
                    .iter()
                    .any(|batch| batch.schema().as_ref() != &port.schema)
                {
                    return Err(Code::Invalid.error("managed profile schema"));
                }
                let Some(packet) = packet else {
                    return Ok(Vec::new());
                };
                let id = packet.request.result_id.clone();
                let result = publication
                    .results
                    .get(call)
                    .ok_or_else(|| Code::Incomplete.error("managed profile result"))?;
                let Some((write, origin)) =
                    self.profile_rows(transaction, packet, managed.attempt)?
                else {
                    return Ok(Vec::new());
                };
                Self::insert_managed_edges(
                    transaction,
                    source.tenant_id,
                    &id,
                    std::slice::from_ref(origin.as_ref().unwrap_or(result)),
                )?;
                profile_receipt = Some(write.receipt);
                Ok(write.relations)
            },
            check,
        )?;
        Ok((receipt, profile_receipt))
    }

    pub(in crate::analysis) fn profile_rows(
        &self,
        transaction: &duckdb::Transaction<'_>,
        mut packet: ProfileCommit,
        attempt: &crate::ManagedAttempt,
    ) -> Result<Option<(ProgressWrite, Option<super::super::PackageResultRefV1>)>> {
        if packet.request.scope.processor_id != crate::DISCOVERY_PROCESSOR
            || !packet.request.body.is_empty()
            || !packet.request.witnesses.is_empty()
        {
            return self.reject("the typed profile publication is invalid");
        }
        packet.request.witnesses = attempt.witnesses().to_vec();
        let mut origin = None;
        let mut historical = false;
        let profile = &packet.profile.profile;
        match &packet.previous {
            Some(head) => {
                let body = self
                    .read_result_from(
                        transaction,
                        packet.request.scope.identity.tenant_id,
                        &head.result_id,
                    )?
                    .ok_or_else(|| Code::Missing.error("previous profile"))?;
                let previous = DiscoveryProfileV1::try_from(body.as_slice())?;
                let revision: u64 = transaction.query_row(
                    "SELECT commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
                    params![profile.scope.identity.tenant_id.as_slice(), head.result_id],
                    |row| row.get(0),
                ).context(crate::AnalysisDatabaseSnafu { operation: "read previous profile revision" })?;
                if revision != head.commit_revision {
                    return Err(Code::Conflict.error("previous profile revision"));
                }
                historical = previous.sealed && profile.interval_id == previous.interval_id;
                if historical {
                    let latest: (String, u64) = transaction.query_row(
                        "SELECT result_id, commit_revision FROM analysis_results
                         WHERE tenant_id = ? AND processor_id = ? AND method_version = ?
                             AND stream_key = ? AND interval_id = ?
                         ORDER BY profile_revision DESC, commit_revision DESC, result_id DESC LIMIT 1",
                        params![profile.scope.identity.tenant_id.as_slice(), profile.scope.processor_id,
                            profile.scope.method_version, profile.scope.identity.key(), profile.interval_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    ).context(crate::AnalysisDatabaseSnafu { operation: "read historical profile head" })?;
                    if latest != (head.result_id.clone(), head.commit_revision)
                        || packet.request.expected_cursor != packet.request.consumed_cursor
                    {
                        return Err(Code::Conflict.error("historical profile frontier"));
                    }
                }
                if let Some((facts, coverage)) = packet.notice {
                    if *profile != previous
                        || !packet.profile.contexts.is_empty()
                        || packet.request.expected_cursor != packet.request.consumed_cursor
                        || (!historical && packet.previous != packet.head)
                    {
                        return Err(Code::Invalid.error("profile notice"));
                    }
                    let current: Option<(u64, bool, String, Option<u64>)> = transaction.query_row(
                        "SELECT GREATEST(p.consumed_cursor, p.resume_floor), p.retired,
                            p.result_id, r.commit_revision FROM processor_progress p
                         LEFT JOIN analysis_results r ON r.tenant_id = p.tenant_id AND r.result_id = p.result_id
                         WHERE p.tenant_id = ? AND p.processor_id = ? AND p.method_version = ? AND p.stream_key = ?",
                        params![profile.scope.identity.tenant_id.as_slice(), profile.scope.processor_id,
                            profile.scope.method_version, profile.scope.identity.key()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    ).optional().context(crate::AnalysisDatabaseSnafu { operation: "read profile notice frontier" })?;
                    if !current.is_some_and(|(cursor, retired, id, revision)| {
                        !retired
                            && cursor == packet.request.expected_cursor
                            && packet.head.as_ref().is_some_and(|head| {
                                head.result_id == id && Some(head.commit_revision) == revision
                            })
                    }) {
                        return Err(Code::Conflict.error("profile notice frontier"));
                    }
                    self.notice_rows(
                        transaction,
                        &profile.scope,
                        &head.result_id,
                        head.commit_revision,
                        facts,
                        coverage,
                    )?;
                    return Ok(None);
                }
                if historical {
                    let current = attempt.instance();
                    let producer = Self::discovery_producer_from(
                        transaction,
                        &current.grant.selection,
                        &previous,
                        head.commit_revision,
                    )?;
                    if !producer.matches(&current.spec) {
                        return Err(Code::Denied.error("historical profile producer"));
                    }
                }
                if profile.profile_id == previous.profile_id
                    || profile.scope != previous.scope
                    || profile.updated_utc_ns < previous.updated_utc_ns
                    || if historical {
                        !profile.sealed
                            || Some(profile.revision) != previous.revision.checked_add(1)
                            || profile.created_utc_ns != previous.created_utc_ns
                            || profile.facts_revision < previous.facts_revision
                            || profile.coverage_revision < previous.coverage_revision
                            || profile.input_bytes != previous.input_bytes
                            || profile.incomplete != previous.incomplete
                            || profile.gaps != previous.gaps
                            || !previous
                                .context_refs
                                .iter()
                                .all(|reference| profile.context_refs.contains(reference))
                    } else if previous.sealed {
                        profile.interval_id == previous.interval_id
                            || profile.revision != 1
                            || profile.created_utc_ns < previous.updated_utc_ns
                    } else {
                        profile.interval_id != previous.interval_id
                            || Some(profile.revision) != previous.revision.checked_add(1)
                            || profile.created_utc_ns != previous.created_utc_ns
                    }
                {
                    return self.reject("the immutable profile transition is invalid");
                }
                if profile.sealed
                    && !previous.sealed
                    && packet.request.expected_cursor == packet.request.consumed_cursor
                    && profile.snapshot == previous.snapshot
                    && profile.context_refs == previous.context_refs
                    && profile.coverage_revision == previous.coverage_revision
                    && profile.facts_revision == previous.facts_revision
                    && profile.input_bytes == previous.input_bytes
                    && profile.incomplete == previous.incomplete
                    && profile.gaps == previous.gaps
                {
                    let metadata: Vec<u8> = transaction
                        .query_row(
                            "SELECT request_meta FROM analysis_results WHERE tenant_id = ?
                            AND result_id = ? AND commit_revision = ?",
                            params![
                                profile.scope.identity.tenant_id.as_slice(),
                                head.result_id,
                                head.commit_revision
                            ],
                            |row| row.get(0),
                        )
                        .context(crate::AnalysisDatabaseSnafu {
                            operation: "read closed profile evidence",
                        })?;
                    let (witnesses, contexts) = AnalysisResultCommitV1::request_refs(&metadata)
                        .context(crate::JsonSnafu { path: &self.root })?;
                    if contexts != previous.context_refs {
                        return self.reject("the prior profile evidence differs from its body");
                    }
                    packet.request.witnesses = witnesses;
                    let mut producers = Self::managed_edges(
                        transaction,
                        profile.scope.identity.tenant_id,
                        &head.result_id,
                    )?;
                    if producers.len() != 1
                        || !Self::managed_profile_version(
                            transaction,
                            profile.scope.identity.tenant_id,
                            &head.result_id,
                        )?
                    {
                        return Err(Code::Incomplete.error("closed profile producer"));
                    }
                    origin = producers.pop();
                }
            }
            None if packet.notice.is_some()
                || profile.revision != 1
                || profile.interval_id != profile.profile_id =>
            {
                return self.reject("the initial profile interval is invalid");
            }
            None => {}
        }
        if packet.notice.is_some() {
            return Err(Code::Invalid.error("profile notice transition"));
        }
        if !historical && packet.previous != packet.head {
            return Err(Code::Conflict.error("profile current head"));
        }
        packet.request.body = packet.profile.body;
        self.progress_rows(
            transaction,
            &packet.request,
            ResultHead::Current(packet.head.as_ref()),
            !historical || packet.head == packet.previous,
            Some(&packet.profile.profile),
            None,
            &packet.profile.contexts,
            &[],
            &[],
            false,
        )
        .map(|write| Some((write, origin)))
    }

    pub fn commit_working_profile(
        &self,
        input: AnalysisResultCommitV1,
        prepared: PreparedProfile,
        previous: Option<u64>,
    ) -> Result<AnalysisResultReceiptV1> {
        self.commit_working_profile_guarded(input, prepared, previous, || Ok(()))
    }

    pub fn commit_working_profile_guarded(
        &self,
        mut input: AnalysisResultCommitV1,
        prepared: PreparedProfile,
        previous: Option<u64>,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id != crate::DISCOVERY_PROCESSOR {
            return self.reject("the working result owner is invalid");
        }
        if !input.body.is_empty() {
            return self.reject("the typed profile commit contains independent body bytes");
        }
        input.body = prepared.body;
        self.commit_progress(
            &input,
            previous,
            true,
            Some(&prepared.profile),
            None,
            &prepared.contexts,
            &[],
            &[],
            &mut check,
        )
    }

    pub fn commit_sealed_profile(
        &self,
        input: AnalysisResultCommitV1,
        prepared: PreparedProfile,
    ) -> Result<AnalysisResultReceiptV1> {
        self.commit_sealed_profile_guarded(input, prepared, || Ok(()))
    }

    pub fn commit_sealed_profile_guarded(
        &self,
        mut input: AnalysisResultCommitV1,
        prepared: PreparedProfile,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id != crate::DISCOVERY_PROCESSOR
            || input.expected_cursor != input.consumed_cursor
        {
            return self.reject("the historical profile cannot advance progress");
        }
        if !input.body.is_empty() {
            return self.reject("the typed profile commit contains independent body bytes");
        }
        if !prepared.profile.sealed {
            return self.reject("the historical profile is not sealed");
        }
        input.body = prepared.body;
        self.commit_progress(
            &input,
            None,
            false,
            Some(&prepared.profile),
            None,
            &prepared.contexts,
            &[],
            &[],
            &mut check,
        )
    }
}

#[cfg(test)]
mod tests;
