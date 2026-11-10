use super::*;
use crate::analysis::{
    managed::PreparedMemory,
    progress::{PreparedProfile, ProfileCommit, ResultHead},
};
use crate::{
    AnalysisResultReceiptV1, DiscoveryProfileV1, ManagedAttempt, ManagedDestination, ManagedReceipt,
};

#[derive(Deserialize, Serialize)]
pub(in crate::analysis::native) struct IntervalHead {
    pub profile: u64,
    pub result: PackageResultRefV1,
}

impl IntervalHead {
    pub(in crate::analysis::native) const PREFIX: &'static [u8] = b"\0data/@progress/interval/";
    pub(super) fn key(owner: u64, name: &str) -> Vec<u8> {
        [
            Processor::key(Self::PREFIX, owner),
            name.as_bytes().to_vec(),
        ]
        .concat()
    }
}

impl DataWrite<'_> {
    pub(super) fn stage_profile_head(
        &mut self,
        owner: u64,
        profile: &DiscoveryProfileV1,
        result: &PackageResultRefV1,
    ) -> Result<()> {
        let key = IntervalHead::key(owner, &profile.interval_id);
        let current = Records::payload(&key, |key| Records::staged(key, &self.transaction))?
            .map(|bytes| Records::decode::<IntervalHead>(&bytes))
            .transpose()?;
        if current.as_ref().is_none_or(|old| {
            (
                old.profile,
                old.result.commit_revision,
                &old.result.result_id,
            ) < (profile.revision, result.commit_revision, &result.result_id)
        }) {
            Records::stage(
                &mut self.transaction,
                key,
                Records::named(&IntervalHead {
                    profile: profile.revision,
                    result: result.clone(),
                })?,
            );
            self.dirty = true;
        }
        Ok(())
    }

    fn profile_rows(
        &mut self,
        mut packet: ProfileCommit,
        attempt: &ManagedAttempt,
        publication: &ManagedReceipt,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<Option<AnalysisResultReceiptV1>> {
        if packet.request.scope.processor_id != crate::DISCOVERY_PROCESSOR
            || !packet.request.body.is_empty()
            || !packet.request.witnesses.is_empty()
        {
            return crate::AnalysisStore::reject_path(
                &self.store.root,
                "the typed profile publication is invalid",
            );
        }
        packet.request.witnesses = attempt.witnesses().to_vec();
        let profile = &packet.profile.profile;
        let ManagedDestination::DiscoveryProfile { source, call, .. } =
            &attempt.instance().spec.destination
        else {
            return Err(Code::Invalid.error("managed profile destination"));
        };
        let mut producer = publication
            .results
            .get(call)
            .cloned()
            .ok_or_else(|| Code::Missing.error("managed profile result"))?;
        let (owner, state) = Processor::read(
            &packet.request.scope,
            self.revision,
            |key| Records::staged(key, &self.transaction),
            &mut |bytes| memory.charge(bytes),
        )?
        .ok_or_else(|| crate::AnalysisConflictSnafu.build())?;
        let mut historical = false;
        if let Some(head) = &packet.previous {
            let (_, prior) = ResultRecord::read(
                &head.result_id,
                self.revision,
                |key| Records::staged(key, &self.transaction),
                &mut |bytes| memory.charge(bytes),
            )?
            .ok_or_else(|| Code::Missing.error("previous profile"))?;
            if prior.revision != head.commit_revision || prior.request.scope != packet.request.scope
            {
                return Err(Code::Conflict.error("previous profile revision"));
            }
            memory.charge(prior.request.body.len().saturating_mul(4))?;
            let previous = DiscoveryProfileV1::try_from(prior.request.body.as_slice())?;
            historical = previous.sealed && profile.interval_id == previous.interval_id;
            if historical {
                let key = IntervalHead::key(owner, &profile.interval_id);
                let latest: IntervalHead =
                    Records::payload(&key, |key| Records::staged(key, &self.transaction))?
                        .map(|bytes| Records::decode(&bytes))
                        .transpose()?
                        .ok_or_else(|| Code::Missing.error("historical profile head"))?;
                if latest.result != *head
                    || packet.request.expected_cursor != packet.request.consumed_cursor
                {
                    return Err(Code::Conflict.error("historical profile frontier"));
                }
            }
            if let Some((facts, coverage)) = packet.notice {
                if *profile != previous
                    || !packet.profile.contexts.is_empty()
                    || packet.request.expected_cursor != packet.request.consumed_cursor
                    || !historical && packet.previous != packet.head
                {
                    return Err(Code::Invalid.error("profile notice"));
                }
                if state.retirement.is_some()
                    || state.consumed.max(state.resumed) != packet.request.expected_cursor
                    || state.head != packet.head
                {
                    return Err(Code::Conflict.error("profile notice frontier"));
                }
                self.stage_profile_notice(&packet.request.scope, head, facts, coverage, memory)?;
                return Ok(None);
            }
            if historical
                && !self
                    .store
                    .view()?
                    .profile_producer(
                        &attempt.instance().grant.selection,
                        &previous,
                        &prior,
                        &mut |bytes| memory.charge(bytes),
                    )?
                    .matches(&attempt.instance().spec)
            {
                return Err(Code::Denied.error("historical profile producer"));
            }
            PreparedProfile::check_transition(profile, &previous, historical, &self.store.root)?;
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
                if prior.request.context_refs != previous.context_refs {
                    return Err(Code::Invalid.error("prior profile evidence"));
                }
                self.store.view()?.profile_producer(
                    &attempt.instance().grant.selection,
                    &previous,
                    &prior,
                    &mut |bytes| memory.charge(bytes),
                )?;
                packet.request.witnesses = prior.request.witnesses;
                producer = prior
                    .producer
                    .ok_or_else(|| Code::Incomplete.error("closed profile producer"))?;
            }
        } else if packet.notice.is_some()
            || profile.revision != 1
            || profile.interval_id != profile.profile_id
        {
            return crate::AnalysisStore::reject_path(
                &self.store.root,
                "the initial profile interval is invalid",
            );
        }
        if packet.notice.is_some() {
            return Err(Code::Invalid.error("profile notice transition"));
        }
        if !historical && packet.previous != packet.head {
            return Err(Code::Conflict.error("profile current head"));
        }
        if packet.request.scope.identity != *source {
            return Err(Code::Invalid.error("managed profile source"));
        }
        packet.request.body = packet.profile.body;
        let output = self.progress_rows(
            &packet.request,
            ResultHead::Current(packet.head.as_ref()),
            !historical || packet.head == packet.previous,
            Some(&mut packet.profile.profile),
            &packet.profile.contexts,
            Some(&producer),
            memory,
        )?;
        Ok(Some(output.receipt))
    }
}

impl NativeStore {
    pub fn commit_managed_profile(
        &self,
        prepared: super::super::PreparedManagedCommit<'_>,
        packet: Option<ProfileCommit>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<(ManagedReceipt, Option<AnalysisResultReceiptV1>)> {
        let input = prepared.input();
        let ManagedDestination::DiscoveryProfile {
            source,
            call,
            output,
        } = &input.attempt.instance().spec.destination
        else {
            return Err(Code::Invalid.error("managed profile destination"));
        };
        let returned = input
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
                || packet.request.created_utc_ns != input.attempt.request().time_utc_ns
        }) {
            return Err(Code::Invalid.error("managed profile capture"));
        }
        let contract = prepared
            .contract(*call)
            .ok_or_else(|| Code::Missing.error("managed profile contract"))?;
        let port = contract
            .exports
            .iter()
            .find(|model| model.name == input.attempt.instance().spec.manifest.calls[call].export)
            .and_then(|model| model.outputs.iter().find(|port| port.name == *output))
            .ok_or_else(|| Code::Invalid.error("managed profile output"))?;
        if data
            .batches
            .iter()
            .any(|batch| batch.schema().as_ref() != &port.schema)
        {
            return Err(Code::Invalid.error("managed profile schema"));
        }
        self.commit_managed_projection(
            prepared,
            move |tx, input, publication, memory| {
                packet
                    .map(|packet| tx.profile_rows(packet, input.attempt, publication, memory))
                    .transpose()
                    .map(Option::flatten)
            },
            check,
        )
    }
}
