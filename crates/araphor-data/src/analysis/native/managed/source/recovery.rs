use std::collections::BTreeMap;

use super::*;

impl NativeStore {
    // shortcut: Recovery scans each retained membership; use journal deltas before scaling append chains.
    pub(in crate::analysis::native) fn validate_source_recovery(&self) -> Result<()> {
        let current = self.view()?;
        let control = AnalysisReadControl::default();
        let mut headers = BTreeSet::new();
        let mut indexes = BTreeMap::new();
        let mut heads = BTreeMap::<Vec<u8>, (u64, u64)>::new();
        let mut windows = BTreeMap::<Vec<u8>, (u64, u64)>::new();
        let mut winners = BTreeMap::<Vec<u8>, (u64, u64)>::new();
        for entry in current.snapshot.prefix(b"\0data/X") {
            let (key, _) = entry.context(crate::NativeStorageSnafu {
                operation: "validate source result owners",
            })?;
            if key.len() != 15 {
                continue;
            }
            let selected = Self::number(&key[7..])?;
            let bytes = Records::payload(&key, |key| Records::read(key, &current.snapshot))?
                .ok_or_else(|| Code::Missing.error("source recovery result"))?;
            let stored: StoredResult = Records::decode(&bytes)?;
            let ResultBody::Selected(step) = &stored.body else {
                continue;
            };
            let Some(source) = &step.source else { continue };
            let header_key = SourceRecord::key(SourceRecord::PREFIX, &[selected]);
            headers.insert(header_key.clone());
            let (header, _) = SourceRecord::publication(
                selected,
                current.metadata_revision,
                |key| Records::read(key, &current.snapshot),
                &mut |_| Ok(()),
            )?;
            let (_, _, owner) =
                current.result_owner(stored.tenant, &stored.id, &control, &mut |_| Ok(()))?;
            let identity = match &owner.instance().spec.destination {
                ManagedDestination::Graph { source, .. } => source,
                _ => return Err(Code::Invalid.error("source recovery destination")),
            };
            header.check_capture(owner.captured_revision(), stored.revision)?;
            if owner.receipt().and_then(|receipt| receipt.graph.as_ref())
                != Some(&header.summary(&stored)?.reference)
                || source.first == 0
                || source.last < source.first
                || source.records.windows(2).any(|pair| pair[0].0 >= pair[1].0)
                || source
                    .derived
                    .windows(2)
                    .any(|pair| pair[0].key >= pair[1].key)
                || source
                    .origins
                    .windows(2)
                    .any(|pair| pair[0].result_id >= pair[1].result_id)
                || source
                    .proofs
                    .windows(2)
                    .any(|pair| (&pair[0].0, &pair[0].1.key) >= (&pair[1].0, &pair[1].1.key))
            {
                return Err(Code::Invalid.error("source recovery scope"));
            }
            let at = self.read_at(stored.revision)?;
            let before = self.read_at(stored.revision - 1)?;
            if Records::payload(&header_key, |key| Records::read(key, &at.snapshot))?
                != Records::payload(&header_key, |key| Records::read(key, &current.snapshot))?
            {
                return Err(Code::Invalid.error("immutable source header"));
            }
            let prior = SourceRecord::head(
                stored.tenant,
                &step.instance,
                identity,
                before.metadata_revision,
                |key| Records::read(key, &before.snapshot),
                &mut |_| Ok(()),
            )?;
            if prior.as_ref().map(|prior| &prior.reference) != source.base.as_ref()
                || header.append
                    && prior.as_ref().is_none_or(|prior| {
                        prior.first != source.first
                            || prior.last > source.last
                            || prior.deadline != source.deadline
                    })
                || source.expired
                    && (header.append
                        || !source.records.is_empty()
                        || prior.as_ref().is_none_or(|prior| {
                            prior.first != source.first
                                || prior.last != source.last
                                || prior.deadline != source.deadline
                        }))
            {
                return Err(Code::Conflict.error("source recovery predecessor"));
            }
            let capture = self.read_at(owner.captured_revision())?;
            header.check_coverage(&capture, identity, source, owner.0.capture.time_utc_ns)?;
            let prefix = at.source_members(&owner)?;
            let mut expected = BTreeMap::new();
            if header.append || source.expired {
                for entry in before.snapshot.prefix(&prefix) {
                    let (key, _) = entry.context(crate::NativeStorageSnafu {
                        operation: "validate prior source membership",
                    })?;
                    let bytes = Records::payload(&key, |key| Records::read(key, &before.snapshot))?
                        .ok_or_else(|| Code::Missing.error("prior source member"))?;
                    expected.insert(key.to_vec(), Records::decode::<Member>(&bytes)?);
                }
            }
            let mut restricted = BTreeMap::<DiscoveryRecordIdV1, u64>::new();
            for reference in &source.derived {
                let (value, revision) = at
                    .context(&reference.key)?
                    .ok_or_else(|| Code::Missing.error("source derived context"))?;
                if revision != reference.commit_revision {
                    return Err(Code::Invalid.error("source derived revision"));
                }
                let fact = crate::analysis::context::FactRecord::from_context(&value)?;
                if fact.is_some() {
                    let fact = crate::GraphFactV1::try_from(&value)?;
                    if source
                        .records
                        .binary_search_by(|(record, _)| record.cmp(&fact.record_id))
                        .is_err()
                    {
                        return Err(Code::Denied.error("source derived record"));
                    }
                    if value.sensitivity == crate::ContextSensitivityV1::HostRestricted {
                        let count = restricted.entry(fact.record_id).or_default();
                        *count = count
                            .checked_add(1)
                            .ok_or_else(|| Code::Limit.error("source restricted count"))?;
                    }
                } else if !owner.0.capture.contexts.contains(reference)
                    && !source.proofs.iter().any(|(_, proof)| proof == reference)
                {
                    return Err(Code::Denied.error("source derived authority"));
                }
            }
            for (record, reference) in &source.proofs {
                if source
                    .records
                    .binary_search_by(|(wanted, _)| wanted.cmp(record))
                    .is_err()
                    || source
                        .derived
                        .binary_search_by(|wanted| wanted.key.cmp(&reference.key))
                        .ok()
                        .is_none_or(|index| source.derived[index] != *reference)
                {
                    return Err(Code::Denied.error("source proof authority"));
                }
            }
            for (record, position) in &source.records {
                header.check_member(identity, source.first..=source.last, record, *position)?;
                if !step.witnesses.iter().any(|witness| {
                    witness.identity == crate::AnalysisStreamIdentityV1::Evidence(identity.clone())
                        && witness.cursor == record.durable_cursor
                }) {
                    return Err(Code::Denied.error("source member authority"));
                }
                let restricted = restricted.get(record).copied().unwrap_or(0);
                let key = SourceRecord::member_key(&prefix, record);
                let bytes = Records::payload(&key, |key| Records::read(key, &at.snapshot))?
                    .ok_or_else(|| Code::Missing.error("source observed member"))?;
                let retained: Member = Records::decode(&bytes)?;
                if expected
                    .insert(
                        key,
                        Member {
                            position: *position,
                            observed: retained.observed,
                            origin: selected,
                            restricted,
                        },
                    )
                    .is_some()
                {
                    return Err(Code::Conflict.error("source append overlap"));
                }
            }
            let restricted = expected.values().try_fold(0u64, |count, member| {
                count
                    .checked_add(member.restricted)
                    .ok_or_else(|| Code::Limit.error("source restricted total"))
            })?;
            if expected.len() as u64 != header.count || restricted != header.restricted {
                return Err(Code::Invalid.error("source membership totals"));
            }
            for entry in at.snapshot.prefix(&prefix) {
                let (key, _) = entry.context(crate::NativeStorageSnafu {
                    operation: "validate source membership",
                })?;
                let bytes = Records::payload(&key, |key| Records::read(key, &at.snapshot))?
                    .ok_or_else(|| Code::Missing.error("source member"))?;
                if expected.remove(key.as_ref()) != Some(Records::decode::<Member>(&bytes)?) {
                    return Err(Code::Invalid.error("source membership transition"));
                }
            }
            if !expected.is_empty() {
                return Err(Code::Missing.error("source membership"));
            }
            let postings = SourceRecord::postings(
                selected,
                step,
                |key| Records::read(key, &at.snapshot),
                &mut |_| Ok(()),
            )?;
            for (key, value) in &postings {
                if Records::read(key, &at.snapshot)?.as_deref() != Some(value.as_slice()) {
                    return Err(Code::Invalid.error("source publication postings"));
                }
            }
            indexes.extend(postings);
            let instance = Records::find(
                &InstanceRecord::identity(stored.tenant, &step.instance)?,
                |key| Records::read(key, &at.snapshot),
            )?
            .ok_or_else(|| Code::Missing.error("source index instance"))?;
            let source_id = Records::find(&SourceRecord::identity(identity)?, |key| {
                Records::read(key, &at.snapshot)
            })?
            .ok_or_else(|| Code::Missing.error("source index identity"))?;
            for (index, key) in [
                (
                    &mut heads,
                    SourceRecord::key(SourceRecord::HEAD, &[instance, source_id]),
                ),
                (
                    &mut windows,
                    SourceRecord::key(SourceRecord::WINDOW, &[source_id, source.first]),
                ),
                (
                    &mut winners,
                    SourceRecord::winner_key(stored.tenant, instance, source_id, source.first),
                ),
            ] {
                if index.get(&key).is_none_or(|old| old.0 < stored.revision) {
                    index.insert(key, (stored.revision, selected));
                }
            }
        }
        let mut members = BTreeMap::new();
        for (_, selected) in heads.values() {
            let (_, result) = SourceRecord::publication(
                *selected,
                current.metadata_revision,
                |key| Records::read(key, &current.snapshot),
                &mut |_| Ok(()),
            )?;
            let (_, _, owner) =
                current.result_owner(result.tenant, &result.id, &control, &mut |_| Ok(()))?;
            let at = self.read_at(result.revision)?;
            let prefix = at.source_members(&owner)?;
            for entry in at.snapshot.prefix(&prefix) {
                let (key, value) = entry.context(crate::NativeStorageSnafu {
                    operation: "validate current source membership",
                })?;
                members.insert(key.to_vec(), value.to_vec());
            }
        }
        for entry in current.snapshot.prefix(SourceRecord::MEMBER) {
            let (key, value) = entry.context(crate::NativeStorageSnafu {
                operation: "validate source member set",
            })?;
            if members.remove(key.as_ref()).as_deref() != Some(value.as_ref()) {
                return Err(Code::Invalid.error("source current member set"));
            }
        }
        if !members.is_empty() {
            return Err(Code::Missing.error("source current membership"));
        }
        for prefix in [
            SourceRecord::PREFIX,
            SourceRecord::FACT,
            SourceRecord::PROOF,
            SourceRecord::HEAD,
            SourceRecord::WINDOW,
            SourceRecord::WINNER,
        ] {
            for entry in current.snapshot.prefix(prefix) {
                let (key, value) = entry.context(crate::NativeStorageSnafu {
                    operation: "validate source index set",
                })?;
                let valid = if prefix == SourceRecord::PREFIX {
                    headers.remove(key.as_ref())
                } else if prefix == SourceRecord::HEAD {
                    heads.remove(key.as_ref()).map(|(_, id)| id) == Some(Self::number(&value)?)
                } else if prefix == SourceRecord::WINDOW {
                    windows.remove(key.as_ref()).map(|(_, id)| id) == Some(Self::number(&value)?)
                } else if prefix == SourceRecord::WINNER {
                    winners.remove(key.as_ref()).map(|(_, id)| id) == Some(Self::number(&value)?)
                } else {
                    indexes.remove(key.as_ref()).as_deref() == Some(value.as_ref())
                };
                if !valid {
                    return Err(Code::Invalid.error("source index set"));
                }
            }
        }
        if !headers.is_empty()
            || !indexes.is_empty()
            || !heads.is_empty()
            || !windows.is_empty()
            || !winners.is_empty()
        {
            return Err(Code::Missing.error("source index set"));
        }
        Ok(())
    }
}

impl SourceRecord {
    fn check_coverage(
        &self,
        view: &DataView,
        identity: &EvidenceIntakeIdentityV1,
        step: &crate::analysis::SourceStep,
        time: u64,
    ) -> Result<()> {
        let receipt = view
            .source_receipt(identity)?
            .ok_or_else(|| Code::Missing.error("source coverage receipt"))?;
        let (_, report) =
            view.source_proof_coverage(identity, receipt.cpu_id, self.coverage, &mut |_| Ok(()))?;
        if step.expired != (step.first <= receipt.retained_floor || step.deadline <= time) {
            return Err(Code::Conflict.error("source expiry authority"));
        }
        let mut intervals = BTreeMap::new();
        for interval in report
            .iter()
            .flat_map(|report| &report.intervals)
            .filter(|interval| interval.source_epoch == identity.source_epoch)
        {
            let id = <[u8; 16]>::try_from(interval.interval_id.as_slice())
                .map_err(|_| Code::Invalid.error("source coverage interval"))?;
            if intervals.insert(id, interval).is_some() {
                return Err(Code::Invalid.error("source coverage duplicate"));
            }
        }
        for key in &step.coverage {
            let interval = intervals
                .get(&key.interval_id)
                .ok_or_else(|| Code::Denied.error("source coverage interval"))?;
            use crate::DiscoveryCoverageStateV1 as State;
            let state = match key.state {
                State::Healthy => {
                    interval.is_complete() && !interval.has_gap() && interval.state != "CLOSED"
                }
                State::Closed => {
                    interval.is_complete() && !interval.has_gap() && interval.state == "CLOSED"
                }
                State::Gapped => interval.has_gap(),
                State::Unknown => true,
            };
            let mut reasons = if !interval.gap_reasons.is_empty() {
                interval.gap_reasons.clone()
            } else if interval.has_gap() {
                vec!["SOURCE_COVERAGE_GAPPED".into()]
            } else if key.state == State::Unknown {
                vec!["COVERAGE_UNQUALIFIED".into()]
            } else {
                Vec::new()
            };
            reasons.sort();
            reasons.dedup();
            if key.source != *identity
                || key.cpu_id != receipt.cpu_id
                || key.report_revision != self.coverage
                || key.interval_revision != interval.revision
                || !state
                || key.gap_reasons != reasons
            {
                return Err(Code::Denied.error("source coverage authority"));
            }
        }
        Ok(())
    }
}
