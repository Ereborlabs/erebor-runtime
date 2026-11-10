use super::{notices::Notice, profile::IntervalHead, *};
use std::collections::{BTreeMap, BTreeSet};

impl NativeStore {
    pub(in crate::analysis::native) fn validate_progress_recovery(&self) -> Result<()> {
        let view = self.view()?;
        let mut intervals = BTreeMap::new();
        let mut bodies = BTreeSet::new();
        let mut gaps = BTreeMap::new();
        for entry in view.snapshot.prefix(ResultRecord::PREFIX) {
            let (key, _) = entry.context(crate::NativeStorageSnafu {
                operation: "validate processor results",
            })?;
            if key.len() != ResultRecord::PREFIX.len() + 8 {
                continue;
            }
            let id = Self::number(&key[ResultRecord::PREFIX.len()..])?;
            let bytes = Records::payload(&key, |key| Records::read(key, &view.snapshot))?
                .ok_or_else(|| Code::Missing.error("processor result"))?;
            let mut row: ResultRecord = Records::decode(&bytes)?;
            let (found, _) = ResultRecord::read_header(
                &row.request.result_id,
                view.metadata_revision,
                |key| Records::read(key, &view.snapshot),
                &mut |_| Ok(()),
            )?
            .ok_or_else(|| Code::Missing.error("processor result identity"))?;
            if found != id
                || view.result_reference(
                    row.request.scope.identity.tenant_id,
                    &row.request.result_id,
                    &mut |_| Ok(()),
                )? != Some((id, row.revision))
            {
                return Err(Code::Invalid.error("processor result identity"));
            }
            let committed = self.read_at(row.revision)?;
            if Records::payload(&key, |key| Records::read(key, &committed.snapshot))?.as_ref()
                != Some(&bytes)
            {
                return Err(Code::Invalid.error("immutable processor result"));
            }
            row.request.body = row.body(
                id,
                |key| Records::read(key, &view.snapshot),
                &mut |_| Ok(()),
            )?;
            if row.body(
                id,
                |key| Records::read(key, &committed.snapshot),
                &mut |_| Ok(()),
            )? != row.request.body
            {
                return Err(Code::Invalid.error("immutable processor body"));
            }
            bodies.insert(Processor::key(ResultRecord::BODY, id));
            if row.body_bytes > u64::from(u32::MAX) - 1 {
                for slot in 0..row.body_bytes.div_ceil(u64::from(u32::MAX)) {
                    bodies.insert(
                        [
                            Processor::key(ResultRecord::BODY, id),
                            slot.to_be_bytes().to_vec(),
                        ]
                        .concat(),
                    );
                }
            }
            let source = self.read_at(row.revision - 1)?;
            let receipt = source
                .source_receipt(&row.request.scope.identity)?
                .ok_or_else(|| Code::Missing.error("processor result source"))?;
            if row.request.consumed_cursor > receipt.contiguous_cursor
                || row.request.coverage_revision > receipt.coverage_revision
            {
                return Err(Code::Invalid.error("processor result source progress"));
            }
            let profile = if row.header.interval_id.is_some() {
                Some(crate::DiscoveryProfileV1::try_from(
                    row.request.body.as_slice(),
                )?)
            } else {
                None
            };
            row.request.check(profile.as_ref(), &[], &self.root)?;
            let header = profile
                .as_ref()
                .map(crate::analysis::progress::ProfileHeader::from)
                .unwrap_or_default();
            if Records::named(&header)? != Records::named(&row.header)? {
                return Err(Code::Invalid.error("processor profile header"));
            }
            if let Some(profile) = profile {
                if let Some(producer) = &row.producer {
                    if producer.commit_revision > row.revision {
                        return Err(Code::Invalid.error("profile producer revision"));
                    }
                    view.profile_producer(
                        &crate::AnalysisSelectionV1::tenant(row.request.scope.identity.tenant_id),
                        &profile,
                        &row,
                        &mut |_| Ok(()),
                    )?;
                }
                let (owner, _) = Processor::read(
                    &profile.scope,
                    view.metadata_revision,
                    |key| Records::read(key, &view.snapshot),
                    &mut |_| Ok(()),
                )?
                .ok_or_else(|| Code::Missing.error("profile processor"))?;
                let key = IntervalHead::key(owner, &profile.interval_id);
                let value = (profile.revision, row.revision, profile.profile_id);
                if intervals.get(&key).is_none_or(|old| old < &value) {
                    intervals.insert(key, value);
                }
            } else if row.producer.is_some() {
                return Err(Code::Invalid.error("processor producer"));
            }
        }
        for entry in view.snapshot.prefix(ResultRecord::BODY) {
            let (key, _) = entry.context(crate::NativeStorageSnafu {
                operation: "validate processor bodies",
            })?;
            if !bodies.remove(key.as_ref()) {
                return Err(Code::Invalid.error("processor body owner"));
            }
        }
        if !bodies.is_empty() {
            return Err(Code::Missing.error("processor body"));
        }
        for entry in view.snapshot.prefix(IntervalHead::PREFIX) {
            let (key, _) = entry.context(crate::NativeStorageSnafu {
                operation: "validate profile intervals",
            })?;
            let bytes = Records::payload(&key, |key| Records::read(key, &view.snapshot))?
                .ok_or_else(|| Code::Missing.error("profile interval"))?;
            let row: IntervalHead = Records::decode(&bytes)?;
            if intervals.remove(key.as_ref())
                != Some((
                    row.profile,
                    row.result.commit_revision,
                    row.result.result_id,
                ))
            {
                return Err(Code::Invalid.error("profile interval winner"));
            }
        }
        if !intervals.is_empty() {
            return Err(Code::Missing.error("profile interval"));
        }
        for entry in view.snapshot.prefix(Processor::PREFIX) {
            let (key, _) = entry.context(crate::NativeStorageSnafu {
                operation: "validate processor states",
            })?;
            if key.len() != Processor::PREFIX.len() + 8 {
                return Err(Code::Invalid.error("processor state key"));
            }
            let bytes = Records::payload(&key, |key| Records::read(key, &view.snapshot))?
                .ok_or_else(|| Code::Missing.error("processor state"))?;
            let state: Processor = Records::decode(&bytes)?;
            let id = Self::number(&key[Processor::PREFIX.len()..])?;
            if let Some((request, revision)) = &state.retirement {
                if request.cutoff_cursor > request.expected_cursor {
                    let gap = crate::AnalysisGapV1 {
                        first_cursor: request.expected_cursor + 1,
                        last_cursor: request.cutoff_cursor,
                        commit_revision: *revision,
                    };
                    let key = [
                        Processor::key(Processor::GAPS, id),
                        gap.first_cursor.to_be_bytes().to_vec(),
                        gap.last_cursor.to_be_bytes().to_vec(),
                    ]
                    .concat();
                    gaps.insert(key, Records::named(&gap)?);
                }
            }
            self.validate_processor_history(id, state)?;
        }
        for entry in view.snapshot.prefix(Processor::GAPS) {
            let (key, value) = entry.context(crate::NativeStorageSnafu {
                operation: "validate processor gaps",
            })?;
            if gaps.remove(key.as_ref()).as_deref() != Some(value.as_ref()) {
                return Err(Code::Invalid.error("processor gap set"));
            }
        }
        if !gaps.is_empty() {
            return Err(Code::Missing.error("processor gap"));
        }
        for entry in view.snapshot.prefix(Notice::PREFIX) {
            let (key, _) = entry.context(crate::NativeStorageSnafu {
                operation: "validate profile notices",
            })?;
            if key.len() != Notice::PREFIX.len() + 8 {
                return Err(Code::Invalid.error("profile notice key"));
            }
            let id = Self::number(&key[Notice::PREFIX.len()..])?;
            let row = Notice::read(
                id,
                view.metadata_revision,
                |key| Records::read(key, &view.snapshot),
                &mut |_| Ok(()),
            )?
            .ok_or_else(|| Code::Missing.error("profile notice"))?;
            self.validate_notice_history(id, row)?;
        }
        Ok(())
    }

    fn validate_processor_history(&self, id: u64, mut state: Processor) -> Result<()> {
        loop {
            let at = self.read_at(state.revision)?;
            let actual = Processor::read(
                &state.scope,
                at.metadata_revision,
                |key| Records::read(key, &at.snapshot),
                &mut |_| Ok(()),
            )?;
            if actual
                .as_ref()
                .is_none_or(|(owner, saved)| *owner != id || *saved != state)
            {
                return Err(Code::Invalid.error("processor declared revision"));
            }
            state = actual
                .ok_or_else(|| Code::Missing.error("processor version"))?
                .1;
            let receipt = at.source_receipt(&state.scope.identity)?;
            let cursor = receipt
                .as_ref()
                .map_or(0, |receipt| receipt.contiguous_cursor);
            let coverage = receipt
                .as_ref()
                .map_or(0, |receipt| receipt.coverage_revision);
            if state.consumed > cursor
                || state.resumed > cursor
                || state.coverage > coverage
                || state
                    .retirement
                    .as_ref()
                    .is_some_and(|(request, revision)| {
                        *revision != state.revision || request.cutoff_cursor != cursor
                    })
            {
                return Err(Code::Invalid.error("processor source bounds"));
            }
            if let Some(head) = &state.head {
                let (_, result) = ResultRecord::read_header(
                    &head.result_id,
                    at.metadata_revision,
                    |key| Records::read(key, &at.snapshot),
                    &mut |_| Ok(()),
                )?
                .ok_or_else(|| Code::Missing.error("processor head"))?;
                if result.revision != head.commit_revision
                    || result.request.scope != state.scope
                    || result.request.consumed_cursor != state.consumed
                    || result.request.coverage_revision != state.coverage
                    || result.request.context_revision != state.context
                {
                    return Err(Code::Invalid.error("processor head progress"));
                }
            }
            let before = self.read_at(state.revision - 1)?;
            let prior = Processor::read(
                &state.scope,
                before.metadata_revision,
                |key| Records::read(key, &before.snapshot),
                &mut |_| Ok(()),
            )?;
            let Some((owner, prior)) = prior else {
                if state.head.is_some()
                    || state.retirement.is_some()
                    || state.consumed != state.start - 1
                    || state.resumed != state.start - 1
                    || state.coverage != 0
                    || state.context != 0
                {
                    return Err(Code::Invalid.error("processor initial state"));
                }
                return Ok(());
            };
            if owner != id
                || prior.revision >= state.revision
                || prior.class != state.class
                || prior.start != state.start
                || prior.retirement.is_some()
                || prior.consumed > state.consumed
                || prior.resumed > state.resumed
                || state.retirement.is_some()
                    && (state.head != prior.head
                        || state.consumed != prior.consumed
                        || state.resumed != prior.resumed
                        || state.coverage != prior.coverage
                        || state.context != prior.context)
            {
                return Err(Code::Invalid.error("processor transition"));
            }
            state = prior;
        }
    }

    fn validate_notice_history(&self, id: u64, mut row: Notice) -> Result<()> {
        loop {
            let at = self.read_at(row.revision)?;
            let current = Notice::read(
                id,
                at.metadata_revision,
                |key| Records::read(key, &at.snapshot),
                &mut |_| Ok(()),
            )?;
            if current.as_ref() != Some(&row) {
                return Err(Code::Invalid.error("notice declared revision"));
            }
            let (owner, result) = ResultRecord::read_header(
                &row.result.result_id,
                at.metadata_revision,
                |key| Records::read(key, &at.snapshot),
                &mut |_| Ok(()),
            )?
            .ok_or_else(|| Code::Missing.error("notice result"))?;
            if owner != id
                || result.revision != row.result.commit_revision
                || result.request.scope != row.scope
                || result
                    .header
                    .facts_revision
                    .is_none_or(|facts| row.facts < facts)
                || result
                    .header
                    .coverage_revision
                    .is_none_or(|coverage| row.coverage < coverage)
            {
                return Err(Code::Invalid.error("notice owner"));
            }
            let before = self.read_at(row.revision - 1)?;
            let prior = Notice::read(
                id,
                before.metadata_revision,
                |key| Records::read(key, &before.snapshot),
                &mut |_| Ok(()),
            )?;
            let Some(prior) = prior else {
                if result.header.facts_revision == Some(row.facts)
                    && result.header.coverage_revision == Some(row.coverage)
                {
                    return Err(Code::Invalid.error("unchanged profile notice"));
                }
                return Ok(());
            };
            if prior.revision >= row.revision
                || prior.scope != row.scope
                || prior.result != row.result
                || prior.facts > row.facts
                || prior.coverage > row.coverage
                || (prior.facts, prior.coverage) == (row.facts, row.coverage)
            {
                return Err(Code::Invalid.error("notice transition"));
            }
            row = prior;
        }
    }
}
