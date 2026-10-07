use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message as _;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;
use tokio::sync::watch;

use super::model::{add, require, InputByteLimit};
use super::*;
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisGapV1,
    AnalysisResultCommitV1, AnalysisSourceStatusV1, AnalysisWitnessV1, ContextSensitivityV1,
    CoverageReport, DiscoveryEncodingSnafu, DiscoveryExecutionSnafu, EvidenceIntakeIdentityV1,
    ProcessorClassV1, ProcessorScopeV1,
};

use crate::analysis::{MAX_RESULT_BYTES, MAX_RESULT_REFS};

impl crate::CoverageInterval {
    fn has_gap(&self) -> bool {
        self.state == "GAPPED"
            || !self.gap_reasons.is_empty()
            || self
                .opening_counters
                .as_ref()
                .zip(self.closing_counters.as_ref())
                .is_some_and(|(before, after)| {
                    after.lost != before.lost
                        || after.suppressed != before.suppressed
                        || after.unresolved != before.unresolved
                        || after.classifier_miss_count != before.classifier_miss_count
                        || after.attempted < before.attempted
                        || after.requested < before.requested
                        || after.emitted < before.emitted
                        || after.next_sequence < before.next_sequence
                })
    }

    fn is_complete(&self) -> bool {
        matches!(self.state.as_str(), "HEALTHY" | "CLOSED")
            && !self.has_gap()
            && self
                .opening_counters
                .as_ref()
                .zip(self.closing_counters.as_ref())
                .is_some_and(|(before, after)| {
                    [before, after].into_iter().all(|counters| {
                        counters.suppressed.checked_add(counters.requested)
                            == Some(counters.attempted)
                            && counters.emitted.checked_add(counters.lost)
                                == Some(counters.requested)
                    }) && before.next_sequence <= self.first_sequence
                        && self
                            .last_sequence
                            .is_some_and(|last| after.next_sequence > last)
                })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryProfileV1 {
    pub schema_version: u32,
    pub scope: ProcessorScopeV1,
    pub profile_id: String,
    pub interval_id: String,
    pub revision: u64,
    pub facts_revision: u64,
    pub coverage_revision: u64,
    pub created_utc_ns: u64,
    pub updated_utc_ns: u64,
    pub sealed: bool,
    pub input_bytes: u64,
    pub incomplete: bool,
    pub gaps: Vec<AnalysisGapV1>,
    pub snapshot: BehaviorSnapshotV1,
    pub context_refs: Vec<AnalysisContextRefV1>,
}

impl DiscoveryProfileV1 {
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema_version == DISCOVERY_SCHEMA_VERSION
                && self.scope.processor_id == DISCOVERY_PROCESSOR
                && self.scope.method_version == DISCOVERY_SCHEMA_VERSION as u64
                && self.scope.identity.valid()
                && self.snapshot.tenant_id == self.scope.identity.tenant_id
                && !self.profile_id.is_empty()
                && self.profile_id.len() <= 256
                && !self.interval_id.is_empty()
                && self.interval_id.len() <= 256
                && self.revision > 0
                && self.created_utc_ns > 0
                && self.updated_utc_ns >= self.created_utc_ns
                && self.input_bytes <= DISCOVERY_INPUT_BYTES as u64
                && self.gaps.len() <= 256
                && (self.gaps.is_empty() || self.incomplete)
                && self.gaps.iter().all(|gap| {
                    gap.first_cursor > 0
                        && gap.last_cursor >= gap.first_cursor
                        && gap.commit_revision > 0
                })
                && self
                    .gaps
                    .windows(2)
                    .all(|pair| pair[0].last_cursor < pair[1].first_cursor)
                && self.context_refs.len() <= 256
                && self
                    .context_refs
                    .windows(2)
                    .all(|pair| pair[0].key < pair[1].key)
                && self.context_refs.iter().all(|reference| {
                    reference.key.tenant_id == self.scope.identity.tenant_id
                        && reference.key.valid()
                        && reference.commit_revision > 0
                })
                && self
                    .snapshot
                    .coverage
                    .iter()
                    .all(|range| range.stream == self.scope.identity),
            "profile bounds",
        )?;
        self.snapshot.validate()
    }
}

impl TryFrom<&[u8]> for DiscoveryProfileV1 {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        require(bytes.len() <= MAX_RESULT_BYTES, "profile bytes")?;
        let profile: Self = serde_json::from_slice(bytes).context(DiscoveryEncodingSnafu)?;
        profile.validate()?;
        Ok(profile)
    }
}

impl DiscoveryOwner {
    pub async fn run(self: Arc<Self>, mut stop: watch::Receiver<bool>) -> Result<()> {
        let mut changes = self.store.subscribe_revision();
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            changes.borrow_and_update();
            let owner = Arc::clone(&self);
            let result = tokio::task::spawn_blocking(move || {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .and_then(|time| u64::try_from(time.as_nanos()).ok())
                    .ok_or_else(|| crate::DiscoveryInvalidSnafu { field: "clock" }.build())?;
                owner.process(now)
            })
            .await
            .context(DiscoveryExecutionSnafu)?;
            let count = match result {
                Ok(count) => count,
                Err(
                    crate::Error::AnalysisBusy { .. } | crate::Error::AnalysisReadDeadline { .. },
                ) => 0,
                Err(error) => return Err(error),
            };
            if count > 0 {
                tokio::task::yield_now().await;
                continue;
            }
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() { return Ok(()); }
                }
                changed = changes.changed() => {
                    if changed.is_err() { return Ok(()); }
                }
                _ = timer.tick() => {}
            }
        }
    }

    pub fn process(&self, now: u64) -> Result<usize> {
        require(now > 0, "clock")?;
        let mut after = self.operation.lock().map_err(|_| {
            crate::DiscoveryInvalidSnafu {
                field: "worker lock",
            }
            .build()
        })?;
        let sources = self.sources(after.as_ref())?;
        *after = sources.last().cloned();
        let mut count = 0;
        for source in sources {
            let processed = self.process_source(source.clone(), now)?;
            if processed == 0 {
                self.refresh_source(&source, now, false)?;
            }
            count += processed;
        }
        Ok(count)
    }

    fn sources(
        &self,
        after: Option<&EvidenceIntakeIdentityV1>,
    ) -> Result<Vec<EvidenceIntakeIdentityV1>> {
        let mut sources = Vec::new();
        if let Some(after) = after {
            sources.extend(self.store.source_page(after.tenant_id, Some(after))?);
        }
        for tenant in self
            .store
            .tenant_page(after.map(|source| source.tenant_id))?
        {
            if sources.len() >= self.config.sources_per_pass {
                break;
            }
            sources.extend(self.store.source_page(tenant, None)?);
        }
        if sources.is_empty() && after.is_some() {
            return self.sources(None);
        }
        sources.truncate(self.config.sources_per_pass);
        Ok(sources)
    }

    pub fn profile(&self, source: &EvidenceIntakeIdentityV1) -> Result<Option<DiscoveryProfileV1>> {
        let scope = ProcessorScopeV1 {
            processor_id: DISCOVERY_PROCESSOR.into(),
            method_version: DISCOVERY_SCHEMA_VERSION as u64,
            identity: source.clone(),
        };
        self.store
            .processor_result(&scope)?
            .map(|result| DiscoveryProfileV1::try_from(result.body.as_slice()))
            .transpose()
    }

    fn process_source(&self, source: EvidenceIntakeIdentityV1, now: u64) -> Result<usize> {
        let scope = ProcessorScopeV1 {
            processor_id: DISCOVERY_PROCESSOR.into(),
            method_version: DISCOVERY_SCHEMA_VERSION as u64,
            identity: source.clone(),
        };
        let Some(status) = self.store.source_status(&source)? else {
            return Ok(0);
        };
        if self.store.processor_health(&scope)?.is_none() {
            self.store
                .register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        }
        let head = self.store.processor_result(&scope)?;
        let previous = head
            .as_ref()
            .map(|head| DiscoveryProfileV1::try_from(head.body.as_slice()))
            .transpose()?;
        require(
            previous
                .as_ref()
                .is_none_or(|profile| profile.scope == scope),
            "profile source scope",
        )?;
        let gap_floor = previous.as_ref().map_or(0, |profile| {
            profile
                .snapshot
                .coverage
                .iter()
                .map(|range| range.last_cursor)
                .chain(profile.gaps.iter().map(|gap| gap.last_cursor))
                .max()
                .unwrap_or(0)
        });
        let mut gap_count = 0;
        while let Some(gap) = self.store.resume_optional(&scope)? {
            gap_count += 1;
            require(gap_count <= 256 && gap.last_cursor > 0, "resume gap count")?;
        }
        let gaps = self.store.processor_gaps(&scope, gap_floor)?;
        let health = self.store.processor_health(&scope)?.ok_or_else(|| {
            crate::DiscoveryInvalidSnafu {
                field: "processor health",
            }
            .build()
        })?;
        let expected = health.consumed_cursor.max(health.resume_floor);
        let continuing = previous.as_ref().is_some_and(|profile| !profile.sealed);
        let mut profile = if continuing {
            previous.ok_or_else(|| {
                crate::DiscoveryInvalidSnafu {
                    field: "working profile",
                }
                .build()
            })?
        } else {
            let profile_id = format!("discovery:{}", uuid::Uuid::new_v4());
            DiscoveryProfileV1 {
                schema_version: DISCOVERY_SCHEMA_VERSION,
                scope: scope.clone(),
                interval_id: profile_id.clone(),
                profile_id,
                revision: 1,
                facts_revision: self.provider.revision(&source)?,
                coverage_revision: status.receipt.coverage_revision,
                created_utc_ns: now,
                updated_utc_ns: now,
                sealed: false,
                input_bytes: 0,
                incomplete: health.incomplete,
                gaps: Vec::new(),
                snapshot: Self::derive_recorded(&DiscoveryInputManifestV1 {
                    schema_version: DISCOVERY_SCHEMA_VERSION,
                    tenant_id: source.tenant_id,
                    source_revision: "live-v1".into(),
                    proof_kind: DiscoveryProofKindV1::ObservedRuntime,
                    coverage: Vec::new(),
                    contexts: Vec::new(),
                    records: Vec::new(),
                    exclusions: Vec::new(),
                    lifecycle: Vec::new(),
                })?
                .snapshot,
                context_refs: Vec::new(),
            }
        };
        require(now >= profile.updated_utc_ns, "clock order")?;
        profile.incomplete |= health.incomplete || !gaps.is_empty();
        profile.gaps.extend(gaps.iter().copied());
        let elapsed = now - profile.created_utc_ns >= self.config.seal_interval_ns;
        let mut records = Vec::new();
        let mut contexts = Vec::new();
        let mut facts = BTreeMap::new();
        let mut consumed = expected;
        let mut bytes = 0_u64;
        let mut bounded = false;
        if expected < status.receipt.contiguous_cursor && !elapsed {
            let page = self.store.read_page(&source, expected + 1)?;
            for stored in page.records {
                if stored.cursor > status.receipt.contiguous_cursor {
                    break;
                }
                require(stored.cursor == consumed + 1, "contiguous input")?;
                if profile.snapshot.accepted_records + records.len() as u64
                    >= self.config.interval_records as u64
                    || profile.input_bytes + bytes + stored.framed_record.len() as u64
                        > self.config.input_bytes as u64
                    || profile.context_refs.len() >= 255
                {
                    require(
                        profile.snapshot.accepted_records + records.len() as u64 > 0,
                        "single record limit",
                    )?;
                    bounded = true;
                    break;
                }
                let record =
                    DiscoveryRecordV1::try_from((&source, status.receipt.cpu_id, &stored))?;
                let mut record_bytes = stored.framed_record.len() as u64;
                if let DiscoveryContextJoinV1::Available(pinned) =
                    self.provider.context(&record)?.into_bounded()
                {
                    pinned.validate()?;
                    require(
                        pinned.binding.record_id == record.id,
                        "context record identity",
                    )?;
                    record_bytes += serde_json::to_vec(&pinned.binding)
                        .context(DiscoveryEncodingSnafu)?
                        .len() as u64;
                    if profile.input_bytes + bytes + record_bytes > self.config.input_bytes as u64 {
                        require(
                            profile.snapshot.accepted_records + records.len() as u64 > 0,
                            "single record limit",
                        )?;
                        bounded = true;
                        break;
                    }
                    let context = AnalysisContextVersionV1::try_from(pinned.as_ref())?;
                    facts.insert(record.id.clone(), context);
                    contexts.push(pinned.binding.clone());
                }
                consumed = stored.cursor;
                bytes += record_bytes;
                records.push(record);
            }
        }
        if !records.is_empty() {
            let mut input = DiscoveryInputManifestV1 {
                schema_version: DISCOVERY_SCHEMA_VERSION,
                tenant_id: source.tenant_id,
                source_revision: "live-v1".into(),
                proof_kind: DiscoveryProofKindV1::ObservedRuntime,
                coverage: Self::coverage(&status, &records)?,
                contexts,
                records,
                exclusions: Vec::new(),
                lifecycle: Vec::new(),
            };
            let admitted = self.bound_page(&profile, &status, &input, &facts, now)?;
            bounded |= admitted < input.records.len();
            if admitted > 0 {
                input.records.truncate(admitted);
                consumed = input
                    .records
                    .last()
                    .map_or(expected, |record| record.id.durable_cursor);
                input
                    .contexts
                    .retain(|context| context.record_id.durable_cursor <= consumed);
                input.coverage = Self::coverage(&status, &input.records)?;
                let next = Self::derive_recorded(&input)?.snapshot;
                profile.snapshot = profile.snapshot.merge(&next)?;
                bytes = Self::input_size(&input)?;
                add(&mut profile.input_bytes, bytes)?;
                let mut distinct = BTreeSet::new();
                for context in facts.into_iter().filter_map(|(record, context)| {
                    (record.durable_cursor <= consumed).then_some(context)
                }) {
                    if distinct.insert(context.body.clone()) {
                        let reference = self.store.intern_context(&context)?;
                        if !profile
                            .context_refs
                            .iter()
                            .any(|stored| stored.key == reference.key)
                        {
                            profile.context_refs.push(reference);
                        }
                    }
                }
                profile
                    .context_refs
                    .sort_by(|left, right| left.key.cmp(&right.key));
            } else {
                consumed = expected;
            }
        }
        profile.sealed = elapsed
            || bounded
            || profile.snapshot.accepted_records >= self.config.interval_records as u64
            || profile.input_bytes >= self.config.input_bytes as u64
            || profile.snapshot.atoms.len() >= self.config.atom_limit
            || profile.context_refs.len() >= 256;
        if consumed == expected && gaps.is_empty() && (!profile.sealed || !continuing) {
            return Ok(0);
        }
        let health_context = self.source_context(&status, &profile, health.consumed_cursor, now)?;
        profile
            .context_refs
            .retain(|reference| reference.key.owner_id != "discovery-source-v1");
        profile.context_refs.push(health_context);
        profile
            .context_refs
            .sort_by(|left, right| left.key.cmp(&right.key));
        require(profile.context_refs.len() <= 256, "profile context count")?;
        profile.sealed |= profile.context_refs.len() >= 256;
        if continuing {
            add(&mut profile.revision, 1)?;
        }
        profile.updated_utc_ns = now;
        profile.coverage_revision = status.receipt.coverage_revision;
        let mut samples = BTreeSet::new();
        if profile.sealed {
            for atom in &profile.snapshot.atoms {
                samples.extend(atom.evidence_sample.iter().cloned());
            }
        }
        require(samples.len() <= MAX_RESULT_REFS, "profile witness count")?;
        let deadline = now.checked_add(self.config.witness_age_ns).ok_or_else(|| {
            crate::DiscoveryInvalidSnafu {
                field: "witness deadline",
            }
            .build()
        })?;
        let witnesses = samples
            .into_iter()
            .filter(|sample| sample.durable_cursor > status.receipt.retained_floor)
            .map(|sample| AnalysisWitnessV1 {
                identity: sample.stream.into(),
                cursor: sample.durable_cursor,
                expires_utc_ns: deadline,
            })
            .collect();
        profile.validate()?;
        self.store.commit_working(
            &AnalysisResultCommitV1 {
                scope,
                expected_cursor: expected,
                consumed_cursor: consumed,
                coverage_revision: status.receipt.coverage_revision,
                context_revision: profile
                    .context_refs
                    .iter()
                    .map(|reference| reference.commit_revision)
                    .max()
                    .unwrap_or(0),
                result_id: profile.profile_id.clone(),
                body: serde_json::to_vec(&profile).context(DiscoveryEncodingSnafu)?,
                created_utc_ns: now,
                witnesses,
                context_refs: profile.context_refs.clone(),
            },
            if continuing {
                head.map(|head| head.commit_revision)
            } else {
                None
            },
        )?;
        Ok(usize::try_from(consumed - expected).unwrap_or(usize::MAX))
    }

    fn input_size(input: &DiscoveryInputManifestV1) -> Result<u64> {
        let mut bytes = 0;
        for record in &input.records {
            add(&mut bytes, record.wire_record.len() as u64)?;
        }
        for context in &input.contexts {
            add(
                &mut bytes,
                serde_json::to_vec(context)
                    .context(DiscoveryEncodingSnafu)?
                    .len() as u64,
            )?;
        }
        Ok(bytes)
    }

    fn bound_page(
        &self,
        profile: &DiscoveryProfileV1,
        status: &AnalysisSourceStatusV1,
        input: &DiscoveryInputManifestV1,
        facts: &BTreeMap<DiscoveryRecordIdV1, AnalysisContextVersionV1>,
        now: u64,
    ) -> Result<usize> {
        let mut count = input.records.len();
        loop {
            let records = input.records[..count].to_vec();
            let cursor = records.last().map_or(0, |record| record.id.durable_cursor);
            let candidate = DiscoveryInputManifestV1 {
                records,
                contexts: input
                    .contexts
                    .iter()
                    .filter(|context| context.record_id.durable_cursor <= cursor)
                    .cloned()
                    .collect(),
                coverage: Self::coverage(status, &input.records[..count])?,
                ..input.clone()
            };
            let snapshot = Self::derive_recorded(&candidate)?.snapshot;
            let atom_count = profile
                .snapshot
                .atoms
                .iter()
                .chain(&snapshot.atoms)
                .map(|atom| &atom.key)
                .collect::<BTreeSet<_>>()
                .len();
            if atom_count > self.config.atom_limit {
                if count <= 1 {
                    require(profile.snapshot.accepted_records > 0, "single result limit")?;
                    return Ok(0);
                }
                count /= 2;
                continue;
            }
            let mut next = profile.clone();
            next.snapshot = profile.snapshot.merge(&snapshot)?;
            add(&mut next.input_bytes, Self::input_size(&candidate)?)?;
            next.updated_utc_ns = now;
            next.revision = next.revision.saturating_add(1);
            next.sealed = true;
            next.context_refs
                .retain(|reference| reference.key.owner_id != "discovery-source-v1");
            let mut distinct = BTreeSet::new();
            for (_, context) in facts
                .iter()
                .filter(|(record, _)| record.durable_cursor <= cursor)
            {
                if distinct.insert(&context.body) {
                    let mut key = context.key.clone();
                    key.entity_key.fill(255);
                    next.context_refs.push(AnalysisContextRefV1 {
                        key,
                        commit_revision: u64::MAX,
                    });
                }
            }
            next.context_refs.push(AnalysisContextRefV1 {
                key: AnalysisContextKeyV1 {
                    tenant_id: profile.scope.identity.tenant_id,
                    owner_id: "discovery-source-v1".into(),
                    entity_key: vec![255; 16],
                    lifetime_key: profile.scope.identity.key(),
                    owner_revision: u64::MAX,
                },
                commit_revision: u64::MAX,
            });
            if self.profile_fits(&next) {
                return Ok(count);
            }
            if count <= 1 {
                require(profile.snapshot.accepted_records > 0, "single result limit")?;
                return Ok(0);
            }
            count /= 2;
        }
    }

    fn profile_fits(&self, profile: &DiscoveryProfileV1) -> bool {
        profile.input_bytes <= self.config.input_bytes as u64
            && profile.snapshot.atoms.len() <= self.config.atom_limit
            && profile.context_refs.len() <= 256
            && profile
                .snapshot
                .atoms
                .iter()
                .flat_map(|atom| &atom.evidence_sample)
                .collect::<BTreeSet<_>>()
                .len()
                <= MAX_RESULT_REFS
            && serde_json::to_writer(InputByteLimit(MAX_RESULT_BYTES), profile).is_ok()
    }

    fn bound_refresh(
        &self,
        profile: &DiscoveryProfileV1,
        input: &mut DiscoveryInputManifestV1,
        facts: &BTreeMap<DiscoveryRecordIdV1, AnalysisContextVersionV1>,
        frozen: usize,
        now: u64,
    ) -> Result<Option<BehaviorSnapshotV1>> {
        let mut count = input.contexts.len() - frozen;
        loop {
            input.contexts.truncate(frozen + count);
            let snapshot = match Self::derive_recorded(input) {
                Ok(result) => Some(result.snapshot),
                Err(crate::Error::DiscoveryInvalid {
                    field: "atom count",
                    ..
                }) => None,
                Err(error) => return Err(error),
            };
            if let Some(snapshot) = snapshot {
                let mut next = profile.clone();
                next.snapshot = snapshot;
                next.input_bytes = Self::input_size(input)?;
                next.updated_utc_ns = now;
                next.revision = next.revision.saturating_add(1);
                next.facts_revision = u64::MAX;
                next.coverage_revision = u64::MAX;
                next.context_refs
                    .retain(|reference| reference.key.owner_id != "discovery-source-v1");
                let admitted: BTreeSet<_> = input.contexts[frozen..]
                    .iter()
                    .map(|context| &context.record_id)
                    .collect();
                for (_, context) in facts.iter().filter(|(record, _)| admitted.contains(record)) {
                    let mut key = context.key.clone();
                    key.entity_key.fill(255);
                    key.owner_revision = u64::MAX;
                    next.context_refs.push(AnalysisContextRefV1 {
                        key,
                        commit_revision: u64::MAX,
                    });
                }
                next.context_refs.push(AnalysisContextRefV1 {
                    key: AnalysisContextKeyV1 {
                        tenant_id: profile.scope.identity.tenant_id,
                        owner_id: "discovery-source-v1".into(),
                        entity_key: vec![255; 16],
                        lifetime_key: profile.scope.identity.key(),
                        owner_revision: u64::MAX,
                    },
                    commit_revision: u64::MAX,
                });
                if self.profile_fits(&next) {
                    return Ok(Some(next.snapshot));
                }
            }
            if count == 0 {
                return Ok(None);
            }
            count /= 2;
        }
    }

    fn coverage(
        status: &AnalysisSourceStatusV1,
        records: &[DiscoveryRecordV1],
    ) -> Result<Vec<DiscoveryCoverageV1>> {
        let report = status
            .latest_coverage_report
            .as_deref()
            .map(CoverageReport::decode)
            .transpose()
            .context(crate::EvidenceDecodeSnafu {
                frame_bytes: status.latest_coverage_report.as_ref().map_or(0, Vec::len),
            })?;
        let mut ranges = Vec::<DiscoveryCoverageV1>::new();
        for record in records {
            let wire = record.decode()?;
            let interval_id = wire
                .coverage_interval_id
                .as_ref()
                .try_into()
                .unwrap_or(status.receipt.identity.source_id);
            let interval = report
                .as_ref()
                .filter(|report| {
                    report.cpu_id == record.id.cpu_id
                        && report.source_id.as_ref() == record.id.stream.source_id
                        && report.source_epoch == record.id.stream.source_epoch
                })
                .and_then(|report| {
                    report.intervals.iter().find(|interval| {
                        interval.interval_id.as_ref() == interval_id
                            && interval.source_epoch == record.id.stream.source_epoch
                    })
                });
            let mut reasons = interval
                .map(|interval| interval.gap_reasons.clone())
                .unwrap_or_else(|| vec!["MISSING_COVERAGE_REPORT".into()]);
            let state = match interval {
                Some(interval) if interval.has_gap() => {
                    if reasons.is_empty() {
                        reasons.push("SOURCE_COVERAGE_GAPPED".into());
                    }
                    DiscoveryCoverageStateV1::Gapped
                }
                Some(interval)
                    if interval.is_complete()
                        && wire.temporal_coverage
                            == crate::EvidenceTemporalCoverage::Complete as i32
                        && wire.decision_context.as_ref().is_some_and(|context| {
                            context.original_kernel_sequence >= interval.first_sequence
                                && interval
                                    .last_sequence
                                    .is_some_and(|last| context.original_kernel_sequence <= last)
                        }) =>
                {
                    if interval.state == "CLOSED" {
                        DiscoveryCoverageStateV1::Closed
                    } else {
                        DiscoveryCoverageStateV1::Healthy
                    }
                }
                _ => {
                    if reasons.is_empty() {
                        reasons.push("COVERAGE_UNQUALIFIED".into());
                    }
                    DiscoveryCoverageStateV1::Unknown
                }
            };
            if let Some(last) = ranges.last_mut().filter(|last| {
                last.coverage_interval_id == interval_id
                    && last.last_cursor + 1 == record.id.durable_cursor
                    && last.state == state
                    && last.gap_reasons == reasons
            }) {
                last.last_cursor = record.id.durable_cursor;
                last.expected_records += 1;
                continue;
            }
            ranges.push(DiscoveryCoverageV1 {
                stream: record.id.stream.clone(),
                cpu_id: record.id.cpu_id,
                first_cursor: record.id.durable_cursor,
                last_cursor: record.id.durable_cursor,
                expected_records: 1,
                coverage_revision: status.receipt.coverage_revision,
                coverage_interval_id: interval_id,
                state,
                gap_reasons: reasons,
            });
        }
        Ok(ranges)
    }

    pub fn refresh(&self, source: &EvidenceIntakeIdentityV1, now: u64) -> Result<bool> {
        require(now > 0, "clock")?;
        let _operation = self.operation.lock().map_err(|_| {
            crate::DiscoveryInvalidSnafu {
                field: "worker lock",
            }
            .build()
        })?;
        self.refresh_source(source, now, true)
    }

    fn refresh_source(
        &self,
        source: &EvidenceIntakeIdentityV1,
        now: u64,
        force: bool,
    ) -> Result<bool> {
        let scope = ProcessorScopeV1 {
            processor_id: DISCOVERY_PROCESSOR.into(),
            method_version: DISCOVERY_SCHEMA_VERSION as u64,
            identity: source.clone(),
        };
        let Some(head) = self.store.processor_result(&scope)? else {
            return Ok(false);
        };
        let coverage = self
            .store
            .source_receipt(source)?
            .map_or(0, |receipt| receipt.coverage_revision);
        let notices =
            self.store
                .profile_notices(&scope, self.provider.revision(source)?, coverage)?;
        let mut changed = false;
        if force && !notices.iter().any(|(id, _)| id == &head.result_id) {
            changed |= self.refresh_profile(
                DiscoveryProfileV1::try_from(head.body.as_slice())?,
                head.commit_revision,
                true,
                now,
            )?;
        }
        for (id, revision) in notices {
            let Some(body) = self.store.read_result(source.tenant_id, &id)? else {
                continue;
            };
            let profile = DiscoveryProfileV1::try_from(body.as_slice())?;
            require(profile.scope == scope, "profile source scope")?;
            changed |= self.refresh_profile(profile, revision, id == head.result_id, now)?;
        }
        Ok(changed)
    }

    fn refresh_profile(
        &self,
        mut profile: DiscoveryProfileV1,
        revision: u64,
        publish: bool,
        now: u64,
    ) -> Result<bool> {
        let source = profile.scope.identity.clone();
        let Some(status) = self.store.source_status(&source)? else {
            return Ok(false);
        };
        let Some(mut input) = self.replay_input(&profile)? else {
            self.store.mark_notice(
                &profile,
                revision,
                self.provider.revision(&source)?,
                status.receipt.coverage_revision,
            )?;
            return Ok(false);
        };
        require(now >= profile.updated_utc_ns, "clock order")?;
        let mut references: Vec<_> = profile
            .context_refs
            .iter()
            .filter(|reference| reference.key.owner_id != "discovery-source-v1")
            .cloned()
            .collect();
        let mut known = BTreeSet::new();
        for reference in &references {
            if reference.key.owner_id == "discovery-facts-v1" {
                let version = self.store.context_version(&reference.key)?.ok_or_else(|| {
                    crate::DiscoveryInvalidSnafu {
                        field: "retained context",
                    }
                    .build()
                })?;
                known.insert(version.body);
            }
        }
        let mut facts = BTreeMap::new();
        let frozen_count = input.contexts.len();
        let frozen: BTreeSet<_> = input
            .contexts
            .iter()
            .map(|context| context.record_id.clone())
            .collect();
        let mut input_bytes = Self::input_size(&input)?;
        for record in &input.records {
            if frozen.contains(&record.id)
                || input
                    .exclusions
                    .iter()
                    .any(|item| item.record_id == record.id)
            {
                continue;
            }
            if let DiscoveryContextJoinV1::Available(pinned) =
                self.provider.context(record)?.into_bounded()
            {
                pinned.validate()?;
                require(
                    pinned.binding.record_id == record.id,
                    "context record identity",
                )?;
                let bytes = serde_json::to_vec(&pinned.binding)
                    .context(DiscoveryEncodingSnafu)?
                    .len();
                let next_bytes = input_bytes.checked_add(bytes as u64).ok_or_else(|| {
                    crate::DiscoveryInvalidSnafu {
                        field: "context input bytes",
                    }
                    .build()
                })?;
                let context = AnalysisContextVersionV1::try_from(pinned.as_ref())?;
                if next_bytes > self.config.input_bytes as u64
                    || (!known.contains(&context.body) && references.len() + facts.len() >= 255)
                {
                    continue;
                }
                if known.insert(context.body.clone()) {
                    facts.insert(record.id.clone(), context);
                }
                input_bytes = next_bytes;
                input.contexts.push(pinned.binding.clone());
            }
        }
        if let Some(bytes) = &status.latest_coverage_report {
            let report =
                CoverageReport::decode(bytes.as_slice()).context(crate::EvidenceDecodeSnafu {
                    frame_bytes: bytes.len(),
                })?;
            if input.coverage.iter().all(|range| {
                report
                    .intervals
                    .iter()
                    .any(|interval| interval.interval_id.as_ref() == range.coverage_interval_id)
            }) {
                input.coverage = Self::coverage(&status, &input.records)?;
            }
        }
        let facts_revision = self.provider.revision(&source)?;
        let Some(snapshot) = self.bound_refresh(&profile, &mut input, &facts, frozen_count, now)?
        else {
            self.store.mark_notice(
                &profile,
                revision,
                facts_revision,
                status.receipt.coverage_revision,
            )?;
            return Ok(false);
        };
        input_bytes = Self::input_size(&input)?;
        if snapshot == profile.snapshot
            && facts_revision <= profile.facts_revision
            && status.receipt.coverage_revision <= profile.coverage_revision
        {
            return Ok(false);
        }
        let admitted: BTreeSet<_> = input.contexts[frozen_count..]
            .iter()
            .map(|context| &context.record_id)
            .collect();
        for (_, context) in facts
            .into_iter()
            .filter(|(record, _)| admitted.contains(record))
        {
            let reference = self.store.intern_context(&context)?;
            if !references.iter().any(|stored| stored.key == reference.key) {
                references.push(reference);
            }
        }
        references.sort_by(|left, right| left.key.cmp(&right.key));
        let prior = if profile.sealed {
            profile.profile_id = format!("discovery:{}", uuid::Uuid::new_v4());
            None
        } else {
            Some(revision)
        };
        profile.snapshot = snapshot;
        profile.input_bytes = input_bytes;
        profile.facts_revision = facts_revision;
        profile.coverage_revision = status.receipt.coverage_revision;
        profile.context_refs = references;
        profile.updated_utc_ns = now;
        add(&mut profile.revision, 1)?;
        profile.validate()?;
        let health = self
            .store
            .processor_health(&profile.scope)?
            .ok_or_else(|| {
                crate::DiscoveryInvalidSnafu {
                    field: "processor health",
                }
                .build()
            })?;
        let cursor = health.consumed_cursor.max(health.resume_floor);
        profile.context_refs.push(self.source_context(
            &status,
            &profile,
            health.consumed_cursor,
            now,
        )?);
        profile
            .context_refs
            .sort_by(|left, right| left.key.cmp(&right.key));
        profile.validate()?;
        let deadline = now.checked_add(self.config.witness_age_ns).ok_or_else(|| {
            crate::DiscoveryInvalidSnafu {
                field: "witness deadline",
            }
            .build()
        })?;
        let samples = if profile.sealed {
            profile
                .snapshot
                .atoms
                .iter()
                .flat_map(|atom| atom.evidence_sample.iter().cloned())
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        require(samples.len() <= MAX_RESULT_REFS, "profile witness count")?;
        let commit = AnalysisResultCommitV1 {
            scope: profile.scope.clone(),
            expected_cursor: cursor,
            consumed_cursor: cursor,
            coverage_revision: status.receipt.coverage_revision,
            context_revision: profile
                .context_refs
                .iter()
                .map(|reference| reference.commit_revision)
                .max()
                .unwrap_or(0),
            result_id: profile.profile_id.clone(),
            body: serde_json::to_vec(&profile).context(DiscoveryEncodingSnafu)?,
            created_utc_ns: now,
            witnesses: samples
                .into_iter()
                .map(|sample| AnalysisWitnessV1 {
                    identity: sample.stream.into(),
                    cursor: sample.durable_cursor,
                    expires_utc_ns: deadline,
                })
                .collect(),
            context_refs: profile.context_refs.clone(),
        };
        if publish {
            self.store.commit_working(&commit, prior)?;
        } else {
            require(profile.sealed, "historical profile state")?;
            self.store.commit_profile(&commit)?;
        }
        Ok(true)
    }

    fn source_context(
        &self,
        status: &AnalysisSourceStatusV1,
        profile: &DiscoveryProfileV1,
        consumed: u64,
        now: u64,
    ) -> Result<AnalysisContextRefV1> {
        let unknown = profile
            .snapshot
            .coverage
            .iter()
            .any(|range| matches!(range.state, DiscoveryCoverageStateV1::Unknown));
        let gapped = profile.incomplete
            || profile
                .snapshot
                .coverage
                .iter()
                .any(|range| matches!(range.state, DiscoveryCoverageStateV1::Gapped));
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: profile.scope.identity.tenant_id,
                owner_id: "discovery-source-v1".into(),
                entity_key: uuid::Uuid::new_v4().as_bytes().to_vec(),
                lifetime_key: profile.scope.identity.key(),
                owner_revision: status.receipt.coverage_revision,
            },
            valid_from_utc_ns: Some(now),
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: serde_json::to_vec(&serde_json::json!({
                "kind": "SOURCE_HEALTH", "source": profile.scope.identity,
                "cpu_id": status.receipt.cpu_id,
                "accepted_cursor": status.receipt.contiguous_cursor,
                "consumed_cursor": consumed,
                "interval_first_cursor": profile.snapshot.coverage.first().map(|range| range.first_cursor),
                "interval_last_cursor": profile.snapshot.coverage.last().map(|range| range.last_cursor),
                "retained_floor": status.receipt.retained_floor,
                "coverage_revision": status.receipt.coverage_revision,
                "unknown": unknown, "gapped": gapped,
                "interval_id": profile.interval_id,
            }))
            .context(DiscoveryEncodingSnafu)?,
        };
        self.store.intern_context(&context)
    }
}

impl TryFrom<&DiscoveryPinnedContextV1> for AnalysisContextVersionV1 {
    type Error = crate::Error;

    fn try_from(pinned: &DiscoveryPinnedContextV1) -> Result<Self> {
        pinned.validate()?;
        let binding = &pinned.binding;
        let key = AnalysisContextKeyV1 {
            tenant_id: binding.record_id.stream.tenant_id,
            owner_id: "discovery-facts-v1".into(),
            entity_key: uuid::Uuid::new_v4().as_bytes().to_vec(),
            lifetime_key: binding.record_id.stream.key(),
            owner_revision: pinned.control_commit_index,
        };
        require(key.valid(), "qualified context key")?;
        let body = serde_json::to_vec(&serde_json::json!({
            "subject_revision": binding.subject_revision,
            "image_digest": binding.image_digest,
            "configuration_digest": binding.configuration_digest,
            "process_instance_id": binding.process_instance_id,
            "entry_instance_id": binding.entry_instance_id,
            "binding_id": binding.binding_id,
            "role_id": binding.role_id, "state_id": binding.state_id,
            "entry_rule_id": binding.entry_rule_id, "catalog_revision": binding.catalog_revision,
            "static_key": binding.static_key, "policy_revision": binding.policy_revision,
            "workload": pinned.workload,
            "policy_source_revision_id": pinned.policy_source_revision_id,
            "target_snapshot_digest": pinned.target_snapshot_digest,
            "signed_profile_digest": pinned.signed_profile_digest,
            "control_commit_index": pinned.control_commit_index,
        }))
        .context(DiscoveryEncodingSnafu)?;
        require(body.len() <= DISCOVERY_PIN_BYTES, "qualified context bytes")?;
        Ok(Self {
            key,
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisCommitStage, EvidenceRetentionOwner, RetentionLimitsV1, ValidatedEvidenceBatchV1,
    };

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    struct MissingContext;

    impl DiscoveryContextProvider for MissingContext {
        fn context(&self, _record: &DiscoveryRecordV1) -> Result<DiscoveryContextJoinV1> {
            Ok(DiscoveryContextJoinV1::Unresolved(
                DiscoveryContextUnavailableV1::MissingDecisionCatalog,
            ))
        }
    }

    struct DiscoveryFixture {
        directory: tempfile::TempDir,
        store: Arc<crate::AnalysisStore>,
        source: EvidenceIntakeIdentityV1,
        frame: Vec<u8>,
    }

    impl DiscoveryFixture {
        fn new(
            retention: RetentionLimitsV1,
        ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
            let input = DiscoveryInputManifestV1::try_from(
                include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
            )?;
            let directory = tempfile::tempdir()?;
            let store = Arc::new(crate::AnalysisStore::open_with_limits(
                directory.path().join("analysis"),
                retention,
                Default::default(),
            )?);
            Ok(Self {
                directory,
                store,
                source: input.records[0].id.stream.clone(),
                frame: input.records[0].wire_record.clone(),
            })
        }

        fn accept(&self, cursor: u64) -> Result<()> {
            self.store.accept_validated_batch(
                self.source.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: cursor,
                    last_cursor: cursor,
                    intake_utc_ns: cursor,
                    framed_records: self.frame.clone().into(),
                    frame_ends: vec![self.frame.len()],
                },
            )?;
            Ok(())
        }

        fn owner(&self, config: DiscoveryConfigV1) -> Result<DiscoveryOwner> {
            DiscoveryOwner::new(self.store.clone(), Arc::new(MissingContext), config)
        }
    }

    #[test]
    fn discovery_live_restart() -> TestResult {
        let fixture = DiscoveryFixture::new(Default::default())?;
        fixture.accept(1)?;
        let owner = fixture.owner(Default::default())?;
        assert_eq!(owner.process(10)?, 1);
        let first = owner.profile(&fixture.source)?.ok_or("profile absent")?;
        assert!(!first.sealed);
        assert_eq!(first.snapshot.accepted_records, 1);
        fixture.accept(2)?;
        assert_eq!(owner.process(11)?, 1);
        let second = owner.profile(&fixture.source)?.ok_or("profile absent")?;
        assert_eq!(second.profile_id, first.profile_id);
        assert_eq!(second.revision, 2);
        assert_eq!(second.snapshot.accepted_records, 2);
        assert_eq!(second.snapshot.unresolved_records, 2);
        assert_eq!(second.schema_version, DISCOVERY_SCHEMA_VERSION);
        assert_eq!(
            DiscoveryProfileV1::try_from(serde_json::to_vec(&second)?.as_slice())?,
            second
        );
        assert_eq!(owner.process(12)?, 0);
        assert_eq!(owner.profile(&fixture.source)?, Some(second.clone()));
        drop(owner);
        let DiscoveryFixture {
            directory,
            store,
            source,
            ..
        } = fixture;
        drop(store);
        let store = Arc::new(crate::AnalysisStore::open(
            directory.path().join("analysis"),
        )?);
        let owner =
            DiscoveryOwner::new(store.clone(), Arc::new(MissingContext), Default::default())?;
        assert_eq!(owner.profile(&source)?, Some(second.clone()));
        assert_eq!(owner.process(13)?, 0);
        assert_eq!(owner.profile(&source)?, Some(second));
        assert!(!directory.path().join("discovery-index.sqlite").exists());
        assert!(!directory.path().join("discovery").exists());
        Ok(())
    }

    #[test]
    fn discovery_live_transaction() -> TestResult {
        let fixture = DiscoveryFixture::new(Default::default())?;
        fixture.accept(1)?;
        let owner = fixture.owner(Default::default())?;
        fixture
            .store
            .set_commit_hook(AnalysisCommitStage::BeforeResultCommit, || {
                crate::AnalysisConflictSnafu.fail()
            })?;
        assert!(owner.process(10).is_err());
        assert!(owner.profile(&fixture.source)?.is_none());
        let mut selection = crate::AnalysisSelectionV1::new(fixture.source.tenant_id, Vec::new());
        selection.contexts = crate::Selection::All;
        let contexts = fixture.store.extract(
            &selection,
            &crate::AnalysisReadControl::default(),
            |input| match input {
                crate::AnalysisInputV1::Context(context)
                    if context.key.owner_id == "discovery-source-v1" =>
                {
                    Ok(Some(context.body.clone()))
                }
                _ => Ok(None),
            },
        )?;
        let rows: Vec<_> = contexts.pages.iter().flat_map(|page| &page.rows).collect();
        assert_eq!(rows.len(), 1);
        let health: serde_json::Value = serde_json::from_slice(rows[0].as_ref())?;
        assert_eq!(health["consumed_cursor"], 0);
        assert_eq!(health["interval_last_cursor"], 1);
        assert_eq!(health["accepted_cursor"], 1);
        assert_eq!(owner.process(11)?, 1);
        let first = owner.profile(&fixture.source)?.ok_or("profile absent")?;
        fixture.accept(2)?;
        fixture
            .store
            .set_commit_hook(AnalysisCommitStage::BeforeResultCommit, || {
                crate::AnalysisConflictSnafu.fail()
            })?;
        assert!(owner.process(12).is_err());
        assert_eq!(owner.profile(&fixture.source)?, Some(first.clone()));
        assert_eq!(
            fixture
                .store
                .processor_health(&first.scope)?
                .ok_or("health absent")?
                .consumed_cursor,
            1
        );
        assert_eq!(owner.process(13)?, 1);
        assert_eq!(
            owner
                .profile(&fixture.source)?
                .ok_or("profile absent")?
                .snapshot
                .accepted_records,
            2
        );
        Ok(())
    }

    #[test]
    fn discovery_live_boundaries() -> TestResult {
        let fixture = DiscoveryFixture::new(Default::default())?;
        fixture.accept(1)?;
        fixture.accept(2)?;
        let config = DiscoveryConfigV1 {
            input_bytes: fixture.frame.len() + 1,
            ..Default::default()
        };
        let owner = fixture.owner(config)?;
        assert_eq!(owner.process(10)?, 1);
        let first = owner.profile(&fixture.source)?.ok_or("profile absent")?;
        assert!(first.sealed);
        assert_eq!(first.snapshot.accepted_records, 1);
        assert_eq!(owner.process(11)?, 1);
        let second = owner.profile(&fixture.source)?.ok_or("profile absent")?;
        assert_ne!(first.profile_id, second.profile_id);
        assert_eq!(second.snapshot.accepted_records, 1);
        let fixture = DiscoveryFixture::new(Default::default())?;
        fixture.accept(1)?;
        let owner = fixture.owner(DiscoveryConfigV1 {
            input_bytes: 1,
            ..Default::default()
        })?;
        assert!(matches!(
            owner.process(10),
            Err(crate::Error::DiscoveryInvalid {
                field: "single record limit",
                ..
            })
        ));
        assert!(owner.profile(&fixture.source)?.is_none());
        Ok(())
    }

    #[test]
    fn discovery_refresh_bounds() -> TestResult {
        let fixture = DiscoveryFixture::new(Default::default())?;
        let mut owner = fixture.owner(DiscoveryConfigV1 {
            atom_limit: 1,
            ..Default::default()
        })?;
        let mut input = DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )?;
        let first = input.records[0].clone();
        let mut second = first.clone();
        second.id.durable_cursor = 2;
        second.original_kernel_sequence = Some(2);
        let mut wire = second.decode()?;
        wire.exact_object_id = vec![91; 16].into();
        second.wire_record = Vec::<u8>::try_from(&wire)?;
        let mut late = input.contexts[0].clone();
        late.record_id = second.id.clone();
        input.records = vec![first, second];
        input.contexts.truncate(1);
        input.coverage.truncate(1);
        input.coverage[0].first_cursor = 1;
        input.coverage[0].last_cursor = 2;
        input.coverage[0].expected_records = 2;
        input.exclusions.clear();
        input.lifecycle.clear();
        let original = DiscoveryOwner::derive_recorded(&input)?.snapshot;
        assert_eq!(original.accepted_records, 2);
        assert_eq!(original.included_records, 1);
        assert_eq!(original.unresolved_records, 1);
        assert_eq!(original.atoms.len(), 1);
        let source = input.records[0].id.stream.clone();
        let key = AnalysisContextKeyV1 {
            tenant_id: source.tenant_id,
            owner_id: "discovery-facts-v1".into(),
            entity_key: vec![1; 16],
            lifetime_key: source.key(),
            owner_revision: 1,
        };
        let mut profile = DiscoveryProfileV1 {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            scope: ProcessorScopeV1 {
                processor_id: DISCOVERY_PROCESSOR.into(),
                method_version: DISCOVERY_SCHEMA_VERSION as u64,
                identity: source,
            },
            profile_id: "discovery:bounded".into(),
            interval_id: "discovery:bounded".into(),
            revision: 1,
            facts_revision: 0,
            coverage_revision: 0,
            created_utc_ns: 1,
            updated_utc_ns: 1,
            sealed: true,
            input_bytes: DiscoveryOwner::input_size(&input)?,
            incomplete: false,
            gaps: Vec::new(),
            snapshot: original.clone(),
            context_refs: vec![AnalysisContextRefV1 {
                key: key.clone(),
                commit_revision: 1,
            }],
        };
        profile.validate()?;
        let facts = BTreeMap::from([(
            late.record_id.clone(),
            AnalysisContextVersionV1 {
                key: AnalysisContextKeyV1 {
                    entity_key: vec![2; 16],
                    ..key.clone()
                },
                valid_from_utc_ns: None,
                valid_until_utc_ns: None,
                sensitivity: ContextSensitivityV1::Tenant,
                body: b"late qualified fact".to_vec(),
            },
        )]);
        let records = input.records.clone();
        let frozen = input.contexts.clone();
        input.contexts.push(late.clone());
        let bounded = owner
            .bound_refresh(&profile, &mut input, &facts, frozen.len(), 2)?
            .ok_or("bounded snapshot absent")?;
        assert_eq!(bounded, original);
        assert_eq!(input.records, records);
        assert_eq!(input.contexts, frozen);
        owner.config.atom_limit = 2;
        profile.context_refs = (1..=255_u16)
            .map(|index| AnalysisContextRefV1 {
                key: AnalysisContextKeyV1 {
                    entity_key: index.to_be_bytes().to_vec(),
                    ..key.clone()
                },
                commit_revision: 1,
            })
            .collect();
        profile.validate()?;
        input.contexts.push(late.clone());
        let bounded = owner
            .bound_refresh(&profile, &mut input, &facts, frozen.len(), 2)?
            .ok_or("ref-bounded snapshot absent")?;
        assert_eq!(bounded, original);
        assert_eq!(input.records, records);
        assert_eq!(input.contexts, frozen);
        profile.context_refs.truncate(1);
        input.contexts.push(late);
        let admitted = owner
            .bound_refresh(&profile, &mut input, &facts, frozen.len(), 2)?
            .ok_or("admitted snapshot absent")?;
        assert_eq!(admitted.accepted_records, 2);
        assert_eq!(admitted.included_records, 2);
        assert_eq!(admitted.unresolved_records, 0);
        assert_eq!(admitted.atoms.len(), 2);
        assert_eq!(input.records, records);
        assert_eq!(input.contexts[..frozen.len()], frozen);
        Ok(())
    }

    #[test]
    fn discovery_coverage_counter_proof() -> TestResult {
        let interval = crate::CoverageInterval {
            state: "HEALTHY".into(),
            first_sequence: 1,
            last_sequence: Some(1),
            opening_counters: Some(Default::default()),
            closing_counters: Some(crate::CoverageCounters {
                attempted: 1,
                requested: 1,
                emitted: 1,
                next_sequence: 2,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(interval.is_complete());
        let mut closed = interval.clone();
        closed.state = "CLOSED".into();
        assert!(closed.is_complete());
        for field in 0..4 {
            let mut gap = interval.clone();
            let counters = gap
                .closing_counters
                .as_mut()
                .ok_or("closing counters absent")?;
            match field {
                0 => {
                    counters.lost = 1;
                    counters.requested += 1;
                    counters.attempted += 1;
                }
                1 => {
                    counters.suppressed = 1;
                    counters.attempted += 1;
                }
                2 => counters.unresolved = 1,
                _ => counters.classifier_miss_count = 1,
            }
            assert!(gap.has_gap());
            assert!(!gap.is_complete());
        }
        let mut absent = interval.clone();
        absent.closing_counters = None;
        assert!(!absent.has_gap());
        assert!(!absent.is_complete());
        let mut invalid = interval;
        invalid
            .closing_counters
            .as_mut()
            .ok_or("closing counters absent")?
            .requested = 2;
        assert!(!invalid.is_complete());
        Ok(())
    }

    #[test]
    fn discovery_coverage_state_mapping() -> TestResult {
        use prost::Message as _;

        let input = DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )?;
        let binding = &input.contexts[0];
        let record = &input.records[0];
        let mut wire = record.decode()?;
        wire.temporal_coverage = crate::EvidenceTemporalCoverage::Complete as i32;
        wire.decision_context = Some(crate::EvidenceDecisionContext {
            schema_version: 1,
            original_kernel_sequence: 1,
            profile_generation_ref_id: wire.profile_generation_ref_id.unwrap_or_default(),
            process_instance_id: binding.process_instance_id.to_vec(),
            entry_instance_id: binding.entry_instance_id.to_vec(),
            binding_id: binding.binding_id.to_vec(),
            role_id: binding.role_id,
            state_id: binding.state_id,
            entry_rule_id: binding.entry_rule_id,
            ..Default::default()
        });
        let report = CoverageReport {
            source_id: record.id.stream.source_id.to_vec(),
            cpu_id: record.id.cpu_id,
            source_epoch: record.id.stream.source_epoch,
            revision: 1,
            intervals: vec![crate::CoverageInterval {
                interval_id: wire.coverage_interval_id.to_vec(),
                source_epoch: record.id.stream.source_epoch,
                revision: 1,
                state: "HEALTHY".into(),
                first_sequence: 1,
                last_sequence: Some(1),
                opening_counters: Some(Default::default()),
                closing_counters: Some(crate::CoverageCounters {
                    attempted: 1,
                    requested: 1,
                    emitted: 1,
                    next_sequence: 2,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        use DiscoveryCoverageStateV1::{Closed, Gapped, Healthy, Unknown};
        for (case, expected) in [
            ("healthy", Healthy),
            ("closed", Closed),
            ("missing closing", Unknown),
            ("lost counter", Gapped),
            ("wrong CPU", Unknown),
            ("wrong report epoch", Unknown),
            ("wrong interval epoch", Unknown),
            ("native sequence", Unknown),
            ("temporal unknown", Unknown),
            ("wrong source", Unknown),
        ] {
            let mut report = report.clone();
            let mut wire = wire.clone();
            let interval = &mut report.intervals[0];
            match case {
                "healthy" => {}
                "closed" => interval.state = "CLOSED".into(),
                "missing closing" => interval.closing_counters = None,
                "lost counter" => {
                    let counters = interval
                        .closing_counters
                        .as_mut()
                        .ok_or("counters absent")?;
                    counters.lost = 1;
                    counters.requested += 1;
                    counters.attempted += 1;
                }
                "wrong CPU" => report.cpu_id += 1,
                "wrong report epoch" => report.source_epoch += 1,
                "wrong interval epoch" => interval.source_epoch += 1,
                "native sequence" => {
                    wire.decision_context
                        .as_mut()
                        .ok_or("context absent")?
                        .original_kernel_sequence = 2
                }
                "temporal unknown" => {
                    wire.temporal_coverage = crate::EvidenceTemporalCoverage::Unknown as i32
                }
                "wrong source" => report.source_id = vec![255; 16],
                _ => return Err("coverage case absent".into()),
            }
            let mut sample = record.clone();
            sample.original_kernel_sequence = wire
                .decision_context
                .as_ref()
                .map(|context| context.original_kernel_sequence);
            sample.wire_record = Vec::<u8>::try_from(&wire)?;
            let status = AnalysisSourceStatusV1 {
                receipt: crate::AnalysisSourceReceiptV1 {
                    identity: record.id.stream.clone(),
                    cpu_id: record.id.cpu_id,
                    contiguous_cursor: record.id.durable_cursor,
                    coverage_revision: 1,
                    retained_floor: 0,
                },
                retained_event_count: 1,
                latest_coverage_report: Some(report.encode_to_vec()),
            };
            let ranges = DiscoveryOwner::coverage(&status, std::slice::from_ref(&sample))?;
            assert_eq!(ranges.len(), 1, "{case}");
            assert_eq!(ranges[0].state, expected, "{case}");
            assert_eq!(
                ranges[0].gap_reasons.is_empty(),
                matches!(expected, Healthy | Closed),
                "{case}"
            );
            assert_eq!(ranges[0].stream, sample.id.stream, "{case}");
            assert_eq!(ranges[0].cpu_id, sample.id.cpu_id, "{case}");
            assert_eq!(
                ranges[0].coverage_interval_id.as_slice(),
                wire.coverage_interval_id.as_ref(),
                "{case}"
            );
        }
        Ok(())
    }

    #[test]
    fn discovery_live_retention() -> TestResult {
        let fixture = DiscoveryFixture::new(RetentionLimitsV1 {
            raw_max_age_ns: 1,
            raw_max_bytes: 1_048_576,
        })?;
        fixture.accept(1)?;
        let owner = fixture.owner(Default::default())?;
        assert_eq!(owner.process(10)?, 1);
        let first = owner.profile(&fixture.source)?.ok_or("profile absent")?;
        fixture.accept(2)?;
        let expiry = EvidenceRetentionOwner::new(&fixture.store).retain(&fixture.source, 100)?;
        assert_eq!(expiry.removed_records, 2);
        assert_eq!(owner.profile(&fixture.source)?, Some(first));
        fixture.accept(3)?;
        fixture
            .store
            .set_commit_hook(AnalysisCommitStage::BeforeResultCommit, || {
                crate::AnalysisConflictSnafu.fail()
            })?;
        assert!(owner.process(101).is_err());
        assert_eq!(owner.process(101)?, 1);
        let profile = owner.profile(&fixture.source)?.ok_or("profile absent")?;
        assert!(profile.incomplete);
        assert_eq!(profile.gaps.len(), 1);
        assert_eq!(
            (profile.gaps[0].first_cursor, profile.gaps[0].last_cursor),
            (2, 2)
        );
        assert_eq!(profile.snapshot.accepted_records, 2);
        assert_eq!(
            profile
                .snapshot
                .coverage
                .iter()
                .map(|range| range.expected_records)
                .sum::<u64>(),
            2
        );
        assert_eq!(
            fixture
                .store
                .processor_health(&profile.scope)?
                .ok_or("health absent")?
                .consumed_cursor,
            3
        );
        let late = fixture.owner(Default::default())?;
        assert_eq!(late.process(102)?, 0);
        assert_eq!(late.profile(&fixture.source)?, Some(profile));
        Ok(())
    }

    #[test]
    fn discovery_live_disabled() -> TestResult {
        let fixture = DiscoveryFixture::new(RetentionLimitsV1 {
            raw_max_age_ns: 1,
            raw_max_bytes: 1_048_576,
        })?;
        fixture.accept(1)?;
        assert_eq!(
            EvidenceRetentionOwner::new(&fixture.store)
                .retain(&fixture.source, 100)?
                .removed_records,
            1
        );
        let owner = fixture.owner(Default::default())?;
        assert_eq!(owner.process(101)?, 0);
        let profile = owner
            .profile(&fixture.source)?
            .ok_or("gap profile absent")?;
        assert!(profile.incomplete);
        assert_eq!(profile.snapshot.accepted_records, 0);
        assert_eq!(
            (profile.gaps[0].first_cursor, profile.gaps[0].last_cursor),
            (1, 1)
        );
        fixture.accept(2)?;
        assert_eq!(owner.process(102)?, 1);
        assert_eq!(
            owner
                .profile(&fixture.source)?
                .ok_or("profile absent")?
                .snapshot
                .accepted_records,
            1
        );
        Ok(())
    }
}
