use super::*;
use crate::{
    AnalysisSourceReceiptV1, CoverageReport, DiscoveryCoverageStateV1, DiscoveryCoverageV1,
    GraphCoverageKeyV1, GraphReplayInputV1,
};

#[derive(Clone, Debug)]
pub(super) struct SourceCoverage {
    receipt: AnalysisSourceReceiptV1,
    report: Option<Arc<CoverageReport>>,
    intervals: BTreeMap<[u8; 16], usize>,
    missing: Vec<(u64, u64)>,
}

impl SourceCoverage {
    pub(super) fn capture(
        source: &mut crate::AnalysisSourceSnapshotV1,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Self> {
        let report = source.typed_coverage(charge)?;
        let count = report.as_ref().map_or(0, |report| report.intervals.len());
        let ranges = source
            .expired
            .len()
            .checked_add(source.recovery.len())
            .and_then(|count| count.checked_add(source.pending.len()))
            .ok_or_else(|| Code::Limit.error("source coverage metadata memory"))?;
        let bytes = Self::index_bytes(count)
            .checked_add(source.receipt.identity.node_id.len())
            .and_then(|bytes| {
                bytes.checked_add(ranges.checked_mul(2 * std::mem::size_of::<(u64, u64)>())?)
            })
            .ok_or_else(|| Code::Limit.error("source coverage metadata memory"))?;
        charge(bytes)?;
        let mut intervals = BTreeMap::new();
        for (index, interval) in report
            .iter()
            .flat_map(|report| report.intervals.iter().enumerate())
            .filter(|(_, interval)| interval.source_epoch == source.receipt.identity.source_epoch)
        {
            charge(0)?;
            let id = <[u8; 16]>::try_from(interval.interval_id.as_slice())
                .map_err(|_| Code::Invalid.error("canonical coverage interval identity"))?;
            if intervals.insert(id, index).is_some() {
                return Err(Code::Invalid.error("canonical coverage interval identity"));
            }
        }
        let mut missing = source
            .expired
            .iter()
            .chain(&source.recovery)
            .chain(&source.pending)
            .map(|gap| (gap.first_cursor, gap.last_cursor))
            .collect::<Vec<_>>();
        if missing
            .iter()
            .any(|(first, last)| *first == 0 || last < first)
        {
            return Err(Code::Invalid.error("canonical coverage gap"));
        }
        missing.sort_unstable();
        missing.dedup();
        Ok(Self {
            receipt: source.receipt.clone(),
            report,
            intervals,
            missing,
        })
    }

    fn index_bytes(count: usize) -> usize {
        if count == 0 {
            return 0;
        }
        let entry = std::mem::size_of::<([u8; 16], usize)>() + 16 * std::mem::size_of::<usize>();
        count.saturating_mul(2 * entry).saturating_add(32 * entry)
    }

    pub(super) fn report_bytes(&self) -> usize {
        let Some(report) = &self.report else { return 0 };
        let mut bytes = std::mem::size_of::<CoverageReport>()
            .saturating_add(2 * std::mem::size_of::<usize>())
            .saturating_add(report.source_id.capacity())
            .saturating_add(
                report
                    .intervals
                    .capacity()
                    .saturating_mul(std::mem::size_of::<crate::CoverageInterval>()),
            );
        for interval in &report.intervals {
            bytes = bytes
                .saturating_add(interval.interval_id.capacity())
                .saturating_add(interval.state.capacity())
                .saturating_add(
                    interval
                        .gap_reasons
                        .capacity()
                        .saturating_mul(std::mem::size_of::<String>()),
                );
            for reason in &interval.gap_reasons {
                bytes = bytes.saturating_add(reason.capacity());
            }
        }
        bytes
    }

    pub(super) fn allocated_bytes(&self) -> usize {
        self.report_bytes()
            .saturating_add(self.receipt.identity.node_id.capacity())
            .saturating_add(Self::index_bytes(self.intervals.len()))
            .saturating_add(
                self.missing
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(u64, u64)>()),
            )
    }

    fn qualify(
        &self,
        record: &crate::DiscoveryRecordV1,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<(DiscoveryCoverageV1, Option<GraphCoverageKeyV1>)> {
        if record.id.stream != self.receipt.identity || record.id.cpu_id != self.receipt.cpu_id {
            return Err(Code::Denied.error("canonical coverage source"));
        }
        let wire = record.decode()?;
        let id = <[u8; 16]>::try_from(wire.coverage_interval_id.as_ref())
            .unwrap_or(record.id.stream.source_id);
        let interval = self.intervals.get(&id).and_then(|index| {
            self.report
                .as_ref()
                .and_then(|report| report.intervals.get(*index))
        });
        let state = crate::CoverageInterval::record_state(
            interval,
            wire.temporal_coverage,
            record.original_kernel_sequence,
        );
        let complete = matches!(
            state,
            DiscoveryCoverageStateV1::Healthy | DiscoveryCoverageStateV1::Closed
        );
        let fallback = match interval {
            None => Some("MISSING_COVERAGE_REPORT"),
            Some(interval) if !interval.gap_reasons.is_empty() => None,
            Some(interval) if interval.has_gap() => Some("SOURCE_COVERAGE_GAPPED"),
            Some(_) if complete => None,
            Some(_) => Some("COVERAGE_UNQUALIFIED"),
        };
        let (count, strings) = if let Some(reason) = fallback {
            (1, reason.len())
        } else {
            interval
                .map_or(Some((0, 0)), |interval| {
                    interval
                        .gap_reasons
                        .iter()
                        .try_fold(0usize, |bytes, reason| bytes.checked_add(reason.len()))
                        .map(|bytes| (interval.gap_reasons.len(), bytes))
                })
                .ok_or_else(|| Code::Limit.error("canonical coverage reason memory"))?
        };
        let bytes = count
            .checked_mul(std::mem::size_of::<String>())
            .and_then(|bytes| bytes.checked_add(strings))
            .and_then(|bytes| bytes.checked_add(record.id.stream.node_id.len()))
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<DiscoveryCoverageV1>()
                        + std::mem::size_of::<GraphCoverageKeyV1>()
                        + 16 * std::mem::size_of::<usize>(),
                )
            })
            .and_then(|bytes| bytes.checked_mul(4))
            .ok_or_else(|| Code::Limit.error("canonical coverage value memory"))?;
        charge(bytes)?;
        let mut reasons = if let Some(reason) = fallback {
            vec![reason.into()]
        } else {
            interval.map_or_else(Vec::new, |interval| interval.gap_reasons.clone())
        };
        reasons.sort();
        reasons.dedup();
        let key = interval.map(|interval| GraphCoverageKeyV1 {
            source: record.id.stream.clone(),
            cpu_id: self.receipt.cpu_id,
            report_revision: self.receipt.coverage_revision,
            interval_id: id,
            interval_revision: interval.revision,
            state,
            gap_reasons: reasons.clone(),
        });
        Ok((
            DiscoveryCoverageV1 {
                stream: record.id.stream.clone(),
                cpu_id: self.receipt.cpu_id,
                first_cursor: record.id.durable_cursor,
                last_cursor: record.id.durable_cursor,
                expected_records: 1,
                coverage_revision: self.receipt.coverage_revision,
                coverage_interval_id: id,
                state,
                gap_reasons: reasons,
            },
            key,
        ))
    }
}

impl ManagedSourceFrame {
    pub fn expired_window(
        &self,
        source: &crate::EvidenceIntakeIdentityV1,
        first: u64,
        deadline: u64,
        time: u64,
    ) -> Result<bool> {
        let coverage = self
            .coverage
            .iter()
            .find(|coverage| coverage.receipt.identity == *source)
            .ok_or_else(|| Code::Denied.error("native source expiry receipt"))?;
        Ok(first <= coverage.receipt.retained_floor || deadline <= time)
    }

    pub(in crate::analysis) fn source_metadata(
        &self,
        source: &crate::EvidenceIntakeIdentityV1,
    ) -> Result<(u64, &[(u64, u64)])> {
        let coverage = self
            .coverage
            .iter()
            .find(|coverage| coverage.receipt.identity == *source)
            .ok_or_else(|| Code::Denied.error("native source metadata"))?;
        Ok((coverage.receipt.coverage_revision, &coverage.missing))
    }

    pub(super) fn prefix_coverage(
        &self,
        source: &crate::EvidenceIntakeIdentityV1,
        first: u64,
        proof: &crate::InputProof,
    ) -> bool {
        let Some(coverage) = self
            .coverage
            .iter()
            .find(|coverage| coverage.receipt.identity == *source)
        else {
            return false;
        };
        coverage.receipt.retained_floor < first
            && coverage.missing.is_empty()
            && proof.boundaries().all(|(cpu, id, sequence)| {
                cpu == coverage.receipt.cpu_id
                    && coverage
                        .intervals
                        .get(&id)
                        .and_then(|index| {
                            coverage
                                .report
                                .as_ref()
                                .and_then(|report| report.intervals.get(*index))
                        })
                        .is_some_and(|interval| {
                            interval.is_complete()
                                && !interval.has_gap()
                                && interval.last_sequence.is_some_and(|last| {
                                    (interval.first_sequence..=last).contains(&sequence)
                                })
                        })
            })
    }

    fn source_coverage(&self, input: &GraphReplayInputV1) -> Result<&SourceCoverage> {
        self.coverage
            .iter()
            .find(|coverage| coverage.receipt.identity == input.source)
            .ok_or_else(|| Code::Denied.error("canonical coverage source receipt"))
    }

    pub(super) fn selection_coverage(
        &self,
        input: &GraphReplayInputV1,
        prior: Option<&crate::InputProof>,
    ) -> Result<Vec<GraphCoverageKeyV1>> {
        let mut keys = input.coverage_keys.iter().cloned().collect::<BTreeSet<_>>();
        if let Some(prior) = prior {
            let source = self.source_coverage(input)?;
            for (cpu, id, sequence) in prior.boundaries() {
                let interval = source
                    .intervals
                    .get(&id)
                    .and_then(|index| {
                        source
                            .report
                            .as_ref()
                            .and_then(|report| report.intervals.get(*index))
                    })
                    .ok_or_else(|| Code::Denied.error("native prefix coverage interval"))?;
                if cpu != source.receipt.cpu_id
                    || !interval.is_complete()
                    || interval.has_gap()
                    || !interval
                        .last_sequence
                        .is_some_and(|last| (interval.first_sequence..=last).contains(&sequence))
                {
                    return Err(Code::Denied.error("native prefix coverage basis"));
                }
                keys.insert(GraphCoverageKeyV1 {
                    source: input.source.clone(),
                    cpu_id: cpu,
                    report_revision: source.receipt.coverage_revision,
                    interval_id: id,
                    interval_revision: interval.revision,
                    state: if interval.state == "CLOSED" {
                        DiscoveryCoverageStateV1::Closed
                    } else {
                        DiscoveryCoverageStateV1::Healthy
                    },
                    gap_reasons: Vec::new(),
                });
            }
        }
        Ok(keys.into_iter().collect())
    }

    pub(super) fn check_coverage(&self, input: &GraphReplayInputV1) -> Result<()> {
        if input.records.is_empty() {
            if !input.coverage.is_empty() || !input.coverage_keys.is_empty() {
                return Err(Code::Invalid.error("empty derived coverage"));
            }
            return Ok(());
        }
        let coverage = self.source_coverage(input)?;
        if coverage.missing.iter().any(|(first, last)| {
            !input
                .missing_ranges
                .iter()
                .any(|(start, end)| start <= first && end >= last)
        }) {
            return Err(Code::Denied.error("derived canonical source gap"));
        }
        let mut ranges = Vec::new();
        let mut keys = BTreeSet::new();
        for record in &input.records {
            let (range, key) = coverage.qualify(record, &mut |_| Ok(()))?;
            ranges.push(range);
            keys.extend(key);
        }
        ranges.sort();
        let mut actual = input.coverage.clone();
        actual.sort();
        if actual != ranges || input.coverage_keys != keys.into_iter().collect::<Vec<_>>() {
            return Err(Code::Denied.error("derived canonical coverage"));
        }
        Ok(())
    }

    pub(in crate::analysis::managed) fn canonical_coverage(
        &self,
        input: &mut GraphReplayInputV1,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<()> {
        let coverage = self.source_coverage(input)?;
        charge(
            coverage
                .missing
                .len()
                .checked_mul(std::mem::size_of::<(u64, u64)>())
                .ok_or_else(|| Code::Limit.error("canonical coverage gap memory"))?,
        )?;
        let mut keys = BTreeSet::new();
        for record in &input.records {
            let (range, key) = coverage.qualify(record, charge)?;
            input.coverage.push(range);
            keys.extend(key);
        }
        input.coverage_keys = keys.into_iter().collect();
        input.missing_ranges = coverage.missing.clone();
        Ok(())
    }
}
