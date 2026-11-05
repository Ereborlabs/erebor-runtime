use std::collections::BTreeMap;

use araphor_analysis_types::source::{DiscoveryRecordIdV1, EvidenceIntakeIdentityV1};

use super::{io::CoverageRow, model::Audit, sdk};

pub(super) struct Coverage {
    sources: BTreeMap<EvidenceIntakeIdentityV1, BTreeMap<u32, Receipt>>,
}

#[derive(Default)]
struct Receipt {
    stamp: Option<(u64, u64)>,
    present: bool,
    expired: Vec<(u64, u64)>,
}

impl Coverage {
    pub(super) fn read(checked: &sdk::CheckedEvaluation<'_>, name: &str) -> sdk::Result<Self> {
        let mut coverage = Self {
            sources: BTreeMap::new(),
        };
        for row in CoverageRow::read(checked, name)? {
            let source = row.source.try_into()?;
            let receipt = coverage
                .sources
                .entry(source)
                .or_default()
                .entry(row.cpu_id)
                .or_default();
            let stamp = (row.coverage_revision, row.retained_floor);
            if receipt.stamp.is_some_and(|prior| prior != stamp) {
                return Err(Audit::invalid("causal coverage receipt stamp"));
            }
            receipt.stamp = Some(stamp);
            match (row.kind.as_str(), row.first_cursor, row.last_cursor) {
                ("receipt", None, None) if !receipt.present => receipt.present = true,
                (kind @ ("expired" | "recovery" | "pending"), Some(first), Some(last))
                    if first != 0 && first <= last =>
                {
                    if kind == "expired" {
                        receipt.expired.push((first, last));
                    }
                }
                _ => return Err(Audit::invalid("causal coverage row")),
            }
        }
        for cpus in coverage.sources.values_mut() {
            for receipt in cpus.values_mut() {
                receipt.finish()?;
            }
        }
        Ok(coverage)
    }

    pub(super) fn sources(&self) -> impl Iterator<Item = &EvidenceIntakeIdentityV1> {
        self.sources.keys()
    }

    pub(super) fn expired(&self, record: &DiscoveryRecordIdV1) -> bool {
        self.sources
            .get(&record.stream)
            .and_then(|cpus| cpus.get(&record.cpu_id))
            .is_none_or(|receipt| receipt.expired(record.durable_cursor))
    }
}

impl Receipt {
    fn finish(&mut self) -> sdk::Result<()> {
        if !self.present {
            return Err(Audit::invalid("causal coverage receipt"));
        }
        self.expired.sort_unstable();
        let mut written = 0;
        for index in 0..self.expired.len() {
            let (first, last) = self.expired[index];
            if written != 0 && first <= self.expired[written - 1].1.saturating_add(1) {
                self.expired[written - 1].1 = self.expired[written - 1].1.max(last);
            } else {
                self.expired[written] = (first, last);
                written += 1;
            }
        }
        self.expired.truncate(written);
        Ok(())
    }

    fn expired(&self, cursor: u64) -> bool {
        let Some((_, floor)) = self.stamp else {
            return true;
        };
        if cursor <= floor {
            return true;
        }
        self.expired
            .partition_point(|(first, _)| *first <= cursor)
            .checked_sub(1)
            .is_some_and(|index| cursor <= self.expired[index].1)
    }
}
