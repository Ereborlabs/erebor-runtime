use std::collections::{BTreeMap, BTreeSet};

use super::RawJournal;
use crate::{Result, RetentionLimitsV1};

#[derive(Default)]
pub(in crate::analysis) struct RawBudget {
    pub required: BTreeMap<Vec<u8>, u64>,
    pub protected: BTreeMap<[u8; 16], u64>,
    pub oldest: BTreeMap<Vec<u8>, u64>,
    owners: BTreeMap<Vec<u8>, BTreeMap<u64, u64>>,
    dirty: BTreeSet<([u8; 16], Vec<u8>)>,
    bytes: BTreeMap<Vec<u8>, u64>,
    ages: BTreeMap<Vec<u8>, BTreeSet<(u64, u64)>>,
    pub pins: BTreeMap<u64, ([u8; 16], u64)>,
    pub expired: BTreeMap<(Vec<u8>, u64), u64>,
    pub trace_reserve: u64,
    pub trace_slots: usize,
    pub deletions: BTreeSet<u64>,
}

impl RawBudget {
    pub(in crate::analysis) fn set_required(
        &mut self,
        owner: u64,
        key: Vec<u8>,
        tenant: [u8; 16],
        floor: Option<u64>,
    ) {
        match floor {
            Some(floor) => {
                self.owners
                    .entry(key.clone())
                    .or_default()
                    .insert(owner, floor);
            }
            None => {
                if let Some(owners) = self.owners.get_mut(&key) {
                    owners.remove(&owner);
                    if owners.is_empty() {
                        self.owners.remove(&key);
                    }
                }
            }
        }
        self.dirty.insert((tenant, key));
    }
}

impl RawJournal {
    pub(in crate::analysis) fn reconcile_all(&mut self, limits: RetentionLimitsV1) -> Result<()> {
        let tenants = self
            .budget
            .dirty
            .iter()
            .map(|(tenant, _)| *tenant)
            .collect::<BTreeSet<_>>();
        for tenant in tenants {
            self.reconcile_backlog(tenant, limits)?;
        }
        Ok(())
    }

    pub(in crate::analysis) fn reconcile_backlog(
        &mut self,
        tenant: [u8; 16],
        limits: RetentionLimitsV1,
    ) -> Result<()> {
        let keys = self
            .budget
            .dirty
            .range((tenant, Vec::new())..)
            .take_while(|(owner, _)| *owner == tenant)
            .map(|(_, key)| key.clone())
            .collect::<Vec<_>>();
        for key in keys {
            self.reconcile_source(&key, tenant, limits)?;
            self.budget.dirty.remove(&(tenant, key));
        }
        Ok(())
    }

    fn reconcile_source(
        &mut self,
        key: &[u8],
        tenant: [u8; 16],
        limits: RetentionLimitsV1,
    ) -> Result<()> {
        let old = self.budget.required.get(key).copied();
        let next = self
            .budget
            .owners
            .get(key)
            .and_then(|owners| owners.values().copied().min());
        if old == next {
            return Ok(());
        }
        let prior_bytes = self.budget.bytes.get(key).copied().unwrap_or(0);
        let Some(floor) = next else {
            if limits.raw_max_bytes.is_some() {
                let total = self.budget.protected.get(&tenant).copied().unwrap_or(0);
                let total = total
                    .checked_sub(prior_bytes)
                    .ok_or_else(|| self.invalid("the protected input count underflows"))?;
                self.budget.protected.insert(tenant, total);
            }
            self.budget.required.remove(key);
            self.budget.bytes.remove(key);
            self.budget.ages.remove(key);
            self.budget.oldest.remove(key);
            return Ok(());
        };
        let (first, last) = old.map_or((floor.saturating_add(1), u64::MAX), |old| {
            (old.min(floor).saturating_add(1), old.max(floor))
        });
        let contiguous = self
            .index
            .sources
            .get(key)
            .map_or(0, |source| source.receipt.cursor());
        let start = self
            .index
            .ranges
            .range((key.to_vec(), 0)..=(key.to_vec(), first))
            .next_back()
            .map_or(first, |((_, cursor), _)| *cursor);
        let mut changed = Vec::new();
        let mut bytes = 0u64;
        for (_, &(revision, slot)) in self
            .index
            .ranges
            .range((key.to_vec(), start)..=(key.to_vec(), last))
        {
            let entry = &self.index.entries[&revision];
            let span = &entry.commit.spans[slot];
            if span.last < first || self.index.expired.contains_key(&entry.reference.id) {
                continue;
            }
            if limits.raw_max_bytes.is_some() {
                let begin = span.first.max(first);
                let end = span.last.min(last);
                let count = if begin == span.first && end == span.last {
                    span.bytes
                } else {
                    let commit = self.read_entry(entry)?;
                    let ends = &commit.spans[slot].ends;
                    ends[(end - span.first) as usize]
                        - if begin == span.first {
                            0
                        } else {
                            ends[(begin - span.first - 1) as usize]
                        }
                };
                bytes = bytes
                    .checked_add(u64::from(count))
                    .ok_or_else(|| self.invalid("the protected input count overflows"))?;
            }
            if limits.raw_max_age_ns.is_some() {
                changed.push((
                    entry.commit.intake,
                    span.first,
                    span.last > floor && span.first <= contiguous,
                ));
            }
        }
        if limits.raw_max_bytes.is_some() {
            let next_bytes = if old.is_some_and(|old| old < floor) {
                prior_bytes.checked_sub(bytes)
            } else {
                prior_bytes.checked_add(bytes)
            }
            .ok_or_else(|| self.invalid("the protected input count is invalid"))?;
            let total = self
                .budget
                .protected
                .get(&tenant)
                .copied()
                .unwrap_or(0)
                .checked_sub(prior_bytes)
                .and_then(|total| total.checked_add(next_bytes))
                .ok_or_else(|| self.invalid("the protected input total is invalid"))?;
            self.budget.bytes.insert(key.to_vec(), next_bytes);
            self.budget.protected.insert(tenant, total);
        }
        if limits.raw_max_age_ns.is_some() {
            let ages = self.budget.ages.entry(key.to_vec()).or_default();
            for (intake, first, keep) in changed {
                if keep {
                    ages.insert((intake, first));
                } else {
                    ages.remove(&(intake, first));
                }
            }
            if let Some((intake, _)) = ages.first() {
                self.budget.oldest.insert(key.to_vec(), *intake);
            } else {
                self.budget.oldest.remove(key);
            }
        }
        self.budget.required.insert(key.to_vec(), floor);
        Ok(())
    }

    pub(in crate::analysis) fn extend_backlog(
        &mut self,
        key: &[u8],
        tenant: [u8; 16],
        prior: u64,
        bytes: u64,
        limits: RetentionLimitsV1,
    ) -> Result<()> {
        let Some(&floor) = self.budget.required.get(key) else {
            return Ok(());
        };
        if limits.raw_max_bytes.is_some() {
            let source = self
                .budget
                .bytes
                .get(key)
                .copied()
                .unwrap_or(0)
                .checked_add(bytes)
                .ok_or_else(|| self.invalid("the protected source count overflows"))?;
            let total = self
                .budget
                .protected
                .get(&tenant)
                .copied()
                .unwrap_or(0)
                .checked_add(bytes)
                .ok_or_else(|| self.invalid("the protected input total overflows"))?;
            self.budget.bytes.insert(key.to_vec(), source);
            self.budget.protected.insert(tenant, total);
        }
        if limits.raw_max_age_ns.is_some() {
            let contiguous = self.index.sources[key].receipt.cursor();
            if let Some(first) = prior
                .max(floor)
                .checked_add(1)
                .filter(|first| *first <= contiguous)
            {
                let ages = self.budget.ages.entry(key.to_vec()).or_default();
                for ((_, first), &(revision, _)) in self
                    .index
                    .ranges
                    .range((key.to_vec(), first)..=(key.to_vec(), contiguous))
                {
                    ages.insert((self.index.entries[&revision].commit.intake, *first));
                }
                if let Some((intake, _)) = ages.first() {
                    self.budget.oldest.insert(key.to_vec(), *intake);
                }
            }
        }
        Ok(())
    }
}
