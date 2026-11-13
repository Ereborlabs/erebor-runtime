use std::collections::BTreeMap;

use super::{Records, References};
use crate::{PackageErrorCodeV1 as Code, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(in crate::analysis::native) enum PinTarget {
    Evidence(u64),
    Segment(u64),
}

impl PinTarget {
    pub(in crate::analysis::native) fn id(self) -> u64 {
        match self {
            Self::Evidence(id) | Self::Segment(id) => id,
        }
    }
    pub(in crate::analysis::native) fn prefix(self) -> &'static [u8] {
        match self {
            Self::Evidence(_) => References::EVIDENCE,
            Self::Segment(_) => References::RAW,
        }
    }
    pub(in crate::analysis::native) fn reverse(self) -> &'static [u8] {
        match self {
            Self::Evidence(_) => References::BATCH,
            Self::Segment(_) => References::SEGMENT,
        }
    }
}

pub(in crate::analysis::native) struct WitnessPin {
    pub(in crate::analysis::native) result: u64,
    pub(in crate::analysis::native) target: PinTarget,
    pub(in crate::analysis::native) expires: u64,
    pub(in crate::analysis::native) ranges: Vec<(u64, u64)>,
}

impl WitnessPin {
    pub(in crate::analysis::native) fn collect(
        result: u64,
        values: impl IntoIterator<Item = Result<(PinTarget, u64, u64)>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Vec<Self>> {
        let mut groups = BTreeMap::<(PinTarget, u64), Vec<u64>>::new();
        for value in values {
            charge(256)?;
            let (target, expires, cursor) = value?;
            groups.entry((target, expires)).or_default().push(cursor);
        }
        Ok(groups
            .into_iter()
            .map(|((target, expires), mut cursors)| {
                cursors.sort_unstable();
                cursors.dedup();
                let mut ranges = Vec::<(u64, u64)>::new();
                for cursor in cursors {
                    if let Some((_, last)) = ranges
                        .last_mut()
                        .filter(|(_, last)| last.checked_add(1) == Some(cursor))
                    {
                        *last = cursor;
                    } else {
                        ranges.push((cursor, cursor));
                    }
                }
                Self {
                    result,
                    target,
                    expires,
                    ranges,
                }
            })
            .collect())
    }

    pub(in crate::analysis::native) fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        let invalid = || Code::Invalid.error("managed witness pin value");
        let (key, native) = if let Some(key) = key.strip_prefix(References::EVIDENCE) {
            (key, true)
        } else {
            (
                key.strip_prefix(References::RAW).ok_or_else(invalid)?,
                false,
            )
        };
        if key.len() != 24 {
            return Err(invalid());
        }
        let payload = value.strip_prefix(&[0]).ok_or_else(invalid)?;
        let ranges: Vec<(u64, u64)> = Records::decode(payload).map_err(|_| invalid())?;
        if ranges.is_empty()
            || ranges
                .iter()
                .any(|(first, last)| *first == 0 || first > last)
            || ranges
                .windows(2)
                .any(|pair| pair[0].1.saturating_add(1) >= pair[1].0)
        {
            return Err(invalid());
        }
        Ok(Self {
            result: super::super::super::NativeStore::number(&key[..8])?,
            target: if native {
                PinTarget::Evidence(super::super::super::NativeStore::number(&key[8..16])?)
            } else {
                PinTarget::Segment(super::super::super::NativeStore::number(&key[8..16])?)
            },
            expires: super::super::super::NativeStore::number(&key[16..])?,
            ranges,
        })
    }

    pub(in crate::analysis::native) fn key(&self) -> Vec<u8> {
        References::key(
            self.target.prefix(),
            &[self.result, self.target.id(), self.expires],
        )
    }

    pub(in crate::analysis::native) fn reverse(&self) -> Vec<u8> {
        References::key(
            self.target.reverse(),
            &[self.target.id(), self.result, self.expires],
        )
    }

    pub(in crate::analysis::native) fn value(&self) -> Result<Vec<u8>> {
        Records::encode(&self.ranges)
    }
}

impl crate::analysis::native::DataView {
    pub(in crate::analysis::native) fn witness_target(
        &self,
        witness: &crate::AnalysisWitnessV1,
        revision: u64,
    ) -> Result<Option<PinTarget>> {
        if witness.cursor == 0 {
            return Err(Code::Invalid.error("source witness cursor"));
        }
        match &witness.identity {
            crate::AnalysisStreamIdentityV1::Evidence(source) => {
                let events = crate::analysis::native::events::Events::new(self);
                Ok(events
                    .lookup(source, witness.cursor)?
                    .and_then(|(batch, _)| {
                        (batch.meta.revision <= revision)
                            .then_some(PinTarget::Evidence(batch.meta.revision))
                    }))
            }
            crate::AnalysisStreamIdentityV1::Diagnostic(_) => {
                let key = witness.identity.key();
                Ok(self
                    .raw
                    .ranges
                    .range((key.clone(), 0)..=(key, witness.cursor))
                    .next_back()
                    .and_then(|(_, &(birth, slot))| {
                        let entry = &self.raw.entries[&birth];
                        (entry.identity == witness.identity
                            && birth <= revision
                            && entry.commit.spans[slot].last >= witness.cursor)
                            .then_some(PinTarget::Segment(entry.reference.id))
                    }))
            }
        }
    }
}
