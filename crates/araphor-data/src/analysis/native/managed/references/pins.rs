use std::collections::BTreeMap;

use super::{Records, References};
use crate::{PackageErrorCodeV1 as Code, Result};

pub(in crate::analysis::native) struct RawPin {
    pub(in crate::analysis::native) result: u64,
    pub(in crate::analysis::native) segment: u64,
    pub(in crate::analysis::native) expires: u64,
    pub(in crate::analysis::native) ranges: Vec<(u64, u64)>,
}

impl RawPin {
    pub(in crate::analysis::native) fn collect(
        result: u64,
        values: impl IntoIterator<Item = Result<(u64, u64, u64)>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Vec<Self>> {
        let mut groups = BTreeMap::<(u64, u64), Vec<u64>>::new();
        for value in values {
            charge(256)?;
            let (segment, expires, cursor) = value?;
            groups.entry((segment, expires)).or_default().push(cursor);
        }
        Ok(groups
            .into_iter()
            .map(|((segment, expires), mut cursors)| {
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
                    segment,
                    expires,
                    ranges,
                }
            })
            .collect())
    }

    pub(in crate::analysis::native) fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        let invalid = || Code::Invalid.error("managed witness pin value");
        let key = key
            .strip_prefix(References::RAW)
            .filter(|key| key.len() == 24)
            .ok_or_else(invalid)?;
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
            segment: super::super::super::NativeStore::number(&key[8..16])?,
            expires: super::super::super::NativeStore::number(&key[16..])?,
            ranges,
        })
    }

    pub(in crate::analysis::native) fn key(&self) -> Vec<u8> {
        References::key(References::RAW, &[self.result, self.segment, self.expires])
    }

    pub(in crate::analysis::native) fn reverse(&self) -> Vec<u8> {
        References::key(
            References::SEGMENT,
            &[self.segment, self.result, self.expires],
        )
    }

    pub(in crate::analysis::native) fn value(&self) -> Result<Vec<u8>> {
        Records::encode(&self.ranges)
    }
}
