use std::collections::{BTreeMap, BTreeSet};

use super::model::{require, same};
use super::*;
use crate::{DiscoveryInvalidSnafu, EvidenceRecord, Result};

mod comparison;
mod coverage;
mod groups;
mod lifecycle;
mod merge;
mod recorded;
#[cfg(test)]
mod tests;

impl BehaviorSnapshotV1 {
    fn unique_rows<'a, K: Ord + 'a, V: PartialEq + 'a>(
        rows: impl Iterator<Item = (&'a K, &'a V)>,
        kind: &'static str,
    ) -> Result<BTreeMap<&'a K, &'a V>> {
        let mut values = BTreeMap::new();
        for (key, row) in rows {
            if let Some(previous) = values.insert(key, row) {
                same(previous == row, kind)?;
            }
        }
        Ok(values)
    }
}
