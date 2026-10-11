use std::collections::{BTreeMap, BTreeSet};

use super::{Adapter, Result};
use crate::discovery::model::{require, same};
use crate::*;

mod coverage;
mod groups;
mod lifecycle;
mod merge;
mod recorded;

impl Adapter {
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
