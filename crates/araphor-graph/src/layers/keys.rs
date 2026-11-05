use std::ops::Range;

use crate::dictionary::{Dictionary, KeyGroup};

use super::{scratch::Scratch, PreparedRows, Result};

struct KeyRanges {
    owners: Range<usize>,
    entities: Range<usize>,
    endpoints: Option<[Range<usize>; 3]>,
}

pub(super) struct LayerKeys {
    owners: Vec<u64>,
    entities: Vec<u64>,
    labels: Vec<u64>,
    ranges: Vec<KeyRanges>,
}

pub(super) struct MemberKeys<'a> {
    pub(super) owners: &'a [u64],
    pub(super) entities: &'a [u64],
    pub(super) endpoints: Option<[&'a [u64]; 3]>,
}

impl LayerKeys {
    pub(super) fn new(
        connection: &duckdb::Connection,
        rows: &[PreparedRows],
        scratch: &mut Scratch<'_>,
    ) -> Result<Self> {
        for row in rows {
            scratch.check(row.writer)?;
            let fields = if row.endpoints.is_some() { 5 } else { 2 };
            let bytes = row
                .keys
                .len()
                .checked_mul(fields * 4 * size_of::<u64>())
                .and_then(|bytes| bytes.checked_add(2 * size_of::<KeyRanges>()))
                .and_then(|bytes| bytes.checked_add(20 * size_of::<KeyGroup<'_>>()))
                .and_then(|bytes| bytes.checked_add(72 * size_of::<u64>()))
                .ok_or_else(|| {
                    crate::error::InvalidSnafu {
                        field: "Graph dictionary memory",
                    }
                    .build()
                })?;
            scratch.charge(row.writer, bytes)?;
        }
        let mut owners = Vec::new();
        let mut entities = Vec::new();
        let mut labels = Vec::new();
        let mut ranges = Vec::with_capacity(rows.len());
        let mut counts = [0; 3];
        let mut writers = [Vec::new(), Vec::new(), Vec::new()];
        for row in rows {
            scratch.check(row.writer)?;
            let owner = Self::push(&mut owners, &mut counts[0], row.writer, &row.owners);
            writers[0].push(row.writer);
            let entity = Self::push(&mut entities, &mut counts[1], row.relation, &row.keys);
            writers[1].push(row.writer);
            let endpoints = row.endpoints.zip(row.edge_keys.as_ref()).map(
                |((from, to, graph), (sources, targets, names))| {
                    writers[1].extend([row.writer; 2]);
                    writers[2].push(row.writer);
                    [
                        Self::push(&mut entities, &mut counts[1], from, sources),
                        Self::push(&mut entities, &mut counts[1], to, targets),
                        Self::push(&mut labels, &mut counts[2], graph, names),
                    ]
                },
            );
            ranges.push(KeyRanges {
                owners: owner,
                entities: entity,
                endpoints,
            });
        }
        let owners = Dictionary::Owners.intern(connection, &owners, |index| {
            scratch.check(writers[0][index])
        })?;
        let entities = Dictionary::Entities.intern(connection, &entities, |index| {
            scratch.check(writers[1][index])
        })?;
        let labels = Dictionary::Labels.intern(connection, &labels, |index| {
            scratch.check(writers[2][index])
        })?;
        Ok(Self {
            owners,
            entities,
            labels,
            ranges,
        })
    }

    fn push<'a>(
        groups: &mut Vec<KeyGroup<'a>>,
        count: &mut usize,
        scope: u64,
        keys: &'a [Vec<u8>],
    ) -> Range<usize> {
        let start = *count;
        *count += keys.len();
        groups.push(KeyGroup { scope, keys });
        start..*count
    }

    pub(super) fn batch(&self, index: usize) -> MemberKeys<'_> {
        let ranges = &self.ranges[index];
        MemberKeys {
            owners: &self.owners[ranges.owners.clone()],
            entities: &self.entities[ranges.entities.clone()],
            endpoints: ranges.endpoints.as_ref().map(|[from, to, label]| {
                [
                    &self.entities[from.clone()],
                    &self.entities[to.clone()],
                    &self.labels[label.clone()],
                ]
            }),
        }
    }
}
