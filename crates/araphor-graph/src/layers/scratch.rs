use std::any::Any;
use std::collections::BTreeMap;

use crate::{error::InvalidSnafu, Result};

pub(super) type Lease = Box<dyn Any + Send + Sync>;
pub(super) type Reserve<'a> = dyn Fn(u64, usize, usize) -> Result<Option<Lease>> + 'a;

pub(super) struct Scratch<'a> {
    reserve: &'a Reserve<'a>,
    bytes: BTreeMap<u64, usize>,
    leases: Vec<Lease>,
}

impl<'a> Scratch<'a> {
    pub(super) fn new(reserve: &'a Reserve<'a>) -> Self {
        Self {
            reserve,
            bytes: BTreeMap::new(),
            leases: Vec::new(),
        }
    }

    pub(super) fn charge(&mut self, writer: u64, bytes: usize) -> Result<()> {
        let bytes = bytes
            .checked_add(std::mem::size_of::<Lease>() * 2)
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "Graph scratch memory",
                }
                .build()
            })?;
        let total = self
            .bytes
            .get(&writer)
            .copied()
            .unwrap_or_default()
            .checked_add(bytes)
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "Graph scratch memory",
                }
                .build()
            })?;
        if let Some(lease) = (self.reserve)(writer, bytes, total)? {
            self.leases.push(lease);
        }
        self.bytes.insert(writer, total);
        Ok(())
    }

    pub(super) fn into_leases(self) -> Vec<Lease> {
        self.leases
    }

    pub(super) fn check(&self, writer: u64) -> Result<()> {
        (self.reserve)(
            writer,
            0,
            self.bytes.get(&writer).copied().unwrap_or_default(),
        )
        .map(|_| ())
    }
}
