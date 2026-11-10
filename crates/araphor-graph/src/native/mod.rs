mod installation;
mod prepare;
mod record;
mod validation;
mod view;
mod write;

pub use crate::scratch::{Lease, Reserve};
pub use prepare::Prepared;
pub use view::{Member, ReadBatch, View};
pub use write::{LayerRequest, Pending};

use std::collections::BTreeMap;

use fjall::{BranchSnapshot, BranchWriteTransaction};
use snafu::ResultExt as _;

use crate::{
    error::{InvalidSnafu, NativeSnafu},
    EntityKind, Relation, Result,
};
use record::{Key, StoredRelation};

#[derive(Clone, Copy)]
pub struct Graph {
    id: u64,
}

pub struct Declaration {
    pub relation: u64,
    pub shape: Relation,
    pub endpoints: Option<(u64, u64)>,
}

impl Graph {
    /// Return stored layers as writer, layer, parent, and logical revision.
    pub fn layers(
        snapshot: &BranchSnapshot,
    ) -> impl Iterator<Item = Result<(u64, u64, Option<u64>, u64)>> + '_ {
        snapshot.prefix(Key::record(b'l', &[])).map(|entry| {
            let (key, value) = entry.context(NativeSnafu {
                operation: "read native Graph layers",
            })?;
            let (writer, head) = record::Head::layer(&key, &value)?;
            Ok((writer, head.layer, head.parent, head.revision))
        })
    }

    pub fn new(id: u64) -> Result<Self> {
        if id == 0 {
            return InvalidSnafu {
                field: "native Graph identity",
            }
            .fail();
        }
        Ok(Self { id })
    }

    pub fn install(
        &self,
        tx: &mut BranchWriteTransaction<'_>,
        writers: &[u64],
        relations: &[Declaration],
    ) -> Result<()> {
        for relation in relations {
            if relation.relation == 0
                || !matches!(
                    (relation.shape.kind, relation.endpoints),
                    (EntityKind::Node, None) | (EntityKind::Edge, Some((1.., 1..)))
                )
            {
                return InvalidSnafu {
                    field: "native Graph declaration",
                }
                .fail();
            }
            let record = StoredRelation::new(self.id, relation)?;
            let key = Key::record(b'f', &[relation.relation]);
            let encoded = Key::encode(&record)?;
            if let Some(stored) = tx.get(&key).context(NativeSnafu {
                operation: "read Graph declaration",
            })? {
                if stored.as_ref() != encoded {
                    return InvalidSnafu {
                        field: "native Graph declaration conflict",
                    }
                    .fail();
                }
            } else {
                tx.insert(key, encoded);
                tx.insert(
                    Key::record(b'g', &[self.id, relation.relation]),
                    relation.relation.to_be_bytes(),
                );
            }
        }
        for relation in relations {
            if let Some((from, to)) = relation.endpoints {
                for endpoint in [from, to] {
                    let stored = tx
                        .get(Key::record(b'f', &[endpoint]))
                        .context(NativeSnafu {
                            operation: "read Graph endpoint declaration",
                        })?
                        .ok_or_else(|| {
                            InvalidSnafu {
                                field: "native Graph endpoint declaration",
                            }
                            .build()
                        })?;
                    let stored: StoredRelation = Key::decode(&stored)?;
                    if stored.graph != self.id || stored.kind != EntityKind::Node as u8 {
                        return InvalidSnafu {
                            field: "native Graph endpoint relation",
                        }
                        .fail();
                    }
                }
            }
        }
        for writer in writers {
            if *writer == 0 {
                return InvalidSnafu {
                    field: "native Graph writer",
                }
                .fail();
            }
            let key = Key::record(b'w', &[*writer]);
            if let Some(value) = tx.get(&key).context(NativeSnafu {
                operation: "read Graph writer",
            })? {
                if Key::number(&value)? != self.id {
                    return InvalidSnafu {
                        field: "native Graph writer conflict",
                    }
                    .fail();
                }
            } else {
                tx.insert(key, self.id.to_be_bytes());
                tx.insert(Key::record(b'v', &[self.id, *writer]), writer.to_be_bytes());
            }
        }
        Ok(())
    }

    pub fn view(
        &self,
        snapshot: BranchSnapshot,
        selected: BTreeMap<u64, BranchSnapshot>,
        reserve: &Reserve<'_>,
    ) -> Result<View> {
        View::new(*self, snapshot, selected, reserve)
    }
}

#[cfg(test)]
mod tests;
