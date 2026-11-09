use std::collections::BTreeSet;

use fjall::BranchSnapshot;
use snafu::ResultExt as _;

use super::{
    record::{Key, StoredRelation},
    Declaration, Graph,
};
use crate::{
    error::{InvalidSnafu, NativeSnafu},
    EntityKind, Result,
};

impl Graph {
    pub fn check_installation(
        &self,
        snapshot: &BranchSnapshot,
        writers: &[u64],
        relations: &[Declaration],
    ) -> Result<()> {
        for relation in relations {
            let expected = StoredRelation::new(self.id, relation)?;
            if relation.relation == 0
                || !matches!(
                    (relation.shape.kind, relation.endpoints),
                    (EntityKind::Node, None) | (EntityKind::Edge, Some((1.., 1..)))
                )
                || snapshot
                    .get(Key::record(b'f', &[relation.relation]))
                    .context(NativeSnafu {
                        operation: "check Graph declaration",
                    })?
                    .as_deref()
                    != Some(Key::encode(&expected)?.as_slice())
            {
                return InvalidSnafu {
                    field: "native Graph installed declaration",
                }
                .fail();
            }
            if let Some((from, to)) = relation.endpoints {
                for endpoint in [from, to] {
                    let bytes = snapshot
                        .get(Key::record(b'f', &[endpoint]))
                        .context(NativeSnafu {
                            operation: "check Graph endpoint declaration",
                        })?
                        .ok_or_else(|| {
                            InvalidSnafu {
                                field: "native Graph endpoint declaration",
                            }
                            .build()
                        })?;
                    let stored: StoredRelation = Key::decode(&bytes)?;
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
            if *writer == 0
                || snapshot
                    .get(Key::record(b'w', &[*writer]))
                    .context(NativeSnafu {
                        operation: "check installed Graph writer",
                    })?
                    .as_deref()
                    != Some(self.id.to_be_bytes().as_slice())
            {
                return InvalidSnafu {
                    field: "native Graph installed writer",
                }
                .fail();
            }
        }
        self.check_index(
            snapshot,
            b'g',
            relations.iter().map(|relation| relation.relation),
        )?;
        self.check_index(snapshot, b'v', writers.iter().copied())
    }

    fn check_index(
        &self,
        snapshot: &BranchSnapshot,
        kind: u8,
        ids: impl Iterator<Item = u64>,
    ) -> Result<()> {
        let mut expected = ids
            .map(|id| Key::record(kind, &[self.id, id]))
            .collect::<BTreeSet<_>>();
        for entry in snapshot.prefix(Key::record(kind, &[self.id])) {
            let (key, value) = entry.context(NativeSnafu {
                operation: "check Graph installation index",
            })?;
            if !expected.remove(key.as_ref()) || value.as_ref() != &key[key.len() - 8..] {
                return InvalidSnafu {
                    field: "native Graph installation index",
                }
                .fail();
            }
        }
        if !expected.is_empty() {
            return InvalidSnafu {
                field: "native Graph installation index",
            }
            .fail();
        }
        Ok(())
    }
}
