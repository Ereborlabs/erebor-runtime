use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use duckdb::params;
use snafu::ResultExt as _;

use super::WriterCut;
use super::scratch::Scratch;
use crate::error::{DatabaseSnafu, InvalidSnafu};
use crate::{GraphReadView, Journal, Member, PendingGraph, Result};

type Identity = (u64, u64, Arc<[u8]>, Arc<[u8]>);
type Entry = (Identity, (u64, u64));

pub(super) struct BaseRows {
    rows: Vec<Entry>,
}

impl BaseRows {
    pub(super) fn closures(&self) -> Vec<(u64, u64, u64, Vec<u8>, u64)> {
        self.rows
            .iter()
            .map(|((writer, relation, _, key), (owner, revision))| {
                (*writer, *owner, *relation, key.to_vec(), *revision)
            })
            .collect()
    }

    pub(super) fn load(
        cuts: &[WriterCut],
        journals: &[&Journal],
        views: &BTreeMap<u64, &GraphReadView>,
        scratch: &mut Scratch<'_>,
    ) -> Result<Self> {
        let scratch = std::cell::RefCell::new(scratch);
        let mut rows = BTreeMap::new();
        for journal in journals {
            let writer = journal.writer();
            let cut = cuts
                .iter()
                .find(|cut| cut.writer == writer)
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "Graph base cut",
                    }
                    .build()
                })?;
            let view = views.get(&writer).ok_or_else(|| {
                InvalidSnafu {
                    field: "Graph base view",
                }
                .build()
            })?;
            let count = journal.touched_keys().count();
            scratch.borrow_mut().charge(
                writer,
                count.saturating_mul(12 * size_of::<(u64, &[u8], &[u8])>()),
            )?;
            let mut wanted = BTreeMap::<u64, BTreeMap<&[u8], BTreeSet<&[u8]>>>::new();
            for (relation, owner, key, _) in journal.touched_keys() {
                scratch.borrow().check(writer)?;
                wanted
                    .entry(relation)
                    .or_default()
                    .entry(key)
                    .or_default()
                    .insert(owner);
            }
            for (relation, wanted) in wanted {
                scratch.borrow_mut().charge(
                    writer,
                    wanted
                        .keys()
                        .map(|key| key.len().saturating_add(size_of::<Vec<u8>>()))
                        .sum(),
                )?;
                let keys = wanted.keys().map(|key| key.to_vec()).collect::<Vec<_>>();
                view.visit_members(
                    relation,
                    Some(&keys),
                    || scratch.borrow().check(writer),
                    |member| {
                        if member.writer == writer
                            && wanted
                                .get(member.key.as_ref())
                                .is_some_and(|owners| owners.contains(member.owner_key.as_ref()))
                        {
                            Self::insert(
                                &mut rows,
                                member,
                                cut.revision,
                                &mut scratch.borrow_mut(),
                            )?;
                        }
                        Ok(())
                    },
                )?;
            }
            let count = journal.clear_owners().count();
            if count != 0 {
                scratch.borrow_mut().charge(
                    writer,
                    count.saturating_mul(12 * size_of::<Option<&[u8]>>()),
                )?;
                let mut clear = journal.clear_owners().collect::<BTreeSet<_>>();
                if clear.contains(&None) {
                    clear = BTreeSet::from([None]);
                }
                for owner in clear {
                    view.visit_writer(
                        writer,
                        owner,
                        || scratch.borrow().check(writer),
                        |member| {
                            Self::insert(&mut rows, member, cut.revision, &mut scratch.borrow_mut())
                        },
                    )?;
                }
            }
        }
        Ok(Self {
            rows: rows.into_iter().collect(),
        })
    }

    fn insert(
        rows: &mut BTreeMap<Identity, (u64, u64)>,
        member: &Member,
        revision: u64,
        scratch: &mut Scratch<'_>,
    ) -> Result<()> {
        if member.writer == 0
            || member.relation == 0
            || member.owner == 0
            || member.revision == 0
            || member.revision > revision
        {
            return InvalidSnafu {
                field: "Graph open base identity",
            }
            .fail();
        }
        let identity = (
            member.writer,
            member.relation,
            Arc::clone(&member.owner_key),
            Arc::clone(&member.key),
        );
        if let Some(prior) = rows.get(&identity) {
            if *prior != (member.owner, member.revision) {
                return InvalidSnafu {
                    field: "Graph duplicate open identity",
                }
                .fail();
            }
            return Ok(());
        }
        scratch.charge(member.writer, 12 * std::mem::size_of::<Entry>())?;
        rows.insert(identity, (member.owner, member.revision));
        Ok(())
    }

    pub(super) fn check(&self, journals: &[&Journal], scratch: &Scratch<'_>) -> Result<()> {
        for journal in journals {
            for (relation, owner, key, expected) in journal.touched_keys() {
                scratch.check(journal.writer())?;
                if let Some(expected) = expected {
                    let present =
                        self.rows
                            .binary_search_by(|entry| {
                                (entry.0.0, entry.0.1, entry.0.2.as_ref(), entry.0.3.as_ref())
                                    .cmp(&(journal.writer(), relation, owner, key))
                            })
                            .is_ok();
                    if present != expected {
                        return InvalidSnafu {
                            field: "Graph journal base state",
                        }
                        .fail();
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn close(
        self,
        graph: &PendingGraph<'_>,
        scratch: &Scratch<'_>,
    ) -> Result<BTreeMap<u64, (u64, u64)>> {
        if self.rows.is_empty() {
            return Ok(BTreeMap::new());
        }
        graph.connection.execute_batch(
            "CREATE TEMP TABLE graph_delta_close (writer_id UBIGINT,owner_ref UBIGINT,relation_id UBIGINT,
                entity_key BLOB,valid_from UBIGINT)"
        ).context(DatabaseSnafu { operation: "create Graph base closes" })?;
        let result = self.close_rows(graph, scratch);
        let cleanup = graph
            .connection
            .execute_batch("DROP TABLE graph_delta_close")
            .context(DatabaseSnafu {
                operation: "release Graph base closes",
            });
        let result = result?;
        cleanup?;
        Ok(result)
    }

    fn close_rows(
        self,
        graph: &PendingGraph<'_>,
        scratch: &Scratch<'_>,
    ) -> Result<BTreeMap<u64, (u64, u64)>> {
        let mut counts = BTreeMap::<u64, (u64, u64)>::new();
        let expected = self.rows.len();
        {
            let mut rows =
                graph
                    .connection
                    .appender("graph_delta_close")
                    .context(DatabaseSnafu {
                        operation: "open Graph base closes",
                    })?;
            for ((writer, relation, _, key), (owner, revision)) in self.rows {
                scratch.check(writer)?;
                rows.append_row(params![writer, owner, relation, key.as_ref(), revision])
                    .context(DatabaseSnafu {
                        operation: "append Graph base close",
                    })?;
                counts.entry(writer).or_default().1 += 1;
            }
            rows.flush().context(DatabaseSnafu {
                operation: "flush Graph base closes",
            })?;
        }
        let closed = graph.connection.execute(
            "UPDATE graph_members m SET valid_to=? WHERE m.valid_to IS NULL AND EXISTS(
                SELECT 1 FROM graph_delta_close c WHERE c.writer_id=m.writer_id AND c.owner_ref=m.owner_ref
                    AND c.relation_id=m.relation_id AND c.entity_key=m.entity_key AND c.valid_from=m.valid_from)",
            params![graph.revision],
        ).context(DatabaseSnafu { operation: "close final Graph base" })?;
        if closed != expected {
            return InvalidSnafu {
                field: "Graph closed base count",
            }
            .fail();
        }
        Ok(counts)
    }
}
