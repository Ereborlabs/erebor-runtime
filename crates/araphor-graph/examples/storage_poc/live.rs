use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound::Included,
    sync::Arc,
    time::Instant,
};

use araphor_graph::{
    native::{Declaration, Graph, LayerRequest, View},
    Read,
};
use arrow_array::RecordBatch;

use super::{
    fixture::{Fixture, Row, Step},
    native::Key,
    Change, GraphRead, Readout, Result, Timing,
};

pub struct Live {
    graph: Graph,
    current: View,
    revision: u64,
}

impl Live {
    pub fn open(branch: &fjall::Branch) -> Result<Self> {
        let graph = Graph::new(1)?;
        let fixture = Fixture::new()?;
        if branch.snapshot()?.get(b"head")?.is_none() {
            let mut tx = branch.write_tx()?;
            graph.install(
                &mut tx,
                &[1, 2],
                &fixture
                    .shapes
                    .iter()
                    .map(|(relation, shape)| Declaration {
                        relation: *relation,
                        shape: shape.clone(),
                        endpoints: (*relation == 3).then_some((2, 2)),
                    })
                    .collect::<Vec<_>>(),
            )?;
            tx.insert(b"head", 1u64.to_be_bytes());
            tx.commit_stamped([Self::cut(1)])?;
        }
        let snapshot = branch.snapshot()?;
        let revision = Key::number(&snapshot.get(b"head")?.ok_or("head absent")?)?;
        let current = graph.view(snapshot, BTreeMap::new(), &|_, _, _| Ok(None))?;
        Ok(Self {
            graph,
            current,
            revision,
        })
    }

    fn cut(revision: u64) -> Vec<u8> {
        [b"cut/".as_slice(), &revision.to_be_bytes()].concat()
    }

    fn snapshot(branch: &fjall::Branch, revision: u64) -> Result<fjall::BranchSnapshot> {
        let (_, cut) = branch
            .snapshot()?
            .range::<Vec<u8>, _>((Included(Self::cut(0)), Included(Self::cut(revision))))
            .next_back()
            .ok_or("Data cut absent")??;
        Ok(branch.read_at(fjall::Revision::from_bytes(cut.as_ref().try_into()?))?)
    }

    fn view(&self, branch: &fjall::Branch, revision: u64) -> Result<View> {
        Ok(self.graph.view(
            Self::snapshot(branch, revision)?,
            BTreeMap::new(),
            &|_, _, _| Ok(None),
        )?)
    }

    pub fn apply(
        &mut self,
        branch: &fjall::Branch,
        step: &Step,
        commit: bool,
        cursor: Option<&[u8]>,
    ) -> Result<Timing> {
        let started = Instant::now();
        let journals = step.journals.values().collect::<Vec<_>>();
        let prepared = self.current.prepare(&journals, &|_, _, _| Ok(None))?;
        let requests = journals
            .iter()
            .map(|journal| {
                Ok(LayerRequest {
                    writer: journal.writer(),
                    layer: step.revision * 10 + journal.writer(),
                    parent: self.current.head(journal.writer())?,
                })
            })
            .collect::<araphor_graph::Result<Vec<_>>>()?;
        let prepare_s = started.elapsed().as_secs_f64();
        let writer = Instant::now();
        let mut tx = branch.write_tx()?;
        assert_eq!(
            Key::number(&tx.get(b"head")?.ok_or("head absent")?)?,
            step.previous
        );
        let mut pending =
            self.graph
                .stage(&mut tx, step.revision, &requests, prepared, &|_, _, _| {
                    Ok(None)
                })?;
        for writer in step.journals.keys() {
            tx.insert(Key::new(b'H', &[*writer]), step.revision.to_be_bytes());
            tx.insert(Key::new(b'S', &[*writer]), step.state(*writer));
            tx.insert(Key::new(b'T', &[*writer]), step.captured.to_be_bytes());
        }
        tx.insert(b"J", rmp_serde::to_vec(&(step.previous, step.captured))?);
        tx.insert(b"head", step.revision.to_be_bytes());
        if let Some(cursor) = cursor {
            tx.insert(b"cursor/package", cursor);
        }
        pending.stamps.push(Self::cut(step.revision));
        let mut sample = Timing {
            revision: step.revision,
            prepare_s,
            work_s: writer.elapsed().as_secs_f64(),
            added: pending.added,
            closed: pending.removed,
            encoded_bytes: pending.encoded_bytes,
            ..Default::default()
        };
        assert_eq!(sample.added, step.added());
        let synced = Instant::now();
        if commit {
            tx.commit_stamped(std::mem::take(&mut pending.stamps))?
                .ok_or("empty Graph commit")?;
            sample.commit_s = synced.elapsed().as_secs_f64();
            self.current = self
                .graph
                .view(branch.snapshot()?, BTreeMap::new(), &|_, _, _| Ok(None))?;
            self.revision = step.revision;
        } else {
            tx.rollback();
            sample.commit_s = synced.elapsed().as_secs_f64();
        }
        sample.total_s = started.elapsed().as_secs_f64();
        Ok(sample)
    }

    pub fn capture<T>(
        &self,
        branch: &fjall::Branch,
        revision: u64,
        action: impl FnOnce(&dyn GraphRead, f64) -> Result<T>,
    ) -> Result<T> {
        let started = Instant::now();
        if revision >= self.revision {
            action(&self.current, started.elapsed().as_secs_f64())
        } else {
            let view = self.view(branch, revision)?;
            action(&view, started.elapsed().as_secs_f64())
        }
    }

    fn rows(view: &View, fixture: &Fixture) -> Result<Vec<Row>> {
        let mut rows = Vec::new();
        let keys = RecordBatch::new_empty(Arc::new(arrow_schema::Schema::empty()));
        for relation in fixture.shapes.keys() {
            for writer in view.writers() {
                view.visit(
                    *relation,
                    Read::Owned(writer),
                    &keys,
                    &|_, _, _| Ok(None),
                    |member| {
                        let properties = Arc::new(member.properties().clone());
                        rows.push(Row {
                            writer: member.writer,
                            relation: member.relation,
                            owner: member.owner,
                            key: member.key,
                            endpoints: member.endpoints,
                            properties,
                            row: member.row,
                            opened: member.revision,
                        });
                        Ok(())
                    },
                )?;
            }
        }
        Ok(rows)
    }

    pub fn inspect(
        &self,
        branch: &fjall::Branch,
        fixture: &Fixture,
        revision: u64,
    ) -> Result<Readout> {
        let started = Instant::now();
        let snapshot = Self::snapshot(branch, revision)?;
        let mut states = Vec::new();
        for writer in [1, 2] {
            for kind in [b'S', b'T'] {
                states.push(
                    snapshot
                        .get(Key::new(kind, &[writer]))?
                        .map(|value| value.to_vec()),
                );
            }
        }
        let capture_s = started.elapsed().as_secs_f64();
        let started = Instant::now();
        let rows = if revision >= self.revision {
            Self::rows(&self.current, fixture)?
        } else {
            Self::rows(&self.view(branch, revision)?, fixture)?
        };
        let read_s = started.elapsed().as_secs_f64();
        let started = Instant::now();
        let mut changes = Vec::new();
        if snapshot.get(b"head")?.as_deref() == Some(revision.to_be_bytes().as_slice()) {
            if let Some(value) = snapshot.get(b"J")? {
                let (previous, _): (u64, u64) = rmp_serde::from_slice(&value)?;
                let before = Self::rows(&self.view(branch, previous)?, fixture)?;
                let after = rows
                    .iter()
                    .map(|row| (row.identity(), row.opened))
                    .collect::<BTreeMap<_, _>>();
                for row in &before {
                    if after.get(&row.identity()) != Some(&row.opened) {
                        changes.push(Change::new(row, row.opened, false));
                    }
                }
                for row in &rows {
                    if row.opened == revision {
                        changes.push(Change::new(row, revision, true));
                    }
                }
            }
        }
        changes.sort();
        Ok(Readout {
            rows,
            states,
            changes,
            capture_s,
            read_s,
            cdc_s: started.elapsed().as_secs_f64(),
        })
    }

    pub fn verify_metadata(
        &self,
        branch: &fjall::Branch,
        fixture: &Fixture,
        revision: u64,
        current: u64,
    ) -> Result<()> {
        assert_eq!(
            Key::number(&branch.snapshot()?.get(b"head")?.ok_or("head absent")?)?,
            current
        );
        let snapshot = Self::snapshot(branch, revision)?;
        let last = fixture
            .steps
            .iter()
            .filter(|step| step.revision <= revision)
            .next_back();
        for writer in [1, 2] {
            assert_eq!(
                snapshot
                    .get(Key::new(b'H', &[writer]))?
                    .map(|value| value.to_vec()),
                last.map(|step| step.revision.to_be_bytes().to_vec())
            );
        }
        let actual = if snapshot.get(b"head")?.as_deref() == Some(revision.to_be_bytes().as_slice())
        {
            snapshot
                .get(b"J")?
                .map(|value| rmp_serde::from_slice::<(u64, u64)>(&value))
                .transpose()?
        } else {
            None
        };
        assert_eq!(
            actual,
            fixture
                .steps
                .iter()
                .find(|step| step.revision == revision)
                .map(|step| (step.previous, step.captured))
        );
        Ok(())
    }

    pub fn assert_keys(
        &self,
        branch: &fjall::Branch,
        changes: &[Change],
        actual: &[Vec<u8>],
    ) -> Result<()> {
        let view = self
            .graph
            .view(branch.snapshot()?, BTreeMap::new(), &|_, _, _| Ok(None))?;
        let expected = changes
            .iter()
            .map(|change| -> Result<_> {
                Ok(view
                    .member_key(change.writer, change.relation, &change.owner, &change.key)?
                    .ok_or("changed Graph identity absent")?)
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let keys = actual.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(keys.len(), actual.len());
        assert_eq!(keys, expected);
        Ok(())
    }

    pub fn assert_stable(branch: &fjall::Branch) -> Result<()> {
        let snapshot = branch.snapshot()?;
        for (kind, fields) in [
            (b'M', 4),
            (b'R', 4),
            (b'K', 4),
            (b'O', 5),
            (b'I', 5),
            (b'E', 7),
        ] {
            let prefix = [b"\0graph/".as_slice(), &[kind]].concat();
            for item in snapshot.prefix(prefix) {
                let (key, _) = item?;
                assert_eq!(key.len(), 8 + fields * 8);
            }
        }
        assert_eq!(snapshot.prefix(b"\0graph/M").count(), 186);
        assert_eq!(snapshot.prefix(b"H").count(), 2);
        assert_eq!(snapshot.prefix(b"J").count(), 1);
        assert!(snapshot.get(b"C")?.is_none());
        assert_eq!(snapshot.prefix(b"\0graph/B").count(), 0);
        Ok(())
    }
}

impl GraphRead for View {
    fn query(&self, relation: u64, read: Read, keys: &RecordBatch) -> Result<Vec<RecordBatch>> {
        let mut batches = Vec::new();
        self.read(relation, read, keys, &|_, _, _| Ok(None), |batch| {
            batches.push(batch.batch().clone());
            Ok(())
        })?;
        Ok(batches)
    }
    fn presence(&self, writer: u64, relation: u64, batch: &RecordBatch) -> Result<Vec<bool>> {
        Ok(self.presence(writer, relation, batch, &|_, _, _| Ok(None))?)
    }
}
