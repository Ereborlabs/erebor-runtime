use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use arrow_array::RecordBatch;
use arrow_ipc::{reader::StreamReader, writer::StreamWriter};

use super::fixture::{Fixture, Member, Row, Step};
use super::kv::{self, Read, Write};
use super::{Change, GraphRead, Readout, Result, Timing};

pub struct Native {
    db: kv::Database,
    properties: BTreeMap<u64, Arc<RecordBatch>>,
    stable: bool,
    snapshots: BTreeMap<u64, fjall::Snapshot>,
    revisions: BTreeMap<u64, [u8; 8]>,
    #[cfg(feature = "cdc-poc")]
    live: Option<super::live::Live>,
}

struct Prepared {
    properties: BTreeMap<u64, Arc<RecordBatch>>,
    added: usize,
    closed: usize,
    encoded: usize,
}

pub struct Key;
impl Key {
    pub fn new(kind: u8, fields: &[u64]) -> Vec<u8> {
        let mut key = vec![kind];
        for field in fields {
            key.extend_from_slice(&field.to_be_bytes());
        }
        key
    }
    fn dictionary(kind: u64, scope: u64, key: &[u8]) -> Vec<u8> {
        [Self::new(b'D', &[kind, scope]), key.to_vec()].concat()
    }
    pub(super) fn number(bytes: &[u8]) -> Result<u64> {
        Ok(u64::from_be_bytes(bytes.try_into()?))
    }
    fn at(kind: u8, fields: &[u64], revision: u64, stable: bool) -> Vec<u8> {
        let mut key = Self::new(kind, fields);
        if !stable {
            key.extend_from_slice(&revision.to_be_bytes());
        }
        key
    }
}

impl Native {
    pub fn shutdown(&self) -> Result<()> {
        self.db.close()
    }

    pub fn maintenance(&self) -> Option<kv::Maintenance> {
        self.db.maintenance()
    }

    pub fn open(kind: &str, path: &Path) -> Result<Self> {
        let stable = matches!(kind, "fjall-stable" | "neon-stable");
        let kind = match kind {
            #[cfg(not(feature = "cdc-poc"))]
            "fjall-stable" => "fjall",
            "neon-stable" => "neon-layers",
            other => other,
        };
        let db = kv::Database::open(kind, path)?;
        #[cfg(feature = "cdc-poc")]
        if let kv::Database::FjallBranch(_, branch) = &db {
            let live = super::live::Live::open(branch)?;
            return Ok(Self {
                db,
                properties: BTreeMap::new(),
                stable,
                snapshots: BTreeMap::new(),
                revisions: BTreeMap::new(),
                live: Some(live),
            });
        }
        let mut revisions = BTreeMap::new();
        if db.read(|r| r.get(b"head"))?.is_none() {
            let (_, _, _, receipt) = db.write_at(1, true, |tx| {
                tx.put(b"head", &1u64.to_be_bytes())?;
                tx.put(b"next", &1u64.to_be_bytes())
            })?;
            if let Some(revision) = receipt {
                revisions.insert(1, revision);
            }
        }
        let properties = db.read(|tx| {
            let mut values = BTreeMap::new();
            for (key, bytes) in tx.prefix(b"P")? {
                let id = Key::number(&key[1..])?;
                let batch = StreamReader::try_new(Cursor::new(bytes), None)?
                    .next()
                    .ok_or("property chunk absent")??;
                values.insert(id, Arc::new(batch));
            }
            Ok(values)
        })?;
        let mut snapshots = BTreeMap::new();
        if stable {
            if let kv::Database::Fjall(database, _) = &db {
                let head = db.read(|tx| Key::number(&tx.get(b"head")?.ok_or("head absent")?))?;
                snapshots.insert(head, database.read_tx());
            }
        }
        Ok(Self {
            db,
            properties,
            stable,
            snapshots,
            revisions,
            #[cfg(feature = "cdc-poc")]
            live: None,
        })
    }

    pub(super) fn take_revisions(&mut self) -> BTreeMap<u64, [u8; 8]> {
        std::mem::take(&mut self.revisions)
    }

    pub(super) fn restore_revisions(&mut self, revisions: BTreeMap<u64, [u8; 8]>) {
        self.revisions = revisions;
    }

    pub fn apply(&mut self, _fixture: &Fixture, step: &Step, commit: bool) -> Result<Timing> {
        self.apply_saved(step, commit, None)
    }

    #[cfg(feature = "cdc-poc")]
    pub fn database(&self) -> &kv::Database {
        &self.db
    }

    #[cfg(feature = "cdc-poc")]
    pub fn apply_checkpoint(&mut self, step: &Step, cursor: &[u8], commit: bool) -> Result<Timing> {
        self.apply_saved(step, commit, Some(cursor))
    }

    #[cfg(feature = "cdc-poc")]
    pub fn assert_member_keys(&self, changes: &[Change], actual: &[Vec<u8>]) -> Result<()> {
        if let (Some(live), kv::Database::FjallBranch(_, branch)) = (&self.live, &self.db) {
            return live.assert_keys(branch, changes, actual);
        }
        self.db.read(|tx| {
            let mut expected = BTreeSet::new();
            for change in changes {
                let owner = Key::number(
                    &tx.get(&Key::dictionary(0, change.writer, &change.owner))?
                        .ok_or("changed owner absent")?,
                )?;
                let entity = Key::number(
                    &tx.get(&Key::dictionary(1, change.relation, &change.key))?
                        .ok_or("changed entity absent")?,
                )?;
                expected.insert(Key::at(
                    b'M',
                    &[change.writer, owner, change.relation, entity],
                    change.opened,
                    self.stable,
                ));
            }
            let keys = actual.iter().cloned().collect::<BTreeSet<_>>();
            assert_eq!(keys.len(), actual.len());
            assert_eq!(keys, expected);
            Ok(())
        })
    }

    #[cfg(feature = "cdc-poc")]
    pub fn assert_stable_keys(&self) -> Result<()> {
        assert!(self.stable);
        if let kv::Database::FjallBranch(_, branch) = &self.db {
            return super::live::Live::assert_stable(branch);
        }
        self.db.read(|tx| {
            for (kind, fields) in [
                (b'M', 4),
                (b'R', 4),
                (b'K', 4),
                (b'O', 5),
                (b'I', 5),
                (b'B', 5),
                (b'H', 1),
                (b'S', 1),
                (b'T', 1),
                (b'J', 0),
                (b'C', 0),
            ] {
                for (key, _) in tx.prefix(&[kind])? {
                    assert_eq!(key.len(), 1 + fields * 8);
                }
            }
            assert_eq!(tx.prefix(b"M")?.len(), 186);
            assert_eq!(tx.prefix(b"H")?.len(), 2);
            assert_eq!(tx.prefix(b"J")?.len(), 1);
            assert_eq!(tx.prefix(b"C")?.len(), 1);
            Ok(())
        })
    }

    fn apply_saved(&mut self, step: &Step, commit: bool, cursor: Option<&[u8]>) -> Result<Timing> {
        #[cfg(feature = "cdc-poc")]
        if let (Some(live), kv::Database::FjallBranch(_, branch)) = (&mut self.live, &self.db) {
            return live.apply(branch, step, commit, cursor);
        }
        let started = Instant::now();
        let prepare_s = started.elapsed().as_secs_f64();
        let (prepared, work, commit_s, receipt) =
            self.db.write_at(step.revision, commit, |tx| {
                let prepared = Self::stage(tx, step, self.stable)?;
                if let Some(cursor) = cursor {
                    tx.put(b"cursor/package", cursor)?;
                }
                Ok(prepared)
            })?;
        let mut sample = Timing {
            revision: step.revision,
            prepare_s,
            work_s: work,
            commit_s,
            added: prepared.added,
            closed: prepared.closed,
            encoded_bytes: prepared.encoded,
            ..Default::default()
        };
        assert_eq!(sample.added, step.added());
        if commit {
            self.properties.extend(prepared.properties);
            if let Some(revision) = receipt {
                self.revisions.insert(step.revision, revision);
            }
            if self.stable {
                if let kv::Database::Fjall(db, _) = &self.db {
                    self.snapshots.insert(step.revision, db.read_tx());
                }
            }
        }
        sample.total_s = started.elapsed().as_secs_f64();
        Ok(sample)
    }

    fn stage(tx: &mut dyn Write, step: &Step, stable: bool) -> Result<Prepared> {
        let head = Key::number(&tx.get(b"head")?.ok_or("head absent")?)?;
        assert_eq!(head, step.previous);
        let mut next = Key::number(&tx.get(b"next")?.ok_or("allocator absent")?)?;
        let mut result = Prepared {
            properties: BTreeMap::new(),
            added: 0,
            closed: 0,
            encoded: 0,
        };
        let mut changes = Vec::new();
        for (writer, owner) in &step.clears {
            let prefix = if let Some(owner) = owner {
                let Some(id) = tx.get(&Key::dictionary(0, *writer, owner))? else {
                    continue;
                };
                Key::new(b'A', &[*writer, Key::number(&id)?])
            } else {
                Key::new(b'A', &[*writer])
            };
            for (active, member) in tx.prefix(&prefix)? {
                changes.push(Self::close(tx, &member, step.revision, stable)?);
                tx.remove(&active)?;
                result.closed += 1;
            }
        }
        for group in &step.groups {
            let chunk = Self::allocate(&mut next);
            let batch = group.rows[0].properties.as_ref();
            let mut writer = StreamWriter::try_new(Vec::new(), &batch.schema())?;
            writer.write(batch)?;
            writer.finish()?;
            let bytes = writer.into_inner()?;
            result.encoded += bytes.len();
            tx.put(&Key::new(b'P', &[chunk]), &bytes)?;
            result
                .properties
                .insert(chunk, Arc::clone(&group.rows[0].properties));
            for row in &group.rows {
                let owner = Self::intern(tx, &mut next, 0, row.writer, &row.owner)?;
                let entity = Self::intern(tx, &mut next, 1, row.relation, &row.key)?;
                let open = Key::new(b'A', &[row.writer, owner, row.relation, entity]);
                let old = tx.get(&open)?;
                if let Some(oldkey) = old {
                    changes.push(Self::close(tx, &oldkey, step.revision, stable)?);
                    tx.remove(&open)?;
                    result.closed += 1;
                }
                let endpoints = if let Some([from, to, label]) = &row.endpoints {
                    Some([
                        Self::intern(tx, &mut next, 1, 2, from)?,
                        Self::intern(tx, &mut next, 1, 2, to)?,
                        Self::intern(tx, &mut next, 2, 1, label)?,
                    ])
                } else {
                    None
                };
                let property = Self::allocate(&mut next);
                tx.put(
                    &Key::new(b'L', &[property]),
                    &rmp_serde::to_vec(&(chunk, row.row))?,
                )?;
                let member = Member {
                    writer: row.writer,
                    owner,
                    relation: row.relation,
                    entity,
                    opened: step.revision,
                    closed: None,
                    property,
                    endpoints,
                };
                let key = Key::at(
                    b'M',
                    &[row.writer, owner, row.relation, entity],
                    step.revision,
                    stable,
                );
                tx.put(&key, &rmp_serde::to_vec(&member)?)?;
                tx.put(&open, &key)?;
                tx.put(
                    &Key::at(
                        b'R',
                        &[row.relation, row.writer, owner, entity],
                        step.revision,
                        stable,
                    ),
                    &key,
                )?;
                tx.put(
                    &Key::at(
                        b'K',
                        &[row.relation, entity, row.writer, owner],
                        step.revision,
                        stable,
                    ),
                    &key,
                )?;
                if let Some([from, to, label]) = endpoints {
                    for (kind, endpoint) in [(b'O', from), (b'I', to), (b'B', label)] {
                        tx.put(
                            &Key::at(
                                kind,
                                &[row.relation, endpoint, row.writer, owner, entity],
                                step.revision,
                                stable,
                            ),
                            &key,
                        )?;
                    }
                }
                changes.push(Change::new(row, step.revision, true));
                result.added += 1;
            }
        }
        for group in &step.groups {
            for row in &group.rows {
                if let Some([from, to, _]) = &row.endpoints {
                    for key in [from, to] {
                        let id = Key::number(
                            &tx.get(&Key::dictionary(1, 2, key))?
                                .ok_or("endpoint identity absent")?,
                        )?;
                        let mut present = false;
                        for (_, key) in tx.prefix(&Key::new(b'K', &[2, id]))? {
                            let member: Member = rmp_serde::from_slice(
                                &tx.get(&key)?.ok_or("endpoint member absent")?,
                            )?;
                            present |= member.closed.is_none();
                        }
                        assert!(present, "edge endpoint absent");
                    }
                }
            }
        }
        for writer in [1, 2] {
            tx.put(
                &Key::at(b'H', &[writer], step.revision, stable),
                &step.revision.to_be_bytes(),
            )?;
            tx.put(
                &Key::at(b'S', &[writer], step.revision, stable),
                &step.state(writer),
            )?;
            tx.put(
                &Key::at(b'T', &[writer], step.revision, stable),
                &step.captured.to_be_bytes(),
            )?;
        }
        changes.sort();
        if stable {
            tx.put(b"C", &rmp_serde::to_vec(&changes)?)?;
        } else {
            for (slot, change) in changes.iter().enumerate() {
                tx.put(
                    &Key::new(b'C', &[step.revision, slot as u64]),
                    &rmp_serde::to_vec(change)?,
                )?;
            }
        }
        tx.put(
            &Key::at(b'J', &[], step.revision, stable),
            &rmp_serde::to_vec(&(step.previous, step.captured))?,
        )?;
        tx.put(b"next", &next.to_be_bytes())?;
        tx.put(b"head", &step.revision.to_be_bytes())?;
        Ok(result)
    }

    fn close(tx: &mut dyn Write, key: &[u8], revision: u64, stable: bool) -> Result<Change> {
        let mut member: Member = rmp_serde::from_slice(&tx.get(key)?.ok_or("member absent")?)?;
        assert!(member.closed.is_none());
        if stable {
            tx.remove(key)?;
            tx.remove(&Key::new(
                b'R',
                &[member.relation, member.writer, member.owner, member.entity],
            ))?;
            tx.remove(&Key::new(
                b'K',
                &[member.relation, member.entity, member.writer, member.owner],
            ))?;
            if let Some([from, to, label]) = member.endpoints {
                for (kind, endpoint) in [(b'O', from), (b'I', to), (b'B', label)] {
                    tx.remove(&Key::new(
                        kind,
                        &[
                            member.relation,
                            endpoint,
                            member.writer,
                            member.owner,
                            member.entity,
                        ],
                    ))?;
                }
            }
        } else {
            member.closed = Some(revision);
            tx.put(key, &rmp_serde::to_vec(&member)?)?;
        }
        Ok(Change {
            writer: member.writer,
            relation: member.relation,
            owner: tx
                .get(&Key::new(b'V', &[member.owner]))?
                .ok_or("owner absent")?,
            key: tx
                .get(&Key::new(b'V', &[member.entity]))?
                .ok_or("entity absent")?,
            opened: member.opened,
            added: false,
        })
    }

    pub fn capture<T>(
        &self,
        fixture: &Fixture,
        revision: u64,
        action: impl FnOnce(&dyn GraphRead, f64) -> Result<T>,
    ) -> Result<T> {
        #[cfg(feature = "cdc-poc")]
        if let (Some(live), kv::Database::FjallBranch(_, branch)) = (&self.live, &self.db) {
            return live.capture(branch, revision, action);
        }
        let started = Instant::now();
        self.read_at(revision, |tx| {
            for writer in [1, 2] {
                let _ = Self::metadata(tx, b'H', writer, revision, self.stable)?;
            }
            let view = View {
                tx,
                properties: &self.properties,
                fixture,
                revision,
                stable: self.stable,
            };
            action(&view, started.elapsed().as_secs_f64())
        })
    }

    fn read_at<T>(&self, revision: u64, action: impl FnOnce(&dyn Read) -> Result<T>) -> Result<T> {
        if self.stable {
            if let kv::Database::Fjall(_, table) = &self.db {
                let (_, snapshot) = self
                    .snapshots
                    .range(..=revision)
                    .next_back()
                    .ok_or("Fjall historical snapshot is not open")?;
                return action(&kv::FjallRead {
                    tx: snapshot.clone(),
                    table,
                });
            }
        }
        self.db.read_at(revision, action)
    }

    fn metadata(
        tx: &dyn Read,
        kind: u8,
        writer: u64,
        revision: u64,
        stable: bool,
    ) -> Result<Option<Vec<u8>>> {
        if stable {
            tx.get(&Key::new(kind, &[writer]))
        } else {
            tx.floor(&Key::new(kind, &[writer]), revision)
        }
    }

    fn allocate(next: &mut u64) -> u64 {
        let value = *next;
        *next += 1;
        value
    }

    fn intern(
        tx: &mut dyn Write,
        next: &mut u64,
        kind: u64,
        scope: u64,
        key: &[u8],
    ) -> Result<u64> {
        let lookup = Key::dictionary(kind, scope, key);
        if let Some(id) = tx.get(&lookup)? {
            return Key::number(&id);
        }
        let id = Self::allocate(next);
        tx.put(&lookup, &id.to_be_bytes())?;
        tx.put(&Key::new(b'V', &[id]), key)?;
        Ok(id)
    }

    pub fn inspect(&self, fixture: &Fixture, revision: u64, _all: bool) -> Result<Readout> {
        #[cfg(feature = "cdc-poc")]
        if let (Some(live), kv::Database::FjallBranch(_, branch)) = (&self.live, &self.db) {
            return live.inspect(branch, fixture, revision);
        }
        let started = Instant::now();
        self.read_at(revision, |tx| {
            for writer in [1, 2] {
                let head = Self::metadata(tx, b'H', writer, revision, self.stable)?;
                if fixture.steps.iter().any(|s| s.revision <= revision) {
                    assert!(head.is_some());
                }
            }
            let mut states = Vec::new();
            for writer in [1, 2] {
                states.push(Self::metadata(tx, b'S', writer, revision, self.stable)?);
                states.push(Self::metadata(tx, b'T', writer, revision, self.stable)?);
            }
            let capture_s = started.elapsed().as_secs_f64();
            let started = Instant::now();
            let mut rows = Vec::new();
            for (_, key) in tx.prefix(b"R")? {
                Self::select(tx, &self.properties, &key, revision, self.stable, &mut rows)?;
            }
            let read_s = started.elapsed().as_secs_f64();
            let started = Instant::now();
            let mut changes = Vec::new();
            if self.stable {
                if tx.get(b"head")?.as_deref() == Some(revision.to_be_bytes().as_slice()) {
                    changes = tx
                        .get(b"C")?
                        .map(|v| rmp_serde::from_slice(&v))
                        .transpose()?
                        .unwrap_or_default();
                }
            } else {
                for (_, value) in tx.prefix(&Key::new(b'C', &[revision]))? {
                    changes.push(rmp_serde::from_slice::<Change>(&value)?);
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
        })
    }

    pub fn verify_metadata(&self, fixture: &Fixture, revision: u64, current: u64) -> Result<()> {
        #[cfg(feature = "cdc-poc")]
        if let (Some(live), kv::Database::FjallBranch(_, branch)) = (&self.live, &self.db) {
            return live.verify_metadata(branch, fixture, revision, current);
        }
        self.db.read(|tx| {
            assert_eq!(
                Key::number(&tx.get(b"head")?.ok_or("head absent")?)?,
                current
            );
            Ok(())
        })?;
        self.read_at(revision, |tx| {
            let last = fixture
                .steps
                .iter()
                .filter(|s| s.revision <= revision)
                .next_back();
            for writer in [1, 2] {
                assert_eq!(
                    Self::metadata(tx, b'H', writer, revision, self.stable)?,
                    last.map(|s| s.revision.to_be_bytes().to_vec())
                );
            }
            let key = Key::at(b'J', &[], revision, self.stable);
            let actual = if self.stable
                && tx.get(b"head")?.as_deref() != Some(revision.to_be_bytes().as_slice())
            {
                None
            } else {
                tx.get(&key)?
                    .map(|bytes| rmp_serde::from_slice::<(u64, u64)>(&bytes))
                    .transpose()?
            };
            let expected = fixture
                .steps
                .iter()
                .find(|s| s.revision == revision)
                .map(|s| (s.previous, s.captured));
            assert_eq!(actual, expected);
            Ok(())
        })
    }

    fn select(
        tx: &dyn Read,
        properties: &BTreeMap<u64, Arc<RecordBatch>>,
        key: &[u8],
        revision: u64,
        stable: bool,
        rows: &mut Vec<Row>,
    ) -> Result<()> {
        let value = tx.get(key)?.ok_or("member absent")?;
        let m: Member = rmp_serde::from_slice(&value)?;
        if !stable && (m.opened > revision || m.closed.is_some_and(|r| r <= revision)) {
            return Ok(());
        }
        let (chunk, row): (u64, usize) = rmp_serde::from_slice(
            &tx.get(&Key::new(b'L', &[m.property]))?
                .ok_or("property reference absent")?,
        )?;
        let bytes = |id| -> Result<Vec<u8>> {
            tx.get(&Key::new(b'V', &[id]))?
                .ok_or_else(|| "dictionary reverse key absent".into())
        };
        let endpoints = match m.endpoints {
            Some([from, to, label]) => Some([bytes(from)?, bytes(to)?, bytes(label)?]),
            None => None,
        };
        rows.push(Row {
            writer: m.writer,
            relation: m.relation,
            owner: bytes(m.owner)?,
            key: bytes(m.entity)?,
            endpoints,
            properties: Arc::clone(properties.get(&chunk).ok_or("property chunk absent")?),
            row,
            opened: m.opened,
        });
        Ok(())
    }
}

struct View<'a> {
    tx: &'a dyn Read,
    properties: &'a BTreeMap<u64, Arc<RecordBatch>>,
    fixture: &'a Fixture,
    revision: u64,
    stable: bool,
}
impl GraphRead for View<'_> {
    fn query(
        &self,
        relation: u64,
        read: araphor_graph::Read,
        keys: &RecordBatch,
    ) -> Result<Vec<RecordBatch>> {
        use araphor_graph::Read as Operation;
        let mut rows = Vec::new();
        let mut seen = BTreeSet::new();
        if let Operation::Owned(writer) = read {
            for (_, key) in self.tx.prefix(&Key::new(b'R', &[relation, writer]))? {
                Native::select(
                    self.tx,
                    self.properties,
                    &key,
                    self.revision,
                    self.stable,
                    &mut rows,
                )?;
            }
        } else {
            let input = super::binary(keys, "key")?;
            for key in input.iter().flatten() {
                let scope = if matches!(read, Operation::Nodes) {
                    relation
                } else {
                    2
                };
                let Some(id) = self.tx.get(&Key::dictionary(1, scope, key))? else {
                    continue;
                };
                let id = Key::number(&id)?;
                let kinds: &[u8] = match read {
                    Operation::Nodes => b"K",
                    Operation::Outgoing => b"O",
                    Operation::Incoming => b"I",
                    Operation::Neighbors => b"OI",
                    _ => unreachable!(),
                };
                for kind in kinds {
                    for (_, key) in self.tx.prefix(&Key::new(*kind, &[relation, id]))? {
                        if seen.insert(key.clone()) {
                            Native::select(
                                self.tx,
                                self.properties,
                                &key,
                                self.revision,
                                self.stable,
                                &mut rows,
                            )?;
                        }
                    }
                }
            }
        }
        let mut batches = super::batches_from_rows(rows, self.fixture)?;
        if batches.is_empty() {
            batches.push(RecordBatch::new_empty(Arc::new(
                self.fixture.shapes[&relation].read_schema(),
            )));
        }
        Ok(batches)
    }
    fn presence(&self, writer: u64, relation: u64, batch: &RecordBatch) -> Result<Vec<bool>> {
        let owners = super::binary(batch, "owner")?;
        let keys = super::binary(batch, "key")?;
        let mut result = Vec::new();
        for i in 0..batch.num_rows() {
            let owner = self.tx.get(&Key::dictionary(0, writer, owners.value(i)))?;
            let entity = self.tx.get(&Key::dictionary(1, relation, keys.value(i)))?;
            let mut present = false;
            if let (Some(owner), Some(entity)) = (owner, entity) {
                let owner = Key::number(&owner)?;
                let entity = Key::number(&entity)?;
                for (_, key) in self
                    .tx
                    .prefix(&Key::new(b'K', &[relation, entity, writer, owner]))?
                {
                    let member: Member =
                        rmp_serde::from_slice(&self.tx.get(&key)?.ok_or("member absent")?)?;
                    present |= self.stable
                        || (member.opened <= self.revision
                            && member.closed.is_none_or(|r| r > self.revision));
                }
            }
            result.push(present);
        }
        Ok(result)
    }
}
