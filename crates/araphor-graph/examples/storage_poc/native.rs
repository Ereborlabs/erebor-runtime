use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use arrow_array::RecordBatch;
use arrow_ipc::{reader::StreamReader, writer::StreamWriter};

use super::fixture::{Fixture, Member, Row, Step};
use super::kv::{self, Read, Write};
use super::{Change, Readout, Result, Timing};

pub struct Native {
    db: kv::Database,
    properties: BTreeMap<u64, Arc<RecordBatch>>,
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
    fn number(bytes: &[u8]) -> Result<u64> {
        Ok(u64::from_be_bytes(bytes.try_into()?))
    }
}

impl Native {
    pub fn open(kind: &str, path: &Path) -> Result<Self> {
        let db = kv::Database::open(kind, path)?;
        if db.read(|r| r.get(b"head"))?.is_none() {
            db.write(true, |tx| {
                tx.put(b"head", &1u64.to_be_bytes())?;
                tx.put(b"next", &1u64.to_be_bytes())
            })?;
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
        Ok(Self { db, properties })
    }

    pub fn apply(&mut self, fixture: &Fixture, step: &Step, commit: bool) -> Result<Timing> {
        let started = Instant::now();
        let journals = fixture.journals(step)?;
        assert_eq!(journals.len(), 2);
        let prepare_s = started.elapsed().as_secs_f64();
        let (prepared, work, commit_s) = self.db.write(commit, |tx| Self::stage(tx, step))?;
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
        assert_eq!(sample.closed, step.closed);
        if commit {
            self.properties.extend(prepared.properties);
        }
        sample.total_s = started.elapsed().as_secs_f64();
        Ok(sample)
    }

    fn stage(tx: &mut dyn Write, step: &Step) -> Result<Prepared> {
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
                assert_eq!(old.is_some(), step.is_update(row));
                if let Some(oldkey) = old {
                    let mut old: Member =
                        rmp_serde::from_slice(&tx.get(&oldkey)?.ok_or("old member absent")?)?;
                    assert_eq!(old.closed, None);
                    old.closed = Some(step.revision);
                    tx.put(&oldkey, &rmp_serde::to_vec(&old)?)?;
                    tx.remove(&open)?;
                    changes.push(Change::new(row, old.opened, false));
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
                let key = Key::new(
                    b'M',
                    &[row.writer, owner, row.relation, entity, step.revision],
                );
                tx.put(&key, &rmp_serde::to_vec(&member)?)?;
                tx.put(&open, &key)?;
                tx.put(
                    &Key::new(
                        b'R',
                        &[row.relation, row.writer, owner, entity, step.revision],
                    ),
                    &key,
                )?;
                tx.put(
                    &Key::new(
                        b'K',
                        &[row.relation, entity, row.writer, owner, step.revision],
                    ),
                    &key,
                )?;
                if let Some([from, to, label]) = endpoints {
                    for (kind, endpoint) in [(b'O', from), (b'I', to), (b'B', label)] {
                        tx.put(
                            &Key::new(
                                kind,
                                &[
                                    row.relation,
                                    endpoint,
                                    row.writer,
                                    owner,
                                    entity,
                                    step.revision,
                                ],
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
                &Key::new(b'H', &[writer, step.revision]),
                &step.revision.to_be_bytes(),
            )?;
            tx.put(
                &Key::new(b'S', &[writer, step.revision]),
                &step.state(writer),
            )?;
            tx.put(
                &Key::new(b'T', &[writer, step.revision]),
                &step.captured.to_be_bytes(),
            )?;
        }
        changes.sort();
        for (slot, change) in changes.iter().enumerate() {
            tx.put(
                &Key::new(b'C', &[step.revision, slot as u64]),
                &rmp_serde::to_vec(change)?,
            )?;
        }
        tx.put(
            &Key::new(b'J', &[step.revision]),
            &rmp_serde::to_vec(&(step.previous, step.captured))?,
        )?;
        tx.put(b"next", &next.to_be_bytes())?;
        tx.put(b"head", &step.revision.to_be_bytes())?;
        Ok(result)
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

    pub fn inspect(&self, fixture: &Fixture, revision: u64, all: bool) -> Result<Readout> {
        let started = Instant::now();
        self.db.read(|tx| {
            for writer in [1, 2] {
                let head = tx.floor(&Key::new(b'H', &[writer]), revision)?;
                if fixture.steps.iter().any(|s| s.revision <= revision) {
                    assert!(head.is_some());
                }
            }
            let mut states = Vec::new();
            for writer in [1, 2] {
                states.push(tx.floor(&Key::new(b'S', &[writer]), revision)?);
                states.push(tx.floor(&Key::new(b'T', &[writer]), revision)?);
            }
            let capture_s = started.elapsed().as_secs_f64();
            let started = Instant::now();
            let mut rows = Vec::new();
            if all {
                for (_, key) in tx.prefix(b"R")? {
                    Self::select(tx, &self.properties, &key, revision, &mut rows)?;
                }
            } else {
                for relation in [2, 3] {
                    let mut seen = BTreeSet::new();
                    for probe in &fixture.probes {
                        let Some(id) = tx.get(&Key::dictionary(1, 2, probe))? else {
                            continue;
                        };
                        let id = Key::number(&id)?;
                        let kind = if relation == 2 { b'K' } else { b'O' };
                        for (_, key) in tx.prefix(&Key::new(kind, &[relation, id]))? {
                            if seen.insert(key.clone()) {
                                Self::select(tx, &self.properties, &key, revision, &mut rows)?;
                            }
                        }
                    }
                }
                for (_, key) in tx.prefix(&Key::new(b'R', &[1, 2]))? {
                    Self::select(tx, &self.properties, &key, revision, &mut rows)?;
                }
            }
            let read_s = started.elapsed().as_secs_f64();
            let started = Instant::now();
            let mut changes = Vec::new();
            for (_, value) in tx.prefix(&Key::new(b'C', &[revision]))? {
                changes.push(rmp_serde::from_slice::<Change>(&value)?);
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
        self.db.read(|tx| {
            assert_eq!(
                Key::number(&tx.get(b"head")?.ok_or("head absent")?)?,
                current
            );
            let last = fixture
                .steps
                .iter()
                .filter(|s| s.revision <= revision)
                .next_back();
            for writer in [1, 2] {
                assert_eq!(
                    tx.floor(&Key::new(b'H', &[writer]), revision)?,
                    last.map(|s| s.revision.to_be_bytes().to_vec())
                );
            }
            let actual = tx
                .get(&Key::new(b'J', &[revision]))?
                .map(|bytes| rmp_serde::from_slice::<(u64, u64)>(&bytes))
                .transpose()?;
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
        rows: &mut Vec<Row>,
    ) -> Result<()> {
        let value = tx.get(key)?.ok_or("member absent")?;
        let m: Member = rmp_serde::from_slice(&value)?;
        if m.opened > revision || m.closed.is_some_and(|r| r <= revision) {
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
