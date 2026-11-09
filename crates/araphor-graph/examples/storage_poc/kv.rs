use std::ops::Bound::{Excluded, Included};
use std::path::Path;
use std::time::Instant;

use fjall::Readable;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use super::Result;

#[derive(Clone, serde::Serialize)]
pub struct Maintenance {
    attempts: usize,
    active: usize,
    compaction_s: f64,
    buffer_bytes: u64,
    queued_flushes: usize,
    sealed_memtables: usize,
    l0_tables: usize,
    tables: usize,
    journals: usize,
}

const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("records");
pub type Entries = Vec<(Vec<u8>, Vec<u8>)>;

pub trait Read {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn prefix(&self, prefix: &[u8]) -> Result<Entries>;
    fn floor(&self, prefix: &[u8], revision: u64) -> Result<Option<Vec<u8>>>;
}

pub trait Write: Read {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()>;
    fn remove(&mut self, key: &[u8]) -> Result<()>;
}

pub enum Database {
    Home(super::home::Home),
    #[cfg(feature = "neon-poc")]
    Neon(super::neon::Neon),
    Surreal(super::surreal::Surreal),
    Redb(redb::Database),
    Fjall(fjall::SingleWriterTxDatabase, fjall::SingleWriterTxKeyspace),
    #[cfg(feature = "cdc-poc")]
    FjallBranch(fjall::SingleWriterTxDatabase, fjall::Branch),
}

impl Database {
    pub fn read_at<T>(
        &self,
        revision: u64,
        action: impl FnOnce(&dyn Read) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Surreal(db) => db.read_at(Some(revision), action),
            #[cfg(feature = "neon-poc")]
            Self::Neon(db) => db.read_at(revision, action),
            #[cfg(feature = "cdc-poc")]
            Self::FjallBranch(_, branch) => action(&BranchRead(
                branch.read_at(fjall::Revision::from_bytes(revision.to_be_bytes()))?,
            )),
            _ => self.read(action),
        }
    }

    pub fn close(&self) -> Result<()> {
        match self {
            Self::Surreal(db) => db.close(),
            #[cfg(feature = "neon-poc")]
            Self::Neon(db) => db.close(),
            _ => Ok(()),
        }
    }

    pub fn maintenance(&self) -> Option<Maintenance> {
        let Self::Fjall(db, table) = self else {
            return None;
        };
        Some(Maintenance {
            attempts: db.inner().compactions_completed(),
            active: db.inner().active_compactions(),
            compaction_s: db.inner().time_compacting().as_secs_f64(),
            buffer_bytes: db.write_buffer_size(),
            queued_flushes: db.inner().outstanding_flushes(),
            sealed_memtables: table.inner().sealed_memtable_count(),
            l0_tables: table.inner().l0_table_count(),
            tables: table.inner().table_count(),
            journals: db.journal_count(),
        })
    }

    pub fn open(kind: &str, path: &Path) -> Result<Self> {
        Ok(match kind {
            "home" => Self::Home(super::home::Home::open(path)?),
            #[cfg(feature = "neon-poc")]
            "neon-layers" => Self::Neon(super::neon::Neon::open(path)?),
            "surrealkv-native" => {
                Self::Surreal(super::surreal::Surreal::open_versioned(path, true)?)
            }
            "surrealkv" => Self::Surreal(super::surreal::Surreal::open(path)?),
            "redb" => {
                let db = redb::Database::create(path.join("store.redb"))?;
                let tx = db.begin_write()?;
                tx.open_table(TABLE)?;
                tx.commit()?;
                Self::Redb(db)
            }
            "fjall" => {
                let builder = fjall::SingleWriterTxDatabase::builder(path.join("fjall"));
                #[cfg(feature = "cdc-poc")]
                let builder = builder.journal_cdc();
                let db = builder.open()?;
                let table = db.keyspace("records", fjall::KeyspaceCreateOptions::default)?;
                Self::Fjall(db, table)
            }
            #[cfg(feature = "cdc-poc")]
            "fjall-stable" => {
                let db = fjall::SingleWriterTxDatabase::builder(path.join("fjall"))
                    .versioned()
                    .open()?;
                let branch = match db.branch("records")? {
                    Some(branch) => branch,
                    None => {
                        let branch = db.create_branch("records")?;
                        branch.retain_history(branch.info()?.head..)?;
                        branch
                    }
                };
                Self::FjallBranch(db, branch)
            }
            _ => return Err("unknown native engine".into()),
        })
    }

    pub fn read<T>(&self, action: impl FnOnce(&dyn Read) -> Result<T>) -> Result<T> {
        match self {
            Self::Home(db) => db.read(action),
            #[cfg(feature = "neon-poc")]
            Self::Neon(db) => db.read_at(u64::MAX, action),
            Self::Surreal(db) => db.read(action),
            Self::Redb(db) => {
                let tx = db.begin_read()?;
                let table = tx.open_table(TABLE)?;
                action(&RedbRead(&table))
            }
            Self::Fjall(db, table) => action(&FjallRead {
                tx: db.read_tx(),
                table,
            }),
            #[cfg(feature = "cdc-poc")]
            Self::FjallBranch(_, branch) => action(&BranchRead(branch.snapshot()?)),
        }
    }

    pub fn write<T>(
        &self,
        commit: bool,
        action: impl FnOnce(&mut dyn Write) -> Result<T>,
    ) -> Result<(T, f64, f64)> {
        self.write_at(1, commit, action)
            .map(|(result, work, sync, _)| (result, work, sync))
    }

    pub fn write_at<T>(
        &self,
        revision: u64,
        commit: bool,
        action: impl FnOnce(&mut dyn Write) -> Result<T>,
    ) -> Result<(T, f64, f64, Option<[u8; 8]>)> {
        let started = Instant::now();
        let (result, work, sync) = match self {
            Self::Home(db) => db.write(commit, action),
            Self::Surreal(db) => db.write_at(revision, commit, action),
            #[cfg(feature = "neon-poc")]
            Self::Neon(db) => db.write_at(revision, commit, action),
            Self::Redb(db) => {
                let mut tx = db.begin_write()?;
                tx.set_durability(redb::Durability::Immediate)?;
                let result = {
                    let mut table = RedbWrite(tx.open_table(TABLE)?);
                    action(&mut table)?
                };
                let work = started.elapsed().as_secs_f64();
                let synced = Instant::now();
                if commit {
                    tx.commit()?;
                } else {
                    tx.abort()?;
                }
                Ok((result, work, synced.elapsed().as_secs_f64()))
            }
            Self::Fjall(db, table) => {
                let mut tx = db.write_tx().durability(Some(fjall::PersistMode::SyncAll));
                let result = action(&mut FjallWrite { tx: &mut tx, table })?;
                let work = started.elapsed().as_secs_f64();
                let synced = Instant::now();
                if commit {
                    tx.commit()?;
                } else {
                    tx.rollback();
                }
                Ok((result, work, synced.elapsed().as_secs_f64()))
            }
            #[cfg(feature = "cdc-poc")]
            Self::FjallBranch(_, branch) => {
                let mut tx = branch.write_tx()?;
                let result = action(&mut BranchWrite(&mut tx))?;
                let work = started.elapsed().as_secs_f64();
                let synced = Instant::now();
                let receipt = if commit {
                    tx.commit()?.map(|receipt| receipt.revision.to_bytes())
                } else {
                    tx.rollback();
                    None
                };
                return Ok((result, work, synced.elapsed().as_secs_f64(), receipt));
            }
        }?;
        Ok((result, work, sync, None))
    }
}

struct RedbRead<'a, T>(&'a T);

impl<T: ReadableTable<&'static [u8], &'static [u8]>> Read for RedbRead<'_, T> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(key)?.map(|v| v.value().to_vec()))
    }
    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        let end = prefix_end(prefix);
        self.0
            .range::<&[u8]>((Included(prefix), Excluded(end.as_slice())))?
            .map(|row| {
                let (k, v) = row?;
                Ok((k.value().to_vec(), v.value().to_vec()))
            })
            .collect()
    }
    fn floor(&self, prefix: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        let end = [prefix, &revision.to_be_bytes()].concat();
        self.0
            .range::<&[u8]>((Included(prefix), Included(end.as_slice())))?
            .next_back()
            .map(|row| {
                let (_, v) = row?;
                Ok(v.value().to_vec())
            })
            .transpose()
    }
}

pub fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    let index = end
        .iter()
        .rposition(|b| *b != 255)
        .expect("PoC prefixes have a successor");
    end[index] += 1;
    end.truncate(index + 1);
    end
}

struct RedbWrite<'a>(redb::Table<'a, &'static [u8], &'static [u8]>);

impl Read for RedbWrite<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        RedbRead(&self.0).get(key)
    }
    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        RedbRead(&self.0).prefix(prefix)
    }
    fn floor(&self, prefix: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        RedbRead(&self.0).floor(prefix, revision)
    }
}
impl Write for RedbWrite<'_> {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.0.insert(key, value)?;
        Ok(())
    }
    fn remove(&mut self, key: &[u8]) -> Result<()> {
        self.0.remove(key)?;
        Ok(())
    }
}

pub(super) struct FjallRead<'a> {
    pub(super) tx: fjall::Snapshot,
    pub(super) table: &'a fjall::SingleWriterTxKeyspace,
}
impl Read for FjallRead<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.tx.get(self.table, key)?.map(|v| v.to_vec()))
    }
    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        self.tx
            .prefix(self.table, prefix)
            .map(|row| {
                let (k, v) = row.into_inner()?;
                Ok((k.to_vec(), v.to_vec()))
            })
            .collect()
    }
    fn floor(&self, prefix: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        let end = [prefix, &revision.to_be_bytes()].concat();
        self.tx
            .range::<&[u8], _>(self.table, (Included(prefix), Included(end.as_slice())))
            .next_back()
            .map(|row| {
                let (_, v) = row.into_inner()?;
                Ok(v.to_vec())
            })
            .transpose()
    }
}

struct FjallWrite<'a, 'b> {
    tx: &'a mut fjall::SingleWriterWriteTx<'b>,
    table: &'a fjall::SingleWriterTxKeyspace,
}
impl Read for FjallWrite<'_, '_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.tx.get(self.table, key)?.map(|v| v.to_vec()))
    }
    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        self.tx
            .prefix(self.table, prefix)
            .map(|row| {
                let (k, v) = row.into_inner()?;
                Ok((k.to_vec(), v.to_vec()))
            })
            .collect()
    }
    fn floor(&self, prefix: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        let end = [prefix, &revision.to_be_bytes()].concat();
        self.tx
            .range::<&[u8], _>(self.table, (Included(prefix), Included(end.as_slice())))
            .next_back()
            .map(|row| {
                let (_, v) = row.into_inner()?;
                Ok(v.to_vec())
            })
            .transpose()
    }
}
impl Write for FjallWrite<'_, '_> {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.tx.insert(self.table, key, value);
        Ok(())
    }
    fn remove(&mut self, key: &[u8]) -> Result<()> {
        self.tx.remove(self.table, key);
        Ok(())
    }
}

#[cfg(feature = "cdc-poc")]
struct BranchRead(fjall::BranchSnapshot);

#[cfg(feature = "cdc-poc")]
impl Read for BranchRead {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(key)?.map(|value| value.to_vec()))
    }

    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        self.0
            .prefix(prefix)
            .map(|row| {
                let (key, value) = row?;
                Ok((key.to_vec(), value.to_vec()))
            })
            .collect()
    }

    fn floor(&self, prefix: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        let end = [prefix, &revision.to_be_bytes()].concat();
        self.0
            .range::<&[u8], _>((Included(prefix), Included(end.as_slice())))
            .next_back()
            .map(|row| Ok(row?.1.to_vec()))
            .transpose()
    }
}

#[cfg(feature = "cdc-poc")]
struct BranchWrite<'a, 'b>(&'a mut fjall::BranchWriteTransaction<'b>);

#[cfg(feature = "cdc-poc")]
impl Read for BranchWrite<'_, '_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(key)?.map(|value| value.to_vec()))
    }

    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        self.0
            .prefix(prefix)
            .map(|row| {
                let (key, value) = row?;
                Ok((key.to_vec(), value.to_vec()))
            })
            .collect()
    }

    fn floor(&self, prefix: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        let end = [prefix, &revision.to_be_bytes()].concat();
        self.0
            .range::<&[u8], _>((Included(prefix), Included(end.as_slice())))
            .next_back()
            .map(|row| Ok(row?.1.to_vec()))
            .transpose()
    }
}

#[cfg(feature = "cdc-poc")]
impl Write for BranchWrite<'_, '_> {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.0.insert(key, value);
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> Result<()> {
        self.0.remove(key);
        Ok(())
    }
}
