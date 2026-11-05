use std::ops::Bound::{Excluded, Included};
use std::path::Path;
use std::time::Instant;

use fjall::Readable;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use super::Result;

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
    Redb(redb::Database),
    Fjall(fjall::SingleWriterTxDatabase, fjall::SingleWriterTxKeyspace),
}

impl Database {
    pub fn open(kind: &str, path: &Path) -> Result<Self> {
        Ok(match kind {
            "redb" => {
                let db = redb::Database::create(path.join("store.redb"))?;
                let tx = db.begin_write()?;
                tx.open_table(TABLE)?;
                tx.commit()?;
                Self::Redb(db)
            }
            "fjall" => {
                let db = fjall::SingleWriterTxDatabase::builder(path.join("fjall")).open()?;
                let table = db.keyspace("records", fjall::KeyspaceCreateOptions::default)?;
                Self::Fjall(db, table)
            }
            _ => return Err("unknown native engine".into()),
        })
    }

    pub fn read<T>(&self, action: impl FnOnce(&dyn Read) -> Result<T>) -> Result<T> {
        match self {
            Self::Redb(db) => {
                let tx = db.begin_read()?;
                let table = tx.open_table(TABLE)?;
                action(&RedbRead(&table))
            }
            Self::Fjall(db, table) => action(&FjallRead {
                tx: db.read_tx(),
                table,
            }),
        }
    }

    pub fn write<T>(
        &self,
        commit: bool,
        action: impl FnOnce(&mut dyn Write) -> Result<T>,
    ) -> Result<(T, f64, f64)> {
        let started = Instant::now();
        match self {
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
        }
    }
}

struct RedbRead<'a, T>(&'a T);

impl<T: ReadableTable<&'static [u8], &'static [u8]>> Read for RedbRead<'_, T> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(key)?.map(|v| v.value().to_vec()))
    }
    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        let end = Self::end(prefix);
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

impl<T> RedbRead<'_, T> {
    fn end(prefix: &[u8]) -> Vec<u8> {
        let mut end = prefix.to_vec();
        let index = end
            .iter()
            .rposition(|b| *b != 255)
            .expect("PoC prefixes have a successor");
        end[index] += 1;
        end.truncate(index + 1);
        end
    }
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

struct FjallRead<'a> {
    tx: fjall::Snapshot,
    table: &'a fjall::SingleWriterTxKeyspace,
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
