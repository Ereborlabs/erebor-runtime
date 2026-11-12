use std::path::Path;
use std::time::Instant;

use surrealkv::{Durability, HistoryOptions, LSMIterator, Mode, Tree, TreeBuilder, WriteOptions};
use tokio::runtime::Runtime;

use super::Result;
use super::kv::{Entries, Read, Write, prefix_end};

pub struct Surreal {
    tree: Tree,
    runtime: Runtime,
    versioned: bool,
}
struct Transaction {
    inner: surrealkv::Transaction,
    read_revision: Option<u64>,
    write_revision: Option<u64>,
}

impl Surreal {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_versioned(path, false)
    }
    pub fn open_versioned(path: &Path, versioned: bool) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let tree = {
            let _entered = runtime.enter();
            TreeBuilder::new()
                .with_path(path.join("surrealkv"))
                .with_versioning(versioned, 0)
                .build()?
        };
        Ok(Self {
            tree,
            runtime,
            versioned,
        })
    }
    pub fn read<T>(&self, action: impl FnOnce(&dyn Read) -> Result<T>) -> Result<T> {
        self.read_at(None, action)
    }
    pub fn read_at<T>(
        &self,
        revision: Option<u64>,
        action: impl FnOnce(&dyn Read) -> Result<T>,
    ) -> Result<T> {
        action(&Transaction {
            inner: self.tree.begin_with_mode(Mode::ReadOnly)?,
            read_revision: revision.filter(|_| self.versioned),
            write_revision: None,
        })
    }
    pub fn write_at<T>(
        &self,
        revision: u64,
        commit: bool,
        action: impl FnOnce(&mut dyn Write) -> Result<T>,
    ) -> Result<(T, f64, f64)> {
        let started = Instant::now();
        let mut tx = Transaction {
            inner: self.tree.begin()?,
            read_revision: None,
            write_revision: self.versioned.then_some(revision),
        };
        tx.inner.set_durability(Durability::Immediate);
        let result = action(&mut tx)?;
        let work = started.elapsed().as_secs_f64();
        let synced = Instant::now();
        if commit {
            self.runtime.block_on(tx.inner.commit())?;
        } else {
            tx.inner.rollback();
        }
        Ok((result, work, synced.elapsed().as_secs_f64()))
    }
    pub fn close(&self) -> Result<()> {
        Ok(self.runtime.block_on(self.tree.close())?)
    }
}

impl Transaction {
    fn history(&self, start: &[u8], end: &[u8], revision: u64) -> Result<Entries> {
        let options = HistoryOptions::new()
            .with_tombstones(true)
            .with_ts_range(0, revision);
        let mut iter = self.inner.history_with_options(start, end, &options)?;
        iter.seek_first()?;
        let mut previous = None;
        let mut rows = Vec::new();
        while iter.valid() {
            let key = iter.key();
            if previous.as_deref() != Some(key.user_key()) {
                previous = Some(key.user_key().to_vec());
                if !key.is_tombstone() {
                    rows.push((key.user_key().to_vec(), iter.value()?));
                }
            }
            iter.next()?;
        }
        Ok(rows)
    }
}

impl Read for Transaction {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(match self.read_revision {
            Some(revision) => self.inner.get_at(key, revision)?,
            None => self.inner.get(key)?,
        })
    }
    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        let end = prefix_end(prefix);
        if let Some(revision) = self.read_revision {
            return self.history(prefix, &end, revision);
        }
        let mut iter = self.inner.range(prefix, end.as_slice())?;
        iter.seek_first()?;
        let mut rows = Vec::new();
        while iter.valid() {
            rows.push((iter.key().user_key().to_vec(), iter.value()?));
            iter.next()?;
        }
        Ok(rows)
    }
    fn floor(&self, prefix: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        let end = [prefix, &revision.to_be_bytes()].concat();
        if let Some(captured) = self.read_revision {
            return Ok(self
                .history(prefix, &prefix_end(&end), captured)?
                .pop()
                .map(|(_, v)| v));
        }
        let mut iter = self.inner.scan(prefix..=end.as_slice())?;
        iter.seek_last()?;
        if iter.valid() {
            Ok(Some(iter.value()?))
        } else {
            Ok(None)
        }
    }
}
impl Write for Transaction {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        Ok(match self.write_revision {
            Some(revision) => self.inner.set_at(key, value, revision)?,
            None => self.inner.set(key, value)?,
        })
    }
    fn remove(&mut self, key: &[u8]) -> Result<()> {
        Ok(match self.write_revision {
            Some(revision) => self.inner.soft_delete_with_options(
                key,
                &WriteOptions::new().with_timestamp(Some(revision)),
            )?,
            None => self.inner.delete(key)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_history_and_reopen() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let db = Surreal::open_versioned(directory.path(), true)?;
        let first = [b"H".as_slice(), &1u64.to_be_bytes()].concat();
        let last = [b"H".as_slice(), &u64::MAX.to_be_bytes()].concat();
        db.write_at(10, true, |tx| {
            tx.put(&first, b"first")?;
            tx.put(&last, b"last")?;
            tx.put(b"empty", b"")
        })?;
        db.write_at(20, true, |tx| tx.put(&last, b"rewritten"))?;
        db.write_at(30, true, |tx| tx.remove(&last))?;
        db.write_at(40, false, |tx| tx.remove(&first))?;
        let check = |db: &Surreal| -> Result<()> {
            for (revision, value) in [
                (10, Some(b"last".to_vec())),
                (20, Some(b"rewritten".to_vec())),
                (30, None),
            ] {
                db.read_at(Some(revision), |tx| {
                    assert_eq!(tx.get(&last)?, value);
                    assert_eq!(tx.get(b"empty")?, Some(Vec::new()));
                    let rows = tx.prefix(b"H")?;
                    assert_eq!(rows.len(), if value.is_some() { 2 } else { 1 });
                    assert_eq!(tx.floor(b"H", 0)?, None);
                    assert_eq!(
                        tx.floor(b"H", u64::MAX)?,
                        value.or_else(|| Some(b"first".to_vec()))
                    );
                    Ok(())
                })?;
            }
            Ok(())
        };
        check(&db)?;
        db.close()?;
        drop(db);
        let db = Surreal::open_versioned(directory.path(), true)?;
        check(&db)?;
        db.close()?;
        Ok(())
    }

    #[test]
    fn native_transactions_and_reopen() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let db = Surreal::open(directory.path())?;
        let first = [b"H".as_slice(), &1u64.to_be_bytes()].concat();
        let last = [b"H".as_slice(), &u64::MAX.to_be_bytes()].concat();
        db.write_at(1, true, |tx| {
            tx.put(&first, b"first")?;
            tx.put(&last, b"last")?;
            tx.put(b"delete", b"old")?;
            assert_eq!(tx.get(&first)?, Some(b"first".to_vec()));
            Ok(())
        })?;
        db.read(|old| {
            db.write_at(1, true, |tx| {
                tx.put(&first, b"new")?;
                tx.remove(b"delete")?;
                tx.put(b"empty", b"")
            })?;
            assert_eq!(old.get(&first)?, Some(b"first".to_vec()));
            assert_eq!(old.get(b"delete")?, Some(b"old".to_vec()));
            assert_eq!(old.floor(b"H", 0)?, None);
            assert_eq!(old.floor(b"H", 2)?, Some(b"first".to_vec()));
            assert_eq!(old.floor(b"H", u64::MAX)?, Some(b"last".to_vec()));
            assert_eq!(old.prefix(b"H")?.len(), 2);
            Ok(())
        })?;
        db.write_at(1, false, |tx| tx.remove(&first))?;
        db.close()?;
        drop(db);
        let db = Surreal::open(directory.path())?;
        db.read(|view| {
            assert_eq!(view.get(&first)?, Some(b"new".to_vec()));
            assert_eq!(view.get(b"delete")?, None);
            assert_eq!(view.get(b"empty")?, Some(Vec::new()));
            Ok(())
        })?;
        db.close()
    }
}
