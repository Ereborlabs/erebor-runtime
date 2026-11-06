use std::path::Path;
use std::time::Instant;

use surrealkv::{Durability, LSMIterator, Mode, Tree, TreeBuilder};
use tokio::runtime::Runtime;

use super::Result;
use super::kv::{Entries, Read, Write, prefix_end};

pub struct Surreal {
    tree: Tree,
    runtime: Runtime,
}
struct Transaction(surrealkv::Transaction);

impl Surreal {
    pub fn open(path: &Path) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let tree = {
            let _entered = runtime.enter();
            TreeBuilder::new()
                .with_path(path.join("surrealkv"))
                .with_versioning(false, 0)
                .build()?
        };
        Ok(Self { tree, runtime })
    }
    pub fn read<T>(&self, action: impl FnOnce(&dyn Read) -> Result<T>) -> Result<T> {
        action(&Transaction(self.tree.begin_with_mode(Mode::ReadOnly)?))
    }
    pub fn write<T>(
        &self,
        commit: bool,
        action: impl FnOnce(&mut dyn Write) -> Result<T>,
    ) -> Result<(T, f64, f64)> {
        let started = Instant::now();
        let mut tx = Transaction(self.tree.begin()?);
        tx.0.set_durability(Durability::Immediate);
        let result = action(&mut tx)?;
        let work = started.elapsed().as_secs_f64();
        let synced = Instant::now();
        if commit {
            self.runtime.block_on(tx.0.commit())?;
        } else {
            tx.0.rollback();
        }
        Ok((result, work, synced.elapsed().as_secs_f64()))
    }
    pub fn close(&self) -> Result<()> {
        Ok(self.runtime.block_on(self.tree.close())?)
    }
}

impl Read for Transaction {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(key)?)
    }
    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        let end = prefix_end(prefix);
        let mut iter = self.0.range(prefix, end.as_slice())?;
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
        let mut iter = self.0.scan(prefix..=end.as_slice())?;
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
        Ok(self.0.set(key, value)?)
    }
    fn remove(&mut self, key: &[u8]) -> Result<()> {
        Ok(self.0.delete(key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_transactions_and_reopen() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let db = Surreal::open(directory.path())?;
        let first = [b"H".as_slice(), &1u64.to_be_bytes()].concat();
        let last = [b"H".as_slice(), &u64::MAX.to_be_bytes()].concat();
        db.write(true, |tx| {
            tx.put(&first, b"first")?;
            tx.put(&last, b"last")?;
            tx.put(b"delete", b"old")?;
            assert_eq!(tx.get(&first)?, Some(b"first".to_vec()));
            Ok(())
        })?;
        db.read(|old| {
            db.write(true, |tx| {
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
        db.write(false, |tx| tx.remove(&first))?;
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
