use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek, SeekFrom, Write as _};
use std::ops::Bound::{Included, Unbounded};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use serde_bytes::ByteBuf;

use super::Result;
use super::kv::{Entries, Read, Write};

const MAGIC: &[u8; 8] = b"ARPHKV01";
type Index = BTreeMap<Arc<[u8]>, Arc<[u8]>>;
type Edits = BTreeMap<ByteBuf, Option<ByteBuf>>;

pub struct Home(RefCell<State>);
struct State {
    file: File,
    root: Arc<Index>,
    poisoned: bool,
    #[cfg(feature = "cdc-poc")]
    readers: Vec<std::sync::mpsc::Sender<Message>>,
}
struct Transaction {
    rows: Index,
    edits: Edits,
}

impl Home {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.join("home.log"))?;
        file.try_lock()?;
        if file.metadata()?.len() == 0 {
            file.write_all(MAGIC)?;
            file.sync_all()?;
            File::open(path)?.sync_all()?;
        }
        file.rewind()?;
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err("home log version invalid".into());
        }
        let length = file.metadata()?.len();
        let mut position = 8;
        let mut rows = Index::new();
        while let Some((edits, next)) = Self::frame(&mut file, position, length)? {
            for (key, value) in edits {
                if let Some(value) = value {
                    rows.insert(Arc::from(key.into_vec()), Arc::from(value.into_vec()));
                } else {
                    rows.remove(key.as_ref());
                }
            }
            position = next;
        }
        if position != length {
            file.set_len(position)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        Ok(Self(RefCell::new(State {
            file,
            root: Arc::new(rows),
            poisoned: false,
            #[cfg(feature = "cdc-poc")]
            readers: Vec::new(),
        })))
    }

    fn frame(file: &mut File, position: u64, length: u64) -> Result<Option<(Edits, u64)>> {
        if length - position < 16 {
            return Ok(None);
        }
        file.seek(SeekFrom::Start(position))?;
        let mut header = [0; 16];
        file.read_exact(&mut header)?;
        if crc32c::crc32c(&header[..12]) != u32::from_le_bytes(header[12..].try_into()?) {
            return Err("home frame header checksum invalid".into());
        }
        let size = u64::from_le_bytes(header[..8].try_into()?);
        if size > length - position - 16 {
            return Ok(None);
        }
        let mut payload = vec![0; usize::try_from(size)?];
        file.read_exact(&mut payload)?;
        if crc32c::crc32c(&payload) != u32::from_le_bytes(header[8..12].try_into()?) {
            return Err("home frame payload checksum invalid".into());
        }
        Ok(Some((
            rmp_serde::from_slice(&payload)?,
            position + 16 + size,
        )))
    }

    pub fn read<T>(&self, action: impl FnOnce(&dyn Read) -> Result<T>) -> Result<T> {
        let root = {
            let state = self.0.try_borrow()?;
            state.check()?;
            Arc::clone(&state.root)
        };
        action(root.as_ref())
    }

    pub fn write<T>(
        &self,
        commit: bool,
        action: impl FnOnce(&mut dyn Write) -> Result<T>,
    ) -> Result<(T, f64, f64)> {
        let started = Instant::now();
        let mut state = self.0.try_borrow_mut()?;
        state.check()?;
        // shortcut: Each write copies the full index; large Graphs need a persistent tree.
        let mut tx = Transaction {
            rows: state.root.as_ref().clone(),
            edits: Edits::new(),
        };
        let result = action(&mut tx)?;
        let work = started.elapsed().as_secs_f64();
        let synced = Instant::now();
        if commit {
            let payload = rmp_serde::to_vec(&tx.edits)?;
            let mut header = [0; 16];
            header[..8].copy_from_slice(&u64::try_from(payload.len())?.to_le_bytes());
            header[8..12].copy_from_slice(&crc32c::crc32c(&payload).to_le_bytes());
            let checksum = crc32c::crc32c(&header[..12]);
            header[12..].copy_from_slice(&checksum.to_le_bytes());
            state.poisoned = true;
            let result = (|| -> std::io::Result<u64> {
                state.file.write_all(&header)?;
                state.file.write_all(&payload)?;
                state.file.sync_all()?;
                state.file.stream_position()
            })();
            #[cfg(feature = "cdc-poc")]
            if result.is_err() {
                state
                    .readers
                    .retain(|reader| reader.send(Message::Failed).is_ok());
            }
            let _end = result?;
            state.root = Arc::new(tx.rows);
            state.poisoned = false;
            #[cfg(feature = "cdc-poc")]
            state
                .readers
                .retain(|reader| reader.send(Message::End(_end)).is_ok());
        }
        Ok((result, work, synced.elapsed().as_secs_f64()))
    }
}

impl State {
    fn check(&self) -> Result<()> {
        if self.poisoned {
            return Err("home log I/O failed; reopen required".into());
        }
        Ok(())
    }
}

impl Read for Index {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(BTreeMap::get(self, key).map(|v| v.to_vec()))
    }
    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        Ok(self
            .range::<[u8], _>((Included(prefix), Unbounded))
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect())
    }
    fn floor(&self, prefix: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        let end = [prefix, &revision.to_be_bytes()].concat();
        Ok(self
            .range::<[u8], _>((Included(prefix), Included(end.as_slice())))
            .next_back()
            .map(|(_, value)| value.to_vec()))
    }
}

impl Read for Transaction {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Read::get(&self.rows, key)
    }
    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        self.rows.prefix(prefix)
    }
    fn floor(&self, prefix: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        self.rows.floor(prefix, revision)
    }
}
impl Write for Transaction {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.rows.insert(Arc::from(key), Arc::from(value));
        self.edits.insert(
            ByteBuf::from(key.to_vec()),
            Some(ByteBuf::from(value.to_vec())),
        );
        Ok(())
    }
    fn remove(&mut self, key: &[u8]) -> Result<()> {
        self.rows.remove(key);
        self.edits.insert(ByteBuf::from(key.to_vec()), None);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transactions_and_snapshots() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Home::open(dir.path())?;
        assert!(Home::open(dir.path()).is_err());
        let a = [b"H".as_slice(), &1u64.to_be_bytes()].concat();
        let b = [b"H".as_slice(), &3u64.to_be_bytes()].concat();
        db.write(true, |tx| {
            tx.put(&a, b"old")?;
            tx.put(&b, b"last")?;
            tx.put(b"x", b"delete")?;
            assert_eq!(tx.get(&a)?, Some(b"old".to_vec()));
            Ok(())
        })?;
        db.read(|old| {
            db.write(true, |tx| {
                tx.put(&a, b"new")?;
                tx.remove(b"x")?;
                tx.put(b"empty", b"")?;
                tx.put(b"gone", b"value")?;
                tx.remove(b"gone")
            })?;
            assert_eq!(old.get(&a)?, Some(b"old".to_vec()));
            assert_eq!(old.get(b"x")?, Some(b"delete".to_vec()));
            assert_eq!(old.floor(b"H", 0)?, None);
            assert_eq!(old.floor(b"H", 2)?, Some(b"old".to_vec()));
            assert_eq!(old.floor(b"H", 3)?, Some(b"last".to_vec()));
            assert_eq!(old.prefix(b"H")?.len(), 2);
            Ok(())
        })?;
        let bytes = std::fs::metadata(dir.path().join("home.log"))?.len();
        db.write(false, |tx| tx.remove(&a))?;
        assert!(
            db.write(true, |tx| -> Result<()> {
                tx.remove(&a)?;
                Err("abort action".into())
            })
            .is_err()
        );
        assert_eq!(std::fs::metadata(dir.path().join("home.log"))?.len(), bytes);
        drop(db);
        let db = Home::open(dir.path())?;
        db.read(|view| {
            assert_eq!(view.get(&a)?, Some(b"new".to_vec()));
            assert_eq!(view.get(b"x")?, None);
            assert_eq!(view.get(b"gone")?, None);
            assert_eq!(view.get(b"empty")?, Some(vec![]));
            Ok(())
        })
    }

    #[test]
    fn incomplete_tail_and_corruption() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("home.log");
        let db = Home::open(dir.path())?;
        db.write(true, |tx| tx.put(b"first", b"safe"))?;
        let first = std::fs::read(&path)?;
        db.write(true, |tx| tx.put(b"second", b"next"))?;
        drop(db);
        let both = std::fs::read(&path)?;
        for cut in first.len()..both.len() {
            std::fs::write(&path, &both[..cut])?;
            let db = Home::open(dir.path())?;
            db.read(|view| {
                assert_eq!(view.get(b"first")?, Some(b"safe".to_vec()));
                assert_eq!(view.get(b"second")?, None);
                Ok(())
            })?;
            assert_eq!(std::fs::read(&path)?, first);
            db.write(true, |tx| tx.put(b"after", b"recovery"))?;
            drop(db);
            Home::open(dir.path())?.read(|view| {
                assert_eq!(view.get(b"after")?, Some(b"recovery".to_vec()));
                Ok(())
            })?;
        }
        for offset in [0, first.len(), first.len() + 8, first.len() + 16] {
            let mut corrupt = both.clone();
            corrupt[offset] ^= 1;
            std::fs::write(&path, corrupt)?;
            assert!(Home::open(dir.path()).is_err());
        }
        Ok(())
    }

    #[test]
    fn failed_append_requires_reopen() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Home::open(dir.path())?;
        db.write(true, |tx| tx.put(b"first", b"safe"))?;
        db.0.borrow_mut().file = File::open(dir.path().join("home.log"))?;
        assert!(db.write(true, |tx| tx.put(b"second", b"lost")).is_err());
        assert!(db.read(|view| view.get(b"first")).is_err());
        assert!(db.write(true, |tx| tx.remove(b"first")).is_err());
        drop(db);
        Home::open(dir.path())?.read(|view| {
            assert_eq!(view.get(b"first")?, Some(b"safe".to_vec()));
            assert_eq!(view.get(b"second")?, None);
            Ok(())
        })
    }
}

#[cfg(feature = "cdc-poc")]
enum Message {
    End(u64),
    Failed,
    Stop,
}

#[cfg(feature = "cdc-poc")]
pub struct Feed {
    file: File,
    cursor: super::cdc::Cursor,
    end: u64,
    receiver: std::sync::mpsc::Receiver<Message>,
    sender: std::sync::mpsc::Sender<Message>,
    stopped: bool,
}

#[cfg(feature = "cdc-poc")]
#[derive(Clone)]
pub struct Cancel(std::sync::mpsc::Sender<Message>);

#[cfg(feature = "cdc-poc")]
impl Cancel {
    pub fn stop(&self) {
        let _ = self.0.send(Message::Stop);
    }
}

#[cfg(feature = "cdc-poc")]
impl Home {
    pub fn journal_head(&self) -> Result<super::cdc::Cursor> {
        let state = self.0.try_borrow()?;
        state.check()?;
        let offset = state.file.metadata()?.len();
        Ok(super::cdc::Cursor {
            journal: 0,
            offset,
            sequence: offset,
        })
    }

    pub fn journal_feed(&self, path: &Path, cursor: super::cdc::Cursor) -> Result<Feed> {
        let mut state = self.0.try_borrow_mut()?;
        state.check()?;
        let end = state.file.metadata()?.len();
        if cursor.journal != 0 || cursor.offset < 8 || cursor.offset > end {
            return Err("home cursor is outside retained history".into());
        }
        let (sender, receiver) = std::sync::mpsc::channel();
        state.readers.push(sender.clone());
        Ok(Feed {
            file: File::open(path.join("home.log"))?,
            cursor,
            end,
            receiver,
            sender,
            stopped: false,
        })
    }
}

#[cfg(feature = "cdc-poc")]
impl Feed {
    pub fn cancellation(&self) -> Cancel {
        Cancel(self.sender.clone())
    }

    pub fn wait(&mut self) -> Result<bool> {
        if self.stopped {
            return Ok(false);
        }
        if self.cursor.offset < self.end {
            return Ok(true);
        }
        match self.receiver.recv()? {
            Message::End(end) => {
                self.end = end;
                Ok(true)
            }
            Message::Failed => Err("home journal write failed".into()),
            Message::Stop => {
                self.stopped = true;
                Ok(false)
            }
        }
    }

    pub fn read(&mut self) -> Result<Vec<super::cdc::Batch>> {
        while let Ok(message) = self.receiver.try_recv() {
            match message {
                Message::End(end) => self.end = end,
                Message::Failed => return Err("home journal write failed".into()),
                Message::Stop => self.stopped = true,
            }
        }
        let mut batches = Vec::new();
        while self.cursor.offset < self.end {
            let (edits, offset) = Home::frame(&mut self.file, self.cursor.offset, self.end)?
                .ok_or("incomplete committed home frame")?;
            self.cursor = super::cdc::Cursor {
                journal: 0,
                offset,
                sequence: offset,
            };
            let items = edits
                .into_iter()
                .map(|(key, value)| super::cdc::Item {
                    key: key.into_vec(),
                    value: value.map(ByteBuf::into_vec),
                })
                .collect();
            batches.push(super::cdc::Batch {
                cursor: self.cursor,
                items,
            });
        }
        Ok(batches)
    }
}
