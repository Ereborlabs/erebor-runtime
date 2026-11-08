use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::ops::Bound::{Excluded, Included};
use std::path::Path;
use std::sync::{Arc, Once};
use std::time::Instant;

use bytes::Bytes;
use camino::Utf8PathBuf;
use neon_utils::id::{TenantId, TimelineId};
use neon_utils::lsn::Lsn;
use neon_utils::sync::gate::Gate;
use pageserver::config::PageServerConf;
use pageserver::context::{DownloadBehavior, RequestContext};
use pageserver::task_mgr::TaskKind;
use pageserver::tenant::storage_layer::{DeltaLayer, DeltaLayerWriter};
use pageserver::{page_cache, virtual_file};
use pageserver_api::key::Key;
use pageserver_api::models::virtual_file::{IoEngineKind, IoMode};
use pageserver_api::shard::TenantShardId;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;
use wal_decoder::models::value::Value;

use super::Result;
use super::kv::{Entries, Read, Write, prefix_end};

type Catalog = BTreeMap<Vec<u8>, Entry>;
#[derive(Clone)]
struct Entry {
    id: u64,
    revisions: Vec<u64>,
}
struct Layer {
    revision: u64,
    file: Arc<DeltaLayer>,
}
struct State {
    catalog: Arc<Catalog>,
    layers: Vec<Arc<Layer>>,
    lock: Option<File>,
    poisoned: bool,
}
pub struct Neon {
    state: RefCell<State>,
    runtime: Runtime,
    conf: &'static PageServerConf,
    path: Utf8PathBuf,
    tenant: TenantShardId,
    timeline: TimelineId,
    context: RequestContext,
    gate: Gate,
}
struct Snapshot<'a> {
    owner: &'a Neon,
    catalog: Arc<Catalog>,
    layers: Vec<Arc<Layer>>,
    revision: u64,
}
struct Transaction<'a> {
    snapshot: Snapshot<'a>,
    edits: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Neon {
    pub fn open(path: &Path) -> Result<Self> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path.join("neon.lock"))?;
        lock.try_lock()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let conf = Box::leak(Box::new(PageServerConf::dummy_conf(
            Utf8PathBuf::from_path_buf(path.to_path_buf()).map_err(|_| "non UTF-8 path")?,
        )));
        static INITIALIZE: Once = Once::new();
        INITIALIZE.call_once(|| {
            virtual_file::init(
                conf.max_file_descriptors,
                IoEngineKind::StdFs,
                IoMode::Buffered,
                virtual_file::SyncMode::Sync,
            );
            page_cache::init(conf.page_cache_size);
        });
        let tenant =
            TenantShardId::unsharded("01010101010101010101010101010101".parse::<TenantId>()?);
        let timeline = "02020202020202020202020202020202".parse::<TimelineId>()?;
        let layer_path = conf.timeline_path(&tenant, &timeline);
        std::fs::create_dir_all(&layer_path)?;
        for directory in layer_path
            .as_std_path()
            .ancestors()
            .take_while(|directory| directory.starts_with(path))
        {
            File::open(directory)?.sync_all()?;
        }
        let context = RequestContext::new(TaskKind::DebugTool, DownloadBehavior::Error)
            .with_scope_debug_tools();
        let mut layers = Vec::new();
        for entry in std::fs::read_dir(&layer_path)? {
            let path =
                Utf8PathBuf::from_path_buf(entry?.path()).map_err(|_| "non UTF-8 layer path")?;
            if pageserver::is_temporary(&path) {
                continue;
            }
            let file = DeltaLayer::new_for_path(&path, File::open(&path)?)?;
            let revision = file.desc.lsn_range.start.0;
            assert_eq!(file.desc.lsn_range.end.0, revision + 1);
            layers.push(Arc::new(Layer {
                revision,
                file: Arc::new(file),
            }));
        }
        layers.sort_by_key(|layer| layer.revision);
        assert!(
            layers
                .windows(2)
                .all(|pair| pair[0].revision < pair[1].revision)
        );
        let mut catalog = Catalog::new();
        let mut revisions = BTreeMap::<u64, Vec<u64>>::new();
        for layer in &layers {
            let keys = runtime.block_on(layer.file.keys_for_bench(&context))?;
            let dictionary = keys
                .iter()
                .copied()
                .filter(|key| key.to_i128() % 2 == 0)
                .collect::<Vec<_>>();
            let values = runtime.block_on(layer.file.images_for_bench(
                &dictionary,
                Lsn(layer.revision),
                &context,
            ))?;
            for (key, bytes) in dictionary.into_iter().zip(values) {
                let number = u64::try_from(key.to_i128())?;
                let id = number / 2;
                assert!(id > 0);
                let entry = Entry {
                    id,
                    revisions: Vec::new(),
                };
                if let Some(previous) =
                    catalog.insert(bytes.ok_or("Neon dictionary value absent")?.to_vec(), entry)
                {
                    assert_eq!(previous.id, id);
                }
            }
            for key in keys {
                let number = u64::try_from(key.to_i128())?;
                if number % 2 == 1 {
                    revisions
                        .entry(number / 2)
                        .or_default()
                        .push(layer.revision);
                }
            }
        }
        for entry in catalog.values_mut() {
            entry.revisions = revisions
                .remove(&entry.id)
                .ok_or("Neon dictionary has no publications")?;
        }
        assert!(revisions.is_empty());
        Ok(Self {
            state: RefCell::new(State {
                catalog: Arc::new(catalog),
                layers,
                lock: Some(lock),
                poisoned: false,
            }),
            runtime,
            conf,
            path: layer_path,
            tenant,
            timeline,
            context,
            gate: Gate::default(),
        })
    }
    fn snapshot(&self, revision: u64) -> Result<Snapshot<'_>> {
        let state = self.state.try_borrow()?;
        state.check()?;
        Ok(Snapshot {
            owner: self,
            catalog: Arc::clone(&state.catalog),
            layers: state.layers.clone(),
            revision,
        })
    }
    pub fn read_at<T>(
        &self,
        revision: u64,
        action: impl FnOnce(&dyn Read) -> Result<T>,
    ) -> Result<T> {
        action(&self.snapshot(revision)?)
    }
    pub fn write_at<T>(
        &self,
        revision: u64,
        commit: bool,
        action: impl FnOnce(&mut dyn Write) -> Result<T>,
    ) -> Result<(T, f64, f64)> {
        let started = Instant::now();
        let mut tx = Transaction {
            snapshot: self.snapshot(u64::MAX)?,
            edits: BTreeMap::new(),
        };
        let result = action(&mut tx)?;
        let Transaction { snapshot, edits } = tx;
        let mut records = BTreeMap::new();
        let mut additions = Vec::new();
        let mut changed = Vec::new();
        for (key, value) in edits {
            let id = if let Some(entry) = snapshot.catalog.get(&key) {
                entry.id
            } else {
                let id = u64::try_from(snapshot.catalog.len() + additions.len())?
                    .checked_add(1)
                    .ok_or("catalog overflow")?;
                records.insert(Self::key(id, false)?, Bytes::copy_from_slice(&key));
                additions.push((key.clone(), id));
                id
            };
            changed.push(key);
            let mut bytes = vec![u8::from(value.is_some())];
            if let Some(value) = value {
                bytes.extend_from_slice(&value);
            }
            records.insert(Self::key(id, true)?, Bytes::from(bytes));
        }
        drop(snapshot);
        let work = started.elapsed().as_secs_f64();
        let synced = Instant::now();
        if commit {
            let mut state = self.state.try_borrow_mut()?;
            state.check()?;
            assert!(
                state
                    .layers
                    .last()
                    .is_none_or(|last| last.revision < revision)
            );
            state.poisoned = true;
            let (desc, temporary) = self
                .runtime
                .block_on(async {
                    let mut writer = DeltaLayerWriter::new(
                        self.conf,
                        self.timeline,
                        self.tenant,
                        Key::MIN,
                        Lsn(revision)..Lsn(revision + 1),
                        &self.gate,
                        CancellationToken::new(),
                        &self.context,
                    )
                    .await?;
                    for (key, bytes) in records {
                        writer
                            .put_value(key, Lsn(revision), Value::Image(bytes), &self.context)
                            .await?;
                    }
                    writer.finish_for_bench(Key::MAX, &self.context).await
                })
                .map_err(|error| format!("Neon layer write: {error:#}"))?;
            let final_path = self.path.join(desc.layer_name().to_string());
            std::fs::rename(&temporary, &final_path)?;
            File::open(&self.path)?.sync_all()?;
            let file = DeltaLayer::new_for_path(&final_path, File::open(&final_path)?)?;
            state.layers.push(Arc::new(Layer {
                revision,
                file: Arc::new(file),
            }));
            let catalog = Arc::make_mut(&mut state.catalog);
            for (key, id) in additions {
                catalog.insert(
                    key,
                    Entry {
                        id,
                        revisions: Vec::new(),
                    },
                );
            }
            for key in changed {
                catalog
                    .get_mut(&key)
                    .ok_or("Neon changed key absent")?
                    .revisions
                    .push(revision);
            }
            state.poisoned = false;
        }
        Ok((result, work, synced.elapsed().as_secs_f64()))
    }
    fn key(id: u64, value: bool) -> Result<Key> {
        Ok(Key::from_i128(i128::from(
            id.checked_mul(2)
                .and_then(|n| n.checked_add(u64::from(value)))
                .ok_or("native key overflow")?,
        )))
    }
    pub fn close(&self) -> Result<()> {
        let mut state = self.state.try_borrow_mut()?;
        state.check()?;
        self.runtime.block_on(self.gate.close());
        let _entered = self.runtime.enter();
        state.layers.clear();
        state.lock.take();
        Ok(())
    }
}
impl State {
    fn check(&self) -> Result<()> {
        if self.poisoned || self.lock.is_none() {
            return Err("Neon owner closed or I/O failed; reopen required".into());
        }
        Ok(())
    }
}
impl Read for Snapshot<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .read(self.catalog.get_key_value(key).into_iter())?
            .pop()
            .map(|(_, value)| value))
    }
    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        let end = prefix_end(prefix);
        self.read(
            self.catalog
                .range::<[u8], _>((Included(prefix), Excluded(end.as_slice()))),
        )
    }
    fn floor(&self, prefix: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        let end = [prefix, &revision.to_be_bytes()].concat();
        for (key, _) in self
            .catalog
            .range::<[u8], _>((Included(prefix), Included(end.as_slice())))
            .rev()
        {
            if let Some(value) = self.get(key)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
}
impl Snapshot<'_> {
    fn read<'a>(&self, entries: impl Iterator<Item = (&'a Vec<u8>, &'a Entry)>) -> Result<Entries> {
        let mut groups = BTreeMap::<u64, Vec<(&Vec<u8>, u64)>>::new();
        for (key, entry) in entries {
            let end = entry.revisions.partition_point(|lsn| *lsn <= self.revision);
            if let Some(index) = end.checked_sub(1) {
                groups
                    .entry(entry.revisions[index])
                    .or_default()
                    .push((key, entry.id));
            }
        }
        self.owner.runtime.block_on(async {
            let mut rows = Vec::new();
            for (revision, entries) in groups {
                let index = self
                    .layers
                    .binary_search_by_key(&revision, |layer| layer.revision)
                    .map_err(|_| "Neon routing layer absent")?;
                let keys = entries
                    .iter()
                    .map(|(_, id)| Neon::key(*id, true))
                    .collect::<Result<Vec<_>>>()?;
                let values = self.layers[index]
                    .file
                    .images_for_bench(&keys, Lsn(revision), &self.owner.context)
                    .await
                    .map_err(|error| format!("Neon indexed batch read: {error:#}"))?;
                for ((key, _), value) in entries.into_iter().zip(values) {
                    let value = value.ok_or("Neon published value absent")?;
                    match value.split_first() {
                        Some((0, rest)) if rest.is_empty() => {}
                        Some((1, rest)) => rows.push((key.clone(), rest.to_vec())),
                        _ => return Err("invalid Neon value envelope".into()),
                    }
                }
            }
            rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            Ok(rows)
        })
    }
}
impl Read for Transaction<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(value) = self.edits.get(key) {
            return Ok(value.clone());
        }
        self.snapshot.get(key)
    }
    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        let mut rows = self
            .snapshot
            .prefix(prefix)?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        for (key, value) in self
            .edits
            .range::<[u8], _>((Included(prefix), Excluded(prefix_end(prefix).as_slice())))
        {
            if let Some(value) = value {
                rows.insert(key.clone(), value.clone());
            } else {
                rows.remove(key);
            }
        }
        Ok(rows.into_iter().collect())
    }
    fn floor(&self, prefix: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        let end = [prefix, &revision.to_be_bytes()].concat();
        Ok(self
            .prefix(prefix)?
            .into_iter()
            .rev()
            .find(|(key, _)| key <= &end)
            .map(|(_, value)| value))
    }
}
impl Write for Transaction<'_> {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.edits.insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }
    fn remove(&mut self, key: &[u8]) -> Result<()> {
        self.edits.insert(key.to_vec(), None);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batched_history_and_overlay() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let db = Neon::open(directory.path())?;
        db.write_at(10, true, |tx| {
            tx.put(b"p/a", b"A0")?;
            tx.put(b"p/c", b"C0")?;
            tx.put(b"other", b"outside")
        })?;
        db.write_at(20, true, |tx| {
            tx.put(b"p/a", b"A1")?;
            tx.put(b"p/b", b"B1")
        })?;
        let rows = |pairs: &[(&[u8], &[u8])]| {
            pairs
                .iter()
                .map(|(k, v)| (k.to_vec(), v.to_vec()))
                .collect::<Entries>()
        };
        let old = rows(&[(b"p/a", b"A0"), (b"p/c", b"C0")]);
        let middle = rows(&[(b"p/a", b"A1"), (b"p/b", b"B1"), (b"p/c", b"C0")]);
        let current = rows(&[(b"p/b", b"B1"), (b"p/c", b"C2"), (b"p/d", b"D2")]);
        db.read_at(25, |held| {
            db.write_at(30, true, |tx| {
                tx.remove(b"p/a")?;
                tx.put(b"p/c", b"C2")?;
                tx.put(b"p/d", b"D2")
            })?;
            assert_eq!(held.prefix(b"p/")?, middle);
            Ok(())
        })?;
        db.write_at(40, false, |tx| {
            tx.remove(b"p/b")?;
            tx.put(b"p/c", b"C3")?;
            tx.put(b"p/e", b"aborted")?;
            assert_eq!(
                tx.prefix(b"p/")?,
                rows(&[(b"p/c", b"C3"), (b"p/d", b"D2"), (b"p/e", b"aborted")])
            );
            Ok(())
        })?;
        db.read_at(40, |tx| {
            assert_eq!(tx.prefix(b"p/")?, current);
            assert_eq!(tx.get(b"p/a")?, None);
            assert_eq!(tx.get(b"p/e")?, None);
            Ok(())
        })?;
        db.write_at(40, true, |tx| tx.put(b"p/e", b"E3"))?;
        let mut latest = current.clone();
        latest.push((b"p/e".to_vec(), b"E3".to_vec()));
        db.close()?;
        drop(db);
        let db = Neon::open(directory.path())?;
        for (cut, expected) in [(15, old), (25, middle), (35, current), (45, latest)] {
            db.read_at(cut, |tx| {
                assert_eq!(tx.prefix(b"p/")?, expected);
                Ok(())
            })?;
        }
        db.close()
    }
    #[test]
    fn transactions_history_and_reopen() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let db = Neon::open(directory.path())?;
        let key = [b"H".as_slice(), &1u64.to_be_bytes()].concat();
        db.write_at(10, true, |tx| {
            tx.put(&key, b"old")?;
            assert_eq!(tx.get(&key)?, Some(b"old".to_vec()));
            Ok(())
        })?;
        db.read_at(10, |old| {
            db.write_at(20, true, |tx| {
                tx.put(&key, b"new")?;
                tx.put(b"empty", b"")
            })?;
            assert_eq!(old.get(&key)?, Some(b"old".to_vec()));
            Ok(())
        })?;
        db.write_at(30, false, |tx| tx.remove(&key))?;
        db.close()?;
        drop(db);
        let db = Neon::open(directory.path())?;
        db.read_at(10, |tx| {
            assert_eq!(tx.floor(b"H", u64::MAX)?, Some(b"old".to_vec()));
            assert_eq!(tx.get(b"empty")?, None);
            Ok(())
        })?;
        db.read_at(20, |tx| {
            assert_eq!(tx.prefix(b"H")?, vec![(key.clone(), b"new".to_vec())]);
            assert_eq!(tx.get(b"empty")?, Some(Vec::new()));
            Ok(())
        })?;
        db.write_at(30, true, |tx| tx.remove(&key))?;
        db.read_at(20, |tx| {
            assert_eq!(tx.get(&key)?, Some(b"new".to_vec()));
            Ok(())
        })?;
        db.read_at(30, |tx| {
            assert_eq!(tx.get(&key)?, None);
            Ok(())
        })?;
        db.close()?;
        drop(db);
        let db = Neon::open(directory.path())?;
        db.read_at(20, |tx| {
            assert_eq!(tx.get(&key)?, Some(b"new".to_vec()));
            assert_eq!(tx.floor(b"H", u64::MAX)?, Some(b"new".to_vec()));
            Ok(())
        })?;
        db.read_at(30, |tx| {
            assert_eq!(tx.get(&key)?, None);
            assert!(tx.prefix(b"H")?.is_empty());
            assert_eq!(tx.floor(b"H", u64::MAX)?, None);
            Ok(())
        })?;
        db.close()
    }
}
