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

type Catalog = BTreeMap<Vec<u8>, u64>;
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
        for layer in &layers {
            for (key, lsn, bytes) in runtime.block_on(layer.file.images_for_bench(&context))? {
                assert_eq!(lsn.0, layer.revision);
                let number = u64::try_from(key.to_i128())?;
                if number % 2 == 0 {
                    let id = number / 2;
                    assert!(id > 0);
                    if let Some(previous) = catalog.insert(bytes.to_vec(), id) {
                        assert_eq!(previous, id);
                    }
                }
            }
        }
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
        let mut catalog = tx.snapshot.catalog.as_ref().clone();
        let result = action(&mut tx)?;
        let mut records = BTreeMap::new();
        for (key, value) in tx.edits {
            let id = if let Some(id) = catalog.get(&key) {
                *id
            } else {
                let id = u64::try_from(catalog.len())?
                    .checked_add(1)
                    .ok_or("catalog overflow")?;
                records.insert(Self::key(id, false)?, Bytes::copy_from_slice(&key));
                catalog.insert(key, id);
                id
            };
            let mut bytes = vec![u8::from(value.is_some())];
            if let Some(value) = value {
                bytes.extend_from_slice(&value);
            }
            records.insert(Self::key(id, true)?, Bytes::from(bytes));
        }
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
            state.catalog = Arc::new(catalog);
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
        let Some(id) = self.catalog.get(key) else {
            return Ok(None);
        };
        let key = Neon::key(*id, true)?;
        for layer in self
            .layers
            .iter()
            .rev()
            .filter(|layer| layer.revision <= self.revision)
        {
            let value = self
                .owner
                .runtime
                .block_on(
                    layer
                        .file
                        .image_for_bench(key, Lsn(layer.revision), &self.owner.context),
                )
                .map_err(|error| format!("Neon indexed read: {error:#}"))?;
            if let Some(value) = value {
                return match value.split_first() {
                    Some((0, rest)) if rest.is_empty() => Ok(None),
                    Some((1, rest)) => Ok(Some(rest.to_vec())),
                    _ => Err("invalid Neon value envelope".into()),
                };
            }
        }
        Ok(None)
    }
    fn prefix(&self, prefix: &[u8]) -> Result<Entries> {
        let end = prefix_end(prefix);
        let mut rows = Vec::new();
        for (key, _) in self
            .catalog
            .range::<[u8], _>((Included(prefix), Excluded(end.as_slice())))
        {
            if let Some(value) = self.get(key)? {
                rows.push((key.clone(), value));
            }
        }
        Ok(rows)
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
