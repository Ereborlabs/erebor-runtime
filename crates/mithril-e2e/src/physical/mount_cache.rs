use std::{collections::BTreeSet, fs, os::unix::fs::MetadataExt as _, path::PathBuf};

use erebor_interceptor::KernelStateReader;
use libbpf_rs::{MapCore as _, MapFlags, MapHandle};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::platform::{Platform, TestResult};

// These layouts match the named cache structures in identity_maps.h.
#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, KnownLayout)]
struct CacheKey {
    namespace: u64,
    root: u64,
    epoch: u64,
    generation: u64,
    mount: u64,
    dentry: u64,
}

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, KnownLayout)]
struct ObjectKey {
    state: CacheKey,
    root_dentry: u64,
}

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, KnownLayout)]
struct CacheState {
    count: u32,
    ready: u32,
}

const READY: u32 = 1;

#[derive(Debug)]
pub(crate) struct CacheView {
    pub(crate) namespace: u64,
    pub(crate) epoch: u64,
    pub(crate) generation: u64,
    pub(crate) keys: BTreeSet<Vec<u8>>,
    pub(crate) mountinfo: Vec<u8>,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct CacheRows {
    pub(crate) objects: usize,
    pub(crate) states: usize,
    pub(crate) old_objects: usize,
    pub(crate) old_states: usize,
}

pub(crate) struct MountCache {
    reader: KernelStateReader,
    states: MapHandle,
    path: PathBuf,
    process: PathBuf,
}

impl MountCache {
    pub(crate) fn new<P: Platform>(env: &P, pid: u32) -> TestResult<Self> {
        let (pin, reader) = env.maps();
        let path = pin.join("maps/canonical_mount_cache_states");
        let states = MapHandle::from_pinned_path(&path)
            .map_err(|error| format!("{}: open cache states: {error}", path.display()))?;
        if states.key_size() as usize != size_of::<CacheKey>()
            || states.value_size() as usize != size_of::<CacheState>()
        {
            return Err(format!(
                "{}: cache ABI does not match identity_maps.h",
                path.display()
            )
            .into());
        }
        Ok(Self {
            reader: reader.clone(),
            states,
            path,
            process: PathBuf::from(format!("/proc/{pid}")),
        })
    }

    fn counter(&self, name: &str) -> TestResult<u64> {
        let bytes = self
            .reader
            .lookup(name, &0_u32.to_ne_bytes())?
            .ok_or_else(|| format!("{}: {name} is missing", self.path.display()))?;
        u64::read_from_bytes(&bytes)
            .map_err(|error| format!("{}: {name} ABI: {error}", self.path.display()).into())
    }

    fn state(&self, key: &[u8]) -> TestResult<CacheState> {
        let bytes = self
            .states
            .lookup(key, MapFlags::ANY)?
            .ok_or_else(|| format!("{}: cache state disappeared", self.path.display()))?;
        CacheState::read_from_bytes(&bytes)
            .map_err(|error| format!("{}: cache state ABI: {error}", self.path.display()).into())
    }

    pub(crate) fn snapshot(&self) -> TestResult<CacheView> {
        let epoch = self.counter("mount_global_mutation_epoch")?;
        let generation = self.counter("canonical_mount_cache_generation")?;
        let mut keys = BTreeSet::new();
        for bytes in self.states.keys() {
            let key = CacheKey::read_from_bytes(&bytes)
                .map_err(|error| format!("{}: cache key ABI: {error}", self.path.display()))?;
            if key.epoch == epoch
                && key.generation == generation
                && self.state(&bytes)?.ready == READY
            {
                keys.insert(bytes);
            }
        }
        Ok(CacheView {
            namespace: fs::metadata(self.process.join("ns/mnt"))?.ino(),
            epoch,
            generation,
            keys,
            mountinfo: fs::read(self.process.join("mountinfo"))?,
        })
    }

    pub(crate) fn rows(&self) -> TestResult<CacheRows> {
        let epoch = self.counter("mount_global_mutation_epoch")?;
        let generation = self.counter("canonical_mount_cache_generation")?;
        let mut rows = CacheRows::default();
        for bytes in self.reader.keys("canonical_mount_cache")? {
            let key = ObjectKey::read_from_bytes(&bytes)
                .map_err(|error| format!("{}: object key ABI: {error}", self.path.display()))?;
            rows.objects += 1;
            if key.state.epoch < epoch || key.state.generation < generation {
                rows.old_objects += 1;
            }
        }
        for bytes in self.reader.keys("canonical_mount_cache_states")? {
            let key = CacheKey::read_from_bytes(&bytes)
                .map_err(|error| format!("{}: state key ABI: {error}", self.path.display()))?;
            rows.states += 1;
            if key.epoch < epoch || key.generation < generation {
                rows.old_states += 1;
            }
        }
        Ok(rows)
    }

    pub(crate) fn stale(&self, view: &CacheView) -> TestResult<()> {
        if view.keys.is_empty() {
            return Err(format!("{}: no READY cache row: {view:?}", self.path.display()).into());
        }
        for key in &view.keys {
            let mut state = self.state(key)?;
            state.count = state
                .count
                .checked_sub(1)
                .filter(|count| *count > 0)
                .ok_or_else(|| {
                    format!(
                        "{}: mount count {} cannot be shortened",
                        self.path.display(),
                        state.count
                    )
                })?;
            self.states
                .update(key, state.as_bytes(), MapFlags::EXIST)
                .map_err(|error| {
                    format!("{}: shorten mount count: {error}", self.path.display())
                })?;
        }
        Ok(())
    }
}
