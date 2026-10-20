use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, TryLockError,
};

use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use tokio::sync::watch;

use crate::{AnalysisReadControl, Result, WasmLimits};

use super::{
    admission::CompileBudget, bindings::AnalysisPackagePre, execution::GuestState, CapacityRelease,
    Code, PreparedComponent,
};

#[derive(Default)]
#[cfg_attr(any(test, feature = "test-fixtures"), derive(Clone))]
pub(super) struct CodeCache {
    entries: VecDeque<Arc<CacheEntry>>,
    budget: Arc<CacheBudget>,
}

struct CacheBudget {
    max_bytes: Option<usize>,
    max_entries: Option<usize>,
    bytes: AtomicUsize,
    entries: AtomicUsize,
    capacity: watch::Sender<()>,
}

pub(super) struct CacheEntry {
    digest: [u8; 32],
    pub(super) prepared: AnalysisPackagePre<GuestState>,
    _reservation: CacheCharge,
}

struct CacheCharge {
    budget: Arc<CacheBudget>,
    bytes: usize,
}

impl Default for CacheBudget {
    fn default() -> Self {
        Self {
            max_bytes: None,
            max_entries: None,
            bytes: AtomicUsize::new(0),
            entries: AtomicUsize::new(0),
            capacity: watch::channel(()).0,
        }
    }
}

impl CacheCharge {
    fn acquire(budget: &Arc<CacheBudget>, bytes: usize) -> Option<Self> {
        budget
            .entries
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |entries| {
                entries
                    .checked_add(1)
                    .filter(|count| budget.max_entries.is_none_or(|maximum| *count <= maximum))
            })
            .ok()?;
        if budget
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|count| budget.max_bytes.is_none_or(|maximum| *count <= maximum))
            })
            .is_err()
        {
            budget.entries.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Self {
            budget: Arc::clone(budget),
            bytes,
        })
    }
}

impl Drop for CacheCharge {
    fn drop(&mut self) {
        self.budget.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        self.budget.entries.fetch_sub(1, Ordering::AcqRel);
        self.budget.capacity.send_replace(());
    }
}

impl CodeCache {
    pub(super) fn new(capacity: watch::Sender<()>, limits: WasmLimits) -> Self {
        Self {
            entries: VecDeque::new(),
            budget: Arc::new(CacheBudget {
                max_bytes: limits.cache_bytes,
                max_entries: limits.cache_entries,
                bytes: AtomicUsize::new(0),
                entries: AtomicUsize::new(0),
                capacity,
            }),
        }
    }

    pub(super) fn available(&self, requested: usize) -> bool {
        let mut bytes = self.budget.bytes.load(Ordering::Acquire);
        let mut entries = self.budget.entries.load(Ordering::Acquire);
        for entry in &self.entries {
            if Arc::strong_count(entry) == 1 {
                bytes = bytes.saturating_sub(entry._reservation.bytes);
                entries = entries.saturating_sub(1);
            }
        }
        entries < self.budget.max_entries.unwrap_or(usize::MAX)
            && requested
                <= self
                    .budget
                    .max_bytes
                    .unwrap_or(usize::MAX)
                    .saturating_sub(bytes)
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub(super) fn charge(&self, digest: &[u8; 32]) -> Option<usize> {
        self.entries
            .iter()
            .find(|entry| entry.digest == *digest)
            .map(|entry| entry._reservation.bytes)
    }

    #[cfg(test)]
    pub(super) fn clear(&mut self) {
        self.entries.clear();
    }

    fn get(&self, digest: &[u8; 32]) -> Option<PreparedComponent> {
        self.entries
            .iter()
            .find(|entry| entry.digest == *digest)
            .map(|entry| PreparedComponent {
                entry: Arc::clone(entry),
                _release: CapacityRelease(self.budget.capacity.clone()),
            })
    }

    fn reserve(&mut self, bytes: usize) -> Result<CacheCharge> {
        if self.budget.max_bytes.is_some_and(|maximum| bytes > maximum) {
            return Err(Code::Limit.error("component cache bytes").into());
        }
        if self.budget.max_entries == Some(0) {
            return Err(Code::Limit.error("component cache entries").into());
        }
        loop {
            if let Some(charge) = CacheCharge::acquire(&self.budget, bytes) {
                return Ok(charge);
            }
            let index = self
                .entries
                .iter()
                .position(|entry| Arc::strong_count(entry) == 1)
                .ok_or_else(|| {
                    crate::AnalysisBusySnafu {
                        resource: "component cache capacity",
                        requested: bytes,
                    }
                    .build()
                })?;
            self.entries.remove(index);
        }
    }

    fn insert(
        &mut self,
        digest: [u8; 32],
        prepared: AnalysisPackagePre<GuestState>,
        reservation: CacheCharge,
    ) -> PreparedComponent {
        let entry = Arc::new(CacheEntry {
            digest,
            prepared,
            _reservation: reservation,
        });
        self.entries.push_back(Arc::clone(&entry));
        PreparedComponent {
            entry,
            _release: CapacityRelease(self.budget.capacity.clone()),
        }
    }
}

impl super::WasmExecution {
    pub fn cached(&self, digest: &[u8; 32]) -> Result<Option<PreparedComponent>> {
        let prepared = self
            .cache
            .lock()
            .map(|cache| cache.get(digest))
            .map_err(|_| Code::Incomplete.error("component cache lock"))?;
        if let Some(prepared) = &prepared {
            CompileBudget::resources(prepared.instance_pre().component(), &self.limits)?;
        }
        Ok(prepared)
    }

    pub(super) fn compiled(
        &self,
        bytes: &[u8],
        control: &AnalysisReadControl,
    ) -> Result<PreparedComponent> {
        control.check()?;
        CompileBudget::check_size(bytes, &self.limits)?;
        let digest = Sha256::digest(bytes).into();
        if let Some(prepared) = self.cached(&digest)? {
            return Ok(prepared);
        }
        let compiler = self.compiler.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => crate::AnalysisBusySnafu {
                resource: "component compiler",
                requested: 1_usize,
            }
            .build(),
            TryLockError::Poisoned(_) => Code::Incomplete.error("component compiler lock").into(),
        })?;
        let _compiler = (compiler, CapacityRelease(self.capacity.clone()));
        if let Some(prepared) = self.cached(&digest)? {
            return Ok(prepared);
        }
        CompileBudget::check(bytes, control, &self.limits)?;
        let reservation;
        let component = wasmtime::component::Component::new(&self.engine, bytes).context(
            crate::PackageWasmSnafu {
                code: Code::Invalid,
                operation: "component compilation",
            },
        )?;
        control.check()?;
        let image = component.image_range();
        let image_bytes = (image.end as usize).saturating_sub(image.start as usize);
        if self
            .limits
            .image_bytes
            .is_some_and(|maximum| image_bytes > maximum)
        {
            return Err(Code::Limit.error("component compiled image").into());
        }
        let charge = image_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| Code::Limit.error("component cache bytes"))?;
        reservation = self
            .cache
            .lock()
            .map_err(|_| Code::Incomplete.error("component cache lock"))?
            .reserve(charge)?;
        CompileBudget::interface(&self.engine, &component, &self.limits)?;
        let instance =
            self.linker
                .instantiate_pre(&component)
                .context(crate::PackageWasmSnafu {
                    code: Code::Unsupported,
                    operation: "component imports",
                })?;
        let prepared = AnalysisPackagePre::new(instance).context(crate::PackageWasmSnafu {
            code: Code::Unsupported,
            operation: "analysis component exports",
        })?;
        control.check()?;
        Ok(self
            .cache
            .lock()
            .map_err(|_| Code::Incomplete.error("component cache lock"))?
            .insert(digest, prepared, reservation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CACHE_BYTES: usize = 80 * 1024 * 1024;
    const CACHE_ENTRIES: usize = 16;

    fn limited_cache() -> CodeCache {
        CodeCache::new(
            watch::channel(()).0,
            WasmLimits {
                cache_bytes: Some(CACHE_BYTES),
                cache_entries: Some(CACHE_ENTRIES),
                ..Default::default()
            },
        )
    }

    #[test]
    fn cache_enforces_each_bound(
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let runtime = super::super::WasmExecution::new(crate::WasmLimits::default())?;
        let prepared = runtime.compiled(
            araphor_analysis_builtins::components::RUNTIME,
            &AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?,
        )?;
        let mut unbounded = CodeCache::default();
        let mut pins = Vec::new();
        for index in 0..=CACHE_ENTRIES {
            let charge = unbounded.reserve(CACHE_BYTES + 1)?;
            pins.push(unbounded.insert([index as u8; 32], prepared.component().clone(), charge));
        }
        assert_eq!(unbounded.entries.len(), CACHE_ENTRIES + 1);
        assert!(unbounded.available(CACHE_BYTES));
        assert_eq!(
            unbounded.budget.bytes.load(Ordering::Acquire),
            (CACHE_ENTRIES + 1) * (CACHE_BYTES + 1)
        );

        let mut cache = limited_cache();
        for index in 0..=CACHE_ENTRIES {
            let charge = cache.reserve(1)?;
            cache.insert([index as u8; 32], prepared.component().clone(), charge);
        }
        assert_eq!(cache.entries.len(), CACHE_ENTRIES);
        assert_eq!(cache.budget.bytes.load(Ordering::Acquire), CACHE_ENTRIES);
        assert!(cache.get(&[0; 32]).is_none());
        assert!(cache.get(&[CACHE_ENTRIES as u8; 32]).is_some());

        let charge = 40 * 1024 * 1024;
        let capacity = (CACHE_BYTES / charge).min(CACHE_ENTRIES);
        let mut cache = limited_cache();
        for index in 0..capacity + 2 {
            let reservation = cache.reserve(charge)?;
            cache.insert(
                [(32 + index) as u8; 32],
                prepared.component().clone(),
                reservation,
            );
            let retained = (index + 1).min(capacity);
            assert_eq!(cache.entries.len(), retained);
            assert_eq!(
                cache.budget.bytes.load(Ordering::Acquire),
                retained * charge
            );
            assert!(cache.get(&[(32 + index) as u8; 32]).is_some());
            if index >= capacity {
                assert!(cache.get(&[(32 + index - capacity) as u8; 32]).is_none());
            }
        }
        Ok(())
    }

    #[test]
    fn pinned_code_retains_charge(
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let runtime = super::super::WasmExecution::new(crate::WasmLimits::default())?;
        let prepared = runtime.compiled(
            araphor_analysis_builtins::components::RUNTIME,
            &AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?,
        )?;
        let mut eviction = limited_cache();
        let mut changes = eviction.budget.capacity.subscribe();
        let charge = eviction.reserve(CACHE_BYTES)?;
        let pin = eviction.insert([0; 32], prepared.component().clone(), charge);
        assert!(matches!(
            eviction.reserve(1),
            Err(crate::Error::AnalysisBusy { .. })
        ));
        assert!(!eviction.available(1));
        changes.borrow_and_update();
        drop(pin);
        assert!(changes.has_changed()?);
        assert_eq!(eviction.budget.bytes.load(Ordering::Acquire), CACHE_BYTES);
        assert!(eviction.available(1));
        drop(eviction.reserve(1)?);

        let mut empty = CodeCache::new(
            watch::channel(()).0,
            WasmLimits {
                cache_entries: Some(0),
                ..Default::default()
            },
        );
        assert!(matches!(
            empty.reserve(0),
            Err(crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Limit,
                    ..
                }
            })
        ));
        assert!(!empty.available(0));

        let mut exact = limited_cache();
        let charge = exact.reserve(CACHE_BYTES - 8)?;
        let pin = exact.insert([1; 32], prepared.component().clone(), charge);
        assert!(exact.available(8));
        assert!(!exact.available(9));
        assert!(matches!(
            exact.reserve(9),
            Err(crate::Error::AnalysisBusy {
                resource: "component cache capacity",
                requested: 9,
                ..
            })
        ));
        drop(pin);
        assert!(exact.available(9));

        for (count, bytes) in [(1, CACHE_BYTES), (CACHE_ENTRIES, 1)] {
            let mut cache = limited_cache();
            let mut handles = Vec::new();
            for index in 0..count {
                let charge = cache.reserve(bytes)?;
                handles.push(cache.insert([index as u8; 32], prepared.component().clone(), charge));
            }
            let second = cache.get(&[0; 32]).ok_or("pinned component")?;
            let mut mirror = cache.clone();
            cache.clear();
            mirror.clear();
            assert!(cache.get(&[0; 32]).is_none());
            assert_eq!(cache.budget.bytes.load(Ordering::Acquire), count * bytes);
            assert_eq!(cache.budget.entries.load(Ordering::Acquire), count);
            assert!(matches!(
                cache.reserve(1),
                Err(crate::Error::AnalysisBusy {
                    resource: "component cache capacity",
                    ..
                })
            ));
            assert_eq!(cache.budget.entries.load(Ordering::Acquire), count);
            handles.clear();
            assert_eq!(cache.budget.bytes.load(Ordering::Acquire), bytes);
            assert_eq!(cache.budget.entries.load(Ordering::Acquire), 1);
            drop(second);
            assert_eq!(cache.budget.bytes.load(Ordering::Acquire), 0);
            assert_eq!(cache.budget.entries.load(Ordering::Acquire), 0);
            let charge = cache.reserve(1)?;
            assert_eq!(cache.budget.bytes.load(Ordering::Acquire), 1);
            drop(charge);
            assert_eq!(cache.budget.bytes.load(Ordering::Acquire), 0);
        }
        Ok(())
    }
}
