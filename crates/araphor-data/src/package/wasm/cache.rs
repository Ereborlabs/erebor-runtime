use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, TryLockError,
};

use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::{AnalysisReadControl, Result};

use super::{
    admission::CompileBudget, bindings::AnalysisPackagePre, execution::GuestState, Code,
    PreparedComponent,
};

pub(super) const MAX_CACHE_BYTES: usize = 80 * 1024 * 1024;
pub(super) const MAX_CACHE_ENTRIES: usize = 16;
pub(super) const MAX_IMAGE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Default)]
#[cfg_attr(any(test, feature = "test-fixtures"), derive(Clone))]
pub(super) struct CodeCache {
    entries: VecDeque<Arc<CacheEntry>>,
    budget: Arc<CacheBudget>,
}

#[derive(Default)]
struct CacheBudget {
    bytes: AtomicUsize,
    entries: AtomicUsize,
}

pub(super) struct CacheEntry {
    digest: [u8; 32],
    pub(super) prepared: AnalysisPackagePre<GuestState>,
    reservation: CacheCharge,
}

struct CacheCharge {
    budget: Arc<CacheBudget>,
    bytes: usize,
}

impl CacheCharge {
    fn acquire(budget: &Arc<CacheBudget>, bytes: usize) -> Option<Self> {
        budget
            .entries
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |entries| {
                entries
                    .checked_add(1)
                    .filter(|count| *count <= MAX_CACHE_ENTRIES)
            })
            .ok()?;
        if budget
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|count| *count <= MAX_CACHE_BYTES)
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
    }
}

impl CodeCache {
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(super) fn charge(&self, digest: &[u8; 32]) -> Option<usize> {
        self.entries
            .iter()
            .find(|entry| entry.digest == *digest)
            .map(|entry| entry.reservation.bytes)
    }

    #[cfg(test)]
    pub(super) fn clear(&mut self) {
        self.entries.clear();
    }

    fn get(&self, digest: &[u8; 32]) -> Option<PreparedComponent> {
        self.entries
            .iter()
            .find(|entry| entry.digest == *digest)
            .map(|entry| PreparedComponent(Arc::clone(entry)))
    }

    fn reserve(&mut self, bytes: usize) -> Result<CacheCharge> {
        if bytes > MAX_CACHE_BYTES {
            return Err(Code::Limit.error("component cache bytes"));
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
            reservation,
        });
        self.entries.push_back(Arc::clone(&entry));
        PreparedComponent(entry)
    }
}

impl super::WasmExecution {
    pub(super) fn cached(&self, digest: &[u8; 32]) -> Result<Option<PreparedComponent>> {
        let prepared = self
            .cache
            .lock()
            .map(|cache| cache.get(digest))
            .map_err(|_| Code::Incomplete.error("component cache lock"))?;
        if let Some(prepared) = &prepared {
            CompileBudget::resources(
                prepared.instance_pre().component(),
                self.limits.memory_bytes,
            )?;
        }
        Ok(prepared)
    }

    pub(super) fn compiled(
        &self,
        bytes: &[u8],
        control: &AnalysisReadControl,
    ) -> Result<PreparedComponent> {
        control.check()?;
        CompileBudget::check_size(bytes)?;
        let digest = Sha256::digest(bytes).into();
        if let Some(prepared) = self.cached(&digest)? {
            return Ok(prepared);
        }
        let mut compiler = self.compiler.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => crate::AnalysisBusySnafu {
                resource: "component compiler",
            }
            .build(),
            TryLockError::Poisoned(_) => Code::Incomplete.error("component compiler lock"),
        })?;
        if *compiler {
            return Err(Code::Incomplete.error("component compiler recovery"));
        }
        if let Some(prepared) = self.cached(&digest)? {
            return Ok(prepared);
        }
        CompileBudget::check(bytes, control)?;
        let compiled = self.compile(bytes, control, &mut compiler, |image| {
            control.check()?;
            let charge = image
                .checked_add(bytes.len())
                .ok_or_else(|| Code::Limit.error("component cache bytes"))?;
            self.cache
                .lock()
                .map_err(|_| Code::Incomplete.error("component cache lock"))?
                .reserve(charge)
        })?;
        // Declare the charge first. Drop code before its charge on failure.
        let reservation = compiled.1;
        let component = compiled.0;
        control.check()?;
        let image = component.image_range();
        let image_bytes = (image.end as usize).saturating_sub(image.start as usize);
        if image_bytes > MAX_IMAGE_BYTES {
            return Err(Code::Limit.error("component compiled image"));
        }
        CompileBudget::interface(&self.engine, &component, self.limits.memory_bytes)?;
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
        if reservation.bytes != image_bytes + bytes.len() {
            return Err(Code::Incomplete.error("component compiled image charge"));
        }
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

    #[test]
    fn cache_enforces_each_bound(
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let runtime = super::super::WasmExecution::new(crate::query::WasmLimits::default())?;
        let prepared = runtime.compiled(
            araphor_analysis_builtins::components::RUNTIME,
            &AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?,
        )?;
        let mut cache = CodeCache::default();
        for index in 0..=MAX_CACHE_ENTRIES {
            let charge = cache.reserve(1)?;
            cache.insert([index as u8; 32], prepared.component().clone(), charge);
        }
        assert_eq!(cache.entries.len(), MAX_CACHE_ENTRIES);
        assert_eq!(
            cache.budget.bytes.load(Ordering::Acquire),
            MAX_CACHE_ENTRIES
        );
        assert!(cache.get(&[0; 32]).is_none());
        assert!(cache.get(&[MAX_CACHE_ENTRIES as u8; 32]).is_some());

        let charge = MAX_IMAGE_BYTES + super::super::admission::MAX_SOURCE_BYTES;
        let capacity = (MAX_CACHE_BYTES / charge).min(MAX_CACHE_ENTRIES);
        let mut cache = CodeCache::default();
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
        let runtime = super::super::WasmExecution::new(crate::query::WasmLimits::default())?;
        let prepared = runtime.compiled(
            araphor_analysis_builtins::components::RUNTIME,
            &AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?,
        )?;
        for (count, bytes) in [(1, MAX_CACHE_BYTES), (MAX_CACHE_ENTRIES, 1)] {
            let mut cache = CodeCache::default();
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
