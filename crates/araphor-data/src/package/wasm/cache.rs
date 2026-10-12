use std::collections::VecDeque;
use std::sync::TryLockError;

use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::{AnalysisReadControl, Result};

use super::{admission::CompileBudget, bindings::AnalysisPackagePre, execution::GuestState, Code};

pub(super) const MAX_CACHE_BYTES: usize = 80 * 1024 * 1024;
pub(super) const MAX_CACHE_ENTRIES: usize = 16;
pub(super) const MAX_IMAGE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Default)]
#[cfg_attr(any(test, feature = "test-fixtures"), derive(Clone))]
pub(super) struct CodeCache {
    entries: VecDeque<CacheEntry>,
    bytes: usize,
}

#[cfg_attr(any(test, feature = "test-fixtures"), derive(Clone))]
struct CacheEntry {
    digest: [u8; 32],
    prepared: AnalysisPackagePre<GuestState>,
    charge: usize,
}

impl CodeCache {
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(super) fn charge(&self, digest: &[u8; 32]) -> Option<usize> {
        self.entries
            .iter()
            .find(|entry| entry.digest == *digest)
            .map(|entry| entry.charge)
    }

    fn get(&self, digest: &[u8; 32]) -> Option<AnalysisPackagePre<GuestState>> {
        self.entries
            .iter()
            .find(|entry| entry.digest == *digest)
            .map(|entry| entry.prepared.clone())
    }

    fn insert(&mut self, entry: CacheEntry) {
        while self.bytes + entry.charge > MAX_CACHE_BYTES || self.entries.len() >= MAX_CACHE_ENTRIES
        {
            if let Some(old) = self.entries.pop_front() {
                self.bytes -= old.charge;
            }
        }
        self.bytes += entry.charge;
        self.entries.push_back(entry);
    }
}

impl super::WasmExecution {
    pub(super) fn cached(
        &self,
        digest: &[u8; 32],
    ) -> Result<Option<AnalysisPackagePre<GuestState>>> {
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
    ) -> Result<AnalysisPackagePre<GuestState>> {
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
        let component = self.compile(bytes, control, &mut compiler)?;
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
        self.cache
            .lock()
            .map_err(|_| Code::Incomplete.error("component cache lock"))?
            .insert(CacheEntry {
                digest,
                prepared: prepared.clone(),
                charge: image_bytes + bytes.len(),
            });
        Ok(prepared)
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
        let entry = |index: u8, charge| CacheEntry {
            digest: [index; 32],
            prepared: prepared.clone(),
            charge,
        };
        let mut cache = CodeCache::default();
        for index in 0..=MAX_CACHE_ENTRIES {
            cache.insert(entry(index as u8, 1));
        }
        assert_eq!(cache.entries.len(), MAX_CACHE_ENTRIES);
        assert_eq!(cache.bytes, MAX_CACHE_ENTRIES);
        assert!(cache.get(&[0; 32]).is_none());
        assert!(cache.get(&[MAX_CACHE_ENTRIES as u8; 32]).is_some());

        let charge = MAX_IMAGE_BYTES + super::super::admission::MAX_SOURCE_BYTES;
        let capacity = (MAX_CACHE_BYTES / charge).min(MAX_CACHE_ENTRIES);
        let mut cache = CodeCache::default();
        for index in 0..capacity + 2 {
            cache.insert(entry((32 + index) as u8, charge));
            let retained = (index + 1).min(capacity);
            assert_eq!(cache.entries.len(), retained);
            assert_eq!(cache.bytes, retained * charge);
            assert!(cache.get(&[(32 + index) as u8; 32]).is_some());
            if index >= capacity {
                assert!(cache.get(&[(32 + index - capacity) as u8; 32]).is_none());
            }
        }
        Ok(())
    }
}
