use std::any::Any;

use crate::Result;

pub trait ManagedBudget: Send + Sync {
    fn limit(&self) -> usize;
    /// Keep the sum of live leases within this operation's limit.
    fn reserve(&self, bytes: usize) -> Result<Box<dyn Any + Send + Sync>>;
    fn check(&self) -> Result<()>;
}

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::{AnalysisReadControl, PackageErrorCodeV1 as Code};

type Lease = Box<dyn Any + Send + Sync>;

pub(in crate::analysis) struct PreparedMemory<'a> {
    control: &'a AnalysisReadControl,
    budget: &'a dyn ManagedBudget,
    used: Arc<PreparedUsage>,
    leases: Vec<Lease>,
}

struct PreparedUsage {
    _root: Lease,
    live: AtomicUsize,
    peak: AtomicUsize,
}

struct PreparedLease {
    _lease: Lease,
    used: Arc<PreparedUsage>,
    bytes: usize,
}

impl Drop for PreparedLease {
    fn drop(&mut self) {
        self.used.live.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

impl<'a> PreparedMemory<'a> {
    pub(in crate::analysis) fn new(
        control: &'a AnalysisReadControl,
        budget: &'a dyn ManagedBudget,
    ) -> Result<Self> {
        control.check()?;
        budget.check()?;
        let bytes = 2 * std::mem::size_of::<PreparedUsage>() + std::mem::size_of::<Self>();
        if bytes > budget.limit() {
            return Err(Code::Limit.error("managed preparation memory"));
        }
        let root = budget.reserve(bytes)?;
        Ok(Self {
            control,
            budget,
            used: Arc::new(PreparedUsage {
                _root: root,
                live: AtomicUsize::new(bytes),
                peak: AtomicUsize::new(bytes),
            }),
            leases: Vec::new(),
        })
    }

    pub(in crate::analysis) fn check(&self) -> Result<()> {
        self.control.check()?;
        self.budget.check()
    }

    pub(in crate::analysis) fn reserve(&self, bytes: usize) -> Result<Lease> {
        self.check()?;
        let bytes = bytes
            .checked_add(2 * std::mem::size_of::<PreparedLease>())
            .ok_or_else(|| Code::Limit.error("managed preparation memory"))?;
        let previous = self
            .used
            .live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|total| *total <= self.budget.limit())
            })
            .map_err(|_| Code::Limit.error("managed preparation memory"))?;
        let lease = match self.budget.reserve(bytes) {
            Ok(lease) => lease,
            Err(error) => {
                self.used.live.fetch_sub(bytes, Ordering::AcqRel);
                return Err(error);
            }
        };
        self.used.peak.fetch_max(previous + bytes, Ordering::AcqRel);
        Ok(Box::new(PreparedLease {
            _lease: lease,
            used: Arc::clone(&self.used),
            bytes,
        }))
    }

    pub(in crate::analysis) fn charge(&mut self, bytes: usize) -> Result<()> {
        let lease = self.reserve(bytes)?;
        self.hold(lease);
        Ok(())
    }

    pub(in crate::analysis) fn hold(&mut self, lease: Lease) {
        self.leases.push(lease);
    }

    pub(in crate::analysis) fn bytes(&self) -> usize {
        self.used.live.load(Ordering::Acquire)
    }

    pub(in crate::analysis) fn peak(&self) -> usize {
        self.used.peak.load(Ordering::Acquire)
    }
}
