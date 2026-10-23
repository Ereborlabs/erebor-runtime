use std::ops::{Deref, DerefMut};
use std::sync::{
    Arc, LockResult, Mutex as StdMutex, MutexGuard as StdMutexGuard, PoisonError,
    RwLock as StdRwLock, RwLockReadGuard as StdReadGuard, RwLockWriteGuard as StdWriteGuard,
    TryLockError, TryLockResult,
};
use std::task::{Context, Wake, Waker};
use std::time::Instant;

use tokio::sync::Notify;

use super::AnalysisReadControl;

pub(in crate::analysis) struct Lock<L> {
    native: L,
    available: Notify,
}

pub(in crate::analysis) type Mutex<T> = Lock<StdMutex<T>>;
pub(in crate::analysis) type RwLock<T> = Lock<StdRwLock<T>>;
pub(in crate::analysis) type MutexGuard<'a, T> = Guard<'a, StdMutexGuard<'a, T>>;
pub(in crate::analysis) type ReadGuard<'a, T> = Guard<'a, StdReadGuard<'a, T>>;
pub(in crate::analysis) type WriteGuard<'a, T> = Guard<'a, StdWriteGuard<'a, T>>;

#[derive(Debug)]
pub(in crate::analysis) struct Guard<'a, G> {
    // Drop the native guard before the release event.
    native: G,
    _released: Released<'a>,
}

#[derive(Debug)]
struct Released<'a>(&'a Notify);

impl Drop for Released<'_> {
    fn drop(&mut self) {
        self.0.notify_waiters();
    }
}

impl<G: Deref> Deref for Guard<'_, G> {
    type Target = G::Target;

    fn deref(&self) -> &Self::Target {
        &self.native
    }
}

impl<G: DerefMut> DerefMut for Guard<'_, G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.native
    }
}

impl<L: Default> Default for Lock<L> {
    fn default() -> Self {
        Self {
            native: L::default(),
            available: Notify::new(),
        }
    }
}

impl<L> Lock<L> {
    fn guard<G>(&self, native: G) -> Guard<'_, G> {
        Guard {
            native,
            _released: Released(&self.available),
        }
    }

    fn result<G>(&self, result: LockResult<G>) -> LockResult<Guard<'_, G>> {
        result
            .map(|guard| self.guard(guard))
            .map_err(|error| PoisonError::new(self.guard(error.into_inner())))
    }

    fn attempted<G>(&self, result: TryLockResult<G>) -> TryLockResult<Guard<'_, G>> {
        result
            .map(|guard| self.guard(guard))
            .map_err(|error| match error {
                TryLockError::WouldBlock => TryLockError::WouldBlock,
                TryLockError::Poisoned(error) => {
                    TryLockError::Poisoned(PoisonError::new(self.guard(error.into_inner())))
                }
            })
    }
}

impl<T> Mutex<T> {
    pub(in crate::analysis) fn new(value: T) -> Self {
        Self {
            native: StdMutex::new(value),
            available: Notify::new(),
        }
    }

    pub(in crate::analysis) fn lock(&self) -> LockResult<MutexGuard<'_, T>> {
        self.result(self.native.lock())
    }

    pub(in crate::analysis) fn try_lock(&self) -> TryLockResult<MutexGuard<'_, T>> {
        self.attempted(self.native.try_lock())
    }

    pub(in crate::analysis) fn until(
        &self,
        control: &AnalysisReadControl,
    ) -> crate::Result<MutexGuard<'_, T>> {
        control.lock(&self.available, || self.try_lock())
    }

    pub(in crate::analysis) fn get_mut(&mut self) -> LockResult<&mut T> {
        self.native.get_mut()
    }
}

impl<T> RwLock<T> {
    pub(in crate::analysis) fn new(value: T) -> Self {
        Self {
            native: StdRwLock::new(value),
            available: Notify::new(),
        }
    }

    pub(in crate::analysis) fn read(&self) -> LockResult<ReadGuard<'_, T>> {
        self.result(self.native.read())
    }

    pub(in crate::analysis) fn write(&self) -> LockResult<WriteGuard<'_, T>> {
        self.result(self.native.write())
    }

    pub(in crate::analysis) fn try_read(&self) -> TryLockResult<ReadGuard<'_, T>> {
        self.attempted(self.native.try_read())
    }

    #[cfg(test)]
    pub(in crate::analysis) fn try_write(&self) -> TryLockResult<WriteGuard<'_, T>> {
        self.attempted(self.native.try_write())
    }

    pub(in crate::analysis) fn read_until(
        &self,
        control: &AnalysisReadControl,
    ) -> crate::Result<ReadGuard<'_, T>> {
        control.lock(&self.available, || self.try_read())
    }
}

struct ThreadWake(std::thread::Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

pub(super) fn wait(deadline: Option<Instant>, mut ready: impl FnMut(&mut Context<'_>) -> bool) {
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    while !ready(&mut context) {
        match deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return;
                }
                std::thread::park_timeout(remaining);
            }
            None => std::thread::park(),
        }
    }
}

#[cfg(test)]
mod tests;
