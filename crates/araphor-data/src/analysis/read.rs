use std::future::Future as _;
#[cfg(any(test, feature = "test-fixtures"))]
use std::sync::Arc;
#[cfg(any(test, feature = "test-fixtures"))]
use std::sync::Mutex;
use std::sync::{TryLockError, TryLockResult};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use crate::Result;

mod lease;
pub(super) mod locks;
pub(in crate::analysis) use lease::AnalysisLease;

#[cfg(any(test, feature = "test-fixtures"))]
type ReadStep = Box<dyn FnOnce() -> Result<()> + Send>;

/// Shared cancellation and an optional read deadline. The default has no deadline.
pub struct AnalysisReadControl {
    deadline: Option<Instant>,
    cancelled: CancellationToken,
    #[cfg(any(test, feature = "test-fixtures"))]
    read_step: Arc<Mutex<Option<ReadStep>>>,
    #[cfg(test)]
    pub(super) snapshot_step: Arc<Mutex<Option<ReadStep>>>,
    #[cfg(test)]
    pub(super) wait_signal: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

impl Default for AnalysisReadControl {
    fn default() -> Self {
        Self::at(None, CancellationToken::new())
    }
}

impl AnalysisReadControl {
    fn at(deadline: Option<Instant>, cancelled: CancellationToken) -> Self {
        Self {
            deadline,
            cancelled,
            #[cfg(any(test, feature = "test-fixtures"))]
            read_step: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            snapshot_step: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            wait_signal: Mutex::new(None),
        }
    }

    fn timeout_deadline(timeout: Duration) -> Result<Instant> {
        Instant::now()
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or_else(|| {
                crate::AnalysisStateSnafu {
                    path: std::path::Path::new("<analysis-read>"),
                    reason: "the read timeout is zero or exceeds the clock range",
                }
                .build()
            })
    }

    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        Ok(Self::at(
            Some(Self::timeout_deadline(timeout)?),
            CancellationToken::new(),
        ))
    }

    fn child(&self, deadline: Option<Instant>) -> Self {
        Self {
            deadline,
            cancelled: self.cancelled.clone(),
            #[cfg(any(test, feature = "test-fixtures"))]
            read_step: Arc::clone(&self.read_step),
            #[cfg(test)]
            snapshot_step: Arc::clone(&self.snapshot_step),
            #[cfg(test)]
            wait_signal: Mutex::new(None),
        }
    }

    pub fn stage(&self, timeout: Option<Duration>) -> Result<Self> {
        Ok(self.child(timeout.map(Self::timeout_deadline).transpose()?))
    }

    pub fn within(&self, timeout: impl Into<Option<Duration>>) -> Result<Self> {
        self.check()?;
        let deadline = match timeout.into() {
            Some(timeout) => {
                let deadline = Self::timeout_deadline(timeout)?;
                Some(
                    self.deadline
                        .map_or(deadline, |parent| parent.min(deadline)),
                )
            }
            None => self.deadline,
        };
        Ok(self.child(deadline))
    }

    /// Inherit parent cancellation.
    pub fn operation(&self) -> Result<Self> {
        self.check()?;
        Ok(Self {
            #[cfg(any(test, feature = "test-fixtures"))]
            read_step: Arc::clone(&self.read_step),
            #[cfg(test)]
            snapshot_step: Arc::clone(&self.snapshot_step),
            ..Self::at(self.deadline, self.cancelled.child_token())
        })
    }

    pub fn cancel(&self) -> Result<()> {
        self.cancelled.cancel();
        Ok(())
    }

    pub async fn cancelled(&self) {
        self.cancelled.cancelled().await;
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn on_read_step(&self, hook: impl FnOnce() -> Result<()> + Send + 'static) -> Result<()> {
        *self.read_step.lock().map_err(|_| Self::lock_error())? = Some(Box::new(hook));
        Ok(())
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub(super) fn test_read_step(&self) -> Result<()> {
        let hook = self
            .read_step
            .lock()
            .map_err(|_| Self::lock_error())?
            .take();
        if let Some(hook) = hook {
            hook()?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn test_snapshot(&self) -> Result<()> {
        let hook = self
            .snapshot_step
            .lock()
            .map_err(|_| Self::lock_error())?
            .take();
        if let Some(hook) = hook {
            hook()?;
        }
        Ok(())
    }

    #[track_caller]
    pub fn check(&self) -> Result<()> {
        if self.cancelled.is_cancelled() {
            return crate::AnalysisReadCancelledSnafu.fail();
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return crate::AnalysisReadDeadlineSnafu.fail();
        }
        Ok(())
    }

    pub fn remaining(&self) -> Result<Option<Duration>> {
        self.check()?;
        Ok(self
            .deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now())))
    }

    pub async fn expired(&self) {
        match self.deadline {
            Some(deadline) => {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await
            }
            None => std::future::pending().await,
        }
    }

    fn lock<T>(
        &self,
        available: &tokio::sync::Notify,
        mut acquire: impl FnMut() -> TryLockResult<T>,
    ) -> Result<T> {
        loop {
            let available = available.notified();
            tokio::pin!(available);
            let _registered = available.as_mut().enable();
            let cancelled = self.cancelled.cancelled();
            tokio::pin!(cancelled);
            self.check()?;
            match acquire() {
                Ok(guard) => {
                    self.check()?;
                    return Ok(guard);
                }
                Err(TryLockError::WouldBlock) => {
                    #[cfg(test)]
                    if let Some(signal) = self
                        .wait_signal
                        .lock()
                        .map_err(|_| Self::lock_error())?
                        .take()
                    {
                        let _sent = signal.send(());
                    }
                    locks::wait(self.deadline, |context| {
                        available.as_mut().poll(context).is_ready()
                            || cancelled.as_mut().poll(context).is_ready()
                    });
                }
                Err(TryLockError::Poisoned(_)) => return Err(Self::lock_error()),
            }
        }
    }

    fn lock_error() -> crate::Error {
        crate::AnalysisStateSnafu {
            path: std::path::Path::new("<analysis-read>"),
            reason: "the read lock is poisoned",
        }
        .build()
    }

    pub async fn query_async<T, E: From<crate::Error>>(
        &self,
        query: impl std::future::Future<Output = std::result::Result<T, E>>,
    ) -> std::result::Result<T, E> {
        let cancelled = self.cancelled.cancelled();
        tokio::pin!(cancelled);
        self.check()?;
        let result = tokio::select! {
            biased;
            _ = &mut cancelled => Err(crate::AnalysisReadCancelledSnafu.build().into()),
            _ = self.expired() => {
                Err(crate::AnalysisReadDeadlineSnafu.build().into())
            }
            result = query => result,
        };
        self.check()?;
        result
    }
}

#[cfg(test)]
mod tests;
