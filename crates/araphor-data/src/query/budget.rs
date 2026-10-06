use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use super::QueryLimits;
use crate::Result;

#[derive(Default)]
struct Usage {
    evaluations: usize,
    streams: usize,
    output_bytes: usize,
    input_bytes: usize,
    tenants: BTreeMap<[u8; 16], (usize, usize)>,
}

pub(super) struct QueryBudget {
    limits: QueryLimits,
    usage: Mutex<Usage>,
    changed: Notify,
    #[cfg(test)]
    pub(super) wait_signal: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

#[derive(Clone, Copy)]
enum LeaseKind {
    Evaluation,
    Stream,
    Output,
}

pub(super) struct QueryLease {
    budget: Arc<QueryBudget>,
    tenant: [u8; 16],
    kind: LeaseKind,
    bytes: usize,
    input_bytes: usize,
}

impl QueryBudget {
    pub(super) fn new(limits: QueryLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            usage: Mutex::new(Usage::default()),
            changed: Notify::new(),
            #[cfg(test)]
            wait_signal: Mutex::new(None),
        })
    }

    pub(super) fn evaluate(self: &Arc<Self>, tenant: [u8; 16]) -> Result<QueryLease> {
        self.reserve(
            tenant,
            LeaseKind::Evaluation,
            self.limits.output_bytes,
            self.limits.input_bytes,
        )
    }

    pub(super) async fn wait(self: &Arc<Self>, tenant: [u8; 16]) -> Result<QueryLease> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match self.evaluate(tenant) {
                Ok(lease) => return Ok(lease),
                Err(crate::Error::AnalysisBusy { .. }) => {}
                Err(error) => return Err(error),
            }
            #[cfg(test)]
            if let Some(signal) = self
                .wait_signal
                .lock()
                .map_err(|_| {
                    crate::QueryInvalidSnafu {
                        field: "test budget wait signal",
                    }
                    .build()
                })?
                .take()
            {
                let _sent = signal.send(());
            }
            changed.await;
        }
    }

    pub(super) fn stream(self: &Arc<Self>, tenant: [u8; 16]) -> Result<QueryLease> {
        self.reserve(tenant, LeaseKind::Stream, 0, 0)
    }

    pub(super) fn output(self: &Arc<Self>, bytes: usize) -> Result<QueryLease> {
        self.reserve([0; 16], LeaseKind::Output, bytes, 0)
    }

    fn reserve(
        self: &Arc<Self>,
        tenant: [u8; 16],
        kind: LeaseKind,
        bytes: usize,
        input_bytes: usize,
    ) -> Result<QueryLease> {
        let mut usage = self.usage.lock().map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "query budget lock",
            }
            .build()
        })?;
        let output_bytes = usage
            .output_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.limits.output_capacity)
            .ok_or_else(|| {
                crate::AnalysisBusySnafu {
                    resource: "query output capacity",
                }
                .build()
            })?;
        let (evaluations, streams) = usage.tenants.get(&tenant).copied().unwrap_or_default();
        let total_input = usage
            .input_bytes
            .checked_add(input_bytes)
            .filter(|total| *total <= self.limits.input_capacity)
            .ok_or_else(|| {
                crate::AnalysisBusySnafu {
                    resource: "query input capacity",
                }
                .build()
            })?;
        match kind {
            LeaseKind::Evaluation => {
                if usage.evaluations >= self.limits.global_evaluations
                    || evaluations >= self.limits.tenant_evaluations
                {
                    return crate::AnalysisBusySnafu {
                        resource: "query evaluation capacity",
                    }
                    .fail();
                }
                usage.evaluations += 1;
                usage.tenants.entry(tenant).or_default().0 += 1;
            }
            LeaseKind::Stream => {
                if usage.streams >= self.limits.global_streams
                    || streams >= self.limits.tenant_streams
                {
                    return crate::AnalysisBusySnafu {
                        resource: "query stream capacity",
                    }
                    .fail();
                }
                usage.streams += 1;
                usage.tenants.entry(tenant).or_default().1 += 1;
            }
            LeaseKind::Output => {}
        }
        usage.output_bytes = output_bytes;
        usage.input_bytes = total_input;
        Ok(QueryLease {
            budget: self.clone(),
            tenant,
            kind,
            bytes,
            input_bytes,
        })
    }
}

impl QueryLease {
    /// Transfer bytes to a separate output guard. The total charge does not change.
    pub(super) fn split(&mut self, bytes: usize) -> Result<Self> {
        if matches!(self.kind, LeaseKind::Stream) || bytes > self.bytes {
            return crate::QueryLimitSnafu {
                resource: "query output bytes",
                limit: self.bytes,
            }
            .fail();
        }
        self.bytes -= bytes;
        Ok(Self {
            budget: self.budget.clone(),
            tenant: self.tenant,
            kind: LeaseKind::Output,
            bytes,
            input_bytes: 0,
        })
    }

    /// Release input and evaluation capacity. Keep output capacity until drop.
    pub(super) fn output(mut self, bytes: usize) -> Result<Self> {
        if matches!(self.kind, LeaseKind::Stream) || bytes > self.bytes {
            return crate::QueryLimitSnafu {
                resource: "query output bytes",
                limit: self.bytes,
            }
            .fail();
        }
        let mut usage = self
            .budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let LeaseKind::Evaluation = self.kind {
            usage.evaluations -= 1;
            if let Some(tenant) = usage.tenants.get_mut(&self.tenant) {
                tenant.0 -= 1;
                if *tenant == (0, 0) {
                    usage.tenants.remove(&self.tenant);
                }
            }
            self.kind = LeaseKind::Output;
            usage.input_bytes -= self.input_bytes;
            self.input_bytes = 0;
        }
        usage.output_bytes -= self.bytes - bytes;
        self.bytes = bytes;
        drop(usage);
        self.budget.changed.notify_waiters();
        Ok(self)
    }
}

impl Drop for QueryLease {
    fn drop(&mut self) {
        let mut usage = self
            .budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match self.kind {
            LeaseKind::Evaluation => {
                usage.evaluations -= 1;
            }
            LeaseKind::Stream => usage.streams -= 1,
            LeaseKind::Output => {}
        }
        usage.output_bytes -= self.bytes;
        usage.input_bytes -= self.input_bytes;
        if let Some(tenant) = usage.tenants.get_mut(&self.tenant) {
            match self.kind {
                LeaseKind::Evaluation => tenant.0 -= 1,
                LeaseKind::Stream => tenant.1 -= 1,
                LeaseKind::Output => {}
            }
            if *tenant == (0, 0) {
                usage.tenants.remove(&self.tenant);
            }
        }
        drop(usage);
        self.budget.changed.notify_waiters();
    }
}

impl std::fmt::Debug for QueryLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QueryLease")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn query_scope_wakeup() -> Result<()> {
        use futures_util::FutureExt as _;
        for output in [true, false] {
            let budget = QueryBudget::new(QueryLimits::default());
            let held = budget.evaluate([1; 16])?;
            let waiting = budget.wait([1; 16]);
            tokio::pin!(waiting);
            assert!(waiting.as_mut().now_or_never().is_none());
            let retained = if output {
                Some(held.output(1)?)
            } else {
                drop(held);
                None
            };
            let lease = tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
                .await
                .map_err(|_| {
                    crate::QueryInvalidSnafu {
                        field: "test budget wait timeout",
                    }
                    .build()
                })??;
            drop(lease);
            drop(retained);
        }
        Ok(())
    }

    #[test]
    fn query_client_capacity() -> Result<()> {
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: 10,
            input_capacity: 30,
            output_bytes: 10,
            output_capacity: 30,
            global_evaluations: 4,
            ..Default::default()
        });
        let first = budget.evaluate([1; 16])?;
        let second = budget.evaluate([2; 16])?;
        let third = budget.evaluate([3; 16])?;
        assert!(budget.evaluate([4; 16]).is_err());
        drop(second);
        drop(third);
        let output = first.output(10)?;
        let next = budget.evaluate([2; 16])?;
        assert!(budget.output(11).is_err());
        drop(next);
        drop(output);
        let usage = budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            (usage.evaluations, usage.input_bytes, usage.output_bytes),
            (0, 0, 0)
        );
        assert!(usage.tenants.is_empty());
        Ok(())
    }

    #[test]
    fn query_scope_capacity() -> Result<()> {
        let limits = QueryLimits {
            input_bytes: 10,
            output_bytes: 10,
            input_capacity: 20,
            output_capacity: 20,
            global_streams: 2,
            tenant_streams: 1,
            ..QueryLimits::default()
        };
        let budget = QueryBudget::new(limits);
        let first = budget.evaluate([1; 16])?;
        assert!(budget.evaluate([1; 16]).is_err());
        let second = budget.evaluate([2; 16])?;
        assert!(budget.evaluate([3; 16]).is_err());
        let output = first.output(10)?;
        assert!(budget.evaluate([1; 16]).is_err());
        drop(output);
        drop(budget.evaluate([1; 16])?);
        drop(second);
        let first = budget.stream([1; 16])?;
        assert!(budget.stream([1; 16]).is_err());
        let second = budget.stream([2; 16])?;
        assert!(budget.stream([3; 16]).is_err());
        drop(first);
        drop(budget.stream([1; 16])?);
        drop(second);
        let usage = budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            (usage.evaluations, usage.streams, usage.output_bytes),
            (0, 0, 0)
        );
        assert!(usage.tenants.is_empty());
        Ok(())
    }

    #[test]
    fn query_scope_output_split() -> Result<()> {
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: 10,
            output_bytes: 10,
            input_capacity: 20,
            output_capacity: 20,
            ..Default::default()
        });
        let mut evaluation = budget.evaluate([1; 16])?;
        let summary = Arc::new(evaluation.split(3)?);
        assert!(evaluation.split(8).is_err());
        let rows = evaluation.output(4)?;
        let retained = summary.clone();
        drop(summary);
        let rest = budget.output(13)?;
        assert!(budget.output(1).is_err());
        drop(rows);
        drop(budget.output(4)?);
        drop(rest);
        drop(retained);
        {
            let usage = budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            assert_eq!((usage.evaluations, usage.output_bytes), (0, 0));
            assert!(usage.tenants.is_empty());
        }

        let mut evaluation = budget.evaluate([1; 16])?;
        let summary = evaluation.split(3)?;
        assert!(evaluation.output(8).is_err());
        drop(budget.output(17)?);
        assert!(budget.output(usize::MAX).is_err());
        drop(summary);
        let stream = budget.stream([1; 16])?;
        assert!(stream.output(0).is_err());
        let usage = budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            (usage.evaluations, usage.streams, usage.output_bytes),
            (0, 0, 0)
        );
        assert!(usage.tenants.is_empty());
        Ok(())
    }

    #[test]
    fn query_scope_idle_output() -> Result<()> {
        let budget = QueryBudget::new(QueryLimits {
            output_bytes: 100,
            output_capacity: 1600,
            ..Default::default()
        });
        let mut summaries = Vec::new();
        for _ in 0..16 {
            let mut evaluation = budget.evaluate([1; 16])?;
            summaries.push(Arc::new(evaluation.split(1)?));
            drop(evaluation.output(0)?);
        }
        drop(budget.evaluate([1; 16])?);
        {
            let usage = budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            assert_eq!((usage.evaluations, usage.output_bytes), (0, 16));
        }
        drop(summaries);
        let usage = budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(usage.output_bytes, 0);
        Ok(())
    }
}
