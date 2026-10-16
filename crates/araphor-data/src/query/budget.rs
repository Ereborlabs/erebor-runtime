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

#[derive(Clone)]
pub(crate) struct QueryLease {
    charge: Arc<LeaseCharge>,
}

struct LeaseCharge {
    budget: Arc<QueryBudget>,
    tenant: [u8; 16],
    state: Mutex<LeaseState>,
}

struct LeaseState {
    kind: LeaseKind,
    bytes: usize,
    input_bytes: usize,
}

#[path = "budget/buffers.rs"]
mod buffers;

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

    pub(super) fn model(self: &Arc<Self>, tenant: [u8; 16], bytes: usize) -> Result<QueryLease> {
        self.reserve(
            tenant,
            LeaseKind::Evaluation,
            bytes,
            self.limits.input_bytes,
        )
    }

    pub(super) fn component(
        self: &Arc<Self>,
        tenant: [u8; 16],
        bytes: usize,
        input_bytes: usize,
    ) -> Result<QueryLease> {
        self.reserve(tenant, LeaseKind::Evaluation, bytes, input_bytes)
    }

    pub(super) fn retained_input(self: &Arc<Self>, bytes: usize) -> Result<QueryLease> {
        self.reserve([0; 16], LeaseKind::Output, 0, bytes)
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
            charge: Arc::new(LeaseCharge {
                budget: self.clone(),
                tenant,
                state: Mutex::new(LeaseState {
                    kind,
                    bytes,
                    input_bytes,
                }),
            }),
        })
    }
}

impl QueryLease {
    #[cfg(test)]
    pub(in crate::query) fn test_reference(
        &self,
    ) -> std::sync::Weak<dyn std::any::Any + Send + Sync> {
        let charge: Arc<dyn std::any::Any + Send + Sync> = self.charge.clone();
        Arc::downgrade(&charge)
    }

    #[cfg(test)]
    pub(in crate::query) fn test_input_active(
        reference: &std::sync::Weak<dyn std::any::Any + Send + Sync>,
    ) -> bool {
        reference
            .upgrade()
            .and_then(|charge| charge.downcast::<LeaseCharge>().ok())
            .is_some_and(|charge| {
                let state = charge
                    .state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                matches!(state.kind, LeaseKind::Evaluation) || state.input_bytes != 0
            })
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, LeaseState>> {
        self.charge.state.lock().map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "query lease lock",
            }
            .build()
        })
    }

    pub(crate) fn grow_input(&mut self, bytes: usize) -> Result<()> {
        let mut state = self.state()?;
        if matches!(state.kind, LeaseKind::Stream) {
            return crate::QueryLimitSnafu {
                resource: "query input bytes",
                limit: state.input_bytes,
            }
            .fail();
        }
        let mut usage = self.charge.budget.usage.lock().map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "query budget lock",
            }
            .build()
        })?;
        let total = usage
            .input_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.charge.budget.limits.input_capacity)
            .ok_or_else(|| {
                crate::AnalysisBusySnafu {
                    resource: "query input capacity",
                }
                .build()
            })?;
        usage.input_bytes = total;
        state.input_bytes += bytes;
        Ok(())
    }

    pub(super) fn reserve_output(&mut self, bytes: usize) -> Result<()> {
        let mut state = self.state()?;
        if !matches!(state.kind, LeaseKind::Evaluation) || state.bytes != 0 {
            return crate::QueryInvalidSnafu {
                field: "model output reservation",
            }
            .fail();
        }
        let mut usage = self.charge.budget.usage.lock().map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "query budget lock",
            }
            .build()
        })?;
        usage.output_bytes = usage
            .output_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.charge.budget.limits.output_capacity)
            .ok_or_else(|| {
                crate::AnalysisBusySnafu {
                    resource: "query output capacity",
                }
                .build()
            })?;
        state.bytes = bytes;
        Ok(())
    }

    pub(super) fn shrink_input(&mut self, bytes: usize) -> Result<()> {
        let mut state = self.state()?;
        if matches!(state.kind, LeaseKind::Stream) || bytes > state.input_bytes {
            return crate::QueryLimitSnafu {
                resource: "query input bytes",
                limit: state.input_bytes,
            }
            .fail();
        }
        let mut usage = self
            .charge
            .budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        usage.input_bytes -= state.input_bytes - bytes;
        state.input_bytes = bytes;
        drop(usage);
        drop(state);
        self.charge.budget.changed.notify_waiters();
        Ok(())
    }

    /// Transfer bytes to a separate output guard. The total charge does not change.
    pub(super) fn split(&mut self, bytes: usize) -> Result<Self> {
        let mut state = self.state()?;
        if matches!(state.kind, LeaseKind::Stream) || bytes > state.bytes {
            return crate::QueryLimitSnafu {
                resource: "query output bytes",
                limit: state.bytes,
            }
            .fail();
        }
        state.bytes -= bytes;
        Ok(Self {
            charge: Arc::new(LeaseCharge {
                budget: self.charge.budget.clone(),
                tenant: self.charge.tenant,
                state: Mutex::new(LeaseState {
                    kind: LeaseKind::Output,
                    bytes,
                    input_bytes: 0,
                }),
            }),
        })
    }

    /// Release input and evaluation capacity. Keep output capacity until drop.
    pub(super) fn output(self, bytes: usize) -> Result<Self> {
        self.finish_output(bytes, false)
    }

    pub(super) fn retained_output(self, bytes: usize) -> Result<Self> {
        self.finish_output(bytes, true)
    }

    fn finish_output(self, bytes: usize, retain_input: bool) -> Result<Self> {
        let mut state = self.state()?;
        if matches!(state.kind, LeaseKind::Stream) || bytes > state.bytes {
            return crate::QueryLimitSnafu {
                resource: "query output bytes",
                limit: state.bytes,
            }
            .fail();
        }
        let mut usage = self
            .charge
            .budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let LeaseKind::Evaluation = state.kind {
            usage.evaluations -= 1;
            if let Some(tenant) = usage.tenants.get_mut(&self.charge.tenant) {
                tenant.0 -= 1;
                if *tenant == (0, 0) {
                    usage.tenants.remove(&self.charge.tenant);
                }
            }
            state.kind = LeaseKind::Output;
            if !retain_input {
                usage.input_bytes -= state.input_bytes;
                state.input_bytes = 0;
            }
        }
        usage.output_bytes -= state.bytes - bytes;
        state.bytes = bytes;
        drop(usage);
        drop(state);
        self.charge.budget.changed.notify_waiters();
        Ok(self)
    }

    #[cfg(test)]
    fn input_bytes(&self) -> usize {
        self.charge
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .input_bytes
    }
}

impl Drop for LeaseCharge {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        let mut usage = self
            .budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match state.kind {
            LeaseKind::Evaluation => usage.evaluations -= 1,
            LeaseKind::Stream => usage.streams -= 1,
            LeaseKind::Output => {}
        }
        usage.output_bytes -= state.bytes;
        usage.input_bytes -= state.input_bytes;
        if let Some(tenant) = usage.tenants.get_mut(&self.tenant) {
            match state.kind {
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
impl super::QueryOwner {
    pub(crate) fn input_charge(&self) -> usize {
        self.budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .input_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_evaluation_charge_drops_with_last_clone() -> Result<()> {
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: 10,
            input_capacity: 10,
            global_evaluations: 1,
            ..Default::default()
        });
        let lease = budget.component([1; 16], 0, 10)?;
        let shared = lease.clone();
        drop(lease);
        assert!(matches!(
            budget.component([2; 16], 0, 0),
            Err(crate::Error::AnalysisBusy {
                resource: "query evaluation capacity",
                ..
            }),
        ));
        assert!(budget.retained_input(1).is_err());
        drop(shared);
        drop(budget.component([2; 16], 0, 10)?);
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
    fn shared_charge_mutations_and_output_transition() -> Result<()> {
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: 10,
            input_capacity: 10,
            output_bytes: 10,
            output_capacity: 20,
            ..Default::default()
        });
        let mut lease = budget.component([1; 16], 0, 6)?;
        let mut shared = lease.clone();
        lease.grow_input(4)?;
        assert_eq!(shared.input_bytes(), 10);
        shared.shrink_input(8)?;
        assert_eq!(lease.input_bytes(), 8);
        lease.reserve_output(10)?;
        assert!(shared.reserve_output(1).is_err());
        let split = shared.split(3)?;
        assert_eq!(lease.state()?.bytes, 7);
        let output = shared.retained_output(4)?;
        assert!(lease.clone().output(5).is_err());
        {
            let usage = budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            assert_eq!(
                (usage.evaluations, usage.input_bytes, usage.output_bytes),
                (0, 8, 7)
            );
            assert!(usage.tenants.is_empty());
        }
        drop(output);
        assert_eq!(lease.input_bytes(), 8);
        drop(lease);
        let usage = budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!((usage.input_bytes, usage.output_bytes), (0, 3));
        drop(usage);
        drop(split);
        assert_eq!(
            budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .output_bytes,
            0
        );
        Ok(())
    }

    #[test]
    fn separate_scalar_output_does_not_retain_input() -> Result<()> {
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: 10,
            input_capacity: 10,
            output_bytes: 10,
            output_capacity: 10,
            ..Default::default()
        });
        let mut lease = budget.evaluate([1; 16])?;
        let output = lease.split(3)?;
        drop(lease.retained_output(0)?);
        {
            let usage = budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            assert_eq!(
                (usage.evaluations, usage.input_bytes, usage.output_bytes),
                (0, 0, 3)
            );
        }
        let shared = output.clone();
        drop(output);
        assert_eq!(
            budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .output_bytes,
            3
        );
        drop(shared);
        assert_eq!(
            budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .output_bytes,
            0
        );
        Ok(())
    }

    #[test]
    fn retained_input_growth() -> Result<()> {
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: 1,
            input_capacity: 10,
            ..Default::default()
        });
        let mut retained = budget.retained_input(3)?;
        let other = budget.retained_input(2)?;
        retained.grow_input(5)?;
        for bytes in [1, usize::MAX] {
            assert!(matches!(
                retained.grow_input(bytes),
                Err(crate::Error::AnalysisBusy {
                    resource: "query input capacity",
                    ..
                })
            ));
            assert_eq!(retained.input_bytes(), 8);
            assert_eq!(
                budget
                    .usage
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .input_bytes,
                10
            );
        }
        let mut stream = budget.stream([1; 16])?;
        assert!(matches!(
            stream.grow_input(1),
            Err(crate::Error::QueryLimit {
                resource: "query input bytes",
                ..
            })
        ));
        drop(stream);
        drop(other);
        retained.grow_input(2)?;
        drop(retained);
        drop(budget.retained_input(10)?);
        assert_eq!(
            budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .input_bytes,
            0
        );
        Ok(())
    }

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

    #[test]
    fn analysis_retains_input_charge() -> Result<()> {
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: 10,
            input_capacity: 10,
            output_bytes: 10,
            output_capacity: 20,
            ..Default::default()
        });
        let retained = budget.evaluate([1; 16])?.retained_output(3)?;
        assert!(budget.evaluate([2; 16]).is_err());
        drop(retained);
        drop(budget.evaluate([2; 16])?);
        let usage = budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            (usage.evaluations, usage.input_bytes, usage.output_bytes),
            (0, 0, 0)
        );
        Ok(())
    }

    #[test]
    fn retained_input_keeps_slots() -> Result<()> {
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: 10,
            input_capacity: 20,
            output_bytes: 10,
            output_capacity: 20,
            ..Default::default()
        });
        let retained = Arc::new(budget.retained_input(7)?);
        let shared = retained.clone();
        let first = budget.component([1; 16], 10, 6)?;
        let second = budget.component([2; 16], 10, 7)?;
        let stream = budget.stream([1; 16])?;
        assert!(matches!(
            budget.retained_input(1),
            Err(crate::Error::AnalysisBusy {
                resource: "query input capacity",
                ..
            })
        ));
        drop(first);
        drop(second);
        drop(stream);
        drop(retained);
        assert!(budget.retained_input(14).is_err());
        drop(shared);
        drop(budget.retained_input(20)?);
        let usage = budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            (
                usage.evaluations,
                usage.streams,
                usage.input_bytes,
                usage.output_bytes
            ),
            (0, 0, 0, 0)
        );
        assert!(usage.tenants.is_empty());
        Ok(())
    }

    #[test]
    fn component_charge_shrinks() -> Result<()> {
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: 10,
            input_capacity: 12,
            output_bytes: 10,
            output_capacity: 20,
            ..Default::default()
        });
        let source = budget.retained_input(2)?;
        let mut component = budget.component([1; 16], 10, 6)?;
        component.shrink_input(3)?;
        let rest = budget.retained_input(7)?;
        assert!(component.shrink_input(4).is_err());
        assert!(budget.retained_input(1).is_err());
        let output = component.retained_output(4)?;
        drop(rest);
        let next = budget.component([1; 16], 10, 7)?;
        assert!(budget.retained_input(1).is_err());
        drop(next);
        drop(output);
        drop(source);
        drop(budget.retained_input(12)?);
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
    fn component_reservation_rejects_growth() -> Result<()> {
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: 10,
            input_capacity: 12,
            output_bytes: 10,
            output_capacity: 20,
            ..Default::default()
        });
        assert!(budget.component([1; 16], 10, 13).is_err());
        assert!(budget.component([1; 16], 21, 1).is_err());
        let mut stream = budget.stream([1; 16])?;
        assert!(stream.shrink_input(0).is_err());
        drop(stream);
        let component = budget.component([1; 16], 10, 12)?;
        assert!(component.retained_output(11).is_err());
        drop(budget.retained_input(12)?);
        let usage = budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            (
                usage.evaluations,
                usage.streams,
                usage.input_bytes,
                usage.output_bytes
            ),
            (0, 0, 0, 0)
        );
        assert!(usage.tenants.is_empty());
        Ok(())
    }
}
