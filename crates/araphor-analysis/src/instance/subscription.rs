use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use araphor_data::{
    AnalysisReadControl, ManagedExit, ManagedFrontier, ManagedRead, ManagedReceipt, ManagedRequest,
    ManagedResume, ManagedTerminal,
};
use araphor_query::definition::Invocation;
use araphor_query::execution::Engine;
use araphor_query::follow::ManagedPublication;
use datafusion::execution::memory_pool::MemoryReservation;
use erebor_runtime_error::{ErrorExt as _, StatusCode};
use futures_util::{future::BoxFuture, FutureExt as _, Stream};

use super::{sink, Code, Instance};
use crate::Result;

pub struct Subscription {
    query: araphor_query::follow::Subscription,
    owner: Arc<Instance>,
    state: Arc<Mutex<sink::Step>>,
    #[cfg(test)]
    control: Arc<AnalysisReadControl>,
    terminal: Option<ManagedExit>,
    diagnostic: Option<Code>,
    _admission: MemoryReservation,
    delivery: Option<BoxFuture<'static, araphor_query::Result<ManagedReceipt>>>,
}

impl Instance {
    /// The stream owns this operation control. Use one control for each stream.
    pub fn subscribe(
        self: &Arc<Self>,
        control: Arc<AnalysisReadControl>,
        witness_expiry: u64,
        expected_lifecycle: u64,
    ) -> Result<Subscription> {
        self.subscribe_on(control, witness_expiry, expected_lifecycle, None)
    }

    pub(super) fn subscribe_on(
        self: &Arc<Self>,
        control: Arc<AnalysisReadControl>,
        witness_expiry: u64,
        expected_lifecycle: u64,
        retry_after_capacity: Option<u64>,
    ) -> Result<Subscription> {
        if self.admitted.spec.destination == araphor_data::ManagedDestination::Notification {
            return Err(Code::Unsupported
                .error("notification managed subscription")
                .into());
        }
        let grant = &self.admitted.grant;
        let changes = self.authority.changes_for(grant);
        let resume = Self::authorize(self.authority.as_ref(), grant, &self.prepared, || {
            control.check()?;
            let resume = self.query.store().managed_resume(
                self.admitted.spec.tenant,
                &self.admitted.spec.id,
                &control,
            )?;
            let current = &resume.instance;
            if current.spec != self.admitted.spec
                || current.grant != self.admitted.grant
                || current.generation != self.admitted.generation
            {
                return Err(Code::Conflict.error("managed instance generation"));
            }
            if current.lifecycle != expected_lifecycle || !current.running {
                return Err(Code::Conflict.error("managed subscription lifecycle"));
            }
            Ok(resume)
        })?;
        let retry_after_capacity = retry_after_capacity == Some(resume.completed)
            && resume.completed > resume.instance.progress;
        let bytes = resume
            .instance
            .allocation_bytes()
            .ok_or_else(|| Code::Limit.error("managed admission metadata"))?;
        let state = Arc::new(Mutex::new(sink::Step {
            completed: resume.completed,
            admission: Some(ManagedResume {
                instance: resume.instance,
                frontier: None,
                completed: resume.completed,
            }),
            ..Default::default()
        }));
        let opened: Result<Subscription> = (|| {
            let admission = self
                .session
                .memory()
                .reserve_input(bytes)
                .map_err(|source| araphor_query::Error::Sql { source })?;
            let publication = Arc::new(sink::Publication {
                owner: Arc::clone(self),
                schema: Arc::clone(self.prepared.plan.schema().inner()),
                mode: sink::Mode::Managed {
                    operation: Box::new(sink::Operation::Follow {
                        lifecycle: expected_lifecycle,
                    }),
                    state: Arc::clone(&state),
                    witness_expiry,
                },
            });
            let session = self
                .session
                .operation(&control.within(grant.remaining()?)?, 0)?;
            let binding = self
                .admitted
                .spec
                .definition
                .digest()
                .map_err(araphor_data::Error::from)?;
            let owner = Arc::clone(self);
            let query = session
                .subscribe_managed(
                    self.prepared.clone(),
                    publication,
                    binding.as_bytes(),
                    if retry_after_capacity {
                        None
                    } else {
                        resume.frontier
                    },
                )?
                .until_checked(changes, move |read| {
                    read.check()?;
                    Self::check_prepared(
                        owner.authority.as_ref(),
                        &owner.admitted.grant,
                        &owner.prepared,
                    )?;
                    read.check()?;
                    Ok(())
                });
            Ok(Subscription {
                query,
                owner: Arc::clone(self),
                state: Arc::clone(&state),
                #[cfg(test)]
                control: Arc::clone(&control),
                terminal: None,
                diagnostic: None,
                _admission: admission,
                delivery: None,
            })
        })();
        if let Err(error) = &opened {
            if let Some(code) = Subscription::admission(error) {
                let state = state.lock().unwrap_or_else(|error| error.into_inner());
                if let Some(expected) = &state.admission {
                    Subscription::record_admission(self.query.store(), expected, code, || {
                        control.check()
                    })?;
                }
            }
        }
        opened
    }
}

impl Subscription {
    /// The diagnostic control must remain valid after this stream is cancelled.
    pub async fn cancel_and_join(
        mut self,
        diagnostic: &AnalysisReadControl,
    ) -> Result<Option<ManagedTerminal>> {
        let cancelled = self.query.cancel();
        if let Some(delivery) = self.delivery.take() {
            let _delivered = delivery.await;
        }
        let joined = cancelled.and(self.query.cancel_and_join().await);
        let (attempt, admission) = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            (state.attempt.clone(), state.admission.take())
        };
        let Some(attempt) = attempt else {
            joined?;
            if let (Some(expected), Some(code)) = (admission, self.diagnostic) {
                let store = Arc::clone(self.owner.query.store());
                let control = Arc::new(diagnostic.within(None)?);
                let stage = Arc::clone(&control);
                Engine::blocking(control, self._admission, move || {
                    Self::record_admission(&store, &expected, code, || stage.check())
                        .map_err(Into::into)
                })
                .await?;
            }
            return Ok(None);
        };
        let exit = self.terminal.unwrap_or(ManagedExit::Cancelled);
        let owner = Arc::clone(&self.owner);
        let control = Arc::new(diagnostic.within(None)?);
        let stage = Arc::clone(&control);
        let store = Arc::clone(self.owner.query.store());
        let terminal = Engine::blocking(control, (), move || {
            let exit = if exit == ManagedExit::Cancelled
                && owner
                    .check()
                    .is_err_and(|error| error.status_code() == StatusCode::PermissionDenied)
            {
                ManagedExit::Failed(Code::Denied)
            } else {
                exit
            };
            stage.check()?;
            store
                .finish_managed(&attempt, exit, || stage.check())
                .map_err(Into::into)
        })
        .await?;
        joined?;
        Ok(Some(terminal))
    }

    pub(super) fn failed(&mut self, error: &crate::Error) {
        let invalidated = Self::causes(error).any(|source| {
            matches!(
                source.downcast_ref::<araphor_data::Error>(),
                Some(araphor_data::Error::AnalysisSourceChanged { .. })
            )
        });
        self.terminal = Some(if invalidated {
            ManagedExit::Cancelled
        } else {
            Self::failure(error)
        });
        self.diagnostic = if invalidated {
            None
        } else {
            Self::admission(error)
        };
    }

    pub(super) fn admission(error: &crate::Error) -> Option<Code> {
        if matches!(
            error,
            crate::Error::Data {
                source: araphor_data::Error::AnalysisBusy { .. }
            }
        ) || matches!(error, crate::Error::Query { source } if araphor_query::Failure::from(source) == araphor_query::Failure::Busy)
        {
            return None;
        }
        match Self::failure(error) {
            ManagedExit::Failed(code) => Some(code),
            ManagedExit::Cancelled => None,
        }
    }

    pub(super) fn record_admission(
        store: &araphor_data::AnalysisStore,
        expected: &ManagedResume,
        code: Code,
        check: impl FnOnce() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        match store.fail_managed(expected, code, check) {
            Err(araphor_data::Error::AnalysisConflict { .. })
            | Err(araphor_data::Error::AnalysisBusy {
                resource: "managed attempt",
                ..
            }) => Ok(()),
            result => result.map(|_| ()),
        }
    }

    fn causes(error: &crate::Error) -> impl Iterator<Item = &(dyn std::error::Error + 'static)> {
        std::iter::successors(
            Some(error as &(dyn std::error::Error + 'static)),
            |source| {
                let source = *source;
                match source.downcast_ref::<crate::Error>() {
                    Some(crate::Error::Data { source }) => Some(source),
                    Some(crate::Error::Query { source }) => Some(source),
                    _ => match source.downcast_ref::<araphor_query::Error>() {
                        Some(araphor_query::Error::Data { source }) => Some(source),
                        Some(araphor_query::Error::Contract { source }) => Some(source),
                        _ => source.source(),
                    },
                }
            },
        )
    }

    pub(super) fn failure(error: &crate::Error) -> ManagedExit {
        if error.status_code() == StatusCode::Cancelled {
            return ManagedExit::Cancelled;
        }
        for source in Self::causes(error) {
            if matches!(
                source.downcast_ref::<araphor_query::Error>(),
                Some(araphor_query::Error::AuthorityChanged { .. })
            ) {
                return ManagedExit::Cancelled;
            }
            if let Some(araphor_data::Error::Package { code, .. }) =
                source.downcast_ref::<araphor_data::Error>()
            {
                return ManagedExit::Failed(*code);
            }
            if source
                .downcast_ref::<araphor_analysis_sdk::Error>()
                .is_some_and(|error| error.code() == araphor_analysis_sdk::ErrorCode::Limit)
            {
                return ManagedExit::Failed(Code::Limit);
            }
        }
        if matches!(error, crate::Error::Query { source } if matches!(araphor_query::Failure::from(source),
            araphor_query::Failure::InputTooLarge | araphor_query::Failure::ResultTooLarge))
            || matches!(
                error,
                crate::Error::Data {
                    source: araphor_data::Error::AnalysisInputTooLarge { .. }
                }
            )
        {
            return ManagedExit::Failed(Code::Limit);
        }
        ManagedExit::Failed(match error.status_code() {
            StatusCode::PermissionDenied => Code::Denied,
            StatusCode::Unsupported => Code::Unsupported,
            StatusCode::NotFound => Code::Missing,
            StatusCode::Unavailable | StatusCode::DeadlineExceeded => Code::Incomplete,
            StatusCode::AlreadyExists => Code::Conflict,
            _ => Code::Invalid,
        })
    }
}

impl Stream for Subscription {
    type Item = Result<ManagedReceipt>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let result: Result<ManagedReceipt> = if let Some(delivery) = self.delivery.as_mut() {
                let result = match std::future::Future::poll(delivery.as_mut(), context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result.map_err(Into::into),
                };
                self.delivery = None;
                result
            } else {
                let update = match Pin::new(&mut self.query).poll_next(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => return Poll::Ready(None),
                    Poll::Ready(Some(update)) => update,
                };
                let receipt = self
                    .state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .receipt
                    .take();
                if receipt.is_none()
                    && update
                        .as_ref()
                        .is_ok_and(|update| update.snapshot.managed().is_none())
                {
                    continue;
                }
                match (update, receipt) {
                    (Err(error), _) => Err(error.into()),
                    (Ok(_), Some(receipt)) => {
                        let owner = Arc::clone(&self.owner);
                        self.delivery = Some(
                            self.query
                                .blocking(move |control| {
                                    Instance::authorize(
                                        owner.authority.as_ref(),
                                        &owner.admitted.grant,
                                        &owner.prepared,
                                        || {
                                            control.check()?;
                                            Ok(receipt)
                                        },
                                    )
                                    .map_err(Into::into)
                                })
                                .boxed(),
                        );
                        continue;
                    }
                    (Ok(_), None) => {
                        Err(Code::Incomplete.error("managed publication receipt").into())
                    }
                }
            };
            if let Err(error) = &result {
                self.failed(error);
                let _cancelled = self.query.cancel();
            }
            return Poll::Ready(Some(result));
        }
    }
}

impl ManagedPublication for sink::Publication {
    fn begin(
        &self,
        control: &AnalysisReadControl,
    ) -> araphor_query::Result<(Invocation, ManagedRead)> {
        let (state, _, mode) = self.managed()?;
        Instance::authorize_actions_for(
            self.owner.authority.as_ref(),
            &self.owner.admitted.grant,
            &self.owner.prepared,
            &[araphor_data::PackageActionV1::Run],
            mode.caller()
                .map(|(grant, action)| (grant, action, control)),
            || {
                control.check()?;
                let lifecycle = match mode {
                    sink::Operation::Once {
                        current, request, ..
                    } => {
                        let state = state.lock().unwrap_or_else(|error| error.into_inner());
                        if state.attempt.is_some() || state.receipt.is_some() {
                            return Err(Code::Incomplete.error("managed finite step"));
                        }
                        return Ok((
                            Invocation {
                                id: request.id.clone(),
                                seed: request.seed,
                                ..Default::default()
                            },
                            ManagedRead {
                                expected: None,
                                instance: current.clone(),
                                rebuild: request.rebuild,
                                completed: None,
                            },
                        ));
                    }
                    sink::Operation::Follow { lifecycle } => *lifecycle,
                    sink::Operation::Version {
                        expected, rebuild, ..
                    } => {
                        let state = state.lock().unwrap_or_else(|error| error.into_inner());
                        if state.attempt.is_some() || state.receipt.is_some() {
                            return Err(Code::Incomplete.error("managed version step"));
                        }
                        return Ok((
                            Invocation {
                                id: uuid::Uuid::new_v4().to_string(),
                                ..Default::default()
                            },
                            ManagedRead {
                                instance: self.owner.admitted.clone(),
                                expected: Some(expected.clone()),
                                rebuild: *rebuild,
                                completed: None,
                            },
                        ));
                    }
                };
                let spec = &self.owner.admitted.spec;
                let resume =
                    self.owner
                        .query
                        .store()
                        .managed_resume(spec.tenant, &spec.id, control)?;
                let current = resume.instance;
                if current.spec != *spec
                    || current.generation != self.owner.admitted.generation
                    || current.lifecycle != lifecycle
                    || !current.running
                {
                    return Err(Code::Conflict.error("managed instance lifecycle"));
                }
                let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
                if resume.completed != state.completed {
                    return Err(Code::Conflict.error("managed subscription completion"));
                }
                if state.attempt.is_some() || state.receipt.is_some() {
                    return Err(Code::Incomplete.error("managed subscription step"));
                }
                state.admission = Some(ManagedResume {
                    instance: current.clone(),
                    frontier: None,
                    completed: resume.completed,
                });
                let invocation = Invocation {
                    id: uuid::Uuid::new_v4().to_string(),
                    ..Default::default()
                };
                Ok((
                    invocation,
                    ManagedRead {
                        expected: None,
                        instance: current,
                        rebuild: false,
                        completed: Some(resume.completed),
                    },
                ))
            },
        )
        .map_err(Into::into)
    }

    fn admit(
        &self,
        snapshot: &araphor_query::sources::ArrowSnapshot,
        invocation: &Invocation,
        frontier: &ManagedFrontier,
        control: &AnalysisReadControl,
    ) -> araphor_query::Result<()> {
        let (state, witness_expiry, mode) = self.managed()?;
        let captured = snapshot
            .managed()
            .ok_or_else(|| Code::Incomplete.error("managed captured state"))?;
        let request = ManagedRequest {
            id: invocation.id.clone(),
            time_utc_ns: captured.time_utc_ns(),
            seed: invocation.seed,
            rebuild: captured.rebuild(),
            witness_expiry,
            frontier: Some(frontier.clone()),
        };
        if let sink::Operation::Once {
            request: expected, ..
        } = mode
        {
            let mut expected = expected.clone();
            expected.frontier = Some(frontier.clone());
            if request != expected {
                return Err(Code::Invalid
                    .error("managed finite capture identity")
                    .into());
            }
        }
        let attempt = Instance::authorize_actions_for(
            self.owner.authority.as_ref(),
            &self.owner.admitted.grant,
            &self.owner.prepared,
            &[araphor_data::PackageActionV1::Run],
            mode.caller()
                .map(|(grant, action)| (grant, action, control)),
            || {
                self.owner
                    .query
                    .store()
                    .register_managed_attempt(captured, &request, || control.check())
            },
        )?;
        if attempt.receipt().is_some() || attempt.terminal().is_some() {
            return Err(Code::Conflict
                .error("managed subscription attempt completed")
                .into());
        }
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        state.attempt = Some(Arc::new(attempt));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
