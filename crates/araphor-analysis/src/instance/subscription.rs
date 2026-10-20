use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use araphor_data::{
    AnalysisReadControl, ManagedExit, ManagedFrontier, ManagedRead, ManagedReceipt, ManagedRequest,
    ManagedTerminal,
};
use araphor_query::definition::Invocation;
use araphor_query::execution::Engine;
use araphor_query::follow::ManagedPublication;
use erebor_runtime_error::{ErrorExt as _, StatusCode};
use futures_util::Stream;

use super::{sink, Code, Instance};
use crate::Result;

pub struct Subscription {
    query: araphor_query::follow::Subscription,
    owner: Arc<Instance>,
    state: Arc<Mutex<sink::Step>>,
    control: Arc<AnalysisReadControl>,
    terminal: Option<ManagedExit>,
}

impl Instance {
    /// The stream owns this operation control. Use one control for each stream.
    pub fn subscribe(
        self: &Arc<Self>,
        control: Arc<AnalysisReadControl>,
        witness_expiry: u64,
        expected_lifecycle: u64,
    ) -> Result<Subscription> {
        let grant = &self.admitted.spec.grant;
        let changes = self.authority.changes_for(grant);
        let resume = Self::authorize(self.authority.as_ref(), grant, &self.prepared, || {
            control.check()?;
            let resume = self.query.store().managed_resume(
                self.admitted.spec.tenant,
                &self.admitted.spec.id,
                &control,
            )?;
            let current = &resume.instance;
            if current.spec != self.admitted.spec || current.generation != self.admitted.generation
            {
                return Err(Code::Conflict.error("managed instance generation"));
            }
            if current.lifecycle != expected_lifecycle || !current.running {
                return Err(Code::Conflict.error("managed subscription lifecycle"));
            }
            Ok(resume)
        })?;
        let state = Arc::new(Mutex::new(sink::Step {
            completed: resume.completed,
            ..Default::default()
        }));
        let publication = Arc::new(sink::Publication {
            owner: Arc::clone(self),
            schema: Arc::clone(self.prepared.plan.schema().inner()),
            state: Arc::clone(&state),
            witness_expiry,
            lifecycle: Some(expected_lifecycle),
        });
        let session = self.query.session(
            grant.selection.clone(),
            &control.within(grant.remaining()?)?,
            0,
        )?;
        let binding = self
            .admitted
            .spec
            .definition
            .digest()
            .map_err(araphor_data::Error::from)?;
        let query = session
            .subscribe_managed(
                self.prepared.clone(),
                publication,
                binding.as_bytes(),
                resume.frontier,
            )?
            .until_change(changes);
        Ok(Subscription {
            query,
            owner: Arc::clone(self),
            state,
            control,
            terminal: None,
        })
    }
}

impl Subscription {
    /// The diagnostic control must remain valid after this stream is cancelled.
    pub async fn cancel_and_join(
        self,
        diagnostic: &AnalysisReadControl,
    ) -> Result<Option<ManagedTerminal>> {
        let joined = self.query.cancel_and_join().await;
        let attempt = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .attempt
            .clone();
        let Some(attempt) = attempt else {
            joined?;
            return Ok(None);
        };
        let mut exit = self.terminal.unwrap_or(ManagedExit::Cancelled);
        if exit == ManagedExit::Cancelled
            && self
                .owner
                .check()
                .is_err_and(|error| error.status_code() == StatusCode::PermissionDenied)
        {
            exit = ManagedExit::Failed(Code::Denied);
        }
        let control = Arc::new(diagnostic.within(None)?);
        let stage = Arc::clone(&control);
        let store = Arc::clone(self.owner.query.store());
        let terminal = Engine::blocking(control, (), move || {
            stage.check()?;
            store
                .finish_managed(&attempt, exit, || stage.check())
                .map_err(Into::into)
        })
        .await?;
        joined?;
        Ok(Some(terminal))
    }

    fn failure(error: &crate::Error) -> ManagedExit {
        if error.status_code() == StatusCode::Cancelled {
            return ManagedExit::Cancelled;
        }
        let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
        while let Some(source) = current {
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
            current = match source.downcast_ref::<crate::Error>() {
                Some(crate::Error::Data { source }) => Some(source),
                Some(crate::Error::Query { source }) => Some(source),
                _ => match source.downcast_ref::<araphor_query::Error>() {
                    Some(araphor_query::Error::Data { source }) => Some(source),
                    Some(araphor_query::Error::Contract { source }) => Some(source),
                    _ => source.source(),
                },
            };
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
            let result = match receipt {
                Some(receipt) => Instance::authorize(
                    self.owner.authority.as_ref(),
                    &self.owner.admitted.spec.grant,
                    &self.owner.prepared,
                    || {
                        self.control.check()?;
                        Ok(receipt)
                    },
                )
                .map_err(Into::into),
                None => match update {
                    Err(error) => Err(error.into()),
                    Ok(_) => Err(Code::Incomplete.error("managed publication receipt").into()),
                },
            };
            if let Err(error) = &result {
                self.terminal = Some(Self::failure(error));
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
        Instance::authorize(
            self.owner.authority.as_ref(),
            &self.owner.admitted.spec.grant,
            &self.owner.prepared,
            || {
                control.check()?;
                let spec = &self.owner.admitted.spec;
                let resume =
                    self.owner
                        .query
                        .store()
                        .managed_resume(spec.tenant, &spec.id, control)?;
                let current = resume.instance;
                if current.spec != *spec
                    || current.generation != self.owner.admitted.generation
                    || self
                        .lifecycle
                        .is_some_and(|lifecycle| current.lifecycle != lifecycle || !current.running)
                {
                    return Err(Code::Conflict.error("managed instance lifecycle"));
                }
                let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                if resume.completed != state.completed {
                    return Err(Code::Conflict.error("managed subscription completion"));
                }
                if state.attempt.is_some() || state.receipt.is_some() {
                    return Err(Code::Incomplete.error("managed subscription step"));
                }
                let invocation = Invocation {
                    id: uuid::Uuid::new_v4().to_string(),
                    ..Default::default()
                };
                Ok((
                    invocation,
                    ManagedRead {
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
        let captured = snapshot
            .managed()
            .ok_or_else(|| Code::Incomplete.error("managed captured state"))?;
        let request = ManagedRequest {
            id: invocation.id.clone(),
            time_utc_ns: captured.time_utc_ns(),
            seed: invocation.seed,
            rebuild: captured.rebuild(),
            witness_expiry: self.witness_expiry,
            frontier: Some(frontier.clone()),
        };
        let attempt = Instance::authorize(
            self.owner.authority.as_ref(),
            &self.owner.admitted.spec.grant,
            &self.owner.prepared,
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
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .attempt = Some(Arc::new(attempt));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
