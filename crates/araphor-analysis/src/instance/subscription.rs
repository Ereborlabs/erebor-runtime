use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use araphor_data::{
    AnalysisReadControl, ManagedFrontier, ManagedRead, ManagedReceipt, ManagedRequest,
};
use araphor_query::definition::Invocation;
use araphor_query::follow::ManagedPublication;
use futures_util::Stream;

use super::{sink, Code, Instance};
use crate::Result;

pub struct Subscription {
    query: araphor_query::follow::Subscription,
    owner: Arc<Instance>,
    state: Arc<Mutex<sink::Step>>,
    control: Arc<AnalysisReadControl>,
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
        let (progress, resume) =
            Self::authorize(self.authority.as_ref(), grant, &self.images, || {
                control.check()?;
                let (current, resume) = self.query.store().managed_resume(
                    self.admitted.spec.tenant,
                    &self.admitted.spec.id,
                    &control,
                )?;
                if current.spec != self.admitted.spec
                    || current.generation != self.admitted.generation
                {
                    return Err(Code::Conflict.error("managed instance generation"));
                }
                if current.lifecycle != expected_lifecycle || !current.running {
                    return Err(Code::Conflict.error("managed subscription lifecycle"));
                }
                Ok((current.progress, resume))
            })?;
        let state = Arc::new(Mutex::new(sink::Step {
            progress,
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
                resume,
            )?
            .until_change(changes);
        Ok(Subscription {
            query,
            owner: Arc::clone(self),
            state,
            control,
        })
    }
}

impl Subscription {
    pub async fn cancel_and_join(self) -> Result<()> {
        self.query.cancel_and_join().await.map_err(Into::into)
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
                    &self.owner.images,
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
            if result.is_err() {
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
            &self.owner.images,
            || {
                control.check()?;
                let spec = &self.owner.admitted.spec;
                let (current, _) =
                    self.owner
                        .query
                        .store()
                        .managed_resume(spec.tenant, &spec.id, control)?;
                if current.spec != *spec
                    || current.generation != self.owner.admitted.generation
                    || self
                        .lifecycle
                        .is_some_and(|lifecycle| current.lifecycle != lifecycle || !current.running)
                {
                    return Err(Code::Conflict.error("managed instance lifecycle"));
                }
                let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                if current.progress != state.progress {
                    return Err(Code::Conflict.error("managed subscription progress"));
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
            &self.owner.images,
            || {
                self.owner
                    .query
                    .store()
                    .register_managed_attempt(captured, &request, || control.check())
            },
        )?;
        if attempt.receipt().is_some() {
            return Err(Code::Conflict
                .error("managed subscription attempt completed")
                .into());
        }
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .attempt = Some(attempt);
        Ok(())
    }
}
