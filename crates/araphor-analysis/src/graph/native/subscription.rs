use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use araphor_query::follow::Subscription;
use futures_util::{future::BoxFuture, FutureExt as _, Stream};

use super::{sink, GraphPublication};
use crate::Result;

pub struct GraphSubscription {
    query: Subscription,
    owner: Arc<GraphPublication>,
    receipt: Arc<Mutex<Option<sink::Receipt>>>,
    delivery: Option<BoxFuture<'static, araphor_query::Result<sink::Receipt>>>,
}

impl GraphPublication {
    /// The stream owns the session control. Use one control for each stream.
    pub async fn subscribe(self, binding: &[u8]) -> Result<GraphSubscription> {
        let definition = self.prepared.clone();
        self.open_subscription(
            definition,
            sink::Kind::Publish(true),
            binding,
            Arc::new(araphor_query::follow::SystemClock::default()),
        )
        .await
    }

    pub async fn subscribe_expiry(self, binding: &[u8]) -> Result<GraphSubscription> {
        let definition = self.expiry_definition().await?;
        self.open_subscription(
            definition,
            sink::Kind::Expire,
            binding,
            Arc::new(araphor_query::follow::SystemClock::default()),
        )
        .await
    }

    pub(super) async fn expiry_definition(
        &self,
    ) -> Result<araphor_query::definition::PreparedDefinition> {
        Ok(self
            .session
            .prepare_definition(&Self::expiry_program())
            .await?)
    }

    pub fn expiry_program() -> araphor_discovery_definition::Definition {
        araphor_discovery_definition::Definition {
            name: "graph-expiry".into(),
            description: String::new(),
            labels: Default::default(),
            program: araphor_discovery_definition::Program::Sql {
                source: araphor_discovery_definition::Source::Inline {
                    inline: "WITH heads AS (
                        SELECT tenant_id, source_key, graph_result_id, commit_revision,
                            snapshot, context_refs, first_cursor, witness_deadline_utc_ns,
                            retained_input_expired FROM graph_manifest
                        QUALIFY ROW_NUMBER() OVER (PARTITION BY tenant_id, source_key,
                            first_cursor ORDER BY commit_revision DESC) = 1
                    ) SELECT h.graph_result_id, h.commit_revision, h.snapshot, h.context_refs, s.*
                    FROM heads h JOIN graph_state s USING (tenant_id, source_key)
                    WHERE NOT h.retained_input_expired AND (
                        h.first_cursor <= s.retained_floor OR h.witness_deadline_utc_ns
                            <= CAST(CAST(CURRENT_TIMESTAMP AS BIGINT) AS BIGINT UNSIGNED))
                    ORDER BY h.tenant_id, h.source_key, h.first_cursor"
                        .into(),
                },
            },
        }
    }

    pub(super) async fn open_subscription(
        self,
        definition: araphor_query::definition::PreparedDefinition,
        kind: sink::Kind,
        binding: &[u8],
        clock: Arc<dyn araphor_query::follow::Clock>,
    ) -> Result<GraphSubscription> {
        let owner = Arc::new(self);
        let mut changes = owner.authority.changes_for(&owner.grant);
        owner.check_current().await?;
        let receipt = Arc::new(Mutex::new(None));
        let definition = owner.publication(definition, kind, None, Arc::clone(&receipt))?;
        let sources = definition.sources().clone();
        let checked = Arc::clone(&owner);
        let denied = async move {
            loop {
                if changes.changed().await.is_err() || checked.check_current().await.is_err() {
                    break;
                }
            }
        };
        let query = Subscription::new(
            owner.session.clone(),
            Arc::new(definition.plan),
            sources,
            binding,
            None,
            clock,
            true,
        )?
        .until(denied);
        Ok(GraphSubscription {
            query,
            owner,
            receipt,
            delivery: None,
        })
    }
}

impl GraphSubscription {
    pub async fn cancel_and_join(self) -> Result<()> {
        let Self {
            mut query,
            delivery,
            ..
        } = self;
        let cancelled = query.cancel();
        if let Some(delivery) = delivery {
            let _delivered = delivery.await;
        }
        cancelled.and(query.cancel_and_join().await)?;
        Ok(())
    }
}

impl Stream for GraphSubscription {
    type Item = Result<sink::Receipt>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let result = if let Some(delivery) = self.delivery.as_mut() {
                let result = match std::future::Future::poll(delivery.as_mut(), context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result.map_err(Into::into),
                };
                self.delivery = None;
                result
            } else {
                match Pin::new(&mut self.query).poll_next(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => return Poll::Ready(None),
                    Poll::Ready(Some(Err(error))) => Err(error.into()),
                    Poll::Ready(Some(Ok(_))) => {
                        let receipt = self
                            .receipt
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .take();
                        let Some(receipt) = receipt else {
                            continue;
                        };
                        let owner = Arc::clone(&self.owner);
                        self.delivery = Some(
                            self.query
                                .blocking(move |control| {
                                    owner.check(control)?;
                                    Ok(receipt)
                                })
                                .boxed(),
                        );
                        continue;
                    }
                }
            };
            if result.is_err() {
                let _cancelled = self.query.cancel();
            }
            return Poll::Ready(Some(result));
        }
    }
}
