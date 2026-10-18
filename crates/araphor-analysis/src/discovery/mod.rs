use std::collections::{BTreeSet, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use araphor_data::{EvidenceIntakeIdentityV1, PackageErrorCodeV1 as Code};
use araphor_query::follow::Update;
use futures_util::stream::SelectAll;
use futures_util::{Stream, StreamExt as _};
use snafu::ResultExt as _;
use tokio::sync::watch;

use crate::{Package, Result};

mod publication;
use publication::Publication;

pub struct DiscoveryOwner {
    packages: Vec<Arc<Package>>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Pipeline {
    Sources([u8; 16]),
    Profile(EvidenceIntakeIdentityV1),
}

struct PipelineStream {
    key: Pipeline,
    stream: araphor_query::follow::Subscription,
}

impl Stream for PipelineStream {
    type Item = (Pipeline, araphor_query::Result<Update>);

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream)
            .poll_next(context)
            .map(|item| item.map(|update| (self.key.clone(), update)))
    }
}

type Updates = SelectAll<PipelineStream>;

impl DiscoveryOwner {
    pub fn new(packages: Vec<Package>) -> Result<Self> {
        if packages.is_empty() {
            return Err(Code::Invalid.error("discovery packages").into());
        }
        let mut tenants = BTreeSet::new();
        for package in &packages {
            package.check()?;
            if !tenants.insert(package.grant.selection.tenant_id) {
                return Err(Code::Invalid.error("duplicate discovery tenant").into());
            }
            if !Arc::ptr_eq(&package.query, &packages[0].query) {
                return Err(Code::Invalid.error("discovery query owner").into());
            }
        }
        packages[0].query.store().register_discovery_owner();
        Ok(Self {
            packages: packages.into_iter().map(Arc::new).collect(),
        })
    }

    pub async fn run(self: Arc<Self>, mut stop: watch::Receiver<bool>) -> Result<()> {
        let mut streams = self.sources().await?;
        loop {
            if *stop.borrow_and_update() {
                return Ok(());
            }
            tokio::select! {
                biased;
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow_and_update() { return Ok(()); }
                }
                update = streams.next() => {
                    let Some((pipeline, update)) = update else { return Ok(()); };
                    let update = update?;
                    let tenant = match &pipeline {
                        Pipeline::Sources(tenant) => *tenant,
                        Pipeline::Profile(source) => source.tenant_id,
                    };
                    let package = self.package(tenant)?;
                    package.check()?;
                    match pipeline {
                        Pipeline::Sources(_) if update.batches.is_some() => {
                            self.derive(&mut streams, tenant, &update).await?;
                        }
                        Pipeline::Sources(_) => {}
                        Pipeline::Profile(_) => match Self::publish(Arc::clone(package), update).await {
                            Ok(_) | Err(crate::Error::Data { source: araphor_data::Error::AnalysisConflict { .. } }) => {}
                            Err(error) => return Err(error),
                        },
                    }
                }
            }
        }
    }

    fn package(&self, tenant: [u8; 16]) -> Result<&Arc<Package>> {
        self.packages
            .iter()
            .find(|package| package.grant.selection.tenant_id == tenant)
            .ok_or_else(|| Code::Denied.error("discovery package tenant").into())
    }

    async fn derive(&self, streams: &mut Updates, tenant: [u8; 16], update: &Update) -> Result<()> {
        if update.limited || !update.exhausted {
            return Err(Code::Incomplete
                .error("source subscription replacement")
                .into());
        }
        let sources = Self::identities(update)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let retained = |entry: &PipelineStream| {
            !matches!(&entry.key, Pipeline::Profile(source)
                if source.tenant_id == tenant && !sources.contains(source))
        };
        if streams.iter().any(|entry| !retained(entry)) {
            *streams = std::mem::take(streams)
                .into_iter()
                .filter(retained)
                .collect();
        }
        let active = streams
            .iter()
            .map(|entry| entry.key.clone())
            .collect::<HashSet<_>>();
        let package = self.package(tenant)?;
        for source in sources {
            let pipeline = Pipeline::Profile(source.clone());
            if !active.contains(&pipeline) {
                streams.push(PipelineStream {
                    key: pipeline,
                    stream: package.subscribe(Some(&source), true).await?,
                });
            }
        }
        Ok(())
    }

    async fn sources(&self) -> Result<Updates> {
        let mut streams = Updates::new();
        for package in &self.packages {
            let changes = package.changes();
            package.check()?;
            let (plan, sources) = package.query.prepare(
                "SELECT DISTINCT tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch FROM discovery_state WHERE NOT coalesce(retired,false)",
                Vec::new(),
            ).await?;
            let session =
                package
                    .query
                    .session(package.selection(None)?, &package.control()?, 0)?;
            let stream = session
                .subscribe(plan, sources, b"discovery sources", true)?
                .until_change(changes);
            streams.push(PipelineStream {
                key: Pipeline::Sources(package.grant.selection.tenant_id),
                stream,
            });
        }
        Ok(streams)
    }

    fn identities(update: &Update) -> Result<Vec<EvidenceIntakeIdentityV1>> {
        update
            .batches
            .iter()
            .flatten()
            .map(|batch| serde_arrow::from_record_batch(batch).context(crate::error::ArrowSnafu))
            .collect::<Result<Vec<Vec<_>>>>()
            .map(|rows| rows.into_iter().flatten().collect())
    }

    async fn publish(package: Arc<Package>, update: Update) -> Result<usize> {
        package.query.check_read(&update.snapshot).await?;
        let mut rows = Vec::new();
        for batch in update.batches.iter().flatten() {
            rows.extend(
                serde_arrow::from_record_batch::<Vec<Publication>>(batch)
                    .context(crate::error::ArrowSnafu)?,
            );
        }
        tokio::task::spawn_blocking(move || {
            let mut count = 0usize;
            for row in rows {
                count = count
                    .checked_add(row.commit(&package, &update)?)
                    .ok_or_else(|| Code::Invalid.error("discovery result count"))?;
            }
            Ok(count)
        })
        .await
        .context(crate::error::TaskSnafu)?
    }
}

impl Drop for DiscoveryOwner {
    fn drop(&mut self) {
        self.packages[0].query.store().release_discovery_owner();
    }
}

#[cfg(test)]
mod tests;
