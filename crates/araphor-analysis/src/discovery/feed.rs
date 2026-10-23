use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use araphor_data::{
    AnalysisReadControl, EvidenceIntakeIdentityV1, ManagedDestination, PackageErrorCodeV1 as Code,
    ProcessorScopeV1, DISCOVERY_PROCESSOR, DISCOVERY_SCHEMA_VERSION,
};
use araphor_package::Qualification;
use araphor_query::follow::Update;
use erebor_runtime_error::{ErrorExt as _, StatusCode};
use futures_util::stream::SelectAll;
use futures_util::{Stream, StreamExt as _};
use snafu::ResultExt as _;
use tokio::sync::watch;

use super::DiscoveryOwner;
use crate::instance::Restored;
use crate::{Instance, Result};

pub(super) struct SourceStream {
    pub(super) tenant: [u8; 16],
    pub(super) stream: araphor_query::follow::Subscription,
}

impl Stream for SourceStream {
    type Item = ([u8; 16], araphor_query::Result<Update>);

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream)
            .poll_next(context)
            .map(|item| item.map(|update| (self.tenant, update)))
    }
}

#[derive(serde::Deserialize)]
struct SourceState {
    source: EvidenceIntakeIdentityV1,
    active: bool,
}

pub(super) type Updates = SelectAll<SourceStream>;
pub(super) type Members = BTreeSet<EvidenceIntakeIdentityV1>;

impl DiscoveryOwner {
    pub async fn run(self: Arc<Self>, stop: watch::Receiver<bool>) -> Result<()> {
        if *stop.borrow() {
            return Ok(());
        }
        let control = Arc::new(AnalysisReadControl::default());
        let stage = Arc::clone(&control);
        crate::instance::Shutdown::join(control, stop, async move { self.feed(stage).await }).await
    }

    pub(super) async fn feed(&self, control: Arc<AnalysisReadControl>) -> Result<()> {
        let mut streams = self.sources(&control).await?;
        let mut members = Members::new();
        let result = async {
            while let Some((tenant, update)) = streams.next().await {
                let result: Result<()> = async {
                    let update = update?;
                    control.check()?;
                    self.package(tenant)?.check()?;
                    if update.batches.is_some() {
                        self.derive(&mut members, tenant, &update, &control).await?;
                    }
                    Ok(())
                }.await;
                if let Err(error) = result {
                    if control.check().is_err() {
                        break;
                    }
                    if error.status_code() != StatusCode::PermissionDenied {
                        return Err(error);
                    }
                    erebor_telemetry::warn!(error; "Discovery source subscription ended", tenant_id = %format_args!("{tenant:?}"));
                    for entry in std::mem::take(&mut streams) {
                        if entry.tenant == tenant {
                            entry.stream.cancel_and_join().await?;
                        } else {
                            streams.push(entry);
                        }
                    }
                    members.retain(|source| source.tenant_id != tenant);
                }
            }
            Ok(())
        }
        .await;
        let joined = futures_util::future::join_all(
            streams
                .into_iter()
                .map(|entry| entry.stream.cancel_and_join()),
        )
        .await;
        for result in joined {
            result?;
        }
        if control.check().is_err() {
            Ok(())
        } else {
            result
        }
    }

    pub(super) async fn derive(
        &self,
        members: &mut Members,
        tenant: [u8; 16],
        update: &Update,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if update.limited || !update.exhausted {
            return Err(Code::Incomplete
                .error("source subscription replacement")
                .into());
        }
        let states = Self::source_states(update)?;
        let sources = states
            .iter()
            .filter(|state| state.active)
            .map(|state| state.source.clone())
            .collect::<BTreeSet<_>>();
        let package = self.package(tenant)?;
        for state in &states {
            package.selection(Some(&state.source))?;
        }
        let removed = members
            .iter()
            .filter(|source| source.tenant_id == tenant && !sources.contains(*source))
            .cloned()
            .chain(
                states
                    .iter()
                    .filter(|state| !state.active)
                    .map(|state| state.source.clone()),
            )
            .collect::<BTreeSet<_>>();
        for source in removed {
            match self
                .host
                .restore(tenant, &Self::instance_id(&source), control)
                .await?
            {
                Restored::Absent => {}
                Restored::Removed(stored) => Self::check_member(&source, &stored)?,
                Restored::Present(instance) => {
                    Self::check_member(&source, instance.admitted())?;
                    self.host
                        .stop(
                            Arc::clone(&instance),
                            instance.admitted().lifecycle,
                            control,
                        )
                        .await?;
                }
            }
            members.remove(&source);
        }
        for source in sources {
            if members.contains(&source) {
                continue;
            }
            let instance = match self
                .host
                .restore(tenant, &Self::instance_id(&source), control)
                .await?
            {
                Restored::Absent => self.admit(&source, control).await?,
                Restored::Removed(stored) => {
                    Self::check_member(&source, &stored)?;
                    members.insert(source);
                    continue;
                }
                Restored::Present(instance) => {
                    Self::check_member(&source, instance.admitted())?;
                    Some(instance)
                }
            };
            if let Some(instance) = instance {
                let admitted = instance.admitted();
                if admitted.running || admitted.lifecycle == admitted.generation {
                    self.host
                        .start(Arc::clone(&instance), admitted.lifecycle, control)
                        .await?;
                }
                members.insert(source);
            }
        }
        Ok(())
    }

    pub(super) async fn admit(
        &self,
        source: &EvidenceIntakeIdentityV1,
        control: &AnalysisReadControl,
    ) -> Result<Option<Arc<Instance>>> {
        let package = self.package(source.tenant_id)?;
        package.check()?;
        let (prepared, call) = package.prepared().await?;
        let destination = ManagedDestination::DiscoveryProfile {
            source: source.clone(),
            call: call.id(),
            output: call.output().into(),
        };
        let session =
            package
                .query
                .session(destination.selection(&package.grant.selection)?, control, 0)?;
        let registration = Arc::clone(package);
        let scope = ProcessorScopeV1 {
            processor_id: DISCOVERY_PROCESSOR.into(),
            method_version: u64::from(DISCOVERY_SCHEMA_VERSION),
            identity: source.clone(),
        };
        let read = Arc::new(control.within(package.grant.remaining()?)?);
        let stage = Arc::clone(&read);
        let registered = araphor_query::execution::Engine::blocking(read, (), move || {
            Ok(registration.commit(|| {
                registration
                    .query
                    .store()
                    .ensure_optional_processor_guarded(&scope, || stage.check())
            }))
        })
        .await?;
        match registered {
            Ok(_) => {}
            Err(crate::Error::Data {
                source: araphor_data::Error::AnalysisConflict { .. },
            }) => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        let id = Self::instance_id(source);
        Ok(Some(
            self.host
                .admit_prepared(
                    session,
                    package.grant.clone(),
                    id,
                    prepared.clone(),
                    destination,
                )
                .await?,
        ))
    }

    fn check_member(
        source: &EvidenceIntakeIdentityV1,
        stored: &araphor_data::ManagedInstance,
    ) -> Result<()> {
        if stored.spec.tenant != source.tenant_id
            || stored.spec.id != Self::instance_id(source)
            || !matches!(&stored.spec.destination,
                ManagedDestination::DiscoveryProfile { source: owned, .. } if owned == source)
        {
            return Err(Code::Conflict.error("discovery member destination").into());
        }
        Ok(())
    }

    fn source_states(update: &Update) -> Result<Vec<SourceState>> {
        update
            .batches
            .iter()
            .flatten()
            .map(|batch| serde_arrow::from_record_batch(batch).context(crate::error::ArrowSnafu))
            .collect::<Result<Vec<Vec<_>>>>()
            .map(|rows| rows.into_iter().flatten().collect())
    }

    #[cfg(test)]
    pub(super) fn identities(update: &Update) -> Result<Vec<EvidenceIntakeIdentityV1>> {
        Ok(Self::source_states(update)?
            .into_iter()
            .filter(|state| state.active)
            .map(|state| state.source)
            .collect())
    }

    pub(super) fn instance_id(source: &EvidenceIntakeIdentityV1) -> String {
        format!("discovery:{}", Qualification::digest(&source.key()))
    }

    pub(super) async fn sources(&self, control: &Arc<AnalysisReadControl>) -> Result<Updates> {
        let mut streams = Updates::new();
        for package in &self.packages {
            let mut changes = package.changes();
            package.check()?;
            let (plan, sources) = package
                .query
                .prepare(
                    "SELECT DISTINCT named_struct('tenant_id',tenant_id,'node_id',node_id,
                    'node_boot_id',node_boot_id,'label_epoch',label_epoch,
                    'source_id',source_id,'source_epoch',source_epoch) AS source,
                    NOT coalesce(retired,false) AS active FROM discovery_state",
                    Vec::new(),
                )
                .await?;
            let read = control.operation()?.within(package.grant.remaining()?)?;
            let session = package.query.session(package.selection(None)?, &read, 0)?;
            let stopped = Arc::clone(control);
            let watched = Arc::clone(package);
            let stream = session
                .subscribe(plan, sources, b"discovery sources", true)?
                .until_error(async move {
                    loop {
                        tokio::select! {
                            _ = stopped.cancelled() => return araphor_query::Error::AuthorityChanged { location: snafu::location!() },
                            changed = changes.changed() => {
                                if changed.is_err() {
                                    return Code::Denied.error("discovery authority watch closed").into();
                                }
                                if let Err(source) = watched.check() {
                                    return source.into();
                                }
                            }
                        }
                    }
                });
            streams.push(SourceStream {
                tenant: package.grant.selection.tenant_id,
                stream,
            });
        }
        Ok(streams)
    }
}
