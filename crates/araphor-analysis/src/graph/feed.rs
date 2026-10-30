use std::collections::BTreeSet;
use std::sync::Arc;

use araphor_data::{
    AnalysisReadControl, EvidenceIntakeIdentityV1, GraphLease, ManagedDestination,
    ManagedGraphOperation, PackageActionV1, PackageAuthorization, PackageErrorCodeV1 as Code,
    PackageGrantV1,
};
use araphor_discovery_definition::ResolvedDefinition;
use araphor_query::execution::Engine;
use araphor_query::follow::{Subscription, Update};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt as _;
use snafu::ResultExt as _;
use tokio::sync::watch;

use super::GraphPublication;
use crate::instance::Restored;
use crate::{Instance, InstanceHost, Result};

#[derive(Clone)]
pub struct GraphProgram {
    pub grant: PackageGrantV1,
    pub definition: ResolvedDefinition,
    pub events_sql: String,
}

impl GraphProgram {
    fn overlaps(&self, other: &Self) -> bool {
        let left = &self.grant.selection;
        let right = &other.grant.selection;
        if left.tenant_id != right.tenant_id {
            return false;
        }
        match (left.sources.is_all(), right.sources.is_all()) {
            (true, true) => {
                left.nodes.is_empty()
                    || right.nodes.is_empty()
                    || left.nodes.iter().any(|node| right.nodes.contains(node))
            }
            (false, _) => left
                .sources
                .as_slice()
                .iter()
                .any(|source| left.includes_source(source) && right.includes_source(source)),
            (true, false) => right
                .sources
                .as_slice()
                .iter()
                .any(|source| left.includes_source(source) && right.includes_source(source)),
        }
    }
}

pub struct GraphOwner {
    query: Arc<Engine>,
    host: Arc<InstanceHost>,
    authority: Arc<dyn PackageAuthorization>,
    programs: Vec<GraphProgram>,
    interest: GraphLease,
    #[cfg(test)]
    pub(in crate::graph) joined: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<usize>>>,
}

#[derive(serde::Deserialize)]
struct SourceState {
    source: EvidenceIntakeIdentityV1,
    active: bool,
    present: bool,
}

impl GraphOwner {
    pub async fn new(
        query: Arc<Engine>,
        host: Arc<InstanceHost>,
        authority: Arc<dyn PackageAuthorization>,
        programs: Vec<GraphProgram>,
        control: &AnalysisReadControl,
    ) -> Result<Self> {
        host.check_query(&query)?;
        if programs.is_empty() {
            return Err(Code::Invalid.error("Graph programs").into());
        }
        for (index, program) in programs.iter().enumerate() {
            program.grant.remaining()?;
            program
                .definition
                .validate()
                .map_err(araphor_data::Error::from)?;
            if program.events_sql.is_empty() {
                return Err(Code::Invalid.error("Graph event SQL").into());
            }
            if programs[index + 1..]
                .iter()
                .any(|other| program.overlaps(other))
            {
                return Err(Code::Conflict.error("Graph program source overlap").into());
            }
        }
        let expiry = query
            .admit_definition(
                programs[0].grant.selection.tenant_id,
                GraphPublication::expiry_program(),
                Arc::new(control.within(None)?),
            )
            .await?;
        let checked = Arc::clone(&authority);
        let store = Arc::clone(query.store());
        let retained = programs.clone();
        let read = Arc::new(control.within(None)?);
        let stage = Arc::clone(&read);
        let interest = Engine::blocking(read, (), move || {
            let grants = retained
                .iter()
                .map(|program| (&program.grant, PackageActionV1::Run, None))
                .collect::<Vec<_>>();
            let mut interest = None;
            checked.commit_many(&grants, &mut || {
                for program in &retained {
                    program.grant.remaining()?;
                    for definition in [&program.definition, &expiry] {
                        let digest = definition.digest().map_err(araphor_data::Error::from)?;
                        let current = store
                            .definition(
                                program.grant.selection.tenant_id,
                                &definition.definition.name,
                                Some(&digest),
                                &stage,
                            )?
                            .ok_or_else(|| Code::Missing.error("Graph admitted definition"))?;
                        if current != *definition {
                            return Err(Code::Conflict.error("Graph admitted definition pin"));
                        }
                    }
                }
                stage.check()?;
                interest = Some(
                    store.lease_graph(
                        retained
                            .iter()
                            .map(|program| program.grant.selection.clone())
                            .collect(),
                    )?,
                );
                Ok(())
            })?;
            interest.ok_or_else(|| Code::Incomplete.error("Graph interest owner").into())
        })
        .await?;
        Ok(Self {
            query,
            host,
            authority,
            programs,
            interest,
            #[cfg(test)]
            joined: Default::default(),
        })
    }

    pub async fn run(self: Arc<Self>, stop: watch::Receiver<bool>) -> Result<()> {
        if *stop.borrow() {
            return Ok(());
        }
        let control = Arc::new(AnalysisReadControl::default());
        let stage = Arc::clone(&control);
        crate::instance::Shutdown::join(control, stop, async move { self.feed(stage).await }).await
    }

    async fn feed(&self, control: Arc<AnalysisReadControl>) -> Result<()> {
        let mut running = FuturesUnordered::new();
        for index in 0..self.programs.len() {
            let control = Arc::clone(&control);
            running.push(async move { (index, self.program_feed(index, control).await) });
        }
        let mut failure = None;
        let mut fatal = None;
        while let Some((index, result)) = running.next().await {
            let program = &self.programs[index];
            if let Err(error) = self.interest.remove(&program.grant.selection) {
                fatal.get_or_insert(error.into());
                let _cancelled = control.cancel();
            }
            #[cfg(test)]
            if let Some(joined) = self
                .joined
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
            {
                let _sent = joined.send(index);
            }
            if let Err(error) = result {
                erebor_telemetry::warn!(error; "Graph source subscription stopped", grant_revision = %program.grant.revision, definition = %program.definition.definition.name);
                failure = Some(error);
            }
        }
        match fatal.or_else(|| failure.filter(|_| control.check().is_ok())) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn program_feed(&self, index: usize, parent: Arc<AnalysisReadControl>) -> Result<()> {
        let grant = &self.programs[index].grant;
        let control = Arc::new(parent.operation()?.within(grant.remaining()?)?);
        let mut changes = self.authority.changes_for(grant);
        let work = async {
            let mut stream = match self.source(index, &control).await {
                Ok(stream) => stream,
                Err(error) => return (Err(error), None),
            };
            let mut members = BTreeSet::new();
            let result = async {
                while let Some(update) = stream.next().await {
                    let update = update?;
                    control.check()?;
                    self.check(index)?;
                    if update.batches.is_some() {
                        self.derive(&mut members, index, &update, &control).await?;
                    }
                }
                Err(Code::Incomplete
                    .error("Graph source subscription ended")
                    .into())
            }
            .await;
            (result, Some(stream))
        };
        tokio::pin!(work);
        let changed = async {
            loop {
                tokio::select! {
                    _ = parent.cancelled() => return Ok(()),
                    update = changes.changed() => {
                        if update.is_err() { return Err(Code::Denied.error("Graph source authority watch").into()); }
                        self.check(index)?;
                    }
                }
            }
        };
        tokio::pin!(changed);
        let (reason, result, stream) = tokio::select! {
            (result, stream) = &mut work => (None, result, stream),
            reason = &mut changed => {
                let cancelled = control.cancel().map_err(Into::into);
                let (result, stream) = work.await;
                (Some(reason.and(cancelled)), result, stream)
            }
        };
        if let Some(stream) = stream {
            stream.cancel_and_join().await?;
        }
        if parent.check().is_err() {
            Ok(())
        } else {
            reason.unwrap_or(result)
        }
    }

    async fn source(
        &self,
        index: usize,
        control: &Arc<AnalysisReadControl>,
    ) -> Result<Subscription> {
        self.check(index)?;
        let session =
            self.query
                .session(self.programs[index].grant.selection.clone(), control, 0)?;
        let (plan, sources) = self.query.prepare("SELECT DISTINCT named_struct('tenant_id', tenant_id, 'node_id', node_id,
            'node_boot_id', node_boot_id, 'label_epoch', label_epoch, 'source_id', source_id, 'source_epoch', source_epoch) AS source,
            NOT coalesce(retired, false) AS active, processor_present AS present FROM graph_state", Vec::new()).await?;
        Ok(session.subscribe(plan, sources, b"Graph sources", true)?)
    }

    async fn derive(
        &self,
        members: &mut BTreeSet<EvidenceIntakeIdentityV1>,
        index: usize,
        update: &Update,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if update.limited || !update.exhausted {
            return Err(Code::Incomplete.error("Graph source replacement").into());
        }
        let mut states = Vec::new();
        for batch in update.batches.iter().flatten() {
            let values: Vec<SourceState> =
                serde_arrow::from_record_batch(batch).context(crate::error::ArrowSnafu)?;
            states.extend(values);
        }
        let grant = &self.programs[index].grant;
        if states
            .iter()
            .any(|state| !grant.selection.includes_source(&state.source))
        {
            return Err(Code::Conflict.error("Graph source owner").into());
        }
        let active = states
            .iter()
            .filter(|state| state.active)
            .map(|state| state.source.clone())
            .collect::<BTreeSet<_>>();
        let removed = members
            .difference(&active)
            .cloned()
            .chain(
                states
                    .iter()
                    .filter(|state| !state.active)
                    .map(|state| state.source.clone()),
            )
            .collect::<BTreeSet<_>>();
        for source in removed {
            for operation in [
                ManagedGraphOperation::Evaluate,
                ManagedGraphOperation::Expire,
            ] {
                match self
                    .host
                    .restore(source.tenant_id, &operation.instance_id(&source), control)
                    .await?
                {
                    Restored::Absent => {}
                    Restored::Removed(instance) => {
                        Self::check_member(&instance, &source, operation, grant)?
                    }
                    Restored::Present(instance) => {
                        Self::check_member(instance.admitted(), &source, operation, grant)?;
                        self.host
                            .stop(
                                Arc::clone(&instance),
                                instance.admitted().lifecycle,
                                control,
                            )
                            .await?;
                    }
                }
            }
            members.remove(&source);
        }
        for state in states.into_iter().filter(|state| state.active) {
            if members.contains(&state.source) {
                continue;
            }
            if !state.present {
                let store = Arc::clone(self.query.store());
                let authority = Arc::clone(&self.authority);
                let grant = grant.clone();
                let source = state.source.clone();
                let read = Arc::new(control.within(grant.remaining()?)?);
                let stage = Arc::clone(&read);
                let revision = update.snapshot.page.extraction.meta.commit_revision;
                let registered = Engine::blocking(read, (), move || {
                    let mut registered = false;
                    authority.commit_many(&[(&grant, PackageActionV1::Run, None)], &mut || {
                        registered = store.register_graph_guarded(&source, revision, || {
                            grant.remaining()?;
                            stage.check()
                        })?;
                        Ok(())
                    })?;
                    Ok(registered)
                })
                .await?;
                if !registered {
                    continue;
                }
            }
            for operation in [
                ManagedGraphOperation::Evaluate,
                ManagedGraphOperation::Expire,
            ] {
                let Some(instance) = self.admit(index, &state.source, operation, control).await?
                else {
                    continue;
                };
                let admitted = instance.admitted();
                if admitted.running || admitted.lifecycle == admitted.generation {
                    self.host
                        .start(Arc::clone(&instance), admitted.lifecycle, control)
                        .await?;
                }
            }
            members.insert(state.source);
        }
        Ok(())
    }

    async fn admit(
        &self,
        index: usize,
        source: &EvidenceIntakeIdentityV1,
        operation: ManagedGraphOperation,
        control: &AnalysisReadControl,
    ) -> Result<Option<Arc<Instance>>> {
        let program = &self.programs[index];
        let id = operation.instance_id(source);
        match self.host.restore(source.tenant_id, &id, control).await? {
            Restored::Absent => {}
            Restored::Removed(instance) => {
                Self::check_member(&instance, source, operation, &program.grant)?;
                return Ok(None);
            }
            Restored::Present(instance) => {
                Self::check_member(instance.admitted(), source, operation, &program.grant)?;
                if operation == ManagedGraphOperation::Evaluate
                    && (instance.admitted().spec.definition != program.definition
                        || !matches!(&instance.admitted().spec.destination, ManagedDestination::Graph { events_sql, .. } if events_sql == &program.events_sql))
                {
                    return Err(Code::Conflict.error("Graph running definition pin").into());
                }
                return Ok(Some(instance));
            }
        }
        let instance = match operation {
            ManagedGraphOperation::Evaluate => {
                self.host
                    .admit_graph(
                        program.grant.clone(),
                        id,
                        source.clone(),
                        program.events_sql.clone(),
                        program.definition.clone(),
                        control,
                    )
                    .await
            }
            ManagedGraphOperation::Expire => {
                self.host
                    .admit_graph_expiry(program.grant.clone(), id, source.clone(), control)
                    .await
            }
        }?;
        Ok(Some(instance))
    }

    fn check_member(
        instance: &araphor_data::ManagedInstance,
        source: &EvidenceIntakeIdentityV1,
        operation: ManagedGraphOperation,
        grant: &PackageGrantV1,
    ) -> Result<()> {
        if &instance.grant != grant {
            return Err(Code::Conflict.error("Graph member grant").into());
        }
        if !matches!(&instance.spec.destination, ManagedDestination::Graph { source: owned, operation: actual, .. } if owned == source && *actual == operation)
        {
            return Err(Code::Conflict.error("Graph member destination").into());
        }
        Ok(())
    }

    fn check(&self, index: usize) -> Result<()> {
        let grant = &self.programs[index].grant;
        grant.remaining()?;
        self.authority.check(grant, PackageActionV1::Run)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
