use std::sync::Arc;

use araphor_data::{
    AnalysisReadControl, AnalysisSelectionV1, EvidenceIntakeIdentityV1, PackageActionV1,
    PackageAuthorization, PackageBundleRef, PackageBundleV1, PackageErrorCodeV1 as Code,
    PackageGrantV1, Selection,
};
use araphor_discovery_definition::{Definition, Program};
use araphor_query::definition::{PackageCall, PreparedDefinition};
use araphor_query::execution::Engine;
use araphor_query::follow::Subscription;
use datafusion::common::DataFusionError;
use tokio::sync::OnceCell;

use crate::Result;

pub(crate) mod builtin;

pub struct Package {
    pub(crate) query: Arc<Engine>,
    pub(crate) grant: PackageGrantV1,
    pub(crate) authority: Arc<dyn PackageAuthorization>,
    bundle: PackageBundleV1,
    digest: String,
    export: String,
    output: String,
    prepared: OnceCell<(PreparedDefinition, PackageCall)>,
}

impl Package {
    pub fn new(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        bundle: PackageBundleV1,
        export: &str,
        output: &str,
    ) -> Result<Self> {
        bundle.validate()?;
        let digest = bundle.digest()?;
        let retained = PackageBundleRef::retained(&bundle, &digest);
        let context = retained.context(grant.selection.tenant_id, &bundle.root, export, output)?;
        grant.remaining()?;
        let mut reference = None;
        authority.commit(&grant, PackageActionV1::Run, &retained, &mut || {
            reference = Some(
                query
                    .store()
                    .intern_context_guarded(&context, || grant.remaining().map(|_| ()))?,
            );
            Ok(())
        })?;
        let _context =
            reference.ok_or_else(|| Code::Denied.error("package retention authority"))?;
        let package = Self {
            query,
            authority,
            grant,
            bundle,
            digest,
            export: export.into(),
            output: output.into(),
            prepared: OnceCell::new(),
        };
        package.check()?;
        Ok(package)
    }

    pub(crate) fn check(&self) -> araphor_data::Result<()> {
        let _remaining = self.grant.remaining()?;
        self.authority.check(&self.grant, PackageActionV1::Run)?;
        self.authority.admit(
            &self.grant,
            &PackageBundleRef::retained(&self.bundle, &self.digest),
        )?;
        Ok(())
    }

    pub(crate) fn control(&self) -> Result<AnalysisReadControl> {
        Ok(match self.grant.remaining()? {
            Some(timeout) => AnalysisReadControl::with_timeout(timeout)?,
            None => AnalysisReadControl::default(),
        })
    }

    pub(crate) fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.authority.changes_for(&self.grant)
    }

    pub(crate) fn selection(
        &self,
        source: Option<&EvidenceIntakeIdentityV1>,
    ) -> Result<AnalysisSelectionV1> {
        let mut selection = self.grant.selection.clone();
        if let Some(source) = source {
            if source.tenant_id != selection.tenant_id
                || (!selection.sources.is_all() && !selection.sources.as_slice().contains(source))
                || (!selection.nodes.is_empty() && !selection.nodes.contains(&source.node_id))
            {
                return Err(Code::Denied.error("package source selection").into());
            }
            selection.sources = Selection::Exact(vec![source.clone()]);
        }
        Ok(selection)
    }

    pub(crate) async fn prepared(&self) -> Result<&(PreparedDefinition, PackageCall)> {
        self.prepared
            .get_or_try_init(|| async {
                self.check()?;
                let definition = Definition {
                    name: format!(
                        "{}/{}/{}/{}",
                        self.bundle.root.package_id,
                        self.bundle.root.revision,
                        self.export,
                        self.output
                    ),
                    description: String::new(),
                    labels: Default::default(),
                    program: Program::call(&self.bundle.root, &self.export, &self.output)
                        .map_err(araphor_data::Error::from)?,
                };
                let control = Arc::new(self.control()?);
                let prepared = self
                    .query
                    .prepare_definition(
                        self.grant.selection.tenant_id,
                        &definition,
                        Arc::clone(&control),
                    )
                    .await?;
                if prepared.resolved().images.len() != 1
                    || prepared.resolved().images[0].image != self.bundle.root
                    || prepared.resolved().images[0].digest != self.digest
                {
                    return Err(Code::Denied.error("package image pin").into());
                }
                let mut root = None;
                PackageCall::any(&prepared.plan, &mut |call| {
                    let model = call
                        .descriptor()
                        .exports
                        .iter()
                        .find(|model| model.name == call.export())
                        .ok_or_else(|| {
                            DataFusionError::External(Box::new(
                                Code::Missing.error("subscription export"),
                            ))
                        })?;
                    if model.checkpoint.is_some() {
                        return Err(DataFusionError::External(Box::new(
                            Code::Unsupported.error("subscription checkpoint"),
                        )));
                    }
                    if call.package() == &self.bundle.root
                        && call.export() == self.export
                        && call.output() == self.output
                        && root.replace(call.clone()).is_some()
                    {
                        return Err(DataFusionError::External(Box::new(
                            Code::Invalid.error("subscription root call"),
                        )));
                    }
                    Ok(false)
                })
                .map_err(|source| araphor_query::Error::Sql { source })?;
                let call = root.ok_or_else(|| Code::Invalid.error("subscription package call"))?;
                control.check()?;
                self.check()?;
                Ok((prepared, call))
            })
            .await
    }

    pub async fn subscribe(
        &self,
        source: Option<&EvidenceIntakeIdentityV1>,
        follow: bool,
    ) -> Result<Subscription> {
        let changes = self.changes();
        self.check()?;
        let selection = self.selection(source)?;
        let (prepared, _) = self.prepared().await?;
        let binding = prepared
            .resolved()
            .digest()
            .map_err(araphor_data::Error::from)?;
        let session = self.query.session(selection, &self.control()?, 0)?;
        let stream = session.subscribe(
            prepared.plan.clone(),
            prepared.sources().clone(),
            binding.as_bytes(),
            follow,
        )?;
        self.check()?;
        Ok(stream.until_change(changes))
    }

    pub(crate) fn commit<T>(
        &self,
        operation: impl FnOnce() -> araphor_data::Result<T>,
    ) -> Result<T> {
        let _remaining = self.grant.remaining()?;
        let mut operation = Some(operation);
        let mut output = None;
        self.authority.commit(
            &self.grant,
            PackageActionV1::Run,
            &PackageBundleRef::retained(&self.bundle, &self.digest),
            &mut || {
                let _remaining = self.grant.remaining()?;
                output = Some(operation
                    .take()
                    .ok_or_else(|| Code::Invalid.error("package publication callback"))?(
                )?);
                Ok(())
            },
        )?;
        output.ok_or_else(|| Code::Denied.error("package publication authority").into())
    }
}

#[cfg(test)]
mod tests;
