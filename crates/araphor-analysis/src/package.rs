use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisContextRefV1, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore,
    EvidenceIntakeIdentityV1, PackageActionV1, PackageAuthorization, PackageBundleRef,
    PackageBundleV1, PackageErrorCodeV1 as Code, PackageGrantV1, PackageImplementationV1,
    Selection,
};
use araphor_query::execution::Engine;
use araphor_query::follow::Subscription;

use crate::Result;

pub struct Package {
    pub(crate) query: Arc<Engine>,
    pub(crate) grant: PackageGrantV1,
    authority: Arc<dyn PackageAuthorization>,
    bundle: PackageBundleV1,
    digest: String,
    sql: String,
    tables: Vec<String>,
    pub(crate) context: AnalysisContextRefV1,
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
        let artifact = bundle.artifact(&bundle.root)?;
        let model = artifact
            .descriptor
            .exports
            .iter()
            .find(|model| model.name == export)
            .ok_or_else(|| Code::Missing.error("SQL export"))?;
        let PackageImplementationV1::Sql { program, .. } = artifact.implementation(export)? else {
            return Err(Code::Unsupported
                .error("native SQL subscription target")
                .into());
        };
        if model.input_mode != sdk::InputMode::Resolved
            || !model.parameters.fields().is_empty()
            || model.checkpoint.is_some()
            || !program.checkpoint.is_empty()
            || program.evidence.is_some()
            || !program.reasons.is_empty()
        {
            return Err(Code::Unsupported.error("SQL subscription contract").into());
        }
        let schemas = AnalysisStore::table_schemas();
        let mut tables = Vec::new();
        for input in &model.inputs {
            if !matches!(&input.source, sdk::InputSource::Table(sdk::TableRef::Named(name)) if name == &input.port.name)
                || schemas.get(&input.port.name).is_none_or(|schema| {
                    input.port.schema.fields().iter().any(|field| {
                        schema
                            .field_with_name(field.name())
                            .map_or(true, |actual| actual != field.as_ref())
                    })
                })
            {
                return Err(Code::Unsupported
                    .error("SQL subscription table binding")
                    .into());
            }
            tables.push(input.port.name.clone());
        }
        let sql = program
            .outputs
            .get(output)
            .cloned()
            .ok_or_else(|| Code::Missing.error("SQL output"))?;
        let digest = bundle.digest()?;
        let retained = PackageBundleRef::retained(&bundle, &digest);
        let context = retained.context(grant.selection.tenant_id, export, output)?;
        let revisions = bundle.revisions(grant.selection.tenant_id)?;
        grant.remaining()?;
        let mut reference = None;
        authority.commit(&grant, PackageActionV1::Run, &retained, &mut || {
            grant.remaining()?;
            query.store().install_package(&revisions, || {
                grant.remaining()?;
                Ok(())
            })?;
            reference = Some(
                query
                    .store()
                    .intern_context_guarded(&context, || grant.remaining().map(|_| ()))?,
            );
            Ok(())
        })?;
        let package = Self {
            query,
            authority,
            grant,
            bundle,
            digest,
            sql,
            tables,
            context: reference
                .ok_or_else(|| Code::Denied.error("SQL package retention authority"))?,
        };
        package.check()?;
        Ok(package)
    }

    pub(crate) fn check(&self) -> Result<()> {
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
                return Err(Code::Denied.error("SQL source selection").into());
            }
            selection.sources = Selection::Exact(vec![source.clone()]);
        }
        Ok(selection)
    }

    pub async fn subscribe(
        &self,
        source: Option<&EvidenceIntakeIdentityV1>,
        follow: bool,
    ) -> Result<Subscription> {
        let changes = self.changes();
        self.check()?;
        let selection = self.selection(source)?;
        let (plan, sources) = self.query.prepare(&self.sql, Vec::new()).await?;
        if sources.keys().any(|name| !self.tables.contains(name)) {
            return Err(Code::Denied.error("undeclared SQL source").into());
        }
        let control = self.control()?;
        let session = self.query.session(selection, &control, 0)?;
        let stream = session.subscribe(plan, sources, self.digest.as_bytes(), follow)?;
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
                    .ok_or_else(|| Code::Invalid.error("SQL publication callback"))?(
                )?);
                Ok(())
            },
        )?;
        output.ok_or_else(|| Code::Denied.error("SQL publication authority").into())
    }
}

#[cfg(test)]
mod tests;
