use super::*;
use araphor_analysis::Instance;
use araphor_data::{AnalysisReadControl, PackageErrorCodeV1 as Code};
use araphor_discovery_definition::Definition;
use snafu::ResultExt as _;
use std::path::{Path, PathBuf};

impl ControlPackages {
    pub(crate) fn start_definitions(
        self: &Arc<Self>,
        directory: Option<&Path>,
    ) -> crate::Result<()> {
        let definitions = Self::read_definitions(directory)?;
        let owner = Arc::clone(self);
        self.query
            .wait(async move { Ok(owner.prepare_definitions(definitions).await) })?
    }

    fn read_definitions(directory: Option<&Path>) -> crate::Result<Vec<Definition>> {
        let definitions = if let Some(directory) = directory {
            let mut files = std::fs::read_dir(directory)
                .context(crate::error::IoSnafu { path: directory })?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()
                .context(crate::error::IoSnafu { path: directory })?;
            files.retain(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "yaml" || extension == "yml")
            });
            files.sort();
            files
                .into_iter()
                .map(|path| Definition::read(&path).map_err(araphor_data::Error::from))
                .collect::<araphor_data::Result<Vec<_>>>()?
        } else {
            serde_json::from_slice(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/default-definitions.json"
            )))
            .context(crate::error::JsonSnafu {
                path: PathBuf::from("<default-package-definitions>"),
            })?
        };
        let mut names = BTreeSet::new();
        for definition in &definitions {
            definition
                .validate_captured()
                .map_err(araphor_data::Error::from)?;
            if !names.insert(&definition.name) {
                return Err(Code::Conflict.error("configured Definition name").into());
            }
        }
        Ok(definitions)
    }

    async fn prepare_definitions(
        self: Arc<Self>,
        definitions: Vec<Definition>,
    ) -> crate::Result<()> {
        let control = AnalysisReadControl::default();
        for tenant in self.authority.tenants.keys() {
            let Some(grant) = self.authority.definition_grant(*tenant) else {
                continue;
            };
            for image in &self.images {
                self.authority
                    .commit(&grant, PackageActionV1::Install, image, &mut || {
                        self.query
                            .store()
                            .install_package_image(*tenant, image, || control.check())?;
                        Ok(())
                    })?;
            }
            for definition in &definitions {
                let session = self.query.session(grant.selection.clone(), &control, 0)?;
                let prepared = session.prepare_definition(definition, None).await?;
                let resolved = prepared.resolved();
                let grants = std::iter::once((&grant, PackageActionV1::Install, None))
                    .chain(
                        prepared
                            .images()
                            .map(|image| (&grant, PackageActionV1::Install, Some(image))),
                    )
                    .collect::<Vec<_>>();
                self.authority.commit_many(&grants, &mut || {
                    self.query
                        .store()
                        .admit_definition(*tenant, resolved, || control.check())?;
                    Ok(())
                })?;
                if let Some(current) =
                    self.query
                        .store()
                        .managed_instance(*tenant, &definition.name, &control)?
                {
                    if current.grant != grant
                        || current.spec.definition != *resolved
                        || current.spec.destination != araphor_data::ManagedDestination::Selected
                    {
                        return Err(Code::Conflict
                            .error("configured Definition instance pin")
                            .into());
                    }
                    continue;
                }
                let instance = Instance::admit(
                    Arc::clone(&self.query),
                    self.authority.clone(),
                    grant.clone(),
                    definition.name.clone(),
                    resolved.clone(),
                    &control,
                )
                .await?;
                let lifecycle = instance.admitted().lifecycle;
                self.instances.start(instance, lifecycle, &control).await?;
            }
        }
        Ok(())
    }
}
