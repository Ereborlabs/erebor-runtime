use super::*;
use araphor_analysis::{GraphOwner, GraphProgram, GraphPublication};
use araphor_data::{AnalysisReadControl, PackageBundleRef};
use araphor_discovery_definition::{Definition, Program, Source};

impl ControlPackages {
    pub(crate) fn graph(self: &Arc<Self>) -> crate::Result<GraphOwner> {
        let owner = Arc::clone(self);
        self.query
            .wait(async move { Ok(owner.prepare_graph().await) })?
    }

    async fn prepare_graph(self: Arc<Self>) -> crate::Result<GraphOwner> {
        let facts = self.facts.as_ref().cloned().ok_or_else(|| {
            crate::error::InvalidConfigurationSnafu {
                reason: "graph processing requires the Control store",
            }
            .build()
        })?;
        let control = Arc::new(AnalysisReadControl::default());
        let images = GraphProgram::images()
            .into_iter()
            .map(|bundle| {
                let digest = bundle.digest().map_err(araphor_data::Error::from)?;
                Ok((bundle, digest))
            })
            .collect::<araphor_data::Result<Vec<_>>>()?;
        let mut programs = Vec::new();
        for tenant in self.authority.tenants.keys() {
            let Some(grant) = self.authority.graph_grant(*tenant) else {
                continue;
            };
            for (bundle, digest) in &images {
                let retained = PackageBundleRef::retained(bundle, digest);
                self.authority
                    .commit(&grant, PackageActionV1::Install, &retained, &mut || {
                        self.query
                            .store()
                            .install_package_image(*tenant, bundle, || control.check())?;
                        Ok(())
                    })?;
            }
            let definition = Definition {
                name: "mithril-control-graph".into(),
                description: "Run the configured Graph detector calls.".into(),
                labels: BTreeMap::new(),
                program: Program::Sql {
                    source: Source::Inline {
                        inline: include_str!("graph-calls.sql").into(),
                    },
                },
            };
            let program = GraphProgram::prepare(
                self.query.session(grant.selection.clone(), &control, 0)?,
                self.authority.clone(),
                grant.clone(),
                include_str!("graph-events.sql").into(),
                definition,
                Arc::clone(&facts),
            )
            .await?;
            if program.definition.images.len() != images.len()
                || program.definition.images.iter().any(|pin| {
                    !images
                        .iter()
                        .any(|(bundle, digest)| bundle.root == pin.image && *digest == pin.digest)
                })
            {
                return Err(crate::error::InvalidConfigurationSnafu {
                    reason: "the configured Graph definition has different image pins",
                }
                .build());
            }
            let expiry = self
                .query
                .admit_definition(
                    *tenant,
                    GraphPublication::expiry_program(),
                    Arc::clone(&control),
                )
                .await?;
            for definition in [&program.definition, &expiry] {
                let retained = images
                    .iter()
                    .filter(|(bundle, digest)| {
                        definition
                            .images
                            .iter()
                            .any(|pin| pin.image == bundle.root && pin.digest == *digest)
                    })
                    .map(|(bundle, digest)| PackageBundleRef::retained(bundle, digest))
                    .collect::<Vec<_>>();
                let mut grants = vec![(&grant, PackageActionV1::Install, None)];
                grants.extend(
                    retained
                        .iter()
                        .map(|image| (&grant, PackageActionV1::Install, Some(image))),
                );
                self.authority.commit_many(&grants, &mut || {
                    self.query
                        .store()
                        .admit_definition(*tenant, definition, || {
                            control.check()?;
                            grant.remaining().map(|_| ())
                        })?;
                    Ok(())
                })?;
            }
            programs.push(program);
        }
        GraphOwner::new(
            Arc::clone(&self.query),
            Arc::clone(&self.instances),
            self.authority.clone(),
            programs,
            &control,
        )
        .await
        .map_err(Into::into)
    }
}
