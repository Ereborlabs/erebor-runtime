use super::*;

impl crate::GraphProgram {
    pub fn images() -> Vec<araphor_data::PackageBundleV1> {
        [
            (
                Detector::Process,
                araphor_analysis_builtins::components::PROCESS,
            ),
            (
                Detector::Credentials,
                araphor_analysis_builtins::components::CREDENTIALS,
            ),
            (
                Detector::Kubernetes,
                araphor_analysis_builtins::components::KUBERNETES,
            ),
        ]
        .into_iter()
        .map(|(detector, component)| {
            let descriptor = detector.descriptor();
            let artifact = araphor_data::PackageArtifactV1 {
                implementations: vec![araphor_data::PackageImplementationV1::Wasm {
                    exports: descriptor
                        .exports
                        .iter()
                        .map(|model| model.name.clone())
                        .collect(),
                    artifact: component.to_vec(),
                }],
                descriptor,
                fixtures: Vec::new(),
            };
            araphor_data::PackageBundleV1 {
                schema_version: 1,
                root: artifact.reference(),
                artifacts: vec![artifact],
            }
        })
        .collect()
    }

    pub async fn prepare(
        session: Session,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        events_sql: String,
        definition: Definition,
        facts: Arc<dyn GraphFacts>,
    ) -> Result<Self> {
        let events = session.engine().prepare(&events_sql, Vec::new()).await?.0;
        let publication =
            GraphPublication::prepare(session, authority, grant.clone(), events, definition, facts)
                .await?;
        Ok(Self {
            grant,
            definition: publication.prepared.resolved().clone(),
            events_sql,
        })
    }
}
