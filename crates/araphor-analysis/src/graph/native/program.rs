use super::*;

impl crate::GraphProgram {
    pub(crate) async fn admit(
        &self,
        authority: Arc<dyn PackageAuthorization>,
        id: String,
        source: araphor_data::EvidenceIntakeIdentityV1,
        revision: u64,
        control: &araphor_data::AnalysisReadControl,
    ) -> Result<Arc<crate::Instance>> {
        let destination = araphor_data::ManagedDestination::Graph {
            source,
            events_sql: self.events_sql.clone(),
            control_sql: self.control_sql.clone(),
            calls: self.publication.calls.keys().copied().collect(),
            operation: araphor_data::ManagedGraphOperation::Evaluate,
        };
        let session = self.publication.session.operation_at(
            destination.selection(&self.grant.selection)?,
            control,
            0,
        )?;
        let prepared = self.publication.prepared.clone();
        let query = Arc::clone(session.engine());
        let read = Arc::new(control.within(self.grant.remaining()?)?);
        let stage = Arc::clone(&read);
        let prepared = araphor_query::execution::Engine::blocking(read, (), move || {
            prepared.bind_revision(&query, revision, &stage)
        })
        .await?;
        crate::Instance::admit_graph(
            session,
            authority,
            self.grant.clone(),
            id,
            prepared,
            destination,
            Arc::clone(&self.publication),
        )
        .await
    }

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
        control_sql: String,
        definition: Definition,
        facts: Arc<dyn GraphFacts>,
    ) -> Result<Self> {
        let publication = Arc::new(
            GraphPublication::prepare_program(
                session,
                authority,
                grant.clone(),
                &events_sql,
                &control_sql,
                DefinitionRef::Fresh(&definition),
                facts,
            )
            .await?,
        );
        Ok(Self {
            grant,
            definition: publication.prepared.resolved().clone(),
            events_sql,
            control_sql,
            publication,
        })
    }
}
