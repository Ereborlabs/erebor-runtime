use std::{error::Error, sync::Arc, time::Duration};

use araphor_analysis_builtins::discovery as builtin;
use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisPackageOwner, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore,
    InstalledAnalysis, PackageActionV1, PackageArtifactV1, PackageAuthorization, PackageBundleV1,
    PackageGrantV1, PackageImplementationV1, PackageRequestV1, QueryLimits, QueryOwner,
};
use sdk::arrow_array::cast::AsArray as _;
use tokio::sync::watch;

const COMPONENT: &[u8] = araphor_analysis_builtins::components::RUNTIME;
const SCOPE: &str = "qualified-context";

pub(super) struct ContextComponent {
    execution: InstalledAnalysis,
    tenant: [u8; 16],
    limits: sdk::Limits,
}

struct Authority {
    grant: PackageGrantV1,
    digest: String,
    changes: watch::Sender<u64>,
}

impl ContextComponent {
    pub(super) async fn install(
        store: Arc<AnalysisStore>,
        tenant: [u8; 16],
    ) -> Result<Self, Box<dyn Error>> {
        let port = builtin::Discovery::port::<builtin::ContextSelection>("context");
        let metadata = sdk::Port::new(
            "metadata",
            sdk::Schema::new(vec![
                sdk::Field::new("dataset", sdk::DataType::Utf8, false),
                sdk::Field::new("revision", sdk::DataType::Utf8, false),
                sdk::Field::new("coverage", sdk::DataType::Utf8, false),
            ]),
        );
        let model = sdk::Model::new("echo-inputs", vec![port.clone()], vec![port, metadata]);
        let limits = model.limits;
        let descriptor = sdk::Package::new("context-fixture", "1", vec![model]);
        let artifact = PackageArtifactV1 {
            descriptor,
            implementations: vec![PackageImplementationV1::Wasm {
                exports: vec!["echo-inputs".into()],
                artifact: COMPONENT.to_vec(),
            }],
            fixtures: Vec::new(),
        };
        let bundle = PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        };
        let grant = PackageGrantV1 {
            principal: "context-qualification".into(),
            revision: 1,
            selection: AnalysisSelectionV1::tenant(tenant),
            expires_utc_ns: None,
            authorization_id: None,
        };
        let authority = Arc::new(Authority {
            grant: grant.clone(),
            digest: bundle.digest()?,
            changes: watch::channel(1).0,
        });
        let query = Arc::new(QueryOwner::new(store.clone(), QueryLimits::default())?);
        let owner = Arc::new(AnalysisPackageOwner::new(store, query, authority)?);
        owner
            .execute(
                grant,
                PackageRequestV1::Install {
                    scope_id: SCOPE.into(),
                    bundle,
                    parameters: None,
                },
                Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(60))?),
            )
            .await?;
        Ok(Self {
            execution: InstalledAnalysis::new(owner, SCOPE)?,
            tenant,
            limits,
        })
    }

    pub(super) fn evaluate(&self, input: &sdk::Input) -> Result<sdk::Input, Box<dyn Error>> {
        let evaluation = sdk::Evaluation {
            export: "echo-inputs".into(),
            inputs: vec![input.clone()],
            parameters: None,
            context: sdk::EvaluationContext {
                id: input.revision.id.clone(),
                time_utc_ns: 3000,
                seed: Some(7),
                limits: self.limits,
            },
            checkpoint: None,
        };
        let result = self.execution.evaluate(
            self.tenant,
            "context-fixture",
            &evaluation,
            &AnalysisReadControl::with_timeout(Duration::from_secs(60))?,
        )?;
        let dataset = |name: &str| {
            result
                .output
                .datasets
                .iter()
                .find(|data| data.name == name)
                .ok_or("component context dataset is absent")
        };
        let data = dataset("context")?;
        let metadata = dataset("metadata")?;
        if data.batches != input.data.batches
            || metadata.batches.len() != 1
            || metadata.batches[0].num_rows() != 1
        {
            return Err("the installed component changed context rows".into());
        }
        let metadata = &metadata.batches[0];
        if metadata.column(0).as_string::<i32>().value(0) != "context" {
            return Err("the installed component changed the context name".into());
        }
        let revision: sdk::Revision =
            serde_json::from_str(metadata.column(1).as_string::<i32>().value(0))?;
        let coverage: sdk::Coverage =
            serde_json::from_str(metadata.column(2).as_string::<i32>().value(0))?;
        if revision != input.revision || coverage != input.coverage {
            return Err("the installed component changed context revision or coverage".into());
        }
        Ok(sdk::Input {
            data: data.clone(),
            revision,
            coverage,
        })
    }
}

impl Authority {
    fn denied() -> araphor_data::Error {
        araphor_data::Error::QueryDenied {
            location: snafu::Location::default(),
        }
    }
}

impl PackageAuthorization for Authority {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        if grant != &self.grant
            || !matches!(
                action,
                PackageActionV1::Install | PackageActionV1::Run | PackageActionV1::Inspect
            )
        {
            return Err(Self::denied());
        }
        Ok(())
    }

    fn admit(
        &self,
        grant: &PackageGrantV1,
        bundle: &araphor_data::PackageBundleRef<'_>,
    ) -> araphor_data::Result<()> {
        self.check(grant, PackageActionV1::Run)?;
        if bundle.digest() != self.digest {
            return Err(Self::denied());
        }
        Ok(())
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &araphor_data::PackageBundleRef<'_>,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.check(grant, action)?;
        self.admit(grant, bundle)?;
        operation()
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}
