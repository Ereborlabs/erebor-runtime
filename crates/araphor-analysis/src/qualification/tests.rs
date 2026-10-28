use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use araphor_data::{AnalysisSelectionV1, AnalysisStore};
use araphor_package::{PackageArtifactV1, PackageBundleV1, PackageImplementationV1, SqlModelV1};
use sdk::arrow_array::{StringArray, UInt64Array};

mod artifact;
mod authority;
mod cancellation;
mod runtime;
mod sql;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Authority {
    digest: String,
    checks: AtomicUsize,
    deny_at: AtomicUsize,
    changes: tokio::sync::watch::Sender<u64>,
}

impl PackageAuthorization for Authority {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        let count = self.checks.fetch_add(1, Ordering::SeqCst) + 1;
        if action != PackageActionV1::Test
            || grant.principal != "fixture"
            || count >= self.deny_at.load(Ordering::SeqCst)
        {
            return Err(Code::Denied.error("fixture authority"));
        }
        grant.remaining().map(|_| ())
    }

    fn admit(&self, _: &PackageGrantV1, bundle: &PackageBundle) -> araphor_data::Result<()> {
        if bundle.digest() != self.digest {
            return Err(Code::Denied.error("fixture trust"));
        }
        Ok(())
    }

    fn commit(
        &self,
        _: &PackageGrantV1,
        _: PackageActionV1,
        _: &PackageBundle,
        _: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        Err(Code::Denied.error("fixture commit"))
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

struct Fixture {
    owner: Qualification,
    grant: PackageGrantV1,
    authority: Arc<Authority>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(bundle: &PackageBundleV1) -> TestResult<Self> {
        Self::limits(bundle, Default::default())
    }

    fn limits(
        bundle: &PackageBundleV1,
        limits: araphor_query::execution::Limits,
    ) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let admitted =
            PackageBundle::try_from(bundle.clone()).map_err(araphor_data::Error::from)?;
        store.install_package_image([1; 16], &admitted, || Ok(()))?;
        let query = Engine::new(store, limits)?;
        let authority = Arc::new(Authority {
            digest: admitted.digest().into(),
            checks: AtomicUsize::new(0),
            deny_at: AtomicUsize::new(usize::MAX),
            changes: tokio::sync::watch::channel(0).0,
        });
        Ok(Self {
            owner: Qualification::new(query, authority.clone()),
            grant: PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant([1; 16]),
                expires_utc_ns: None,
                authorization_id: None,
            },
            authority,
            _directory: directory,
        })
    }

    async fn run(&self, bundle: &PackageBundleV1) -> Result<Vec<FixtureResult>> {
        self.owner
            .run(
                &self.grant,
                &bundle.root,
                None,
                &AnalysisReadControl::default(),
            )
            .await
    }

    fn schema() -> sdk::Schema {
        sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)])
    }

    fn data(name: &str, values: &[u64]) -> TestResult<sdk::Dataset> {
        Ok(sdk::Dataset {
            name: name.into(),
            batches: vec![sdk::RecordBatch::try_new(
                Arc::new(Self::schema()),
                vec![Arc::new(UInt64Array::from(values.to_vec()))],
            )?],
        })
    }

    fn evaluation(model: &sdk::Model) -> sdk::Evaluation {
        sdk::Evaluation {
            previous_outputs: Vec::new(),
            export: model.name.clone(),
            inputs: Vec::new(),
            parameters: None,
            context: sdk::EvaluationContext {
                id: "case".into(),
                time_utc_ns: 0,
                seed: Some(u64::MAX),
            },
            checkpoint: None,
        }
    }

    fn save(
        bundle: &mut PackageBundleV1,
        evaluation: &sdk::Evaluation,
        expected: &sdk::Output,
        parameters: Option<serde_json::Value>,
    ) -> TestResult {
        let artifact = &mut bundle.artifacts[0];
        let descriptor = &artifact.descriptor;
        let checked = descriptor.check_evaluation(evaluation)?;
        let wire = checked.encode()?;
        let saved = PackageFixtureV1 {
            previous_outputs: wire.previous_outputs,
            name: evaluation.context.id.clone(),
            export: evaluation.export.clone(),
            time_utc_ns: evaluation.context.time_utc_ns,
            seed: evaluation.context.seed,
            inputs: wire.inputs,
            parameters,
            checkpoint: wire.checkpoint,
            expected: sdk::wire::Output::encode(descriptor, evaluation, expected)?,
        };
        artifact.fixtures.push(saved);
        Ok(())
    }

    fn bundle(target: &str, model: sdk::Model, sql: SqlModelV1) -> TestResult<PackageBundleV1> {
        let export = model.name.clone();
        let implementation = match target {
            "sql" => PackageImplementationV1::Sql {
                export,
                program: sql,
            },
            "wasm" => PackageImplementationV1::Wasm {
                exports: vec![export],
                artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
            },
            "native" => {
                let directory = std::path::PathBuf::from(
                    std::env::var_os("ARAPHOR_NATIVE_DIR")
                        .ok_or("ARAPHOR_NATIVE_DIR is required")?,
                );
                let artifact = std::fs::read(
                    directory.join(format!("runtime.{}", std::env::consts::DLL_EXTENSION)),
                )?;
                let qualification = araphor_package::Qualification::inspect(
                    &artifact,
                    vec![export.clone()],
                    std::env::var("ARAPHOR_NATIVE_TARGET")?,
                )?;
                PackageImplementationV1::Native {
                    export,
                    artifact,
                    qualification: Some(qualification),
                }
            }
            _ => return Err("unknown target".into()),
        };
        Ok(PackageBundleV1 {
            schema_version: 1,
            root: PackageRefV1 {
                package_id: "runtime-fixture".into(),
                revision: "1".into(),
            },
            artifacts: vec![PackageArtifactV1 {
                descriptor: sdk::Package::new("runtime-fixture", "1", vec![model]),
                implementations: vec![implementation],
                fixtures: Vec::new(),
            }],
        })
    }
}
