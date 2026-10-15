use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sdk::arrow_array::UInt64Array;

use crate::package::tests::{Authority, Fixture, TestResult};
use crate::package::{
    PackageArtifactV1, PackageAuthorization, PackageBundleV1, PackageGrantV1,
    PackageImplementationV1, PackageRequestV1,
};
use crate::{AnalysisReadControl, QueryLimits, QueryOwner};

use super::*;

mod descriptors;
mod retained;

struct SelectionAuthority {
    base: Arc<Authority>,
    expected: PackageBundleV1,
    checks: AtomicUsize,
    admissions: AtomicUsize,
}

impl PackageAuthorization for SelectionAuthority {
    fn check(&self, grant: &PackageGrantV1, action: Action) -> Result<()> {
        self.base.check(grant, action)?;
        if grant.principal == "unrelated" {
            return Err(Code::Denied.error("unrelated fixture grant"));
        }
        if action == Action::Run {
            self.checks.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }

    fn admit(&self, grant: &PackageGrantV1, bundle: &PackageBundleV1) -> Result<()> {
        self.base.admit(grant, bundle)?;
        self.check(grant, Action::Run)?;
        if bundle.schema_version != self.expected.schema_version
            || bundle.root != self.expected.root
            || bundle.artifacts != self.expected.artifacts
        {
            return Err(Code::Denied.error("selected fixture bundle"));
        }
        self.admissions.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: Action,
        bundle: &PackageBundleV1,
        operation: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.check(grant, action)?;
        self.admit(grant, bundle)?;
        operation()
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.base.changes()
    }
}

fn component() -> PackageBundleV1 {
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
    let mut model = sdk::Model::new(
        "count-input",
        vec![sdk::Port::new("input", schema.clone())],
        vec![sdk::Port::new("data", schema.clone())],
    );
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    let mut descriptor = sdk::Package::new("runtime-fixture", "1", vec![model]);
    descriptor.exports[0].inputs[0].source =
        sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "test.model".into(),
            revision: "1".into(),
            export: "count".into(),
            output: "rows".into(),
        }));
    let mut source = crate::package::tests::bundle("1", "SELECT 7::UBIGINT AS value")
        .artifacts
        .remove(0);
    source.descriptor.exports[0].outputs[0].schema = schema;
    let root = PackageArtifactV1 {
        descriptor,
        implementations: vec![PackageImplementationV1::Wasm {
            exports: vec!["count-input".into()],
            artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
        }],
        fixtures: Vec::new(),
    };
    PackageBundleV1 {
        schema_version: 1,
        root: root.reference(),
        artifacts: vec![root, source],
    }
}

fn evaluation(selected: &PackageBundleV1) -> sdk::Result<sdk::Evaluation> {
    let model = &selected.artifacts[0].descriptor.exports[0];
    Ok(sdk::Evaluation {
        export: model.name.clone(),
        inputs: vec![sdk::Input {
            data: sdk::Dataset {
                name: "input".into(),
                batches: vec![sdk::RecordBatch::try_new(
                    Arc::new(model.inputs[0].port.schema.clone()),
                    vec![Arc::new(UInt64Array::from(vec![7]))],
                )?],
            },
            revision: sdk::Revision {
                owner: "fixture".into(),
                id: "selected".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        }],
        parameters: None,
        context: sdk::EvaluationContext {
            id: "selected".into(),
            time_utc_ns: 0,
            seed: None,
            limits: model.limits,
        },
        checkpoint: None,
    })
}

#[test]
fn exact_export_checks_bundle() -> TestResult {
    let fixture = Fixture::new()?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    let selected = component();
    fixture.owner.execute_sync(
        fixture.grant.clone(),
        PackageRequestV1::Install {
            scope_id: "test".into(),
            bundle: selected.clone(),
            parameters: Some(serde_json::json!({
                "runtime-fixture": {"count-input": {"mode": "sum-input", "amount": 0}}
            })),
        },
        &control,
    )?;
    let unrelated = AnalysisPackageOwner::required_bundles()
        .into_iter()
        .nth(1)
        .ok_or("unrelated component")?;
    let mut grant = fixture.grant.clone();
    grant.principal = "unrelated".into();
    fixture.owner.execute_sync(
        grant,
        PackageRequestV1::Install {
            scope_id: "test".into(),
            bundle: unrelated,
            parameters: None,
        },
        &control,
    )?;
    let authority = Arc::new(SelectionAuthority {
        base: fixture.authority.clone(),
        expected: selected.clone(),
        checks: AtomicUsize::new(0),
        admissions: AtomicUsize::new(0),
    });
    let query = Arc::new(QueryOwner::new(
        fixture.store.clone(),
        QueryLimits {
            evaluate_timeout: Duration::from_secs(30),
            ..Default::default()
        },
    )?);
    let mut owner = AnalysisPackageOwner::new(fixture.store.clone(), query, authority.clone())?;
    owner.prepare_test_code()?;
    let execution = InstalledAnalysis::new(Arc::new(owner), "test")?;
    let evaluation = evaluation(&selected)?;
    let result = execution.evaluate([1; 16], &selected.root.package_id, &evaluation, &control)?;
    assert_eq!(result.descriptor, selected.artifacts[0].descriptor);
    assert_eq!(result.revision, selected.root.revision);
    let values = result.output.datasets[0].batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("selected component output")?;
    assert_eq!(values.values().as_ref(), &[7]);
    assert_eq!(authority.admissions.load(Ordering::SeqCst), 2);
    assert_eq!(authority.checks.load(Ordering::SeqCst), 4);
    drop(result);
    assert!(matches!(
        execution.snapshot([1; 16]),
        Err(crate::Error::Package {
            code: Code::Denied,
            field: "unrelated fixture grant",
            ..
        })
    ));
    let mut unprepared = evaluation.clone();
    unprepared.export = "count".into();
    assert!(matches!(
        execution.evaluate([1; 16], "test.model", &unprepared, &control),
        Err(crate::Error::Package {
            code: Code::Unsupported,
            field: "host-prepared target",
            ..
        })
    ));
    fixture.authority.set_revision(0);
    assert!(matches!(
        execution.evaluate([1; 16], &selected.root.package_id, &evaluation, &control),
        Err(crate::Error::Package {
            code: Code::Denied,
            field: "fixture grant",
            ..
        })
    ));
    Ok(())
}
