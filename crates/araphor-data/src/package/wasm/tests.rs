use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use crate::{query::WasmLimits, AnalysisReadControl};

use super::{admission::CompileBudget, execution::EvaluationPermit, WasmExecution};

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

mod runtime;

#[test]
fn admission_requires_analysis_contract() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits {
        memory_bytes: Some(256 * 1024 * 1024),
        ..WasmLimits::default()
    })?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(10))?;
    for source in [
        "(component)",
        "(component (import \"wasi:filesystem/types@0.2.0\" (instance)))",
        "(component (component (component)))",
    ] {
        let bytes = wat::parse_str(source)?;
        assert!(runtime.admit(&bytes, &control).is_err(), "{source}");
    }
    let bytes = wat::parse_str(
        "(component (core module $large (memory 4097)) (core instance (instantiate $large)))",
    )?;
    assert!(matches!(
        runtime.admit(&bytes, &control),
        Err(crate::Error::Package {
            code: super::Code::Limit,
            ..
        })
    ));
    assert!(runtime.admit(b"not a component", &control).is_err());
    assert!(runtime
        .admit(&wat::parse_str("(module)")?, &control)
        .is_err());
    Ok(())
}

#[test]
fn sdk_components_pass_admission() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits::default())?;
    let components: [(&str, &[u8]); 5] = [
        (
            "discovery",
            include_bytes!("../../../../araphor-analysis-builtins/artifacts/discovery.wasm"),
        ),
        (
            "process",
            include_bytes!("../../../../araphor-analysis-builtins/artifacts/process.wasm"),
        ),
        (
            "credentials",
            include_bytes!("../../../../araphor-analysis-builtins/artifacts/credentials.wasm"),
        ),
        (
            "kubernetes",
            include_bytes!("../../../../araphor-analysis-builtins/artifacts/kubernetes.wasm"),
        ),
        (
            "detector-example",
            include_bytes!("../../../../araphor-detector-example/artifacts/detector.wasm"),
        ),
    ];
    for (name, bytes) in components {
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(45))?;
        let result = runtime.admit(bytes, &control);
        assert!(result.is_ok(), "{name}: {result:?}");
    }
    Ok(())
}

#[test]
fn admission_bounds_compile_work() -> TestResult {
    let control = AnalysisReadControl::default();
    let body = "nop ".repeat(65_536);
    let bytes = wat::parse_str(format!("(component (core module (func {body})))"))?;
    assert!(CompileBudget::check(&bytes, &control).is_err());
    let bytes = wat::parse_str("(component (core module (func (local i32))))")?;
    CompileBudget::check(&bytes, &control)?;
    let instances = "(core instance (instantiate $empty))".repeat(17);
    let bytes = wat::parse_str(format!("(component (core module $empty) {instances})"))?;
    assert!(matches!(
        CompileBudget::check(&bytes, &control),
        Err(crate::Error::Package {
            code: super::Code::Limit,
            ..
        })
    ));
    let bytes = wat::parse_str("(component (core module (func (local i32))))")?;
    control.cancel()?;
    assert!(matches!(
        CompileBudget::check(&bytes, &control),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}

#[test]
fn evaluation_capacity_recovers() -> TestResult {
    let running = AtomicUsize::new(0);
    let permits = (0..4)
        .map(|_| EvaluationPermit::acquire(&running))
        .collect::<crate::Result<Vec<_>>>()?;
    assert!(matches!(
        EvaluationPermit::acquire(&running),
        Err(crate::Error::AnalysisBusy { .. })
    ));
    drop(permits);
    let _permit = EvaluationPermit::acquire(&running)?;
    Ok(())
}
