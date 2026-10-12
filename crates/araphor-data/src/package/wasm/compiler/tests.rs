use std::sync::mpsc;
use std::time::Duration;

use crate::{AnalysisPackageOwner, AnalysisReadControl};

use super::{CompilerChild, MAX_ADDRESS_BYTES, TEST_ENTRY};

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

const BLOCKING_ENTRY: &str = "package::wasm::compiler::tests::araphor_component_compiler_blocking";
const MEMORY_ENTRY: &str = "package::wasm::compiler::tests::araphor_component_compiler_memory";
const CPU_ENTRY: &str = "package::wasm::compiler::tests::araphor_component_compiler_cpu";

#[test]
#[ignore]
fn araphor_component_compiler() -> TestResult {
    AnalysisPackageOwner::run_compiler_worker()?;
    Ok(())
}

#[test]
#[ignore]
fn araphor_component_compiler_blocking() -> TestResult {
    super::WasmExecution::worker_limits()?;
    std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink())?;
    loop {
        std::thread::park();
    }
}

#[test]
#[ignore]
fn araphor_component_compiler_memory() -> TestResult {
    super::WasmExecution::worker_limits()?;
    super::input::CompilerInput::read(std::io::stdin().lock())?.request()?;
    let mut allocation = Vec::<u8>::new();
    assert!(allocation
        .try_reserve_exact(MAX_ADDRESS_BYTES as usize + 1)
        .is_err());
    super::image::CompilerImage::write(
        &Err(super::Code::Limit.error("component compiler memory fixture")),
        std::io::stderr().lock(),
    )?;
    Ok(())
}

#[test]
#[ignore]
fn araphor_component_compiler_cpu() -> TestResult {
    use rustix::process::{setrlimit, Resource, Rlimit};

    super::WasmExecution::worker_limits()?;
    super::input::CompilerInput::read(std::io::stdin().lock())?.request()?;
    setrlimit(
        Resource::Cpu,
        Rlimit {
            current: Some(1),
            maximum: Some(1),
        },
    )?;
    loop {
        std::hint::black_box(1u64.wrapping_add(1));
    }
}

#[test]
fn compiler_enforces_os_limits() -> TestResult {
    let runtime = super::WasmExecution::new(crate::query::WasmLimits::default())?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(5))?;
    let mut failed = false;
    let image = CompilerChild::capture(MEMORY_ENTRY, &[], false, &control, &mut failed, None)?;
    assert!(matches!(
        image.component(&runtime.engine),
        Err(crate::Error::PackageWasm {
            code: super::Code::Limit,
            ..
        })
    ));
    assert!(matches!(
        CompilerChild::capture(CPU_ENTRY, &[], false, &control, &mut failed, None),
        Err(crate::Error::PackageWasm {
            code: super::Code::Limit,
            ..
        })
    ));
    assert!(!failed);
    Ok(())
}

#[test]
fn compiler_reaps_interrupted_children() -> TestResult {
    for cancel in [true, false] {
        let control = AnalysisReadControl::with_timeout(Duration::from_millis(200))?;
        let (entered, entered_rx) = mpsc::channel();
        let mut failed = false;
        let (result, pid) = std::thread::scope(
            |scope| -> std::result::Result<_, Box<dyn std::error::Error + Send + Sync>> {
                let control_worker = &control;
                let failed_worker = &mut failed;
                let worker = scope.spawn(move || {
                    CompilerChild::capture(
                        BLOCKING_ENTRY,
                        &[],
                        false,
                        control_worker,
                        failed_worker,
                        Some(entered),
                    )
                });
                let pid = entered_rx.recv_timeout(Duration::from_secs(5))?;
                if cancel {
                    control.cancel()?;
                }
                Ok((worker.join().map_err(|_| "compiler test thread")?, pid))
            },
        )?;
        assert!(!failed);
        if cancel {
            assert!(matches!(
                result,
                Err(crate::Error::AnalysisReadCancelled { .. })
            ));
        } else {
            assert!(matches!(
                result,
                Err(crate::Error::AnalysisReadDeadline { .. })
            ));
        }
        let pid = rustix::process::Pid::from_raw(pid as i32).ok_or("compiler child pid")?;
        assert_eq!(
            rustix::process::test_kill_process(pid),
            Err(rustix::io::Errno::SRCH)
        );
        let image = CompilerChild::capture(
            TEST_ENTRY,
            &wat::parse_str("(component)")?,
            false,
            &AnalysisReadControl::default(),
            &mut failed,
            None,
        )?;
        let runtime = super::WasmExecution::new(crate::query::WasmLimits::default())?;
        image.component(&runtime.engine)?;
    }
    Ok(())
}

#[test]
fn installation_rejects_native_images() -> TestResult {
    let runtime = super::WasmExecution::new(crate::query::WasmLimits::default())?;
    let mut failed = false;
    let image = CompilerChild::capture(
        TEST_ENTRY,
        &wat::parse_str("(component)")?,
        false,
        &AnalysisReadControl::default(),
        &mut failed,
        None,
    )?;
    assert!(matches!(
        runtime.admit(image.native_image()?, &AnalysisReadControl::default()),
        Err(crate::Error::Package {
            code: super::Code::Invalid,
            ..
        })
    ));
    Ok(())
}

#[test]
fn compiler_requires_worker_dispatch() -> TestResult {
    let runtime = super::WasmExecution::new(crate::query::WasmLimits::default())?;
    let mut failed = false;
    let image = CompilerChild::capture(
        "missing_component_compiler",
        &[],
        false,
        &AnalysisReadControl::with_timeout(Duration::from_secs(5))?,
        &mut failed,
        None,
    )?;
    assert!(matches!(
        image.component(&runtime.engine),
        Err(crate::Error::PackageWasm {
            code: super::Code::Incomplete,
            ..
        })
    ));
    assert!(!failed);
    Ok(())
}
