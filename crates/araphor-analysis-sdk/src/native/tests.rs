use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arrow_array::UInt64Array;

use super::*;
use crate::guest::Guest;
use crate::{CheckpointSpec, DataType, Field, Port, RecordBatch, Schema};

use crate::tests::sensitive_access::SensitiveAccess;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

struct Detector;

impl Guest for Detector {
    fn package() -> Package {
        let mut package = SensitiveAccess::package();
        let schema = Schema::new(vec![Field::new("count", DataType::UInt64, false)]);
        package.exports[0].parameters = schema.clone();
        package.exports[0].checkpoint = Some(CheckpointSpec {
            version: 3,
            datasets: vec![Port::new("state", schema)],
        });
        package
    }

    fn evaluate(evaluation: &Evaluation) -> Result<Output> {
        assert_eq!(evaluation.context.time_utc_ns, -55);
        assert_eq!(evaluation.context.seed, Some(u64::MAX));
        assert_eq!(
            evaluation.inputs[0]
                .revision
                .window
                .as_ref()
                .map(|window| window.start_utc_ns),
            Some(-100)
        );
        let mut output = SensitiveAccess::evaluate(evaluation)?;
        let state = evaluation
            .parameters
            .as_ref()
            .ok_or_else(|| Error::contract(ErrorCode::Invalid, "parameters"))?
            .clone();
        output.checkpoint = Some(crate::Checkpoint {
            version: 3,
            datasets: vec![crate::Dataset {
                name: "state".into(),
                batches: vec![state],
            }],
        });
        Ok(output)
    }
}

fn evaluation() -> Result<Evaluation> {
    let mut value = SensitiveAccess::fixture()?.evaluation;
    value.context.time_utc_ns = -55;
    value.context.seed = Some(u64::MAX);
    value.inputs[0].revision.window = Some(crate::SourceWindow {
        source: vec![0, 255],
        start_utc_ns: -100,
        end_utc_ns: 0,
    });
    value.parameters = Some(RecordBatch::try_new(
        Arc::new(Detector::package().exports[0].parameters.clone()),
        vec![Arc::new(UInt64Array::from(vec![u64::MAX]))],
    )?);
    Ok(value)
}

#[test]
fn native_parity_and_checkpoint() -> TestResult {
    let package = Detector::package();
    let mut value = evaluation()?;
    let expected = Detector::evaluate(&value)?;
    let result = unsafe {
        Invocation::new(&package, &value, || false)?
            .call(&Api::for_guest::<Detector>(), value.context.limits)?
    };
    assert_eq!(result.datasets.len(), expected.datasets.len());
    for (actual, expected) in result.datasets.iter().zip(&expected.datasets) {
        assert_eq!(actual.name, expected.name);
        assert_eq!(actual.batches, expected.batches);
    }
    assert_eq!(result.evidence, expected.evidence);
    assert_eq!(result.reasons.len(), expected.reasons.len());
    for (actual, expected) in result.reasons.iter().zip(&expected.reasons) {
        assert_eq!(actual.output, expected.output);
        assert_eq!(actual.code, expected.code);
        assert_eq!(actual.details, expected.details);
    }
    let actual = result.checkpoint.as_ref().ok_or("native checkpoint")?;
    let expected = expected.checkpoint.as_ref().ok_or("direct checkpoint")?;
    assert_eq!(actual.version, expected.version);
    assert_eq!(actual.datasets[0].name, expected.datasets[0].name);
    assert_eq!(actual.datasets[0].batches, expected.datasets[0].batches);
    value.checkpoint = result.checkpoint;
    let result = unsafe {
        Invocation::new(&package, &value, || false)?
            .call(&Api::for_guest::<Detector>(), value.context.limits)?
    };
    assert_eq!(result.reasons.len(), 2);
    drop(value);
    assert_eq!(result.datasets[0].batches[0].num_rows(), 2);
    Ok(())
}

struct CheckedDetector<const INVALID: bool>;

impl<const INVALID: bool> Guest for CheckedDetector<INVALID> {
    fn package() -> Package {
        Detector::package()
    }

    fn evaluate(_evaluation: &Evaluation) -> Result<Output> {
        Err(Error::contract(ErrorCode::Failed, "unchecked guest entry"))
    }

    fn evaluate_checked(checked: &crate::CheckedEvaluation<'_>) -> Result<Output> {
        assert_eq!(checked.model().name, checked.evaluation().export);
        let mut output = Detector::evaluate(checked.evaluation())?;
        if INVALID {
            output.evidence.clear();
        }
        Ok(output)
    }
}

#[test]
fn checked_guest_keeps_output_boundary() -> TestResult {
    let package = Detector::package();
    let value = evaluation()?;
    let output = unsafe {
        Invocation::new(&package, &value, || false)?.call(
            &Api::for_guest::<CheckedDetector<false>>(),
            value.context.limits,
        )?
    };
    assert_eq!(output.evidence, Detector::evaluate(&value)?.evidence);
    let error = unsafe {
        Invocation::new(&package, &value, || false)?.call(
            &Api::for_guest::<CheckedDetector<true>>(),
            value.context.limits,
        )
    }
    .err()
    .ok_or("unchecked output accepted")?;
    assert_eq!(error.code(), ErrorCode::Incomplete);
    Ok(())
}

#[test]
fn release_success_failure_and_repeat() -> TestResult {
    let package = Detector::package();
    let value = evaluation()?;
    let mut invocation = Invocation::new(&package, &value, || false)?;
    let api = Api::for_guest::<Detector>();
    let evaluate = api.evaluate.ok_or("evaluate")?;
    let release = api.release.ok_or("release")?;
    let mut response = Response::default();
    assert_eq!(unsafe { evaluate(&invocation.request(), &mut response) }, 0);
    assert!(!response.private_data.is_null());
    assert!(unsafe {
        (*invocation.exchange.inputs[0].data.batches)
            .release
            .is_some()
    });
    unsafe {
        release(&mut response);
        release(&mut response);
    }
    assert!(response.private_data.is_null());
    assert!(response.datasets.is_null());
    assert_eq!(response.dataset_count, 0);
    assert_eq!(
        unsafe { evaluate(std::ptr::null(), &mut response) },
        ErrorCode::Invalid as u32
    );
    assert!(!response.private_data.is_null());
    unsafe {
        release(&mut response);
        release(&mut response);
    }
    assert!(response.private_data.is_null());
    Ok(())
}

#[test]
fn invalid_abi_values_are_errors() -> TestResult {
    let package = Detector::package();
    let value = evaluation()?;
    let mut api = Api::for_guest::<Detector>();
    api.struct_size += 1;
    let error =
        unsafe { Invocation::new(&package, &value, || false)?.call(&api, value.context.limits) }
            .err()
            .ok_or("invalid table accepted")?;
    assert_eq!(error.code(), ErrorCode::Incompatible);
    let api = Api::for_guest::<Detector>();
    let evaluate = api.evaluate.ok_or("evaluate")?;
    let release = api.release.ok_or("release")?;
    for invalid in 0..6 {
        let mut invocation = Invocation::new(&package, &value, || false)?;
        let mut request = invocation.request();
        match invalid {
            0 => request.context.has_seed = 2,
            1 => request.inputs = std::ptr::null(),
            2 => request.input_count = u64::MAX,
            3 => request.context.limits.max_rows = 1,
            4 => invocation.exchange.inputs[0].coverage.state = 999,
            _ => request.export_name.data = std::ptr::null(),
        }
        let mut response = Response::default();
        assert_ne!(unsafe { evaluate(&request, &mut response) }, 0);
        unsafe {
            release(&mut response);
        }
        assert!(response.private_data.is_null());
    }
    Ok(())
}

struct Panicking;

impl Guest for Panicking {
    fn package() -> Package {
        Detector::package()
    }
    #[allow(clippy::panic)]
    fn evaluate(_evaluation: &Evaluation) -> Result<Output> {
        panic!("native fixture panic")
    }
}

#[test]
fn panic_and_cancellation_preserve_boundary() -> TestResult {
    let package = Detector::package();
    let value = evaluation()?;
    let error = unsafe {
        Invocation::new(&package, &value, || false)?
            .call(&Api::for_guest::<Panicking>(), value.context.limits)
    }
    .err()
    .ok_or("panic accepted")?;
    assert_eq!(error.code(), ErrorCode::Failed);
    let polls = Cell::new(0);
    let error = unsafe {
        Invocation::new(&package, &value, || {
            polls.set(polls.get() + 1);
            polls.get() > 2
        })?
        .call(&Api::for_guest::<Detector>(), value.context.limits)
    }
    .err()
    .ok_or("cancelled output accepted")?;
    assert_eq!(error.code(), ErrorCode::Incomplete);
    assert!(!cancelled());
    Ok(())
}

static RELEASES: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn malformed_output(_request: *const Request, response: *mut Response) -> u32 {
    unsafe {
        (*response).dataset_count = 1;
    }
    0
}

unsafe extern "C" fn invalid_error(_request: *const Request, response: *mut Response) -> u32 {
    unsafe {
        (*response).error.code = 999;
    }
    999
}

unsafe extern "C" fn oversized_error(_request: *const Request, response: *mut Response) -> u32 {
    unsafe {
        (*response).error.code = ErrorCode::Failed as u32;
        (*response).error.field.size = 1025;
    }
    ErrorCode::Failed as u32
}

unsafe extern "C" fn count_release(response: *mut Response) {
    RELEASES.fetch_add(1, Ordering::SeqCst);
    unsafe {
        *response = Response::default();
    }
}

#[test]
fn malformed_outputs_release_response() -> TestResult {
    let package = Detector::package();
    let value = evaluation()?;
    RELEASES.store(0, Ordering::SeqCst);
    for (evaluate, expected) in [
        (
            malformed_output as unsafe extern "C" fn(_, _) -> _,
            ErrorCode::Invalid,
        ),
        (invalid_error, ErrorCode::Invalid),
        (oversized_error, ErrorCode::Limit),
    ] {
        let mut api = Api::for_guest::<Detector>();
        api.evaluate = Some(evaluate);
        api.release = Some(count_release);
        let error = unsafe {
            Invocation::new(&package, &value, || false)?.call(&api, value.context.limits)
        }
        .err()
        .ok_or("malformed output accepted")?;
        assert_eq!(error.code(), expected);
    }
    assert_eq!(RELEASES.load(Ordering::SeqCst), 3);
    Ok(())
}

#[test]
fn rust_layout_matches_header() -> TestResult {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut compiler = Command::new("cc")
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-x",
            "c",
            "-fsyntax-only",
            "-",
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = compiler.stdin.take().ok_or("compiler stdin")?;
    input.write_all(Detector::package().interfaces()?.native_header.as_bytes())?;
    macro_rules! layout {
        ($rust:ty, $c:literal) => {
            writeln!(
                input,
                "_Static_assert(sizeof({}) == {}, \"size\");",
                $c,
                std::mem::size_of::<$rust>()
            )?;
            writeln!(
                input,
                "_Static_assert(_Alignof({}) == {}, \"alignment\");",
                $c,
                std::mem::align_of::<$rust>()
            )?;
        };
    }
    layout!(Bytes, "araphor_analysis_bytes_v1");
    layout!(NativeLimits, "araphor_analysis_limits_v1");
    layout!(Context, "araphor_analysis_context_v1");
    layout!(Window, "araphor_analysis_window_v1");
    layout!(Revision, "araphor_analysis_revision_v1");
    layout!(Coverage, "araphor_analysis_coverage_v1");
    layout!(Dataset, "araphor_analysis_dataset_v1");
    layout!(Input, "araphor_analysis_input_v1");
    layout!(Checkpoint, "araphor_analysis_checkpoint_v1");
    layout!(RowRef, "araphor_analysis_row_ref_v1");
    layout!(Evidence, "araphor_analysis_evidence_link_v1");
    layout!(Reason, "araphor_analysis_reason_value_v1");
    layout!(NativeError, "araphor_analysis_error_v1");
    layout!(Request, "araphor_analysis_request_v1");
    layout!(Response, "araphor_analysis_response_v1");
    layout!(Api, "araphor_analysis_api_v1");
    drop(input);
    let output = compiler.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn caller_output_capacity_is_independent_of_input_limits() -> TestResult {
    let package = Detector::package();
    let value = evaluation()?;
    let original = value.context.limits;
    let output_limits = crate::Limits {
        max_bytes: 1,
        ..original
    };
    let error = unsafe {
        Invocation::new(&package, &value, || false)?
            .call(&Api::for_guest::<Detector>(), output_limits)
    }
    .err()
    .ok_or("output capacity ignored")?;
    assert_eq!(error.code(), ErrorCode::Limit);
    assert_eq!(value.context.limits, original);
    Ok(())
}

struct ErrorField<const SIZE: usize>;

impl<const SIZE: usize> Guest for ErrorField<SIZE> {
    fn package() -> Package {
        Detector::package()
    }

    fn evaluate(_evaluation: &Evaluation) -> Result<Output> {
        Err(Error::contract(ErrorCode::Failed, "x".repeat(SIZE)))
    }
}

#[test]
fn producer_error_field_uses_existing_transport_bound() -> TestResult {
    let package = Detector::package();
    let value = evaluation()?;
    let boundary = unsafe {
        Invocation::new(&package, &value, || false)?
            .call(&Api::for_guest::<ErrorField<1024>>(), value.context.limits)
    }
    .err()
    .ok_or("error accepted")?;
    assert_eq!(boundary.code(), ErrorCode::Failed);
    let oversized = unsafe {
        Invocation::new(&package, &value, || false)?
            .call(&Api::for_guest::<ErrorField<1025>>(), value.context.limits)
    }
    .err()
    .ok_or("oversized error accepted")?;
    assert_eq!(oversized.code(), ErrorCode::Limit);
    Ok(())
}
