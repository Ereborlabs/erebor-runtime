use super::*;

use std::sync::mpsc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixture_cancellation_joins_guest() -> TestResult {
    const BYTES: usize = 16 * 1024;
    const INPUT_BYTES: usize = 2 * 1024 * 1024;
    let mut model = sdk::Model::new(
        "evaluate",
        Vec::new(),
        vec![sdk::Port::new("data", Fixture::schema())],
    );
    model.limits.max_bytes = BYTES as u64;
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    let parameters = serde_json::json!({"mode":"cancel","amount":7});
    let mut evaluation = Fixture::evaluation(&model);
    evaluation.parameters = araphor_data::decode_parameters(&model.parameters, Some(&parameters))?;
    let expected = sdk::Output {
        datasets: vec![Fixture::data("data", &[7])?],
        ..Default::default()
    };
    let mut bundle = Fixture::bundle("wasm", model, SqlModelV1::default())?;
    Fixture::save(&mut bundle, &evaluation, &expected, Some(parameters))?;
    let parameters = serde_json::json!({"mode":"echo","amount":7});
    evaluation.context.id = "success".into();
    evaluation.parameters = araphor_data::decode_parameters(
        &bundle.artifacts[0].descriptor.exports[0].parameters,
        Some(&parameters),
    )?;
    Fixture::save(&mut bundle, &evaluation, &expected, Some(parameters))?;
    let fixture = Arc::new(Fixture::limits(
        &bundle,
        araphor_query::execution::Limits {
            input_bytes: INPUT_BYTES,
            input_capacity: Some(INPUT_BYTES),
            output_bytes: BYTES * 4,
            output_capacity: Some(BYTES * 4),
            global_evaluations: 1,
            tenant_evaluations: 1,
            ..Default::default()
        },
    )?);
    for revoke in [false, true] {
        let (entry, observed) = mpsc::channel();
        let (release, waiting) = mpsc::channel();
        fixture.owner.query.guest_entry(entry, Some(waiting))?;
        let control = Arc::new(AnalysisReadControl::default());
        let read = Arc::clone(&control);
        let owner = Arc::clone(&fixture);
        let image = bundle.root.clone();
        let worker = tokio::spawn(async move {
            owner
                .owner
                .run(&owner.grant, &image, Some("case"), &read)
                .await
        });
        let entered =
            tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30)))
                .await?;
        if let Err(error) = entered {
            let _released = release.send(());
            control.cancel()?;
            let result = worker.await?;
            return Err(format!("guest entry failed: {error}; execution: {result:?}").into());
        }
        assert!(fixture.owner.query.memory().reserve_output(1).is_err());
        assert!(fixture.owner.query.reserve_evaluation([1; 16]).is_err());
        if revoke {
            fixture.authority.deny_at.store(
                fixture.authority.checks.load(Ordering::SeqCst) + 1,
                Ordering::SeqCst,
            );
            fixture.authority.changes.send_replace(1);
        } else {
            control.cancel()?;
        }
        assert!(!worker.is_finished());
        release.send(())?;
        let result = tokio::time::timeout(Duration::from_secs(30), worker).await??;
        if revoke {
            assert!(matches!(
                result,
                Err(crate::Error::Data {
                    source: araphor_data::Error::Package {
                        code: Code::Denied,
                        ..
                    }
                })
            ));
            fixture
                .authority
                .deny_at
                .store(usize::MAX, Ordering::SeqCst);
        } else {
            assert!(matches!(
                result,
                Err(crate::Error::Data {
                    source: araphor_data::Error::AnalysisReadCancelled { .. }
                })
            ));
        }
        drop(fixture.owner.query.memory().reserve_input(INPUT_BYTES)?);
        drop(fixture.owner.query.memory().reserve_output(BYTES * 4)?);
        drop(fixture.owner.query.reserve_evaluation([1; 16])?);
        let success = AnalysisReadControl::default();
        assert!(fixture
            .owner
            .run(&fixture.grant, &bundle.root, Some("success"), &success)
            .await?
            .iter()
            .all(|result| result.passed));
        success.check()?;
    }
    Ok(())
}
