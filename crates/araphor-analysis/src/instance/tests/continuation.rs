use futures_util::StreamExt as _;

use super::*;

#[tokio::test]
async fn finite_follow_keeps_frontier() -> TestResult {
    for implementation in ["sql", "wasm"] {
        let fixture = Fixture::new(Default::default())?;
        fixture.install(&bundle(implementation)?)?;
        fixture.context(1)?;
        let instance = fixture
            .admit(
                "finite-follow",
                r#"SELECT value FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(1 AS BIGINT UNSIGNED) AS value)) WHERE EXISTS (SELECT 1 FROM context_versions)"#,
            )
            .await?;
        let control = AnalysisReadControl::default();
        let input = request("exact-finite-call");
        let first = instance.run(input.clone(), &control).await?;
        assert_eq!(first.attempt, input.id);
        assert_eq!(fixture.selected("finite-follow", &first.attempt)?, [1]);
        let frontier = first.frontier.clone().ok_or("finite native frontier")?;
        let attempt = fixture
            .query
            .store()
            .managed_attempt([1; 16], "finite-follow", &first.attempt, &control)?
            .ok_or("saved finite attempt")?;
        let mut recorded_request = input.clone();
        recorded_request.frontier = Some(frontier.clone());
        assert_eq!(attempt.request(), &recorded_request);
        assert_eq!(attempt.receipt(), Some(&first));
        let reference = first.results.values().next().ok_or("finite call result")?;
        let evaluation = fixture.query.store().managed_evaluation(
            instance.admitted(),
            &reference.result_id,
            &control,
        )?;
        assert_eq!(evaluation.context.id, input.id);
        assert_eq!(evaluation.context.time_utc_ns, input.time_utc_ns as i64);
        assert_eq!(evaluation.context.seed, input.seed);
        drop(evaluation);
        let before = fixture.query.store().meta()?;
        let error = instance
            .run(attempt.request().clone(), &control)
            .await
            .err()
            .ok_or("caller frontier admitted")?;
        assert!(matches!(
            error,
            crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Invalid,
                    field: "finite managed frontier",
                    ..
                }
            }
        ));
        assert_eq!(fixture.query.store().meta()?, before);
        assert_eq!(instance.run(input, &control).await?, first);
        assert_eq!(fixture.query.store().meta()?, before);
        let lifecycle = fixture.start(&instance)?;
        let resumed = fixture
            .query
            .store()
            .managed_resume([1; 16], "finite-follow", &control)?;
        assert_eq!(resumed.frontier, Some(frontier));
        assert_eq!(resumed.instance.progress, first.commit_revision);
        let retained = fixture.query.memory().input_reserved();
        let mut stream = instance.subscribe(
            Arc::new(AnalysisReadControl::default()),
            u64::MAX,
            lifecycle,
        )?;
        let subscribed = fixture.query.memory().input_reserved();
        let mut next = Box::pin(stream.next());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), next.as_mut())
                .await
                .is_err()
        );
        assert_eq!(fixture.query.memory().input_reserved(), subscribed);
        assert_eq!(fixture.progress("finite-follow")?, first.commit_revision);
        fixture.context(2)?;
        let second = tokio::time::timeout(Duration::from_secs(30), next)
            .await?
            .ok_or("changed finite-follow receipt")??;
        assert_ne!(second.attempt, first.attempt);
        assert!(second.commit_revision > first.commit_revision);
        assert_eq!(fixture.selected("finite-follow", &second.attempt)?, [2]);
        assert_eq!(fixture.selected("finite-follow", &first.attempt)?, [1]);
        assert_eq!(stream.cancel_and_join(&control).await?, None);
        assert_eq!(fixture.query.memory().input_reserved(), retained);
    }
    Ok(())
}
