use super::*;

impl Fixture {
    async fn sum_reference(
        &self,
        current: &[RecordBatch],
    ) -> datafusion::common::Result<Vec<RecordBatch>> {
        SubscribeExec::bind(
            &self.plan,
            &self.source,
            current.to_vec(),
            Arc::clone(&self.context),
        )?
        .try_collect()
        .await
    }

    async fn sum_matches(
        &mut self,
        before: &[RecordBatch],
        after: &[RecordBatch],
        current: &[RecordBatch],
    ) {
        let expected = self.sum_reference(current).await.unwrap();
        let change = self.change(before, after).await;
        let snapshot = Arc::clone(&change.snapshot);
        let control = Arc::clone(&change.control);
        let position = change.position;
        self.send(change).await;
        let output = self.output.next().await.unwrap().unwrap();
        assert!(Arc::ptr_eq(&output.snapshot, &snapshot));
        assert!(Arc::ptr_eq(&output._control, &control));
        assert_eq!(output.snapshot.page.scanned_through, position);
        let actual = output.batches.as_ref().unwrap();
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].schema(), self.plan.schema());
        assert_eq!(actual, &expected);
    }
}

#[tokio::test]
async fn sums_match_native_cuts() {
    let mut fixture = Fixture::new(
        "SELECT COUNT(*) AS rows, COUNT(value) AS present, SUM(value) AS signed_total, \
         SUM(CAST(ABS(value) AS BIGINT UNSIGNED)) AS unsigned_total, \
         SUM(CAST(10 AS BIGINT) / CAST(value AS BIGINT)) \
         FILTER (WHERE flag AND value <> 0) AS filtered_total FROM input",
    )
    .await;
    assert_eq!(fixture.plan.schema().field(2).data_type(), &DataType::Int64);
    assert_eq!(
        fixture.plan.schema().field(3).data_type(),
        &DataType::UInt64
    );
    fixture.sum_matches(&[], &[], &[]).await;
    let first = fixture.batch(
        vec![Some(-7), None, Some(9)],
        vec![Some(true), Some(true), Some(false)],
    );
    let second = fixture.batch(
        vec![Some(0), Some(12), Some(-3)],
        vec![None, Some(true), Some(true)],
    );
    fixture
        .sum_matches(
            &[],
            &[first.clone(), second.clone()],
            &[first.clone(), second.clone()],
        )
        .await;
    fixture
        .sum_matches(
            &[first.slice(2, 1), second.slice(0, 1)],
            &[],
            &[first.slice(0, 2), second.slice(1, 2)],
        )
        .await;
    let third = fixture.batch(
        vec![Some(5), None, Some(-2)],
        vec![Some(true), Some(false), None],
    );
    fixture
        .sum_matches(
            &[first.slice(0, 1)],
            std::slice::from_ref(&third),
            &[first.slice(1, 1), second.slice(1, 2), third.clone()],
        )
        .await;
    fixture
        .sum_matches(
            &[second.slice(1, 2), third.slice(0, 1)],
            &[],
            &[first.slice(1, 1), third.slice(1, 2)],
        )
        .await;
    fixture
        .sum_matches(
            &[third.slice(2, 1)],
            &[],
            &[first.slice(1, 1), third.slice(1, 1)],
        )
        .await;
    fixture
        .sum_matches(&[first.slice(1, 1), third.slice(1, 1)], &[], &[])
        .await;
    let fourth = fixture.batch(vec![Some(-11), Some(4)], vec![Some(true); 2]);
    fixture
        .sum_matches(
            &[],
            std::slice::from_ref(&fourth),
            std::slice::from_ref(&fourth),
        )
        .await;
    fixture
        .sum_matches(&[], &[], std::slice::from_ref(&fourth))
        .await;
    fixture
        .sum_matches(std::slice::from_ref(&fourth), &[], &[])
        .await;
}

#[tokio::test]
async fn sums_wrap_native_integers() {
    let mut fixture = Fixture::new(
        "SELECT COUNT(*) AS rows, \
         SUM(CASE \"value\" \
             WHEN 1 THEN CAST('9223372036854775807' AS BIGINT) \
             WHEN 2 THEN CAST(1 AS BIGINT) \
             WHEN 3 THEN CAST('-9223372036854775808' AS BIGINT) \
             WHEN 4 THEN CAST(-1 AS BIGINT) \
             ELSE CAST(value AS BIGINT) END) AS signed_total, \
         SUM(CASE \"value\" \
             WHEN 1 THEN CAST('18446744073709551615' AS BIGINT UNSIGNED) \
             WHEN 2 THEN CAST(1 AS BIGINT UNSIGNED) \
             WHEN 3 THEN CAST(0 AS BIGINT UNSIGNED) \
             WHEN 4 THEN CAST(1 AS BIGINT UNSIGNED) \
             ELSE CAST(value AS BIGINT UNSIGNED) END) AS unsigned_total FROM input",
    )
    .await;
    assert_eq!(fixture.plan.schema().field(1).data_type(), &DataType::Int64);
    assert_eq!(
        fixture.plan.schema().field(2).data_type(),
        &DataType::UInt64
    );
    fixture.sum_matches(&[], &[], &[]).await;
    let first = fixture.batch(vec![Some(1)], vec![None]);
    let second = fixture.batch(vec![Some(2)], vec![None]);
    fixture
        .sum_matches(
            &[],
            std::slice::from_ref(&first),
            std::slice::from_ref(&first),
        )
        .await;
    fixture
        .sum_matches(
            &[],
            std::slice::from_ref(&second),
            &[first.clone(), second.clone()],
        )
        .await;
    let third = fixture.batch(vec![Some(3), Some(4), None], vec![None; 3]);
    fixture
        .sum_matches(
            &[],
            std::slice::from_ref(&third),
            &[first.clone(), second.clone(), third.clone()],
        )
        .await;
    fixture
        .sum_matches(
            std::slice::from_ref(&second),
            &[],
            &[first.clone(), third.clone()],
        )
        .await;
    fixture
        .sum_matches(
            &[third.slice(1, 1)],
            &[],
            &[first.clone(), third.slice(0, 1), third.slice(2, 1)],
        )
        .await;
    fixture
        .sum_matches(
            std::slice::from_ref(&first),
            &[],
            &[third.slice(0, 1), third.slice(2, 1)],
        )
        .await;
    fixture
        .sum_matches(&[third.slice(0, 1)], &[], &[third.slice(2, 1)])
        .await;
    fixture.sum_matches(&[third.slice(2, 1)], &[], &[]).await;
}

#[tokio::test]
async fn sum_error_keeps_frontier() {
    let mut fixture = Fixture::new(
        "SELECT COUNT(*) AS rows, \
         SUM(CAST(10 AS BIGINT) / CAST(value AS BIGINT)) AS total FROM input",
    )
    .await;
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &fixture.control, 0)
        .unwrap();
    let mut kernel = Kernel::new(
        fixture
            .plan
            .as_any()
            .downcast_ref::<AggregateExec>()
            .unwrap(),
        Arc::clone(&fixture.source),
        Arc::clone(&fixture.context),
        Arc::new(session),
    )
    .unwrap();
    let first = fixture.batch(vec![Some(2)], vec![None]);
    let expected = fixture
        .sum_reference(std::slice::from_ref(&first))
        .await
        .unwrap();
    let change = fixture.change(&[], std::slice::from_ref(&first)).await;
    let previous = change.position;
    let output = kernel.apply(change).await.unwrap();
    assert_eq!(output.batches.as_ref().unwrap(), &expected);
    assert_eq!(kernel.frontier, Some(previous));
    drop(output);
    drop(expected);
    let good = fixture.batch(vec![Some(4)], vec![None]);
    let bad = fixture.batch(vec![Some(0)], vec![None]);
    assert!(fixture
        .sum_reference(std::slice::from_ref(&good))
        .await
        .is_ok());
    let error = fixture
        .sum_reference(&[good.clone(), bad.clone()])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Divide by zero"));
    let change = fixture
        .change(std::slice::from_ref(&first), &[good, bad])
        .await;
    assert!(change.position > previous);
    let error = match kernel.apply(change).await {
        Err(error) => error,
        Ok(_) => panic!("failed SUM cut produced output"),
    };
    assert!(matches!(
        &error,
        crate::Error::Sql { source }
            if matches!(
                source.find_root(),
                DataFusionError::ArrowError(cause, _)
                    if matches!(
                        cause.as_ref(),
                        datafusion::arrow::error::ArrowError::DivideByZero
                    )
            )
    ));
    assert_eq!(kernel.frontier, Some(previous));
    drop(error);
    drop(kernel);
    drop(first);
    assert!(fixture
        .engine
        .memory()
        .reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .expect("configured input capacity")
        )
        .is_ok());
}
