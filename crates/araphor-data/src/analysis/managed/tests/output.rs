use super::*;

#[test]
fn raw_output_keeps_packet() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let mut receipts = Vec::new();
    for id in ["first", "second"] {
        let capture = fixture.capture(&store, false)?;
        let request = request(id);
        let attempt = store.register_managed_attempt(&capture, &request, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&request, 10, Some(&capture))?,
            fixture.evaluation(&request, 11, Some(&capture))?,
        ];
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        receipts.push(fixture.publish(&store, &attempt, &evaluations, &outputs)?);
    }
    let control = AnalysisReadControl::default();
    let current = fixture.current(&store)?;
    let before = store.meta()?;
    for (call, reference) in &receipts[0].results {
        let expected = {
            let mut reader = store.reader_until(&control)?;
            control.run(&mut reader, |reader| {
                AnalysisStore::managed_record_from(reader, [1; 16], &reference.result_id)
            })?
        };
        let result = store.managed_output(&current, &reference.result_id, 10, &control)?;
        assert_eq!(result.output, expected.1);
        assert_eq!(result.instance_id, current.spec.id);
        assert_eq!(result.result_id, reference.result_id);
        assert_eq!(result.commit_revision, reference.commit_revision);
        assert_eq!(result.commit_revision, expected.2);
        assert_eq!(result.context, expected.0.context);
        assert_eq!(result.image, current.spec.manifest.calls[call].image);
        assert_eq!(result.package, current.spec.manifest.calls[call].package);
        assert_eq!(result.export, "count");
        assert_eq!(result.context.target, "sql");
        assert_eq!(result.context.artifact, None);
        assert_eq!(result.context.context.id, "first");
        assert_eq!(result.limits, fixture.model.limits);
        assert!(!result.current);
        assert_eq!(result.output.datasets.len(), 1);
        assert_eq!(result.output.evidence.len(), 1);
        assert_eq!(result.output.reasons.len(), 1);
        assert_eq!(result.output.checkpoint.as_ref().ok_or("state")?.version, 1);
        let decoded = result.output.decode_model(&fixture.model)?;
        assert_eq!(decoded.datasets[0].batches[0].num_rows(), 1);
        assert_eq!(
            decoded.checkpoint.as_ref().ok_or("decoded state")?.datasets[0].batches,
            decoded.datasets[0].batches
        );
        let encoded = crate::PackageResponseV1::Result(Box::new(result.clone())).encode()?;
        assert!(!encoded
            .windows(b"definition-grant".len())
            .any(|bytes| bytes == b"definition-grant"));
        let crate::PackageResponseV1::Result(returned) =
            crate::PackageResponseV1::from_bytes(&encoded)?
        else {
            return Err("retained packet variant".into());
        };
        assert_eq!(returned.output, result.output);
        let cancelled = AnalysisReadControl::default();
        cancelled.cancel()?;
        assert!(matches!(
            store.managed_output(&current, &reference.result_id, 10, &cancelled),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
    }
    assert_eq!(store.meta()?, before);
    Ok(())
}
