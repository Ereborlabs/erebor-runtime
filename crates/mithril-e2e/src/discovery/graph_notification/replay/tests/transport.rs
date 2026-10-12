use super::super::*;

#[tokio::test]
async fn reordered_uploads_keep_frames() -> crate::platform::TestResult<()> {
    let fixture = ReplayQualification::new(1_791_400_000_000_000_000)?;
    let tls = MtlsFixture::new(false)?;
    let server = tls
        .start(tls.control_from_intake(fixture.intake.clone(), 1)?)
        .await?;
    let result: crate::platform::TestResult<()> = async {
        let batches = fixture.transport_batches()?;
        assert_eq!(batches.len(), 2);
        let original: Vec<_> = batches
            .iter()
            .map(|batch| batch.decode_records())
            .collect::<std::result::Result<_, _>>()?;
        let mut trust = TrustCache::load(&tls.path().join("trust"))?;
        let mut registration =
            OutagePolicyFixture::registration(fixture.authenticated.node_boot_id, false);
        registration.effect_prevention_claims_enabled = false;
        let connector = tls.connector(&server, "node-a", fixture.authenticated.node_boot_id);
        let mut connection = connector
            .connect(registration.clone(), false, &mut trust)
            .await?;
        let mut acknowledgements = Vec::new();
        let mut cursors = Vec::new();
        for index in [1, 1, 0, 0] {
            connection
                .send_evidence_batch(batches[index].clone())
                .await?;
            let response = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let NodeControlMessage::EvidenceAck(ack) = connection.next_message().await? {
                        return Ok::<_, mithril_node::Error>(ack);
                    }
                }
            })
            .await?;
            if index == 1 {
                let Err(mithril_node::Error::ControlRpc { source, .. }) = response else {
                    return Err("pending upload did not return a Control RPC error".into());
                };
                assert_eq!(source.code(), tonic::Code::Unavailable);
                assert_eq!(
                    source.message(),
                    "evidence batch is durable but waits for an earlier cursor range"
                );
                acknowledgements.push(None);
                connection = connector
                    .connect(registration.clone(), false, &mut trust)
                    .await?;
            } else {
                acknowledgements.push(Some(response?.contiguous_cursor));
            }
            let source = fixture
                .data
                .source_page(fixture.authenticated.tenant_id, None)?
                .into_iter()
                .next()
                .ok_or("accepted source absent")?;
            cursors.push(fixture.intake.contiguous_cursor(&source)?);
        }
        assert_eq!(acknowledgements, [None, None, Some(2), Some(2)]);
        assert_eq!(cursors, [0, 0, 2, 2]);
        let source = fixture
            .data
            .source_page(fixture.authenticated.tenant_id, None)?
            .into_iter()
            .next()
            .ok_or("accepted source absent")?;
        let records = fixture.data.read_page(&source, 1)?.records;
        assert_eq!(records.len(), 2);
        for (retained, original) in records.iter().zip(original.iter().flatten()) {
            assert_eq!(
                EvidenceRecord::try_from(retained.framed_record.as_slice())?,
                *original
            );
        }
        Ok(())
    }
    .await;
    let shutdown = server.shutdown().await;
    result.and(shutdown)
}

#[tokio::test]
async fn existing_output_is_rejected() -> crate::platform::TestResult<()> {
    let root = tempfile::tempdir()?;
    let output = root.path().join("proof");
    fs::create_dir(&output)?;
    let retained = br#"{"retained":true}"#;
    for file in ["graph.json", "result.json"] {
        fs::write(output.join(file), retained)?;
    }
    let runner = GraphNotificationQualification::new(output.clone());
    let error = runner.run().await.err().ok_or("existing output accepted")?;
    assert_eq!(error.to_string(), "the qualification output already exists");
    for file in ["graph.json", "result.json"] {
        assert_eq!(fs::read(output.join(file))?, retained.as_slice());
    }
    Ok(())
}

impl ReplayQualification {
    fn transport_batches(&self) -> crate::platform::TestResult<Vec<mithril_node::EvidenceBatchV1>> {
        let wal = EffectObservationStore::durable(
            8,
            self.root.path().join("transport-wal"),
            EvidenceWalLimits {
                maximum_batch_records: 1,
                ..Default::default()
            },
            ObservationCanonicalizer::new(
                self.authenticated.tenant_id.into(),
                [3; 16].into(),
                1,
                self.authenticated.node_boot_id.into(),
            )?,
        )?;
        wal.sample_coverage_health([EffectObservationHealthV1::default(); 4].as_bytes())?;
        wal.record_bytes(GraphNotificationQualification::native(1, true).as_bytes());
        wal.record_bytes(GraphNotificationQualification::native(2, false).as_bytes());
        Ok(wal.next_evidence_batches())
    }
}
