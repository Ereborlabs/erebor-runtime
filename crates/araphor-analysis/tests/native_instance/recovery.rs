use super::*;

#[tokio::test]
async fn native_host_failed_input() -> TestResult {
    for (mode, code) in [("trap", Code::Incomplete), ("limit", Code::Limit)] {
        let fixture = Fixture::new()?;
        let mut model = sdk::Model::new(
            "evaluate",
            Vec::new(),
            vec![sdk::Port::new(
                "data",
                sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
            )],
        );
        model.parameters = sdk::Schema::new(vec![
            sdk::Field::new("mode", sdk::DataType::Utf8, false),
            sdk::Field::new("amount", sdk::DataType::UInt64, false),
        ]);
        let artifact = PackageArtifactV1 {
            descriptor: sdk::Package::new("runtime-fixture", "1", vec![model]),
            implementations: vec![PackageImplementationV1::Wasm {
                exports: vec!["evaluate".into()],
                artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
            }],
            fixtures: Vec::new(),
        };
        let image = PackageBundle::try_from(PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        })?;
        fixture
            .engine
            .store()
            .install_package_image(TENANT, &image, || Ok(()))?;
        let amount = "(SELECT COALESCE(MAX(source_cursor), 0) FROM events)";
        let definition = Definition {
            name: "failed-source".into(),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: format!(
                        r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => (CASE WHEN {amount} = 2 THEN '{mode}' ELSE 'echo' END), amount => CAST({amount} AS BIGINT UNSIGNED))"#
                    ),
                },
            },
        };
        let control = AnalysisReadControl::default();
        let prepared = fixture
            .engine
            .prepare_definition(
                TENANT,
                &definition,
                Arc::new(AnalysisReadControl::default()),
            )
            .await?;
        fixture
            .engine
            .store()
            .admit_definition(TENANT, prepared.resolved(), || Ok(()))?;
        let instance = Instance::admit(
            fixture.engine.clone(),
            fixture.authority.clone(),
            fixture.grant.clone(),
            "instance".into(),
            prepared.resolved().clone(),
            &control,
        )
        .await?;
        fixture.event(1)?;
        let prior = instance.run(request("prior"), &control).await?;
        assert_eq!(values(&instance, &prior, &control).await?, [1]);
        fixture.event(2)?;
        let current = fixture
            .engine
            .store()
            .managed_resume(TENANT, "instance", &control)?;
        let host = InstanceHost::new(fixture.engine.clone(), fixture.authority.clone());
        let running = host
            .start(instance.clone(), current.instance.lifecycle, &control)
            .await?;
        let mut changes = fixture.engine.store().subscribe_revision();
        let (stop, stopped) = watch::channel(false);
        let worker = tokio::spawn(host.clone().serve(stopped, u64::MAX));
        let proof: TestResult = async {
            let failed = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    match fixture.engine.store().managed_status(&fixture.grant.selection, "instance", &control) {
                        Ok(status) if matches!(status.readiness, araphor_data::PackageReadinessV1::Failed { code: actual, .. } if actual == code) => return fixture.engine.store().managed_resume(TENANT, "instance", &control),
                        Ok(_) | Err(araphor_data::Error::Package { code: Code::Incomplete, field: "managed pending attempt", .. }) => {},
                        Err(error) => return Err(error),
                    }
                    changes.changed().await.map_err(|_| Code::Incomplete.error("native recovery notice"))?;
                }
            }).await??;
            assert_eq!(failed.instance.progress, prior.commit_revision);
            assert!(failed.completed > prior.commit_revision);
            assert!(failed.instance.running);
            assert_eq!(values(&running, &prior, &control).await?, [1]);
            let attempts = fixture.engine.store().view()?.snapshot().prefix(b"\0data/a").collect::<Result<Vec<_>, _>>()?;
            assert_eq!(attempts.len(), 2);
            let frame = Vec::<u8>::try_from(&EvidenceRecord { task_cookie: 1, ..Default::default() })?;
            fixture.engine.store().accept_validated_batch(EvidenceIntakeIdentityV1 {
                tenant_id: [2; 16], node_id: "foreign".into(), node_boot_id: [2; 16], label_epoch: 1, source_id: [3; 16], source_epoch: 1,
            }, ValidatedEvidenceBatchV1 { cpu_id: 0, first_cursor: 1, last_cursor: 1, intake_utc_ns: 1, frame_ends: vec![frame.len()], framed_records: frame.into() })?;
            assert!(tokio::time::timeout(Duration::from_millis(30), fixture.progress(prior.commit_revision)).await.is_err());
            assert_eq!(fixture.engine.store().managed_resume(TENANT, "instance", &control)?, failed);
            assert_eq!(fixture.engine.store().view()?.snapshot().prefix(b"\0data/a").collect::<Result<Vec<_>, _>>()?, attempts);
            fixture.event(3)?;
            let recovered = fixture.progress(prior.commit_revision).await?;
            assert_eq!(values(&running, &prior, &control).await?, [1]);
            assert_eq!(values(&running, &recovered, &control).await?, [3]);
            assert_eq!(fixture.engine.store().managed_history(&fixture.grant.selection, "instance", &control)?.len(), 2);
            Ok(())
        }.await;
        stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(30), worker).await???;
        proof?;
    }
    Ok(())
}

async fn values(
    instance: &Arc<Instance>,
    receipt: &ManagedReceipt,
    control: &AnalysisReadControl,
) -> TestResult<Vec<u64>> {
    let output = instance
        .replay(&receipt.selected.result_id, control)
        .await?;
    let mut values = Vec::new();
    for batch in output.batches {
        values.extend_from_slice(
            batch
                .column(0)
                .as_any()
                .downcast_ref::<sdk::arrow_array::UInt64Array>()
                .ok_or("replayed value type")?
                .values(),
        );
    }
    Ok(values)
}
