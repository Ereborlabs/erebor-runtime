use araphor_data::{AnalysisSelectionV1, ManagedRequest, PackageActionV1};
use araphor_discovery_definition::{Definition, Program, Source};

use super::*;

impl Fixture {
    pub(super) async fn retained_instance(
        &self,
        id: &str,
        sql: &str,
    ) -> TestResult<Arc<araphor_analysis::Instance>> {
        self.retained_program(
            id,
            Program::Sql {
                source: Source::Inline { inline: sql.into() },
            },
        )
        .await
    }

    async fn retained_program(
        &self,
        id: &str,
        program: Program,
    ) -> TestResult<Arc<araphor_analysis::Instance>> {
        let access = self
            .service
            .authenticate(&self.request(proto::QueryRequest::default(), false)?, false)
            .await?;
        let grant =
            access.package_grant(AnalysisSelectionV1::tenant([1; 16]), PackageActionV1::Run)?;
        let query = Arc::clone(&self.service.data()?.query);
        let PackageResponseV1::Definition {
            snapshot: definition,
            ..
        } = self
            .package(
                PackageRequestV1::AdmitDefinition {
                    definition: Definition {
                        name: "retained-count".into(),
                        description: "Read a retained package result.".into(),
                        labels: BTreeMap::new(),
                        program,
                    },
                },
                true,
            )
            .await?
        else {
            return Err("admitted definition variant".into());
        };
        Ok(araphor_analysis::Instance::admit(
            query,
            self.service.auth.clone(),
            grant,
            id.into(),
            definition,
            &AnalysisReadControl::default(),
        )
        .await?)
    }
}

#[tokio::test]
async fn selected_rpc_refs_and_replay() -> TestResult {
    for (program, rows) in [
        (
            Program::Sql {
                source: Source::Inline {
                    inline: "SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into(),
                },
            },
            1,
        ),
        (
            Program::Sql {
                source: Source::Inline {
                    inline: "SELECT CAST(7 AS BIGINT UNSIGNED) AS value WHERE false".into(),
                },
            },
            0,
        ),
        (
            Program::Prql {
                source: Source::Inline {
                    inline: "from s\"SELECT CAST(7 AS BIGINT UNSIGNED) AS value\"".into(),
                },
            },
            1,
        ),
    ] {
        let fixture = Fixture::new()?;
        fixture
            .service
            .auth
            .replace_package_managers(vec![crate::InvestigateGrant {
                subject: "alice".into(),
                tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            }])?;
        let instance = fixture.retained_program("selected", program).await?;
        fixture.retained_instance("foreign", "SELECT 1").await?;
        assert!(instance.admitted().spec.manifest.calls.is_empty());
        let receipt = instance
            .run(
                ManagedRequest {
                    id: "selected-result".into(),
                    time_utc_ns: ClientGrpcOwner::now()?,
                    seed: None,
                    rebuild: false,
                    witness_expiry: u64::MAX,
                    frontier: None,
                },
                &AnalysisReadControl::default(),
            )
            .await?;
        assert!(receipt.results.is_empty());
        fixture.service.auth.replace_package_managers(Vec::new())?;
        let store = &fixture.service.data()?.store;
        let before = store.meta()?;
        let PackageResponseV1::Result(result) = fixture
            .package(
                PackageRequestV1::ReadInstanceResult {
                    instance_id: "selected".into(),
                    result_id: receipt.selected.result_id.clone(),
                },
                false,
            )
            .await?
        else {
            return Err("selected reference variant".into());
        };
        assert_eq!(result.result, receipt.selected);
        assert_eq!(result.receipt, receipt);
        assert!(matches!(
            &result.kind,
            araphor_data::InstanceResultKindV1::Selected
        ));
        assert!(serde_json::to_value(&result)?.get("output").is_none());
        let replay = PackageRequestV1::ReplayInstanceResult {
            instance_id: "selected".into(),
            result_id: receipt.selected.result_id.clone(),
        };
        for secure in [false, true] {
            let error = fixture
                .package(replay.clone(), secure)
                .await
                .err()
                .ok_or("read authority executed replay")?;
            assert_eq!(
                error.code(),
                if secure {
                    tonic::Code::PermissionDenied
                } else {
                    tonic::Code::Unauthenticated
                }
            );
        }
        fixture
            .service
            .auth
            .replace_package_managers(vec![crate::InvestigateGrant {
                subject: "alice".into(),
                tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            }])?;
        let PackageResponseV1::Output(packet) = fixture.package(replay, true).await? else {
            return Err("replayed selected variant".into());
        };
        let data = packet.decode_any()?;
        assert_eq!(data.name, "selected");
        assert_eq!(data.rows(), rows);
        assert_eq!(
            data.batches[0].schema_ref().as_ref(),
            &instance.admitted().spec.manifest.selected_schema
        );
        if rows != 0 {
            assert_eq!(
                data.batches[0]
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow_array::UInt64Array>()
                    .ok_or("selected value")?
                    .value(0),
                7
            );
        }
        let error = fixture
            .package(
                PackageRequestV1::ReadInstanceResult {
                    instance_id: "foreign".into(),
                    result_id: receipt.selected.result_id.clone(),
                },
                false,
            )
            .await
            .err()
            .ok_or("foreign selected result returned")?;
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert_eq!(store.meta()?, before);
    }
    Ok(())
}

#[tokio::test]
async fn host_joins_control_shutdown() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    let image = bundle();
    fixture
        .service
        .auth
        .replace_package_trust(vec![crate::PackageTrustPinV1 {
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: image.digest()?,
        }])?;
    fixture
        .package(PackageRequestV1::InstallImage { bundle: image }, true)
        .await?;
    let instance = fixture
        .retained_instance("host-counts", r#"SELECT * FROM "api.fixture"."1".count()"#)
        .await?;
    let data = fixture.service.data()?;
    let store = Arc::clone(&data.store);
    let read = AnalysisReadControl::default();
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let admitted = store
        .managed_instance([1; 16], "host-counts", &read)?
        .ok_or("managed instance")?;
    assert!(!admitted.running);
    assert!(store
        .managed_history(&selection, "host-counts", &read)?
        .is_empty());
    let mut changes = store.subscribe_revision();
    let runtime = fixture.service.control.analysis_packages(None)?;
    let host = Arc::clone(&runtime.instances);
    assert!(Arc::ptr_eq(&runtime.query, &data.query));
    assert!(Arc::ptr_eq(
        &host,
        &fixture.service.control.analysis_packages(None)?.instances,
    ));
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    let running = host.start(instance, admitted.lifecycle, &read).await?;
    let running = running.admitted();
    let receipt = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let history = store.managed_history(&selection, "host-counts", &read)?;
            if let Some(receipt) = history.into_iter().next() {
                return Ok::<_, Box<dyn std::error::Error>>(receipt);
            }
            changes.changed().await?;
        }
    })
    .await??;
    assert!(receipt.commit_revision > running.progress);
    assert!(store.lease_managed().is_err());
    stop.send_replace(true);
    tokio::time::timeout(std::time::Duration::from_secs(30), task).await???;
    let lease = store.lease_managed()?;
    assert_eq!(
        store
            .managed_history(&selection, "host-counts", &read)?
            .len(),
        1
    );
    let current = store
        .managed_instance([1; 16], "host-counts", &read)?
        .ok_or("managed instance after shutdown")?;
    assert!(current.running);
    assert_eq!(current.lifecycle, running.lifecycle);
    assert_eq!(current.progress, receipt.commit_revision);
    drop(lease);
    Ok(())
}

#[tokio::test]
async fn instance_rpc_inspects_history() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    let image = bundle();
    fixture
        .service
        .auth
        .replace_package_trust(vec![crate::PackageTrustPinV1 {
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: image.digest()?,
        }])?;
    fixture
        .package(PackageRequestV1::InstallImage { bundle: image }, true)
        .await?;
    let instance = fixture
        .retained_instance("counts", r#"SELECT * FROM "api.fixture"."1".count()"#)
        .await?;
    let other = fixture
        .retained_instance("other", r#"SELECT * FROM "api.fixture"."1".count()"#)
        .await?;
    let PackageResponseV1::History(history) = fixture
        .package(
            PackageRequestV1::InspectInstanceHistory {
                instance_id: "counts".into(),
            },
            false,
        )
        .await?
    else {
        return Err("empty history variant".into());
    };
    assert!(history.is_empty());
    let mut receipts = Vec::new();
    for id in ["first", "second"] {
        receipts.push(
            instance
                .run(
                    ManagedRequest {
                        id: id.into(),
                        time_utc_ns: ClientGrpcOwner::now()?,
                        seed: None,
                        rebuild: false,
                        witness_expiry: u64::MAX,
                        frontier: None,
                    },
                    &AnalysisReadControl::default(),
                )
                .await?,
        );
    }
    let reference = receipts[0]
        .results
        .values()
        .next()
        .ok_or("retained result")?;
    fixture.service.auth.replace_package_managers(Vec::new())?;
    fixture.service.auth.replace_package_trust(Vec::new())?;
    let store = &fixture.service.data()?.store;
    let before = store.meta()?;
    let response = fixture
        .package(
            PackageRequestV1::InspectInstance {
                instance_id: "counts".into(),
            },
            false,
        )
        .await?;
    let PackageResponseV1::Instance(status) = response else {
        return Err("instance status variant".into());
    };
    assert_eq!(status.id, "counts");
    assert_eq!(status.generation, instance.admitted().generation);
    assert_eq!(status.lifecycle, instance.admitted().lifecycle);
    assert_eq!(status.progress, receipts[1].commit_revision);
    assert!(!status.running);
    assert!(matches!(
        status.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    let PackageResponseV1::History(history) = fixture
        .package(
            PackageRequestV1::InspectInstanceHistory {
                instance_id: "counts".into(),
            },
            false,
        )
        .await?
    else {
        return Err("history variant".into());
    };
    assert_eq!(history, receipts);
    let document = serde_json::to_value(&status)?;
    assert!(document.get("grant").is_none());
    assert!(document.get("manifest").is_none());
    assert!(!serde_json::to_string(&status)?.contains("alice"));
    let PackageResponseV1::Result(result) = fixture
        .package(
            PackageRequestV1::ReadInstanceResult {
                instance_id: "counts".into(),
                result_id: reference.result_id.clone(),
            },
            false,
        )
        .await?
    else {
        return Err("retained reference variant".into());
    };
    assert_eq!(result.result, *reference);
    assert_eq!(result.receipt, receipts[0]);
    assert!(!result.current);
    let error = fixture
        .package(
            PackageRequestV1::ReadInstanceResult {
                instance_id: other.admitted().spec.id.clone(),
                result_id: reference.result_id.clone(),
            },
            false,
        )
        .await
        .err()
        .ok_or("foreign instance reference returned")?;
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(store.meta()?, before);
    assert!(
        !store
            .managed_instance([1; 16], "counts", &AnalysisReadControl::default())?
            .ok_or("retained instance")?
            .running
    );
    Ok(())
}

#[tokio::test]
async fn replay_rpc_keeps_auxiliaries() -> TestResult {
    use araphor_analysis_sdk as sdk;
    let fixture = Fixture::new()?;
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    let mut image = bundle();
    let model = &mut image.artifacts[0].descriptor.exports[0];
    let scalar = model.outputs[0].schema.clone();
    model.outputs[0].evidence_required = true;
    model.outputs.push(sdk::Port::new("other", scalar.clone()));
    model.outputs[1].evidence_required = true;
    model.inputs.push(
        sdk::Port::new(
            "source",
            sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
        )
        .into(),
    );
    model.parameters = sdk::Schema::new(vec![sdk::Field::new(
        "increment",
        sdk::DataType::UInt64,
        false,
    )]);
    model.checkpoint = Some(sdk::CheckpointSpec {
        resume_input_changes: false,
        version: 7,
        datasets: vec![sdk::Port::new("state", scalar)],
    });
    model.reasons.push(sdk::Reason {
        code: "api.fixture.counted".into(),
        details: sdk::Schema::new(vec![sdk::Field::new("detail", sdk::DataType::Utf8, false)]),
    });
    let model = model.clone();
    image.artifacts[0].implementations = vec![PackageImplementationV1::Sql {
        export: "count".into(), program: SqlModelV1 {
            outputs: BTreeMap::from([
                ("rows".into(), "SELECT value + increment AS count FROM source CROSS JOIN parameters".into()),
                ("other".into(), "SELECT value + increment + 1::BIGINT UNSIGNED AS count FROM source CROSS JOIN parameters".into()),
            ]),
            checkpoint: BTreeMap::from([("state".into(), "SELECT count FROM output_rows".into())]),
            evidence: Some("SELECT 'rows' AS output_dataset, __row_index AS output_row, 'source' AS input_dataset, __row_index AS input_row FROM source UNION ALL SELECT 'other' AS output_dataset, __row_index AS output_row, 'source' AS input_dataset, __row_index AS input_row FROM source".into()),
            reasons: ["rows", "other"].into_iter().map(|name| araphor_data::SqlReasonV1 { output: name.into(), code: "api.fixture.counted".into(), sql: format!("SELECT __row_index AS output_row, '{name} reason' AS detail FROM output_{name}") }).collect(),
        }
    }];
    let pin = araphor_discovery_definition::ImagePin {
        image: image.root.clone(),
        digest: image.digest()?,
    };
    fixture
        .service
        .auth
        .replace_package_trust(vec![crate::PackageTrustPinV1 {
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: pin.digest.clone(),
        }])?;
    fixture
        .package(PackageRequestV1::InstallImage { bundle: image }, true)
        .await?;
    let sql = r#"SELECT * FROM "api.fixture"."1".count('rows', source => (SELECT 1::BIGINT UNSIGNED AS value), increment => 2)"#;
    let instance = fixture.retained_instance("complete", sql).await?;
    let other = fixture.retained_instance("other-complete", sql).await?;
    let mut requests = Vec::new();
    let mut receipts = Vec::new();
    for id in ["first", "second"] {
        let request = ManagedRequest {
            id: id.into(),
            time_utc_ns: ClientGrpcOwner::now()?,
            seed: Some(7),
            rebuild: false,
            witness_expiry: u64::MAX,
            frontier: None,
        };
        receipts.push(
            instance
                .run(request.clone(), &AnalysisReadControl::default())
                .await?,
        );
        requests.push(request);
    }
    let reference = receipts[0]
        .results
        .values()
        .next()
        .ok_or("first call result")?;
    fixture.service.auth.replace_package_managers(Vec::new())?;
    fixture.service.auth.replace_package_trust(Vec::new())?;
    let store = &fixture.service.data()?.store;
    let before = store.meta()?;
    let reply = fixture
        .package(
            PackageRequestV1::ReadInstanceResult {
                instance_id: "complete".into(),
                result_id: reference.result_id.clone(),
            },
            false,
        )
        .await?;
    let PackageResponseV1::Result(result) = reply else {
        return Err("complete call packet variant".into());
    };
    assert_eq!(result.instance_id, "complete");
    assert_eq!(result.result, *reference);
    assert!(!result.current);
    assert_eq!(result.receipt, receipts[0]);
    let araphor_data::InstanceResultKindV1::Call {
        image,
        package,
        export,
        context,
        ..
    } = &result.kind
    else {
        return Err("call reference kind".into());
    };
    assert_eq!(*image, pin);
    assert_eq!(*package, image.image);
    assert_eq!(export, "count");
    assert_eq!(context.target, "sql");
    assert_eq!(context.artifact, None);
    assert_eq!(context.context.id, requests[0].id);
    assert_eq!(context.context.time_utc_ns, requests[0].time_utc_ns as i64);
    assert_eq!(context.context.seed, Some(7));
    assert_eq!(context.inputs.len(), 1);
    assert_eq!(context.input_coverage.len(), 1);
    let replay = PackageRequestV1::ReplayInstanceResult {
        instance_id: "complete".into(),
        result_id: reference.result_id.clone(),
    };
    let error = fixture
        .package(replay.clone(), true)
        .await
        .err()
        .ok_or("Inspect authority executed call replay")?;
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    fixture
        .service
        .auth
        .replace_package_trust(vec![crate::PackageTrustPinV1 {
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: pin.digest.clone(),
        }])?;
    let PackageResponseV1::Replayed(packet) = fixture.package(replay, true).await? else {
        return Err("replayed call variant".into());
    };
    assert_eq!(packet.datasets.len(), 2);
    assert_eq!(packet.evidence.len(), 2);
    assert_eq!(packet.reasons.len(), 2);
    let output = packet.decode_model(&model)?;
    for (name, expected) in [("rows", 3), ("other", 4)] {
        let data = output
            .datasets
            .iter()
            .find(|data| data.name == name)
            .ok_or("named output")?;
        assert_eq!(data.rows(), 1);
        assert_eq!(
            data.batches[0]
                .column(0)
                .as_any()
                .downcast_ref::<arrow_array::UInt64Array>()
                .ok_or("output count")?
                .value(0),
            expected
        );
        let reason = output
            .reasons
            .iter()
            .find(|reason| reason.output.dataset == name)
            .ok_or("named reason")?;
        assert_eq!(reason.code, "api.fixture.counted");
        assert_eq!(
            reason
                .details
                .column(0)
                .as_any()
                .downcast_ref::<arrow_array::StringArray>()
                .ok_or("reason detail")?
                .value(0),
            format!("{name} reason")
        );
        assert!(output
            .evidence
            .iter()
            .any(|link| link.output.dataset == name
                && link.output.row == 0
                && link.input.dataset == "source"
                && link.input.row == 0));
    }
    let state = output.checkpoint.ok_or("checkpoint")?;
    assert_eq!(state.version, 7);
    assert_eq!(state.datasets.len(), 1);
    assert_eq!(state.datasets[0].name, "state");
    assert_eq!(
        state.datasets[0].batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<arrow_array::UInt64Array>()
            .ok_or("saved state")?
            .value(0),
        3
    );
    let error = fixture
        .package(
            PackageRequestV1::ReadInstanceResult {
                instance_id: other.admitted().spec.id.clone(),
                result_id: reference.result_id.clone(),
            },
            false,
        )
        .await
        .err()
        .ok_or("cross-instance packet returned")?;
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    let document = serde_json::to_value(&result)?;
    for field in ["grant", "principal", "authorization_id", "manifest"] {
        assert!(document.get(field).is_none());
    }
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[tokio::test]
async fn history_lists_sql_receipts() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    let instance = fixture
        .retained_instance("plain", "SELECT 7::BIGINT UNSIGNED AS value")
        .await?;
    let receipt = instance
        .run(
            ManagedRequest {
                id: "first".into(),
                time_utc_ns: ClientGrpcOwner::now()?,
                seed: None,
                rebuild: false,
                witness_expiry: u64::MAX,
                frontier: None,
            },
            &AnalysisReadControl::default(),
        )
        .await?;
    assert!(receipt.results.is_empty());
    fixture.service.auth.replace_package_managers(Vec::new())?;
    fixture.service.auth.replace_package_trust(Vec::new())?;
    let before = fixture.service.data()?.store.meta()?;
    let PackageResponseV1::History(history) = fixture
        .package(
            PackageRequestV1::InspectInstanceHistory {
                instance_id: "plain".into(),
            },
            false,
        )
        .await?
    else {
        return Err("SQL history variant".into());
    };
    assert_eq!(history, vec![receipt]);
    assert_eq!(fixture.service.data()?.store.meta()?, before);
    Ok(())
}
