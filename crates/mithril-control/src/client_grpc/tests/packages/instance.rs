use araphor_data::{AnalysisSelectionV1, ManagedRequest, PackageActionV1};
use araphor_discovery_definition::{Definition, Program, Source};

use super::*;

impl Fixture {
    async fn retained_instance(
        &self,
        id: &str,
        sql: &str,
    ) -> TestResult<Arc<araphor_analysis::Instance>> {
        let access = self
            .service
            .authenticate(&self.request(proto::QueryRequest::default(), false)?, false)
            .await?;
        let grant =
            access.package_grant(AnalysisSelectionV1::tenant([1; 16]), PackageActionV1::Run)?;
        let query = Arc::clone(&self.service.data()?.query);
        let PackageResponseV1::Definition(definition) = self
            .package(
                PackageRequestV1::AdmitDefinition {
                    definition: Definition {
                        name: "retained-count".into(),
                        description: "Read a retained package result.".into(),
                        labels: BTreeMap::new(),
                        program: Program::Sql {
                            source: Source::Inline { inline: sql.into() },
                        },
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
    let response = fixture
        .package(
            PackageRequestV1::QueryInstanceResult {
                instance_id: "counts".into(),
                result_id: reference.result_id.clone(),
                sql: "SELECT count, __row_index FROM rows".into(),
            },
            false,
        )
        .await?;
    let PackageResponseV1::Output(output) = response else {
        return Err("retained selected rows variant".into());
    };
    let data = output.decode_any(Default::default())?;
    assert_eq!(data.name, "query");
    assert_eq!(data.rows(), 1);
    assert_eq!(data.batches[0].num_columns(), 2);
    for (column, value) in [(0, 3), (1, 0)] {
        assert_eq!(
            data.batches[0]
                .column(column)
                .as_any()
                .downcast_ref::<arrow_array::UInt64Array>()
                .ok_or("unsigned column")?
                .value(0),
            value
        );
    }
    let error = fixture
        .package(
            PackageRequestV1::QueryInstanceResult {
                instance_id: other.admitted().spec.id.clone(),
                result_id: reference.result_id.clone(),
                sql: "SELECT * FROM rows".into(),
            },
            false,
        )
        .await
        .err()
        .ok_or("foreign instance result returned")?;
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    for sql in [
        "SELECT * FROM events",
        "WITH unused AS (SELECT * FROM events) SELECT * FROM rows",
        "DELETE FROM rows",
    ] {
        assert!(fixture
            .package(
                PackageRequestV1::QueryInstanceResult {
                    instance_id: "counts".into(),
                    result_id: reference.result_id.clone(),
                    sql: sql.into(),
                },
                false
            )
            .await
            .is_err());
    }
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
async fn raw_rpc_keeps_auxiliaries() -> TestResult {
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
    assert_eq!(result.result_id, reference.result_id);
    assert_eq!(result.image, pin);
    assert_eq!(result.package, result.image.image);
    assert_eq!(result.export, "count");
    assert_eq!(result.commit_revision, reference.commit_revision);
    assert!(!result.current);
    assert_eq!(result.context.target, "sql");
    assert_eq!(result.context.artifact, None);
    assert_eq!(result.context.context.id, requests[0].id);
    assert_eq!(
        result.context.context.time_utc_ns,
        requests[0].time_utc_ns as i64
    );
    assert_eq!(result.context.context.seed, Some(7));
    assert_eq!(result.limits, model.limits);
    assert_eq!(result.context.inputs.len(), 1);
    assert_eq!(result.context.input_coverage.len(), 1);
    assert_eq!(result.output.datasets.len(), 2);
    assert_eq!(result.output.evidence.len(), 2);
    assert_eq!(result.output.reasons.len(), 2);
    let output = result.output.decode_model(&model)?;
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
