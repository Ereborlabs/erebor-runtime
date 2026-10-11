use std::collections::BTreeMap;

use araphor_analysis_sdk::{DataType, Field, Model, Package, Port, Schema};
use araphor_data::{
    PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1, PackageRequestV1,
    PackageResponseV1, SqlModelV1,
};

use super::*;

fn bundle() -> PackageBundleV1 {
    let descriptor = Package::new(
        "api.fixture",
        "1",
        vec![Model::new(
            "count",
            Vec::new(),
            vec![Port::new(
                "rows",
                Schema::new(vec![Field::new("count", DataType::UInt64, false)]),
            )],
        )],
    );
    PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: descriptor.id.clone(),
            revision: descriptor.revision.clone(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor,
            implementations: vec![PackageImplementationV1::Sql {
                export: "count".into(),
                inputs: BTreeMap::new(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([("rows".into(), "SELECT 3::UBIGINT AS count".into())]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        }],
    }
}

impl Fixture {
    async fn package(
        &self,
        operation: PackageRequestV1,
        mutation: bool,
    ) -> Result<PackageResponseV1, tonic::Status> {
        let request = proto::PackageOperationRequest {
            definition_json: serde_json::to_vec(&operation)
                .map_err(|_| Status::internal("test encoding"))?,
            selection: None,
        };
        let request = self
            .request(request, mutation)
            .map_err(|_| Status::internal("test request"))?;
        let reply = self.service.package_operation(request).await?.into_inner();
        serde_json::from_slice(&reply.result_json).map_err(|_| Status::internal("test result"))
    }
}

#[tokio::test]
async fn package_rpc_authority_trust() -> TestResult {
    let fixture = Fixture::new()?;
    let bundle = bundle();
    let operation = PackageRequestV1::Install {
        scope_id: "test".into(),
        bundle: bundle.clone(),
        parameters: None,
    };
    assert_eq!(
        fixture
            .package(operation.clone(), true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    assert_eq!(
        fixture
            .package(operation.clone(), false)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    assert_eq!(
        fixture
            .package(operation.clone(), true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    fixture
        .service
        .auth
        .replace_package_trust(vec![crate::PackageTrustPinV1 {
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: bundle.digest()?,
        }])?;
    let installed = fixture.package(operation, true).await?;
    assert_eq!(installed.package_id, "api.fixture");
    assert!(installed.exports.iter().all(|export| export.active));
    let inspected = fixture
        .package(
            PackageRequestV1::Inspect {
                scope_id: "test".into(),
                package_id: "api.fixture".into(),
            },
            false,
        )
        .await?;
    assert_eq!(inspected.exports.len(), 1);
    fixture.service.auth.replace_package_managers(Vec::new())?;
    assert_eq!(
        fixture
            .package(
                PackageRequestV1::Run {
                    scope_id: "test".into(),
                    package_id: "api.fixture".into(),
                    export: None,
                    evaluation_id: "denied".into(),
                    parameters: None,
                },
                true
            )
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    Ok(())
}

#[test]
fn package_response_encoding_bound() -> TestResult {
    let mut response = PackageResponseV1 {
        scope_id: "test".into(),
        package_id: "api.fixture".into(),
        exports: Vec::new(),
        tests: Vec::new(),
        output: None,
    };
    let bytes = ClientGrpcOwner::package_response(&response)?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes)?,
        serde_json::to_value(&response)?
    );
    response.output = Some(araphor_data::PackageOutputV1 {
        datasets: vec![araphor_data::PackageDatasetV1 {
            name: "rows".into(),
            ipc: vec![255; araphor_data::MAX_PACKAGE_BYTES],
        }],
        ..Default::default()
    });
    let error = ClientGrpcOwner::package_response(&response)
        .err()
        .ok_or("oversized response passed")?;
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(error.details())?,
        serde_json::json!({"code":"limit","field":"response bytes"})
    );
    Ok(())
}
