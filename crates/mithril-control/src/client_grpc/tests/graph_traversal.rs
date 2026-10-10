use araphor_data::{
    GraphSubjectAuthorityV1, GraphSubjectKeyV1, GraphSubjectKindV1, GraphTraversalV1,
};

use super::*;

fn definition(tenant_id: [u8; 16]) -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(&GraphTraversalV1 {
        seeds: vec![GraphSubjectKeyV1 {
            tenant_id,
            authority: GraphSubjectAuthorityV1::Native {
                node_id: "node-a".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
            },
            kind: GraphSubjectKindV1::Task,
            identity: vec![3; 16],
        }],
        ..Default::default()
    })?)
}

#[tokio::test]
async fn graph_traversal_grpc_contract() -> TestResult {
    let fixture = Fixture::new()?;
    let request = fixture.request(proto::QueryRequest::default(), false)?;
    let access = fixture.service.authenticate(&request, false).await?;
    let valid = definition([1; 16])?;
    for (definition_json, follow, bookmark, expected) in [
        (b"{}".to_vec(), false, vec![], tonic::Code::InvalidArgument),
        (
            vec![b' '; GraphTraversalV1::MAX_BYTES + 1],
            false,
            vec![],
            tonic::Code::InvalidArgument,
        ),
        (
            definition([4; 16])?,
            false,
            vec![],
            tonic::Code::PermissionDenied,
        ),
        (valid.clone(), true, vec![], tonic::Code::Unimplemented),
        (valid, false, vec![1], tonic::Code::Unimplemented),
    ] {
        let error = fixture
            .service
            .query_request(
                proto::QueryRequest {
                    sql: "SELECT * FROM graph_subjects".into(),
                    follow,
                    bookmark,
                    graph_traversal: Some(proto::GraphTraversal { definition_json }),
                    ..Default::default()
                },
                access.clone(),
            )
            .err()
            .ok_or("invalid graph request was accepted")?;
        assert_eq!(error.code(), expected);
    }
    Ok(())
}

#[tokio::test]
async fn graph_traversal_grpc_receipt() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.service.control = fixture.service.control.clone().with_graph()?;
    let request = fixture.request(
        proto::QueryRequest {
            sql: "SELECT COUNT(*) FROM graph_subjects".into(),
            graph_traversal: Some(proto::GraphTraversal {
                definition_json: definition([1; 16])?,
            }),
            ..Default::default()
        },
        false,
    )?;
    let access = fixture.service.authenticate(&request, false).await?;
    let mut stream = fixture
        .service
        .query_request(request.into_inner(), access)?;
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::query_frame::Payload::Metadata(_))
    ));
    let Some(proto::query_frame::Payload::Rows(rows)) = Fixture::next(&mut stream).await?.payload
    else {
        return Err("graph query rows are absent".into());
    };
    assert_eq!(rows.rows.len(), 1);
    assert_eq!(
        rows.graph_traversal,
        Some(proto::GraphTraversalReceipt {
            result_ids: vec![],
            unique_subject_count: 0,
            versioned_subject_count: 0,
            relationship_count: 0,
            max_hops: 1,
            hop_boundary: false,
        })
    );
    Ok(())
}
