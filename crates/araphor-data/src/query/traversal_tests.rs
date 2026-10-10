use super::*;
use crate::{
    Error, GraphEdgeTypeV1, GraphSubjectAuthorityV1, GraphSubjectKeyV1, GraphSubjectKindV1,
    GraphTraversalDirectionV1,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn seed(tenant_id: [u8; 16]) -> GraphSubjectKeyV1 {
    GraphSubjectKeyV1 {
        tenant_id,
        authority: GraphSubjectAuthorityV1::Native {
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
        },
        kind: GraphSubjectKindV1::Task,
        identity: vec![3; 16],
    }
}

fn grant() -> QueryGrant {
    QueryGrant {
        principal: "graph-reader".into(),
        revision: 1,
        selection: AnalysisSelectionV1::tenant([1; 16]),
    }
}

#[test]
fn graph_traversal_definition_bounds() -> TestResult {
    let request = GraphTraversalV1 {
        seeds: vec![seed([1; 16])],
        result_ids: vec!["graph-v1".into()],
        direction: GraphTraversalDirectionV1::Both,
        edge_types: vec![GraphEdgeTypeV1::NativeParent],
        max_hops: 0,
        max_subjects: 1,
        max_relationships: 1,
    };
    let bytes = serde_json::to_vec(&request)?;
    assert_eq!(GraphTraversalV1::try_from(bytes.as_slice())?, request);
    let defaults = serde_json::to_vec(&serde_json::json!({ "seeds": request.seeds }))?;
    let decoded = GraphTraversalV1::try_from(defaults.as_slice())?;
    assert_eq!(decoded.direction, GraphTraversalDirectionV1::Outgoing);
    assert_eq!(decoded.max_hops, 1);
    assert!(decoded.result_ids.is_empty());
    assert!(decoded.edge_types.is_empty());
    let unknown = serde_json::to_vec(&serde_json::json!({
        "seeds": decoded.seeds, "partial": true,
    }))?;
    assert!(matches!(
        GraphTraversalV1::try_from(unknown.as_slice()),
        Err(Error::QueryInvalid { .. })
    ));
    assert!(
        GraphTraversalV1::try_from(vec![b' '; GraphTraversalV1::MAX_BYTES + 1].as_slice()).is_err()
    );
    let mut duplicate = request.clone();
    duplicate.seeds.push(request.seeds[0].clone());
    assert!(duplicate.validate().is_err());
    duplicate = request;
    duplicate.max_hops = GraphTraversalV1::MAX_HOPS + 1;
    assert!(duplicate.validate().is_err());
    Ok(())
}

#[test]
fn graph_traversal_plan_scope() -> TestResult {
    let request = GraphTraversalV1 {
        seeds: vec![seed([1; 16])],
        result_ids: vec!["graph-v1".into(), "graph-v2".into()],
        ..Default::default()
    };
    let sql = QuerySql::admit(
        "SELECT s.graph_result_id, s.subject_id FROM graph_subjects s JOIN relationships r ON s.graph_result_id = r.graph_result_id",
        vec![], false,
    )?;
    let plan = QueryPlan::client_graph(grant(), sql, request.clone())?;
    let selection = plan.dependencies(100)?;
    assert_eq!(selection.graph_traversal.as_ref(), Some(&request));
    assert_eq!(selection.graphs, request.result_ids);
    assert!(!selection.graph);
    assert!(matches!(selection.sources, Selection::All));
    for (sql, follow) in [
        ("SELECT * FROM graph_subjects", true),
        ("SELECT * FROM catalog", false),
        (
            "SELECT s.subject_id FROM graph_subjects s JOIN events e ON s.tenant_id = e.tenant_id",
            false,
        ),
    ] {
        assert!(matches!(
            QueryPlan::client_graph(
                grant(),
                QuerySql::admit(sql, vec![], follow)?,
                request.clone()
            ),
            Err(Error::QueryUnsupported { .. }),
        ));
    }
    let mut foreign = request;
    foreign.seeds[0].tenant_id = [4; 16];
    assert!(matches!(
        QueryPlan::client_graph(
            grant(),
            QuerySql::admit("SELECT * FROM graph_subjects", vec![], false)?,
            foreign
        ),
        Err(Error::QueryDenied { .. }),
    ));
    Ok(())
}
