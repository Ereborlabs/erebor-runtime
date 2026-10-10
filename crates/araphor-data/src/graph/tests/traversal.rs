use std::collections::{BTreeMap, BTreeSet};

use duckdb::types::Value;

use super::*;
use crate::query::graph_tests::Authority;

mod bindings;
mod fixtures;
mod limits;
mod recovery;
use fixtures::TraversalFixture;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const SUBJECT_SQL: &str = "SELECT DISTINCT subject_id, traversal_depth FROM graph_subjects";

impl TraversalFixture {
    fn request(max_hops: u32) -> GraphTraversalV1 {
        GraphTraversalV1 {
            seeds: vec![Self::subject(0)],
            max_hops,
            ..Default::default()
        }
    }

    async fn query(&self, request: GraphTraversalV1, sql: &str) -> Result<QueryResult> {
        self.selected(
            request,
            AnalysisSelectionV1::new(source().tenant_id, vec![source()]),
            QueryLimits::default(),
            Arc::new(AnalysisReadControl::default()),
            sql,
        )
        .await
    }

    async fn selected(
        &self,
        request: GraphTraversalV1,
        selection: AnalysisSelectionV1,
        limits: QueryLimits,
        control: Arc<AnalysisReadControl>,
        sql: &str,
    ) -> Result<QueryResult> {
        let tenant = selection.tenant_id;
        let plan = QueryPlan::client_graph(
            QueryGrant {
                principal: "traversal-test".into(),
                revision: 1,
                selection,
            },
            QuerySql::admit(sql, vec![], false)?,
            request,
        )?;
        Arc::new(QueryOwner::new(self.native.store.clone(), limits)?)
            .query_client(plan, Arc::new(Authority::new(tenant)), 100, control)
            .await
    }

    fn depths(result: &QueryResult) -> TestResult<BTreeMap<GraphSubjectKeyV1, u64>> {
        result
            .rows
            .iter()
            .map(|row| match row.as_slice() {
                [Value::Blob(subject), Value::UInt(depth)] => {
                    Ok((serde_json::from_slice(subject)?, u64::from(*depth)))
                }
                _ => Err("the traversal subject row is invalid".into()),
            })
            .collect()
    }
}

#[tokio::test]
async fn native_traversal_large_graph() -> TestResult {
    let fixture = TraversalFixture::new(true)?;
    let mut subjects = BTreeSet::new();
    let mut edges = 0;
    for request in &fixture.requests {
        let snapshot = GraphSnapshotV1::try_from(request.body.as_slice())?;
        assert!(snapshot.graph.subjects.len() <= 2048);
        assert!(snapshot.graph.edges.len() <= 4096);
        subjects.extend(snapshot.graph.subjects);
        edges += snapshot.graph.edges.len();
    }
    assert_eq!(fixture.requests.len(), 17);
    assert_eq!(subjects.len(), 16_385);
    assert_eq!(edges, 32_769);
    let result = fixture
        .query(TraversalFixture::request(8), SUBJECT_SQL)
        .await?;
    let expected = [
        (0, 0),
        (1, 1),
        (2, 1),
        (3, 2),
        (1024, 3),
        (1025, 4),
        (2048, 5),
        (2049, 6),
    ]
    .into_iter()
    .map(|(index, depth)| (TraversalFixture::subject(index), depth))
    .collect();
    assert_eq!(TraversalFixture::depths(&result)?, expected);
    assert!(!result.limited);
    let receipt = result.graph_traversal.as_ref().ok_or("traversal receipt")?;
    assert_eq!(receipt.unique_subject_count, 8);
    assert_eq!(receipt.versioned_subject_count, 10);
    assert_eq!(receipt.relationship_count, 9);
    assert_eq!(receipt.max_hops, 8);
    assert!(!receipt.hop_boundary);
    let counted = fixture
        .query(
            TraversalFixture::request(8),
            "SELECT COUNT(*) FROM relationships",
        )
        .await?;
    assert_eq!(counted.rows, vec![vec![Value::BigInt(9)]]);
    let mut request = TraversalFixture::request(8);
    request.seeds.push(TraversalFixture::subject(1025));
    let multiple = fixture.query(request, SUBJECT_SQL).await?;
    let mut expected = expected;
    for (index, depth) in [(1025, 0), (2048, 1), (2049, 2)] {
        expected.insert(TraversalFixture::subject(index), depth);
    }
    assert_eq!(TraversalFixture::depths(&multiple)?, expected);
    Ok(())
}

#[tokio::test]
async fn native_traversal_directions_and_hops() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    for (direction, expected) in [
        (
            GraphTraversalDirectionV1::Outgoing,
            vec![(0, 0), (1, 1), (2, 1)],
        ),
        (GraphTraversalDirectionV1::Incoming, vec![(0, 0), (3, 1)]),
        (
            GraphTraversalDirectionV1::Both,
            vec![(0, 0), (1, 1), (2, 1), (3, 1)],
        ),
    ] {
        let mut request = TraversalFixture::request(1);
        request.direction = direction;
        let result = fixture.query(request, SUBJECT_SQL).await?;
        let expected = expected
            .into_iter()
            .map(|(index, depth)| (TraversalFixture::subject(index), depth))
            .collect();
        assert_eq!(TraversalFixture::depths(&result)?, expected);
        let receipt = result.graph_traversal.as_ref().ok_or("traversal receipt")?;
        assert_eq!(receipt.max_hops, 1);
        assert!(receipt.hop_boundary);
    }
    let zero = fixture
        .query(TraversalFixture::request(0), SUBJECT_SQL)
        .await?;
    assert_eq!(
        TraversalFixture::depths(&zero)?,
        BTreeMap::from([(TraversalFixture::subject(0), 0)])
    );
    assert_eq!(
        zero.graph_traversal
            .as_ref()
            .ok_or("zero-hop receipt")?
            .relationship_count,
        0
    );
    assert!(
        zero.graph_traversal
            .as_ref()
            .ok_or("zero-hop receipt")?
            .hop_boundary
    );
    let mut request = TraversalFixture::request(8);
    request.edge_types = vec![GraphEdgeTypeV1::NativeEffect];
    let filtered = fixture.query(request, SUBJECT_SQL).await?;
    assert_eq!(
        TraversalFixture::depths(&filtered)?,
        TraversalFixture::depths(&zero)?
    );
    Ok(())
}

#[tokio::test]
async fn native_traversal_exact_lifetimes() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    for change in ["node", "boot", "label", "kind"] {
        let mut seed = TraversalFixture::subject(0);
        if let GraphSubjectAuthorityV1::Native {
            node_id,
            node_boot_id,
            label_epoch,
        } = &mut seed.authority
        {
            match change {
                "node" => *node_id = "other-node".into(),
                "boot" => *node_boot_id = [99; 16],
                "label" => *label_epoch = 2,
                "kind" => seed.kind = GraphSubjectKindV1::Process,
                _ => unreachable!(),
            }
        }
        let mut request = TraversalFixture::request(8);
        request.seeds = vec![seed];
        let result = fixture.query(request, SUBJECT_SQL).await?;
        assert!(result.rows.is_empty(), "borrowed {change} identity");
        assert_eq!(
            result
                .graph_traversal
                .as_ref()
                .ok_or("empty receipt")?
                .unique_subject_count,
            0
        );
    }
    let mut request = TraversalFixture::request(8);
    request.seeds[0].tenant_id = [99; 16];
    assert!(matches!(
        fixture.query(request, SUBJECT_SQL).await,
        Err(Error::QueryDenied { .. })
    ));
    let mut selection = AnalysisSelectionV1::new(source().tenant_id, vec![source()]);
    selection.binding_ids.push([11; 16]);
    let scoped = fixture
        .selected(
            TraversalFixture::request(8),
            selection,
            QueryLimits::default(),
            Arc::new(AnalysisReadControl::default()),
            SUBJECT_SQL,
        )
        .await?;
    assert!(scoped.rows.is_empty());
    Ok(())
}
