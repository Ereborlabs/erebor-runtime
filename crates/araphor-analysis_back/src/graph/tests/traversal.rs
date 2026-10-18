use std::collections::{BTreeMap, BTreeSet};

use araphor_query::datafusion::arrow::array::{Array, BinaryArray, RecordBatch, UInt32Array};
use araphor_query::datafusion::common::ScalarValue;
use araphor_query::execution::Read;
use araphor_query::sources::ArrowSnapshot;
use futures_util::TryStreamExt;

use super::*;

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

    async fn query(
        &self,
        request: GraphTraversalV1,
        sql: &str,
    ) -> Result<(Arc<ArrowSnapshot>, Vec<RecordBatch>)> {
        self.selected(
            request,
            AnalysisSelectionV1::new(source().tenant_id, vec![source()]),
            Limits::default(),
            Arc::new(AnalysisReadControl::default()),
            sql,
        )
        .await
    }

    async fn selected(
        &self,
        request: GraphTraversalV1,
        selection: AnalysisSelectionV1,
        limits: Limits,
        control: Arc<AnalysisReadControl>,
        sql: &str,
    ) -> Result<(Arc<ArrowSnapshot>, Vec<RecordBatch>)> {
        Self::read(
            Arc::clone(&self.native.store),
            request,
            selection,
            limits,
            control,
            sql,
        )
        .await
    }

    async fn read(
        store: Arc<AnalysisStore>,
        request: GraphTraversalV1,
        mut selection: AnalysisSelectionV1,
        limits: Limits,
        control: Arc<AnalysisReadControl>,
        sql: &str,
    ) -> Result<(Arc<ArrowSnapshot>, Vec<RecordBatch>)> {
        let graphs = if selection.graphs().is_empty() {
            Selection::All
        } else {
            Selection::Exact(selection.graphs().to_vec())
        };
        selection.select_graphs(graphs, Some(request))?;
        let engine = Engine::new(store, limits)?;
        let (plan, sources) = engine.prepare(sql, Vec::new()).await?;
        let session = engine.session(selection, &control, 100)?;
        let (snapshot, stream) = session.stream(&plan, &sources, Read::Snapshot).await?;
        let batches = stream.try_collect().await?;
        Ok((snapshot, batches))
    }

    fn depths(batches: &[RecordBatch]) -> TestResult<BTreeMap<GraphSubjectKeyV1, u64>> {
        let mut depths = BTreeMap::new();
        for batch in batches {
            let subjects = batch
                .column(0)
                .as_any()
                .downcast_ref::<BinaryArray>()
                .ok_or("the traversal subject array is invalid")?;
            let values = batch
                .column(1)
                .as_any()
                .downcast_ref::<UInt32Array>()
                .ok_or("the traversal depth array is invalid")?;
            for row in 0..batch.num_rows() {
                assert!(!subjects.is_null(row) && !values.is_null(row));
                depths.insert(
                    serde_json::from_slice(subjects.value(row))?,
                    u64::from(values.value(row)),
                );
            }
        }
        Ok(depths)
    }

    fn count(batches: &[RecordBatch]) -> TestResult<i64> {
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
        let batch = batches
            .iter()
            .find(|batch| batch.num_rows() > 0)
            .ok_or("the traversal count batch is absent")?;
        match ScalarValue::try_from_array(batch.column(0), 0)? {
            ScalarValue::Int64(Some(value)) => Ok(value),
            _ => Err("the traversal count value is invalid".into()),
        }
    }

    fn data_error<'a>(
        mut error: &'a (dyn std::error::Error + 'static),
    ) -> Option<&'a araphor_data::Error> {
        loop {
            if let Some(crate::Error::Data { source }) = error.downcast_ref::<crate::Error>() {
                return Some(source);
            }
            if let Some(crate::Error::Query { source }) = error.downcast_ref::<crate::Error>() {
                error = source;
                continue;
            }
            if let Some(araphor_query::Error::Data { source }) =
                error.downcast_ref::<araphor_query::Error>()
            {
                return Some(source);
            }
            if let Some(error) = error.downcast_ref::<araphor_data::Error>() {
                return Some(error);
            }
            error = error.source()?;
        }
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
    assert_eq!(TraversalFixture::depths(&result.1)?, expected);
    assert!(result.0.page.exhausted);
    let receipt = result
        .0
        .page
        .extraction
        .graph_traversal()
        .ok_or("traversal receipt")?;
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
    assert_eq!(TraversalFixture::count(&counted.1)?, 9);
    let mut request = TraversalFixture::request(8);
    request.seeds.push(TraversalFixture::subject(1025));
    let multiple = fixture.query(request, SUBJECT_SQL).await?;
    let mut expected = expected;
    for (index, depth) in [(1025, 0), (2048, 1), (2049, 2)] {
        expected.insert(TraversalFixture::subject(index), depth);
    }
    assert_eq!(TraversalFixture::depths(&multiple.1)?, expected);
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
        assert_eq!(TraversalFixture::depths(&result.1)?, expected);
        let receipt = result
            .0
            .page
            .extraction
            .graph_traversal()
            .ok_or("traversal receipt")?;
        assert_eq!(receipt.max_hops, 1);
        assert!(receipt.hop_boundary);
    }
    let zero = fixture
        .query(TraversalFixture::request(0), SUBJECT_SQL)
        .await?;
    assert_eq!(
        TraversalFixture::depths(&zero.1)?,
        BTreeMap::from([(TraversalFixture::subject(0), 0)])
    );
    assert_eq!(
        zero.0
            .page
            .extraction
            .graph_traversal()
            .ok_or("zero-hop receipt")?
            .relationship_count,
        0
    );
    assert!(
        zero.0
            .page
            .extraction
            .graph_traversal()
            .ok_or("zero-hop receipt")?
            .hop_boundary
    );
    let mut request = TraversalFixture::request(8);
    request.edge_types = vec![GraphEdgeTypeV1::NativeEffect];
    let filtered = fixture.query(request, SUBJECT_SQL).await?;
    assert_eq!(
        TraversalFixture::depths(&filtered.1)?,
        TraversalFixture::depths(&zero.1)?
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
        assert_eq!(
            result.1.iter().map(RecordBatch::num_rows).sum::<usize>(),
            0,
            "borrowed {change} identity"
        );
        assert_eq!(
            result
                .0
                .page
                .extraction
                .graph_traversal()
                .ok_or("empty receipt")?
                .unique_subject_count,
            0
        );
    }
    let mut selection = AnalysisSelectionV1::new(source().tenant_id, vec![source()]);
    selection.binding_ids.push([11; 16]);
    let scoped = fixture
        .selected(
            TraversalFixture::request(8),
            selection,
            Limits::default(),
            Arc::new(AnalysisReadControl::default()),
            SUBJECT_SQL,
        )
        .await?;
    assert_eq!(scoped.1.iter().map(RecordBatch::num_rows).sum::<usize>(), 0);
    Ok(())
}
