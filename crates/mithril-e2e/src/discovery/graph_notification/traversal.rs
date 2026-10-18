use std::collections::BTreeSet;

use araphor_query::datafusion::arrow::array::RecordBatch;
use araphor_query::execution::{Engine, Limits, Read};
use datafusion_common::ScalarValue;
use futures_util::TryStreamExt;

use super::*;

const TRAVERSAL_SQL: &str =
    "SELECT r.relationship_key, r.proof_quality, r.required_coverage_interval_ids,
        r.graph_result_id, source.traversal_depth, destination.traversal_depth
     FROM relationships r JOIN graph_subjects source
     ON r.tenant_id = source.tenant_id AND r.graph_result_id = source.graph_result_id
        AND r.from_subject_id = source.subject_id
     JOIN graph_subjects destination
     ON r.tenant_id = destination.tenant_id AND r.graph_result_id = destination.graph_result_id
        AND r.to_subject_id = destination.subject_id";

struct TraversalSelection<'a> {
    subjects: BTreeSet<GraphSubjectKeyV1>,
    edges: Vec<&'a GraphEdgeV1>,
    hop_boundary: bool,
}

impl<'a> TraversalSelection<'a> {
    fn new(snapshot: &'a GraphSnapshotV1, seed: &GraphSubjectKeyV1) -> Self {
        let mut subjects = BTreeSet::from([seed.clone()]);
        for edge in &snapshot.graph.edges {
            if edge.key.from == *seed {
                subjects.insert(edge.key.to.clone());
            }
        }
        let edges = snapshot
            .graph
            .edges
            .iter()
            .filter(|edge| subjects.contains(&edge.key.from) && subjects.contains(&edge.key.to))
            .collect();
        let hop_boundary = snapshot.graph.edges.iter().any(|edge| {
            edge.key.from != *seed
                && subjects.contains(&edge.key.from)
                && !subjects.contains(&edge.key.to)
        });
        Self {
            subjects,
            edges,
            hop_boundary,
        }
    }

    fn chunks(&self) -> Vec<&[&'a GraphEdgeV1]> {
        let limit = Limits::default().output_rows;
        if self.edges.len() <= limit {
            vec![self.edges.as_slice()]
        } else {
            self.edges.chunks(limit).collect()
        }
    }
}

impl GraphNotificationQualification {
    pub(super) async fn traverse(
        data: Arc<AnalysisStore>,
        snapshot: &GraphSnapshotV1,
        finding: &FindingV1,
        result_id: &str,
        now: u64,
    ) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
        let seed = &finding.subject_id;
        let selected = TraversalSelection::new(snapshot, seed);
        let chunks = selected.chunks();
        let paged = chunks.len() > 1;
        assert_eq!(finding.tenant_id, snapshot.scope.identity.tenant_id);
        let mut selection =
            AnalysisSelectionV1::new(finding.tenant_id, vec![snapshot.scope.identity.clone()]);
        selection.select_graphs(
            Selection::Exact(vec![result_id.to_owned()]),
            Some(Self::traversal_request(seed, result_id)),
        )?;
        let engine = Engine::new(data, Limits::default())?;
        let mut receipt = None;
        let mut returned = BTreeSet::new();
        for chunk in &chunks {
            let edges = if paged { *chunk } else { &[] };
            let parameters = edges
                .iter()
                .map(|edge| {
                    serde_json::to_vec(&edge.key).map(|bytes| ScalarValue::Binary(Some(bytes)))
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let (plan, sources) = engine
                .prepare(
                    &Self::traversal_sql(paged.then_some(chunk.len())),
                    parameters,
                )
                .await?;
            let session =
                engine.session(selection.clone(), &AnalysisReadControl::default(), now)?;
            let (snapshot, stream) = session.stream(&plan, &sources, Read::Snapshot).await?;
            let batches = stream.try_collect::<Vec<_>>().await?;
            assert!(snapshot.page.exhausted);
            for key in Self::check_traversal(&batches, chunk, seed, result_id)? {
                assert!(returned.insert(key));
            }
            let current = snapshot
                .page
                .extraction
                .graph_traversal()
                .cloned()
                .ok_or("the traversal receipt is absent")?;
            Self::check_receipt(&current, &selected, result_id);
            if let Some(previous) = &receipt {
                assert_eq!(previous, &current);
            } else {
                receipt = Some(current);
            }
        }
        assert_eq!(
            returned,
            selected.edges.iter().map(|edge| edge.key.clone()).collect()
        );
        let denied = finding
            .effects
            .first()
            .ok_or("the denied effect is absent")?;
        assert!(selected
            .edges
            .iter()
            .any(|edge| edge.key.evidence.contains(&denied.evidence)));
        let receipt = receipt.ok_or("the traversal receipt is absent")?;
        Ok(json!({
            "result": "PASS", "caller": "araphor_query::execution::Session::stream",
            "exact_version_selected": true, "exact_subject_and_version_joins": true,
            "evidence_and_proof_preserved": true, "required_coverage_preserved": true,
            "denied_record_reached": true, "receipt": receipt,
            "query_scope": "exact tenant, source, and graph result",
            "performance_claim": false, "cross_node_physical_qualified": false,
            "input": Self::traversal_input(snapshot, finding, result_id),
            "sql_chunks": chunks.len(), "returned_relationships": returned.len(),
        }))
    }

    pub(super) fn traversal_input(
        snapshot: &GraphSnapshotV1,
        finding: &FindingV1,
        result_id: &str,
    ) -> serde_json::Value {
        let limits = Limits::default();
        let selected = TraversalSelection::new(snapshot, &finding.subject_id);
        let chunks = selected.chunks();
        let queries = chunks
            .iter()
            .map(|chunk| {
                json!({
                    "sql": Self::traversal_sql((chunks.len() > 1).then_some(chunk.len())),
                    "relationship_key_parameters": if chunks.len() > 1 { chunk.len() } else { 0 },
                    "expected_rows": chunk.len(),
                })
            })
            .collect::<Vec<_>>();
        json!({
            "request": Self::traversal_request(&finding.subject_id, result_id),
            "sql": TRAVERSAL_SQL,
            "sql_queries": queries, "parameter_encoding": "JSON_BLOB",
            "parameter_order": "selected snapshot.graph.edges order",
            "first_cursor": snapshot.first_cursor, "last_cursor": snapshot.last_cursor,
            "records": snapshot.input_manifest.evidence.len(),
            "subjects": snapshot.graph.subjects.len(), "relationships": snapshot.graph.edges.len(),
            "findings": snapshot.findings.len(), "context_facts": snapshot.graph.facts.len(),
            "manifest_contexts": snapshot.input_manifest.context.len(),
            "coverage_intervals": snapshot.input_manifest.coverage.len(),
            "limits": {
                "scan_bytes": limits.scan_bytes, "input_bytes": limits.input_bytes,
                "output_rows": limits.output_rows, "output_bytes": limits.output_bytes,
                "extract_timeout_ns": limits.extract_timeout.as_nanos(),
                "evaluate_timeout_ns": limits.evaluate_timeout.map(|timeout| timeout.as_nanos()),
            },
        })
    }

    fn traversal_request(seed: &GraphSubjectKeyV1, result_id: &str) -> GraphTraversalV1 {
        GraphTraversalV1 {
            seeds: vec![seed.clone()],
            result_ids: vec![result_id.into()],
            max_hops: 1,
            ..Default::default()
        }
    }

    fn traversal_sql(keys: Option<usize>) -> String {
        match keys {
            Some(keys) => format!(
                "{TRAVERSAL_SQL} WHERE r.relationship_key IN ({})",
                (1..=keys)
                    .map(|index| format!("${index}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            None => TRAVERSAL_SQL.to_owned(),
        }
    }

    fn check_receipt(
        receipt: &GraphTraversalReceiptV1,
        selected: &TraversalSelection<'_>,
        result_id: &str,
    ) {
        assert_eq!(receipt.result_ids, vec![result_id.to_owned()]);
        assert_eq!(receipt.unique_subject_count, selected.subjects.len());
        assert_eq!(receipt.versioned_subject_count, selected.subjects.len());
        assert_eq!(receipt.relationship_count, selected.edges.len());
        assert_eq!(receipt.max_hops, 1);
        assert_eq!(receipt.hop_boundary, selected.hop_boundary);
    }

    fn check_traversal(
        batches: &[RecordBatch],
        expected: &[&GraphEdgeV1],
        seed: &GraphSubjectKeyV1,
        result_id: &str,
    ) -> std::result::Result<BTreeSet<GraphEdgeKeyV1>, Box<dyn StdError>> {
        assert_eq!(
            batches.iter().map(RecordBatch::num_rows).sum::<usize>(),
            expected.len()
        );
        let mut returned = BTreeSet::new();
        for batch in batches {
            for row in 0..batch.num_rows() {
                let row = batch
                    .columns()
                    .iter()
                    .map(|array| ScalarValue::try_from_array(array, row))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let [ScalarValue::Binary(Some(key)), ScalarValue::Binary(Some(proof)), ScalarValue::Binary(Some(coverage)), ScalarValue::Utf8(Some(version)), ScalarValue::UInt32(Some(from)), ScalarValue::UInt32(Some(to))] =
                    row.as_slice()
                else {
                    return Err("the graph traversal join row is invalid".into());
                };
                let key: GraphEdgeKeyV1 = serde_json::from_slice(key)?;
                assert!(returned.insert(key.clone()));
                let edge = expected
                    .iter()
                    .find(|edge| edge.key == key)
                    .ok_or("the traversal returned an unexpected edge")?;
                assert_eq!(
                    serde_json::from_slice::<ProofQualityV1>(proof)?,
                    edge.proof_quality
                );
                assert_eq!(
                    serde_json::from_slice::<Vec<[u8; 16]>>(coverage)?,
                    edge.required_coverage_interval_ids
                );
                assert_eq!(version, result_id);
                assert_eq!(*from, u32::from(key.from != *seed));
                assert_eq!(*to, u32::from(key.to != *seed));
            }
        }
        assert_eq!(
            returned,
            expected.iter().map(|edge| edge.key.clone()).collect()
        );
        Ok(returned)
    }
}
