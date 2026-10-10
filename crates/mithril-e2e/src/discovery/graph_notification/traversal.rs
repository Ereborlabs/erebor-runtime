use std::collections::BTreeSet;

use duckdb::types::Value;
use tokio::sync::watch;

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

struct TraversalAccess {
    tenant: [u8; 16],
    revision: watch::Sender<u64>,
}

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
        let limit = QueryLimits::default()
            .output_rows
            .min(QuerySql::PARAMETER_COUNT);
        if self.edges.len() <= limit {
            vec![self.edges.as_slice()]
        } else {
            self.edges.chunks(limit).collect()
        }
    }
}

impl QueryAuthorization for TraversalAccess {
    fn check(&self, grant: &QueryGrant) -> Result<()> {
        if grant.principal != "qualification-graph"
            || grant.selection.tenant_id != self.tenant
            || grant.revision != *self.revision.borrow()
        {
            return Err(Error::QueryDenied {
                location: snafu::Location::default(),
            });
        }
        Ok(())
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.revision.subscribe()
    }

    fn expires_ns(&self) -> Option<u64> {
        None
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
        let access = Arc::new(TraversalAccess {
            tenant: finding.tenant_id,
            revision: watch::channel(1).0,
        });
        let query = Arc::new(QueryOwner::new(data, QueryLimits::default())?);
        let mut receipt = None;
        let mut returned = BTreeSet::new();
        for chunk in &chunks {
            let plan = Self::traversal_plan(snapshot, seed, result_id, paged.then_some(*chunk))?;
            let result = query
                .clone()
                .query_client(
                    plan,
                    access.clone(),
                    now,
                    Arc::new(AnalysisReadControl::default()),
                )
                .await?;
            for key in Self::check_traversal(&result, chunk, seed, result_id)? {
                assert!(returned.insert(key));
            }
            let current = result
                .graph_traversal
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
            "result": "PASS", "caller": "QueryOwner::query_client",
            "exact_version_selected": true, "exact_subject_and_version_joins": true,
            "evidence_and_proof_preserved": true, "required_coverage_preserved": true,
            "denied_record_reached": true, "receipt": receipt,
            "query_authorization": "fixed qualification grant",
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
        let limits = QueryLimits::default();
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
                "evaluate_timeout_ns": limits.evaluate_timeout.as_nanos(),
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

    fn traversal_plan(
        snapshot: &GraphSnapshotV1,
        seed: &GraphSubjectKeyV1,
        result_id: &str,
        edges: Option<&[&GraphEdgeV1]>,
    ) -> Result<QueryPlan> {
        let sql = Self::traversal_sql(edges.map(|edges| edges.len()));
        let parameters = edges
            .unwrap_or_default()
            .iter()
            .map(|edge| serde_json::to_vec(&edge.key).map(Value::Blob))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|source| Error::GraphEncoding {
                source,
                location: snafu::Location::default(),
            })?;
        QueryPlan::client_graph(
            QueryGrant {
                principal: "qualification-graph".into(),
                revision: 1,
                selection: AnalysisSelectionV1::new(
                    snapshot.scope.identity.tenant_id,
                    vec![snapshot.scope.identity.clone()],
                ),
            },
            QuerySql::admit(&sql, parameters, false)?,
            Self::traversal_request(seed, result_id),
        )
    }

    fn traversal_sql(keys: Option<usize>) -> String {
        match keys {
            Some(keys) => format!(
                "{TRAVERSAL_SQL} WHERE r.relationship_key IN ({})",
                std::iter::repeat_n("?", keys)
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
        result: &QueryResult,
        expected: &[&GraphEdgeV1],
        seed: &GraphSubjectKeyV1,
        result_id: &str,
    ) -> std::result::Result<BTreeSet<GraphEdgeKeyV1>, Box<dyn StdError>> {
        assert!(!result.limited);
        assert_eq!(result.rows.len(), expected.len());
        let mut returned = BTreeSet::new();
        for row in &result.rows {
            let [Value::Blob(key), Value::Blob(proof), Value::Blob(coverage), Value::Text(version), Value::UInt(from), Value::UInt(to)] =
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
        assert_eq!(
            returned,
            expected.iter().map(|edge| edge.key.clone()).collect()
        );
        Ok(returned)
    }
}
