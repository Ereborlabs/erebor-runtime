use super::*;
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, ContextSensitivityV1,
    GraphEdgeTypeV1, GraphSubjectKeyV1, GraphSubjectKindV1,
};

pub(super) struct NativeFixture {
    pub(super) stored: CommitFixture,
    pub(super) subjects: Vec<GraphSubjectKeyV1>,
    pub(super) selection: AnalysisSelectionV1,
    pub(super) request: GraphTraversalV1,
}

impl NativeFixture {
    pub(super) fn new(restricted: bool) -> TestResult<Self> {
        let mut stored = CommitFixture::new()?;
        let source = &stored.snapshot.scope.identity;
        let subjects = (0_u64..3)
            .map(|index| {
                GraphSubjectKeyV1::native(
                    source,
                    GraphSubjectKindV1::Task,
                    index.to_be_bytes().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
        let request = GraphTraversalV1 {
            seeds: vec![subjects[0].clone()],
            ..Default::default()
        };
        stored.snapshot.graph.subjects = subjects.clone();
        let edge = stored.snapshot.graph.edges[0].clone();
        stored.snapshot.graph.edges = subjects
            .windows(2)
            .map(|pair| {
                let mut edge = edge.clone();
                edge.key.from = pair[0].clone();
                edge.key.to = pair[1].clone();
                edge.key.edge_type = GraphEdgeTypeV1::NativeParent;
                edge
            })
            .collect();
        if restricted {
            Self::restrict(&mut stored)?;
        }
        stored.request.body = serde_json::to_vec(&stored.snapshot)?;
        stored.store.commit_graph(&stored.request, true)?;
        Ok(Self {
            stored,
            subjects,
            selection,
            request,
        })
    }

    pub(super) fn owner(&self, mut limits: QueryLimits) -> crate::Result<QueryOwner> {
        limits.extract_timeout = std::time::Duration::from_secs(30);
        QueryOwner::new(self.stored.store.clone(), limits)
    }

    pub(super) fn replace_empty(&self) -> TestResult<String> {
        let mut snapshot = self.stored.snapshot.clone();
        snapshot.previous_result_id = Some(self.stored.request.result_id.clone());
        snapshot.graph.subjects.clear();
        snapshot.graph.edges.clear();
        snapshot.graph.branches.clear();
        snapshot.findings.clear();
        let mut request = self.stored.request.clone();
        request.expected_cursor = 1;
        request.result_id = "graph:sdk-empty".into();
        request.created_utc_ns += 1;
        request.body = serde_json::to_vec(&snapshot)?;
        self.stored.store.commit_graph(&request, false)?;
        Ok(request.result_id)
    }

    fn restrict(stored: &mut CommitFixture) -> TestResult {
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: stored.snapshot.scope.identity.tenant_id,
                owner_id: "sdk-native-fixture".into(),
                entity_key: b"entity".to_vec(),
                lifetime_key: b"lifetime".to_vec(),
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::HostRestricted,
            body: b"retained context".to_vec(),
        };
        let revision = stored.store.commit_context(&context)?;
        stored
            .snapshot
            .input_manifest
            .context
            .push(context.key.clone());
        stored.snapshot.graph.revision = stored.snapshot.input_manifest.clone();
        for finding in &mut stored.snapshot.findings {
            finding.revision = stored.snapshot.input_manifest.clone();
        }
        stored.request.context_revision = revision;
        stored.request.context_refs.push(AnalysisContextRefV1 {
            key: context.key,
            commit_revision: revision,
        });
        Ok(())
    }
}

pub(super) fn control() -> crate::Result<AnalysisReadControl> {
    AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))
}

pub(super) fn column<'a, T: sdk::arrow_array::Array + 'static>(
    batch: &'a sdk::RecordBatch,
    name: &str,
) -> sdk::Result<&'a T> {
    batch
        .column_by_name(name)
        .and_then(|value| value.as_any().downcast_ref())
        .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, format!("column {name}")))
}
