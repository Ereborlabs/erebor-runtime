use super::*;

pub(super) struct TraversalFixture {
    pub(super) native: native_storage::CommitFixture,
    pub(super) requests: Vec<AnalysisResultCommitV1>,
}

impl TraversalFixture {
    pub(super) fn new(large: bool) -> TestResult<Self> {
        let native = native_storage::CommitFixture::new()?;
        let mut fixture = Self {
            native,
            requests: Vec::new(),
        };
        for window in 0..if large { 17 } else { 3 } {
            fixture.commit_window(window, large)?;
        }
        Ok(fixture)
    }

    pub(super) fn subject(index: u64) -> GraphSubjectKeyV1 {
        GraphSubjectKeyV1::native(
            &source(),
            GraphSubjectKindV1::Task,
            index.to_be_bytes().to_vec(),
        )
    }

    pub(super) fn replace(
        &self,
        window: usize,
        mut snapshot: GraphSnapshotV1,
        result_id: &str,
    ) -> TestResult {
        let original = &self.requests[window];
        snapshot.previous_result_id = Some(original.result_id.clone());
        let mut request = original.clone();
        request.result_id = result_id.into();
        request.expected_cursor = self.requests.len() as u64;
        request.consumed_cursor = request.expected_cursor;
        request.created_utc_ns += 10;
        request.body = serde_json::to_vec(&snapshot)?;
        self.native.store.commit_graph(&request, false)?;
        Ok(())
    }

    fn commit_window(&mut self, window: u64, large: bool) -> TestResult {
        let cursor = window + 1;
        let first = window * 1024;
        let mut event = wire(cursor, DeniedBeforeEffect, 2, 2, [20; 16]);
        if window != 0 {
            event.task_cookie = if window == 16 { first } else { first + 1 };
        }
        let observation = record(cursor, &event)?;
        if window != 0 {
            accept(&self.native.store, std::slice::from_ref(&observation))?;
            coverage(&self.native.store, cursor, cursor, "HEALTHY")?;
        }
        let mut replay = input(vec![observation]);
        replay.coverage[0].coverage_revision = cursor;
        replay.coverage_keys[0].report_revision = cursor;
        replay.coverage_keys[0].interval_revision = cursor;
        let mut snapshot = GraphAndFindingOwner::derive(&replay)?;
        snapshot.witness_deadline_utc_ns = 10 + cursor + GRAPH_WITNESS_TTL_NS;
        snapshot.graph.subjects = Self::subjects(window, large);
        snapshot.graph.edges = Self::edges(&snapshot, window, large);
        let request = AnalysisResultCommitV1 {
            scope: snapshot.scope.clone(),
            expected_cursor: window,
            consumed_cursor: cursor,
            coverage_revision: cursor,
            context_revision: 0,
            result_id: format!("graph:traversal:{window}"),
            body: serde_json::to_vec(&snapshot)?,
            created_utc_ns: 10 + cursor,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source().into(),
                cursor,
                expires_utc_ns: snapshot.witness_deadline_utc_ns,
            }],
            context_refs: vec![],
        };
        self.native.store.commit_graph(&request, true)?;
        self.requests.push(request);
        Ok(())
    }

    fn subjects(window: u64, large: bool) -> Vec<GraphSubjectKeyV1> {
        let first = window * 1024;
        let indices = if large {
            (first..if window == 16 {
                first + 1
            } else {
                first + 1024
            })
                .collect()
        } else {
            match window {
                0 => vec![0, 1, 2, 3, 9, 1024],
                1 => vec![1024, 1025, 2048],
                _ => vec![2048, 2049],
            }
        };
        let mut subjects: Vec<_> = indices.into_iter().map(Self::subject).collect();
        if large && window < 2 {
            subjects.push(Self::subject(first + 1024));
        }
        subjects.sort();
        subjects
    }

    fn edges(snapshot: &GraphSnapshotV1, window: u64, large: bool) -> Vec<GraphEdgeV1> {
        let first = window * 1024;
        let connected = match window {
            0 => vec![(0, 1), (0, 2), (1, 3), (2, 3), (3, 0), (3, 1024)],
            1 => vec![(1024, 1025), (1025, 2048)],
            2 => vec![(2048, 2049)],
            _ => vec![],
        };
        let mut edges: Vec<_> = connected
            .into_iter()
            .map(|(from, to)| Self::edge(snapshot, from, to))
            .collect();
        if large {
            let maximum = if window == 16 { 1 } else { 2048 };
            for index in 0..maximum - edges.len() {
                let offset = index as u64 % 924;
                let from = if window == 16 {
                    first
                } else {
                    first + 100 + offset
                };
                let to = if window == 16 {
                    first
                } else {
                    first + 100 + (offset + index as u64 / 924 + 1) % 924
                };
                edges.push(Self::edge(snapshot, from, to));
            }
        }
        edges.sort_by(|left, right| left.key.cmp(&right.key));
        edges
    }

    fn edge(snapshot: &GraphSnapshotV1, from: u64, to: u64) -> GraphEdgeV1 {
        GraphEdgeV1 {
            key: GraphEdgeKeyV1 {
                from: Self::subject(from),
                to: Self::subject(to),
                edge_type: GraphEdgeTypeV1::NativeParent,
                package_id: "HF-PROC-001".into(),
                evidence: snapshot.input_manifest.evidence.clone(),
                cause: GraphCauseV1::Direct,
            },
            proof_quality: ProofQualityV1::kernel_decision(TemporalCoverageV1::Complete),
            required_coverage_interval_ids: vec![[4; 16]],
            first_boottime_ns: snapshot.first_cursor * 1_000,
            last_boottime_ns: snapshot.last_cursor * 1_000,
        }
    }
}
