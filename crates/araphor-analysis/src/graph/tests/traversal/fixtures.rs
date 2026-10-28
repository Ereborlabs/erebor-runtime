use super::*;

use araphor_data::{
    AnalysisWitnessV1, CoverageCounters, CoverageInterval, CoverageReport, EvidenceStoreOutcomeV1,
    PackageArtifactV1, PackageBundleV1, PackageImplementationV1, ValidatedCoverageV1,
    ValidatedEvidenceBatchV1,
};
use prost::Message as _;

pub(super) struct TraversalFixture {
    pub(super) store: Arc<AnalysisStore>,
    pub(super) directory: tempfile::TempDir,
    pub(super) requests: Vec<AnalysisResultCommitV1>,
    pub(super) _graph: araphor_data::GraphLease,
}

impl TraversalFixture {
    pub(super) fn new(large: bool) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
        let graph = store.lease_graph(vec![AnalysisSelectionV1::tenant(source().tenant_id)])?;
        store.register_graph(&source())?;
        for (descriptor, bytes) in [
            (
                araphor_analysis_builtins::discovery::Discovery::package(),
                araphor_analysis_builtins::components::DISCOVERY,
            ),
            (
                algorithm::Detector::Process.descriptor(),
                araphor_analysis_builtins::components::PROCESS,
            ),
            (
                algorithm::Detector::Credentials.descriptor(),
                araphor_analysis_builtins::components::CREDENTIALS,
            ),
            (
                algorithm::Detector::Kubernetes.descriptor(),
                araphor_analysis_builtins::components::KUBERNETES,
            ),
        ] {
            let exports = descriptor
                .exports
                .iter()
                .map(|model| model.name.clone())
                .collect();
            let artifact = PackageArtifactV1 {
                descriptor,
                implementations: vec![PackageImplementationV1::Wasm {
                    exports,
                    artifact: bytes.to_vec(),
                }],
                fixtures: Vec::new(),
            };
            let bundle = PackageBundleV1 {
                schema_version: 1,
                root: artifact.reference(),
                artifacts: vec![artifact],
            };
            let bundle = araphor_package::PackageBundle::try_from(bundle)?;
            let installed = store.install_package_image(source().tenant_id, &bundle, || Ok(()))?;
            let retained = store
                .package_image(
                    source().tenant_id,
                    &bundle.bundle().root.package_id,
                    Some(&bundle.bundle().root.revision),
                    &AnalysisReadControl::default(),
                )?
                .ok_or("builtin image is absent")?;
            assert_eq!(
                retained.bundle().schema_version,
                bundle.bundle().schema_version
            );
            assert_eq!(retained.bundle().root, bundle.bundle().root);
            assert!(
                retained.bundle().artifacts == bundle.bundle().artifacts,
                "builtin artifacts differ"
            );
            assert_eq!(retained.digest(), bundle.digest());
            let before = store.meta()?;
            let revision = *store.subscribe_revision().borrow();
            assert_eq!(
                store.install_package_image(source().tenant_id, &bundle, || Ok(()))?,
                installed
            );
            assert_eq!(store.meta()?, before);
            assert_eq!(*store.subscribe_revision().borrow(), revision);
            assert!(store
                .active_managed(&AnalysisReadControl::default())?
                .1
                .is_empty());
        }
        let mut fixture = Self {
            directory,
            store,
            requests: Vec::new(),
            _graph: graph,
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
        let head = self
            .store
            .graph_window_headers(
                &original.scope.identity,
                snapshot.first_cursor.checked_sub(1),
            )?
            .into_iter()
            .find(|(_, head, _)| head.first_cursor == snapshot.first_cursor)
            .ok_or("the replacement graph window is absent")?;
        snapshot.previous_result_id = Some(head.0);
        let mut request = original.clone();
        request.result_id = result_id.into();
        request.expected_cursor = self.requests.len() as u64;
        request.consumed_cursor = request.expected_cursor;
        request.created_utc_ns += 10;
        request.body = serde_json::to_vec(&snapshot)?;
        self.store.commit_graph(&request, false, || Ok(()))?;
        Ok(())
    }

    fn commit_window(&mut self, window: u64, large: bool) -> TestResult {
        let cursor = window + 1;
        let first = window * 1024;
        let mut event = wire(
            cursor,
            EffectPhysicalResultV1::DeniedBeforeEffect,
            2,
            2,
            [20; 16],
        );
        if window != 0 {
            event.task_cookie = if window == 16 { first } else { first + 1 };
        }
        let observation = record(cursor, &event)?;
        assert_eq!(
            self.store.accept_validated_batch(
                source(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: cursor,
                    last_cursor: cursor,
                    intake_utc_ns: 1,
                    frame_ends: vec![observation.wire_record.len()],
                    framed_records: observation.wire_record.clone().into(),
                },
            )?,
            EvidenceStoreOutcomeV1::Accepted
        );
        self.store.accept_validated_coverage(ValidatedCoverageV1 {
            identity: source(),
            cpu_id: 0,
            revision: cursor,
            encoded_report: CoverageReport {
                source_id: source().source_id.to_vec(),
                cpu_id: 0,
                source_epoch: source().source_epoch,
                revision: cursor,
                intervals: vec![CoverageInterval {
                    interval_id: vec![4; 16],
                    source_epoch: source().source_epoch,
                    revision: cursor,
                    state: "HEALTHY".into(),
                    first_sequence: 1,
                    last_sequence: Some(cursor),
                    opening_counters: Some(Default::default()),
                    closing_counters: Some(CoverageCounters {
                        attempted: cursor,
                        requested: cursor,
                        emitted: cursor,
                        next_sequence: cursor + 1,
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
            }
            .encode_to_vec(),
        })?;
        let mut replay = input(vec![observation]);
        replay.coverage[0].coverage_revision = cursor;
        replay.coverage_keys[0].report_revision = cursor;
        replay.coverage_keys[0].interval_revision = cursor;
        let mut snapshot = super::super::derive(&replay)?;
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
        self.store.commit_graph(&request, true, || Ok(()))?;
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

    pub(super) fn add_subject(snapshot: &mut GraphSnapshotV1, subject: GraphSubjectKeyV1) -> u32 {
        let index = match snapshot.graph.subjects.binary_search(&subject) {
            Ok(index) => return index as u32,
            Err(index) => index as u32,
        };
        snapshot.graph.subjects.insert(index as usize, subject);
        for edge in &mut snapshot.graph.edges {
            if edge.key.from >= index {
                edge.key.from += 1;
            }
            if edge.key.to >= index {
                edge.key.to += 1;
            }
        }
        index
    }

    #[expect(
        clippy::expect_used,
        reason = "Fixture endpoints must exist in the declared subject dictionary."
    )]
    fn edge(snapshot: &GraphSnapshotV1, from: u64, to: u64) -> GraphEdgeV1 {
        GraphEdgeV1 {
            key: GraphEdgeKeyV1 {
                from: snapshot
                    .graph
                    .subjects
                    .binary_search(&Self::subject(from))
                    .expect("fixture source subject") as u32,
                to: snapshot
                    .graph
                    .subjects
                    .binary_search(&Self::subject(to))
                    .expect("fixture target subject") as u32,
                edge_type: GraphEdgeTypeV1::NativeParent,
                package_id: "HF-PROC-001".into(),
                evidence: (0..snapshot.input_manifest.evidence.len())
                    .map(|index| index as u32)
                    .collect(),
                cause: GraphCauseV1::Direct,
            },
            proof_quality: ProofQualityV1::kernel_decision(TemporalCoverageV1::Complete),
            required_coverage_interval_ids: vec![[4; 16]],
            first_boottime_ns: snapshot.first_cursor * 1_000,
            last_boottime_ns: snapshot.last_cursor * 1_000,
        }
    }
}
