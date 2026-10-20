use std::sync::Arc;

use prost::Message as _;

use crate::*;

pub(in crate::analysis) struct CommitFixture {
    pub(in crate::analysis) store: Arc<AnalysisStore>,
    pub(in crate::analysis) snapshot: GraphSnapshotV1,
    pub(in crate::analysis) request: AnalysisResultCommitV1,
    pub(super) _directory: tempfile::TempDir,
}

impl CommitFixture {
    pub(in crate::analysis) fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        Self::limits(Default::default())
    }

    pub(in crate::analysis) fn limits(
        storage: StorageLimitsV1,
    ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let mut snapshot: GraphSnapshotV1 = serde_json::from_slice(include_bytes!("graph.json"))?;
        snapshot.witness_deadline_utc_ns = 10 + GRAPH_WITNESS_TTL_NS;
        snapshot.validate()?;
        let source = snapshot.scope.identity.clone();
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            Default::default(),
            storage,
        )?);
        store.enable_graph_owner()?;
        store.register_graph(&source)?;
        let wire = EvidenceRecord {
            observed_boottime_ns: 1_000,
            ingested_utc_ns: 1,
            coverage_interval_id: vec![4; 16].into(),
            profile_generation_ref_id: Some(1),
            task_cookie: 9,
            process_lineage_id: vec![5; 16].into(),
            authority_domain_id: vec![6; 16].into(),
            execution_set_id: vec![7; 16].into(),
            exact_object_id: vec![20; 16].into(),
            reason: 9,
            decision: erebor_interceptor_abi::EffectPhysicalResultV1::DeniedBeforeEffect as u32,
            effect_family: 2,
            operation: 2,
            configured_errno: -13,
            kernel_result: -13,
            temporal_coverage: EvidenceTemporalCoverage::Complete as i32,
            decision_context: Some(EvidenceDecisionContext {
                schema_version: 1,
                original_kernel_sequence: 1,
                process_instance_id: vec![8; 16],
                entry_instance_id: vec![9; 16],
                binding_id: vec![10; 16],
                profile_generation_ref_id: 1,
                role_id: 1,
                state_id: 1,
                entry_rule_id: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        let frame = Vec::<u8>::try_from(&wire)?;
        store.accept_validated_batch(
            source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        let report = CoverageReport {
            source_id: source.source_id.to_vec(),
            cpu_id: 0,
            source_epoch: source.source_epoch,
            revision: 1,
            intervals: vec![CoverageInterval {
                interval_id: vec![4; 16],
                source_epoch: source.source_epoch,
                revision: 1,
                state: "HEALTHY".into(),
                first_sequence: 1,
                last_sequence: Some(1),
                opening_counters: Some(Default::default()),
                closing_counters: Some(CoverageCounters {
                    attempted: 1,
                    requested: 1,
                    emitted: 1,
                    next_sequence: 2,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        store.accept_validated_coverage(ValidatedCoverageV1 {
            identity: source.clone(),
            cpu_id: 0,
            revision: 1,
            encoded_report: report.encode_to_vec(),
        })?;
        let request = AnalysisResultCommitV1 {
            scope: snapshot.scope.clone(),
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 1,
            context_revision: 0,
            result_id: "graph:native-storage".into(),
            body: serde_json::to_vec(&snapshot)?,
            created_utc_ns: 10,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source.into(),
                cursor: 1,
                expires_utc_ns: snapshot.witness_deadline_utc_ns,
            }],
            context_refs: vec![],
        };
        Ok(Self {
            store,
            snapshot,
            request,
            _directory: directory,
        })
    }

    pub(in crate::analysis) fn add_findings(
        &mut self,
        count: usize,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        for index in 0..count {
            let mut finding = self.snapshot.findings[0].clone();
            finding.finding_id = format!("finding-{index}");
            self.snapshot.findings.push(finding);
        }
        self.snapshot
            .findings
            .sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
        self.request.body = serde_json::to_vec(&self.snapshot)?;
        Ok(())
    }
}
