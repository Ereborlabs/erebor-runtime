use super::*;

struct WindowInput {
    records: Vec<EffectObservationV1>,
    source: u8,
    subjects: usize,
    relationships: usize,
    manifest_min: usize,
}

impl ReplayQualification {
    pub(super) async fn mixed_window(
        self,
    ) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
        let records = (1..=64)
            .map(|cursor| GraphNotificationQualification::native(cursor, cursor % 2 == 1))
            .collect::<Vec<_>>();
        self.native_window(WindowInput {
            records,
            source: 240,
            subjects: 5,
            relationships: 192,
            manifest_min: 0,
        })
        .await
    }

    pub(super) async fn physical_window(
        mut self,
    ) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
        self.authenticated.tenant_id = [201; 16];
        self.authenticated.node_boot_id = [202; 16];
        self.authenticated.node_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into();
        let records = (897..=1081)
            .map(|cursor| {
                let mut record = GraphNotificationQualification::native(cursor, cursor == 1060);
                record.source_cpu_id = 1;
                record.task_cookie = 66;
                record.process_instance_id = [203; 16].into();
                record.entry_instance_id = [204; 16].into();
                record.binding_id = [205; 16].into();
                record.execution_set_id = [206; 16].into();
                record.authority_domain_id = [207; 16].into();
                record.exact_object_key_id = 0;
                record.composite_atom_id = 0;
                record
            })
            .collect();
        self.native_window(WindowInput {
            records,
            source: 241,
            subjects: 3,
            relationships: 370,
            manifest_min: 59_070,
        })
        .await
    }

    async fn native_window(
        self,
        input: WindowInput,
    ) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
        let raw = &input.records;
        let denied = raw
            .iter()
            .filter(|record| record.reason == EffectObservationReasonV1::ExactPolicyDeny as u8)
            .count();
        let source = self.accept_node(input.source, raw, &self.authenticated, false)?;
        let graph = GraphAndFindingOwner::new(self.data.clone(), self.inputs.clone())?;
        let mut snapshot = None;
        for _ in 0..32 {
            graph.process(self.now)?;
            snapshot = graph.snapshot(&source)?;
            if snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.last_cursor == raw.len() as u64)
            {
                break;
            }
        }
        let snapshot = snapshot
            .filter(|snapshot| snapshot.last_cursor == raw.len() as u64)
            .ok_or("the native window did not reach the accepted cursor")?;
        assert_eq!(
            (snapshot.first_cursor, snapshot.last_cursor),
            (1, raw.len() as u64)
        );
        assert_eq!(snapshot.input_manifest.evidence.len(), raw.len());
        assert_eq!(snapshot.graph.edges.len(), input.relationships);
        assert_eq!(snapshot.graph.subjects.len(), input.subjects);
        assert!(snapshot.graph.facts.is_empty());
        assert!(snapshot.input_manifest.context.is_empty());
        let manifest_bytes = serde_json::to_vec(&snapshot.input_manifest)?.len();
        assert!(manifest_bytes >= input.manifest_min);
        assert_eq!(
            snapshot
                .graph
                .subjects
                .iter()
                .filter(|subject| subject.kind == GraphSubjectKindV1::Task)
                .count(),
            1
        );
        assert_eq!(snapshot.findings.len(), denied);
        for finding in &snapshot.findings {
            assert_eq!(finding.state, FindingStateV1::CoverageInsufficient);
            assert!(!finding.effects.is_empty());
            assert!(finding.effects.iter().all(|effect| {
                raw[effect.evidence.durable_cursor as usize - 1].reason
                    == EffectObservationReasonV1::ExactPolicyDeny as u8
                    && effect.proof_quality.temporal_coverage != TemporalCoverageV1::Complete
            }));
        }
        let finding = snapshot
            .findings
            .first()
            .ok_or("native window finding absent")?;
        let reference = GraphNotificationQualification::finding_ref(&graph, finding)?;
        let traversal = GraphNotificationQualification::traverse(
            self.data.clone(),
            &snapshot,
            finding,
            &reference.result_id,
            self.now,
        )
        .await?;
        drop(graph);
        assert_eq!(
            self.reopen_window(&snapshot, finding, &reference.result_id)
                .await?,
            traversal
        );
        Ok(json!({
            "result": "PASS", "qualification": "RECORDED_GRAPH_REPLAY",
            "records": raw.len(), "denied_records": denied, "allowed_records": raw.len() - denied,
            "original_sequence_first": raw.first().map(|record| record.source_sequence),
            "original_sequence_last": raw.last().map(|record| record.source_sequence),
            "manifest_bytes": manifest_bytes,
            "initial_health_sampled": false, "repeated_native_task": true,
            "fresh_query_owner": true, "exact_version_selected": true,
            "reopen_equal": true, "native_traversal": traversal,
            "physical_incident_reproduced": false, "performance_claim": false,
        }))
    }

    async fn reopen_window(
        self,
        snapshot: &GraphSnapshotV1,
        finding: &FindingV1,
        result_id: &str,
    ) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
        let Self {
            root,
            intake,
            data,
            inputs,
            authenticated,
            now,
        } = self;
        drop(intake);
        drop(data);
        let data = Arc::new(AnalysisStore::open(root.path().join("analysis"))?);
        let graph = GraphAndFindingOwner::new(data.clone(), inputs)?;
        assert_eq!(
            graph.snapshot_result(authenticated.tenant_id, result_id)?,
            Some(snapshot.clone())
        );
        GraphNotificationQualification::traverse(data, snapshot, finding, result_id, now).await
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn graph_notification_mixed_window() -> crate::platform::TestResult<()> {
        super::ReplayQualification::new(1_791_400_000_000_000_000)?
            .mixed_window()
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn graph_notification_physical_window() -> crate::platform::TestResult<()> {
        let result = super::ReplayQualification::new(1_791_400_000_000_000_000)?
            .physical_window()
            .await?;
        assert_eq!(result["native_traversal"]["sql_chunks"], 2);
        assert_eq!(result["native_traversal"]["returned_relationships"], 370);
        Ok(())
    }
}
