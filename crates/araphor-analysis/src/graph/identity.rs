use super::*;

impl Graph<'_> {
    pub(super) fn subject(
        &mut self,
        kind: GraphSubjectKindV1,
        identity: Vec<u8>,
    ) -> GraphSubjectKeyV1 {
        GraphSubjectKeyV1::native(&self.input.source, kind, identity)
    }

    pub(super) fn task(
        &mut self,
        record: &DiscoveryRecordV1,
        wire: &EvidenceRecord,
    ) -> GraphSubjectKeyV1 {
        if wire.task_cookie > 0 {
            self.subject(
                GraphSubjectKindV1::Task,
                wire.task_cookie.to_be_bytes().to_vec(),
            )
        } else {
            GraphSubjectKeyV1 {
                tenant_id: record.id.stream.tenant_id,
                authority: GraphSubjectAuthorityV1::External {
                    authority_id: "unresolved-native-observation".into(),
                },
                kind: GraphSubjectKindV1::External,
                identity: record
                    .id
                    .stream
                    .key()
                    .into_iter()
                    .chain(record.id.durable_cursor.to_be_bytes())
                    .collect(),
            }
        }
    }

    pub(super) fn subject_index(&mut self, subject: GraphSubjectKeyV1) -> Result<u32> {
        let next = u32::try_from(self.subjects.len()).map_err(|_| {
            GraphInvalidSnafu {
                field: "graph subject count",
            }
            .build()
        })?;
        Ok(*self.subjects.entry(subject).or_insert(next))
    }

    pub(super) fn edge(
        &mut self,
        mut key: GraphEdgeKeyV1,
        proof: ProofQualityV1,
        wire: &EvidenceRecord,
    ) -> Result<()> {
        key.evidence.sort();
        key.evidence.dedup();
        let coverage = <[u8; 16]>::try_from(wire.coverage_interval_id.as_ref()).map_err(|_| {
            GraphInvalidSnafu {
                field: "edge coverage interval",
            }
            .build()
        })?;
        let edge = GraphEdgeV1 {
            key: key.clone(),
            proof_quality: proof,
            required_coverage_interval_ids: vec![coverage],
            first_boottime_ns: wire.observed_boottime_ns,
            last_boottime_ns: wire.observed_boottime_ns,
        };
        if let Some(previous) = self.edges.get_mut(&key) {
            if *previous != edge {
                if key.cause != GraphCauseV1::Contradicted {
                    return GraphInvalidSnafu {
                        field: "conflicting edge value",
                    }
                    .fail();
                }
                previous.proof_quality.operation_result_authority =
                    OperationResultAuthorityV1::Unknown;
            }
        } else {
            self.edges.insert(key, edge);
        }
        Ok(())
    }
}
