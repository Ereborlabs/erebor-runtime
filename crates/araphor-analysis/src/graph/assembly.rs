use super::*;

impl Graph<'_> {
    pub(super) fn insert_subject(&mut self, subject: GraphSubjectKeyV1) -> Result<u32> {
        let next = u32::try_from(self.subjects.len()).map_err(|_| {
            GraphInvalidSnafu {
                field: "graph subject count",
            }
            .build()
        })?;
        Ok(*self.subjects.entry(subject).or_insert(next))
    }

    pub(super) fn insert_edge(&mut self, edge: GraphEdgeV1) -> Result<()> {
        Self::require(
            self.edges.get(&edge.key).is_none_or(|prior| prior == &edge),
            "conflicting edge value",
        )?;
        self.edges.insert(edge.key.clone(), edge);
        Ok(())
    }

    pub fn finish(self) -> Result<GraphSnapshotV1> {
        let mut branches: Vec<_> = self
            .findings
            .values()
            .map(algorithm::GraphBranchV1::from_value)
            .collect();
        branches.sort_by(|left, right| {
            (
                &left.package_id,
                &left.seed,
                &left.evidence,
                &left.missing_fields,
            )
                .cmp(&(
                    &right.package_id,
                    &right.seed,
                    &right.evidence,
                    &right.missing_fields,
                ))
        });
        branches.dedup();
        let first = self
            .input
            .records
            .first()
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph first record",
                }
                .build()
            })?
            .id
            .durable_cursor;
        let last = self
            .input
            .records
            .last()
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph last record",
                }
                .build()
            })?
            .id
            .durable_cursor;
        let mut indices = vec![0; self.subjects.len()];
        let subjects = self
            .subjects
            .into_iter()
            .enumerate()
            .map(|(index, (subject, prior))| {
                indices[prior as usize] = index as u32;
                subject
            })
            .collect();
        let mut edges = self
            .edges
            .into_values()
            .map(|mut edge| {
                edge.key.from = indices[edge.key.from as usize];
                edge.key.to = indices[edge.key.to as usize];
                edge
            })
            .collect::<Vec<_>>();
        edges.sort_by(|left, right| left.key.cmp(&right.key));
        let snapshot = GraphSnapshotV1 {
            schema_version: GRAPH_SCHEMA_VERSION,
            scope: ProcessorScopeV1 {
                processor_id: GRAPH_PROCESSOR.into(),
                method_version: u64::from(GRAPH_SCHEMA_VERSION),
                identity: self.input.source.clone(),
            },
            first_cursor: first,
            last_cursor: last,
            input_manifest: self.revision,
            graph: GraphVersionV1 {
                subjects,
                edges,
                branches,
                facts: self.facts,
            },
            findings: self.findings.into_values().collect(),
            packages: self.packages,
            missing_ranges: self.input.missing_ranges.clone(),
            input_positions: Vec::new(),
            previous_result_id: None,
            context_notice_revision: 0,
            witness_deadline_utc_ns: 0,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
}
