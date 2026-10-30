use super::*;

pub struct Graph<'a> {
    pub(super) input: Cow<'a, GraphReplayInputV1>,
    pub(super) projection: std::cell::OnceCell<[sdk::Dataset; 3]>,
    pub(super) observations: Vec<algorithm::Observation>,
    pub(super) revision: GraphRevisionV1,
    pub(super) facts: Vec<GraphFactV1>,
    pub(super) packages: Vec<GraphPackageCheckpointV1>,
    pub(super) subjects: BTreeMap<GraphSubjectKeyV1, u32>,
    pub(super) edges: BTreeMap<GraphEdgeKeyV1, GraphEdgeV1>,
    pub(super) findings: BTreeMap<String, FindingV1>,
    pub(super) _memory: Option<datafusion::execution::memory_pool::MemoryReservation>,
}

impl<'a> Graph<'a> {
    pub fn new(input: &'a GraphReplayInputV1) -> Result<Self> {
        Self::from_input(Cow::Borrowed(input))
    }

    fn from_input(mut input: Cow<'a, GraphReplayInputV1>) -> Result<Self> {
        input.validate()?;
        if input
            .records
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
            || input
                .facts
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
        {
            input = Cow::Owned(input.normalized()?);
        }
        let revision = input.manifest();
        revision.validate(input.source.tenant_id)?;
        let facts = input
            .facts
            .iter()
            .map(GraphFactV1::try_from)
            .collect::<Result<_>>()?;
        let mut graph = Self {
            input,
            projection: std::cell::OnceCell::new(),
            observations: Vec::new(),
            revision,
            facts,
            packages: Vec::new(),
            subjects: BTreeMap::new(),
            edges: BTreeMap::new(),
            findings: BTreeMap::new(),
            _memory: None,
        };
        let positions = graph
            .input
            .input_positions
            .iter()
            .map(|(id, position)| (id, position))
            .collect::<BTreeMap<_, _>>();
        graph.observations = graph
            .input
            .records
            .iter()
            .map(|record| {
                let position = positions.get(&record.id).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph input position",
                    }
                    .build()
                })?;
                graph.qualify_record(record, **position)
            })
            .collect::<Result<_>>()?;
        Ok(graph)
    }

    pub fn supports(model: &sdk::Model) -> bool {
        algorithm::Detector::supports(model)
    }

    pub fn apply(mut self, call: &PackageCall, result: &CallResult) -> Result<Self> {
        self.check_call(call, result)?;
        let model = call
            .descriptor()
            .exports
            .iter()
            .find(|model| model.name == call.export())
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph export contract",
                }
                .build()
            })?;
        self.check_inputs(model, result.evaluation())?;
        self.apply_output(
            call.descriptor(),
            result.evaluation(),
            result.output(),
            result.retained().is_some(),
            result.graph_prior(),
        )?;
        Ok(self)
    }

    pub(super) fn check_call(&self, call: &PackageCall, result: &CallResult) -> Result<()> {
        let package = call.descriptor();
        Self::require(
            result.belongs_to(call)
                && call.tenant() == self.input.source.tenant_id
                && package.id == call.package().package_id
                && package.revision == call.package().revision
                && call.export() == result.evaluation().export
                && !self
                    .packages
                    .iter()
                    .any(|prior| prior.package_id == package.id),
            "graph package call",
        )?;
        Self::require(
            package
                .exports
                .iter()
                .any(|model| model.name == call.export() && Self::supports(model)),
            "graph export contract",
        )
    }

    pub fn finish(self) -> Result<GraphSnapshotV1> {
        let mut remap = vec![0; self.subjects.len()];
        let subjects = self
            .subjects
            .into_iter()
            .enumerate()
            .map(|(index, (key, old))| {
                remap[old as usize] = index as u32;
                key
            })
            .collect();
        let mut edges = self
            .edges
            .into_values()
            .map(|mut edge| {
                edge.key.from = remap[edge.key.from as usize];
                edge.key.to = remap[edge.key.to as usize];
                edge
            })
            .collect::<Vec<_>>();
        edges.sort_by(|left, right| left.key.cmp(&right.key));
        let mut branches = self
            .findings
            .values()
            .map(algorithm::GraphBranchV1::from_value)
            .collect::<Vec<_>>();
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
        let snapshot = GraphSnapshotV1 {
            schema_version: GRAPH_SCHEMA_VERSION,
            scope: ProcessorScopeV1 {
                processor_id: GRAPH_PROCESSOR.into(),
                method_version: u64::from(GRAPH_SCHEMA_VERSION),
                identity: self.input.source.clone(),
            },
            first_cursor: self
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
                .durable_cursor,
            last_cursor: self
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
                .durable_cursor,
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
            input_positions: self.input.input_positions.clone(),
            previous_result_id: None,
            context_notice_revision: 0,
            witness_deadline_utc_ns: 0,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn expire(
        previous: &GraphSnapshotV1,
        result: &str,
        notice: u64,
    ) -> Result<GraphSnapshotV1> {
        previous.validate()?;
        let mut value = previous.clone();
        value.previous_result_id = Some(result.into());
        value.context_notice_revision = notice;
        value
            .missing_ranges
            .push((value.first_cursor, value.last_cursor));
        value.missing_ranges.sort();
        value.missing_ranges.dedup();
        value.input_manifest.missing_ranges = value.missing_ranges.clone();
        for edge in &mut value.graph.edges {
            edge.key.cause = GraphCauseV1::Superseded;
            edge.proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
        }
        value
            .graph
            .edges
            .sort_by(|left, right| left.key.cmp(&right.key));
        value
            .graph
            .edges
            .dedup_by(|left, right| left.key == right.key);
        for branch in &mut value.graph.branches {
            branch.state = GraphBranchStateV1::CoverageUnknown;
            branch.missing_fields.push("RETAINED_INPUT_EXPIRED".into());
            branch.missing_fields.sort();
            branch.missing_fields.dedup();
        }
        for finding in &mut value.findings {
            finding.state = FindingStateV1::CoverageInsufficient;
            finding.limits.extend([
                "RETAINED_INPUT_EXPIRED".into(),
                "LATE_EVIDENCE_UNSUPPORTED_AFTER_RETENTION".into(),
            ]);
            finding.limits.sort();
            finding.limits.dedup();
            for effect in &mut finding.effects {
                effect.proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
            }
        }
        for package in &mut value.packages {
            package.state = GraphPackageStateV1::CoverageInsufficient;
        }
        value.validate()?;
        Ok(value)
    }
}

impl TryFrom<GraphReplayInputV1> for Graph<'static> {
    type Error = araphor_data::Error;
    fn try_from(input: GraphReplayInputV1) -> Result<Self> {
        Self::from_input(Cow::Owned(input))
    }
}
