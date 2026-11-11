use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisReferenceOriginV1, AnalysisReferenceV1, AnalysisSelectionV1,
    AnalysisSourceSnapshotV1, CoverageInterval, CoverageReport,
};
use datafusion::physical_plan::ExecutionPlan;
use prost::Message as _;
use snafu::ResultExt as _;

use super::Inputs;
use crate::sources::{ArrowSnapshot, SourceOrigin, SourceSnapshot};
use crate::{InvalidSnafu, Result, SqlSnafu};

pub(super) struct PortScope<'a> {
    pub(super) slot: usize,
    invocation: Option<(&'a str, u64)>,
    pub(super) selection: AnalysisSelectionV1,
    window: Option<(i64, i64)>,
    context_revision: Option<Option<u64>>,
    time: i64,
    seed: Option<u64>,
}

impl Inputs {
    pub(crate) fn window(&self, slot: usize) -> Option<Option<crate::follow::Window>> {
        self.plans.get(slot).map(|port| port.window.clone())
    }

    pub(crate) fn uses_events(&self, slot: usize) -> bool {
        self.plans.get(slot).is_some_and(|port| {
            port.origins
                .iter()
                .any(|origin| origin.durable() == Some("events"))
                || Self::event_source(&port.plan)
        })
    }

    fn event_source(plan: &datafusion::logical_expr::LogicalPlan) -> bool {
        crate::planner::SourceDemand::collect(plan, false).is_ok_and(|origins| {
            origins
                .iter()
                .any(|origin| origin.durable() == Some("events"))
        })
    }

    pub(crate) fn check_supplied(&self, supplied: &[sdk::Input]) -> Result<()> {
        let mut names = std::collections::BTreeSet::new();
        if supplied.len() != self.ports.len()
            || supplied.iter().any(|input| {
                !names.insert(input.data.name.as_str())
                    || !self.ports.iter().any(|port| port.name == input.data.name)
            })
            || self.plans.iter().any(|port| {
                port.origins.is_empty()
                    || port
                        .origins
                        .iter()
                        .any(|origin| !matches!(origin, SourceOrigin::Local(_)))
            })
        {
            return Err(araphor_data::PackageErrorCodeV1::Invalid
                .error("supplied input scope")
                .into());
        }
        Ok(())
    }

    pub(crate) fn supplied_inputs(
        &self,
        inputs: &mut [sdk::Input],
        supplied: &[sdk::Input],
    ) -> Result<()> {
        self.check_supplied(supplied)?;
        if inputs.len() != self.ports.len() {
            return Err(araphor_data::PackageErrorCodeV1::Invalid
                .error("supplied input count")
                .into());
        }
        for port in &self.ports {
            let actual = inputs
                .iter_mut()
                .find(|input| input.data.name == port.name)
                .ok_or_else(|| araphor_data::PackageErrorCodeV1::Invalid.error("supplied input"))?;
            let expected = supplied
                .iter()
                .find(|input| input.data.name == port.name)
                .ok_or_else(|| araphor_data::PackageErrorCodeV1::Invalid.error("supplied input"))?;
            let schema = Arc::new(port.schema.clone());
            if actual
                .data
                .batches
                .iter()
                .chain(&expected.data.batches)
                .any(|batch| batch.schema() != schema)
                || !Self::same_rows(&actual.data.batches, &expected.data.batches)
            {
                return Err(araphor_data::PackageErrorCodeV1::Invalid
                    .error("supplied input rows")
                    .into());
            }
            actual.revision.clone_from(&expected.revision);
            actual.coverage.clone_from(&expected.coverage);
        }
        Ok(())
    }

    fn same_rows(actual: &[sdk::RecordBatch], expected: &[sdk::RecordBatch]) -> bool {
        let mut left = actual.iter().filter(|batch| batch.num_rows() > 0);
        let mut right = expected.iter().filter(|batch| batch.num_rows() > 0);
        let (mut a, mut b) = (left.next(), right.next());
        let (mut ai, mut bi) = (0, 0);
        while let (Some(av), Some(bv)) = (a, b) {
            let count = (av.num_rows() - ai).min(bv.num_rows() - bi);
            if av.slice(ai, count) != bv.slice(bi, count) {
                return false;
            }
            ai += count;
            bi += count;
            if ai == av.num_rows() {
                a = left.next();
                ai = 0;
            }
            if bi == bv.num_rows() {
                b = right.next();
                bi = 0;
            }
        }
        a.is_none() && b.is_none()
    }

    pub(crate) fn input_for(
        &self,
        data: sdk::Dataset,
        source: &SourceSnapshot,
        (call, slot, _child, invocation): (u64, usize, usize, &str),
        physical: &Arc<dyn ExecutionPlan>,
        inherited: &[&sdk::Input],
        owner: &crate::definition::CallContext,
    ) -> Result<sdk::Input> {
        let port = self.plans.get(slot).ok_or_else(|| {
            InvalidSnafu {
                field: "package input slot",
            }
            .build()
        })?;
        let bounds = source
            .input_bounds(physical, Some(owner))
            .context(SqlSnafu)?;
        if let Some(identity) = &port.identity {
            let identity = match identity {
                SourceOrigin::Port(family) => {
                    let reads = bounds
                        .qualified
                        .get(family)
                        .filter(|reads| reads.len() == 1)
                        .ok_or_else(|| {
                            araphor_data::PackageErrorCodeV1::Incomplete
                                .error("bound source identity")
                        })?;
                    SourceOrigin::Port(*reads.first().ok_or_else(|| {
                        araphor_data::PackageErrorCodeV1::Incomplete.error("bound source identity")
                    })?)
                }
                other => other.clone(),
            };
            let input = source
                .captured_input(&identity)
                .context(SqlSnafu)?
                .ok_or_else(|| {
                    araphor_data::PackageErrorCodeV1::Incomplete.error("bound input metadata")
                })?;
            let schema = &self.ports[slot].schema;
            if (matches!(identity, SourceOrigin::Port(_)) && input.data.name != data.name)
                || data
                    .batches
                    .iter()
                    .any(|batch| batch.schema().as_ref() != schema)
                || !Self::same_rows(&data.batches, &input.data.batches)
            {
                return Err(araphor_data::PackageErrorCodeV1::Invalid
                    .error("bound input rows")
                    .into());
            }
            return Ok(sdk::Input {
                data,
                revision: input.revision.clone(),
                coverage: input.coverage.clone(),
            });
        }
        let snapshot = source.snapshot().context(SqlSnafu)?;
        let mut bound = Vec::new();
        for origin in &port.origins {
            if matches!(origin, SourceOrigin::Port(id) if !bounds.ports.contains(id)
                && !bounds.qualified.contains_key(id))
            {
                continue;
            }
            if let SourceOrigin::Port(id) = origin {
                if let Some(reads) = bounds.qualified.get(id) {
                    for read in reads {
                        if let Some(input) = source
                            .captured_input(&SourceOrigin::Port(*read))
                            .context(SqlSnafu)?
                        {
                            bound.push((*read, input));
                        }
                    }
                } else if let Some(input) = source.captured_input(origin).context(SqlSnafu)? {
                    bound.push((*id, input));
                }
            }
        }
        let sources = port
            .origins
            .iter()
            .filter_map(|origin| {
                origin
                    .durable()
                    .map(|name| (name.to_owned(), Some(Default::default())))
            })
            .collect();
        let selection = snapshot.selection.project(&sources)?;
        let selection =
            if sources.contains_key("trace_output") || sources.contains_key("trace_measurements") {
                selection
            } else {
                SourceSnapshot::prune_selection(selection, &bounds)
            };
        self.input(
            data,
            &snapshot,
            &PortScope {
                slot,
                invocation: Some((invocation, call)),
                selection,
                context_revision: source.context_revision(&bounds).context(SqlSnafu)?,
                time: owner
                    .window_clock(crate::follow::WindowSource::Input { call, slot })
                    .context(SqlSnafu)?
                    .or(owner.invocation().time_utc_ns)
                    .unwrap_or(snapshot.now as i64),
                seed: owner.invocation().seed,
                window: snapshot
                    .windows
                    .iter()
                    .find(|window| {
                        window.source == crate::follow::WindowSource::Input { call, slot }
                    })
                    .map(|window| (window.start_utc_ns, window.end_utc_ns)),
            },
            inherited
                .iter()
                .copied()
                .chain(bound.iter().map(|(_, input)| input.as_ref())),
        )
    }

    pub(super) fn input<'a>(
        &self,
        data: sdk::Dataset,
        snapshot: &ArrowSnapshot,
        scope: &PortScope<'_>,
        inherited: impl Iterator<Item = &'a sdk::Input>,
    ) -> Result<sdk::Input> {
        let port = self
            .plans
            .iter()
            .find(|port| port.slot == scope.slot)
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "input slot",
                }
                .build()
            })?;
        let has = |name: &str| {
            port.origins
                .iter()
                .any(|origin| origin.durable() == Some(name))
        };
        let graph_source = |name: &str| {
            matches!(
                name,
                "findings"
                    | "relationships"
                    | "graph_subjects"
                    | "graph_branches"
                    | "correlation_packages"
                    | "policy_observations"
                    | "graph_manifest"
            )
        };
        let has_graph = port
            .origins
            .iter()
            .filter_map(SourceOrigin::durable)
            .any(graph_source);
        let target_only = has("targets")
            && !has("events")
            && !has("context")
            && !has("context_versions")
            && !has("compiled_policies");
        let context = |key: &AnalysisContextKeyV1| {
            (scope.selection.contexts.is_all() || scope.selection.contexts.as_slice().contains(key))
                && (!target_only || key.owner_id == "mithril-control/target")
        };
        let includes =
            |origin: &AnalysisReferenceOriginV1, key: Option<&AnalysisContextKeyV1>| match origin {
                AnalysisReferenceOriginV1::Context => key.is_some_and(context),
                AnalysisReferenceOriginV1::Profile => has("behaviors") || has("discovery_state"),
                AnalysisReferenceOriginV1::Graph => has_graph,
                AnalysisReferenceOriginV1::Notification => has("notifications"),
                AnalysisReferenceOriginV1::ExplicitResult => true,
            };
        let mut context_revision = 0;
        let mut result_revision = 0;
        let mut graph_count = 0;
        let mut graph_coverage = sdk::Coverage {
            state: sdk::CoverageState::Complete,
            limits: Vec::new(),
        };
        for reference in &snapshot.page.extraction.references {
            match reference {
                AnalysisReferenceV1::Context { reference, origins }
                    if origins
                        .iter()
                        .any(|origin| includes(origin, Some(&reference.key))) =>
                {
                    context_revision = context_revision.max(reference.commit_revision);
                }
                AnalysisReferenceV1::Result { reference, origins }
                    if origins.iter().any(|origin| includes(origin, None)) =>
                {
                    result_revision = result_revision.max(reference.commit_revision);
                    if has_graph && origins.contains(&AnalysisReferenceOriginV1::Graph) {
                        let saved = snapshot
                            .page
                            .extraction
                            .graph_coverage(&reference.result_id)
                            .ok_or_else(|| {
                                araphor_data::PackageErrorCodeV1::Incomplete
                                    .error("captured graph coverage")
                            })?;
                        if saved.state == sdk::CoverageState::Gapped
                            || (saved.state == sdk::CoverageState::Unknown
                                && graph_coverage.state != sdk::CoverageState::Gapped)
                        {
                            graph_coverage.state = saved.state;
                        }
                        graph_coverage.limits.extend(saved.limits.iter().cloned());
                        graph_count += 1;
                    }
                }
                _ => {}
            }
        }
        let sources = snapshot
            .page
            .extraction
            .sources
            .iter()
            .filter(|source| {
                scope.selection.sources.is_all()
                    || scope
                        .selection
                        .sources
                        .as_slice()
                        .contains(&source.receipt.identity)
            })
            .collect::<Vec<_>>();
        let missing = snapshot
            .page
            .extraction
            .missing_contexts
            .iter()
            .any(context);
        if has_graph {
            if graph_count == 0 {
                graph_coverage.state = sdk::CoverageState::Unknown;
                graph_coverage
                    .limits
                    .push("NO_SELECTED_GRAPH_VERSION".into());
            }
            if snapshot
                .page
                .extraction
                .graph_traversal()
                .is_some_and(|receipt| receipt.hop_boundary)
            {
                if graph_coverage.state != sdk::CoverageState::Gapped {
                    graph_coverage.state = sdk::CoverageState::Unknown;
                }
                graph_coverage.limits.push("GRAPH_HOP_BOUNDARY".into());
            }
            graph_coverage.limits.sort_unstable();
            graph_coverage.limits.dedup();
        }
        let mut coverage = if has_graph
            && port
                .origins
                .iter()
                .filter_map(SourceOrigin::durable)
                .all(graph_source)
        {
            graph_coverage
        } else {
            let source = Self::source_coverage(&sources, missing)?;
            if has_graph {
                Self::coverage([&source, &graph_coverage].into_iter())
            } else {
                source
            }
        };
        let inherited = inherited.collect::<Vec<_>>();
        if !inherited.is_empty() {
            let builtin = port.origins.iter().any(|origin| origin.durable().is_some());
            coverage = Self::coverage(
                inherited
                    .iter()
                    .map(|input| &input.coverage)
                    .chain(builtin.then_some(&coverage)),
            );
        }
        let meta = &snapshot.page.extraction.meta;
        let window = match scope.window {
            Some(range) => Some(range),
            None => port
                .window
                .as_ref()
                .map(|window| window.fixed_range(snapshot.now))
                .transpose()
                .context(SqlSnafu)?
                .flatten(),
        };
        let window = window.map(|(start, end)| sdk::SourceWindow {
            source: meta.store_uuid.as_bytes().to_vec(),
            start_utc_ns: start,
            end_utc_ns: end,
        });
        if data.batches.is_empty() {
            return InvalidSnafu {
                field: "input batches",
            }
            .fail();
        }
        let point = !inherited.is_empty()
            || port.origins.iter().any(|origin| {
                matches!(origin, SourceOrigin::Port(_))
                    || origin.durable().is_some_and(|name| {
                        !matches!(
                            name,
                            "events" | "coverage" | "context_versions" | "context" | "catalog"
                        )
                    })
            });
        let local = port
            .origins
            .iter()
            .any(|origin| matches!(origin, SourceOrigin::Local(_)));
        let mut version = sources
            .iter()
            .map(|source| source.commit_revision)
            .max()
            .unwrap_or(0);
        if has("context") || has("context_versions") {
            version = version.max(match scope.context_revision {
                Some(Some(revision)) => revision,
                Some(None) => meta.commit_revision,
                None => context_revision,
            });
        }
        version = version.max(result_revision);
        if point || port.changes && snapshot.managed().is_some() {
            version = meta.commit_revision;
        }
        let varying = port.varying || local;
        if varying {
            version = meta.commit_revision;
        }
        let time = if varying || point { scope.time } else { 0 };
        let (invocation, call) = scope.invocation.unwrap_or(("", 0));
        let invocation = if varying { invocation } else { "" };
        let seed = varying.then_some(scope.seed).flatten();
        let generation = snapshot
            .managed()
            .map_or(0, |capture| capture.instance().generation);
        let catalog = if has("catalog") {
            format!(
                ":{}:{}:{}",
                u8::from(snapshot.page.extraction.discovery_enabled),
                u8::from(snapshot.page.extraction.graph_enabled),
                u8::from(snapshot.page.extraction.notification_enabled),
            )
        } else {
            String::new()
        };
        let revision = sdk::Revision {
            owner: "araphor-query.Inputs".into(),
            id: format!(
                "{}:{}:{}:{generation}:{call}:{}:{version}:{time}:{}:{}:{invocation}{catalog}",
                meta.store_uuid,
                meta.schema_version,
                meta.recovery_epoch,
                scope.slot,
                u8::from(seed.is_some()),
                seed.unwrap_or(0),
            ),
            window,
        };
        Ok(sdk::Input {
            data,
            revision,
            coverage,
        })
    }

    pub(crate) fn coverage<'a>(values: impl Iterator<Item = &'a sdk::Coverage>) -> sdk::Coverage {
        let (mut state, mut limits) = (sdk::CoverageState::Complete, Vec::new());
        for coverage in values {
            if coverage.state == sdk::CoverageState::Unknown
                || (coverage.state == sdk::CoverageState::Gapped
                    && state == sdk::CoverageState::Complete)
            {
                state = coverage.state;
            }
            limits.extend(coverage.limits.iter().cloned());
        }
        limits.sort();
        limits.dedup();
        sdk::Coverage { state, limits }
    }

    fn source_coverage(
        sources: &[&AnalysisSourceSnapshotV1],
        missing: bool,
    ) -> Result<sdk::Coverage> {
        let mut gaps = false;
        for source in sources {
            gaps |= !source.expired.is_empty()
                || !source.recovery.is_empty()
                || !source.pending.is_empty();
            if let Some(bytes) = &source.coverage_report {
                let report = CoverageReport::decode(bytes.as_slice()).map_err(|source| {
                    araphor_data::Error::EvidenceDecode {
                        source,
                        frame_bytes: bytes.len(),
                        location: snafu::location!(),
                    }
                })?;
                gaps |= report.intervals.iter().any(CoverageInterval::has_gap);
            }
        }
        let mut limits = Vec::new();
        if gaps {
            limits.push("SOURCE_GAPS".into());
        }
        if sources.is_empty() {
            limits.push("NO_SOURCE_COVERAGE".into());
        }
        if missing {
            limits.push("MISSING_CONTEXT".into());
        }
        if !gaps {
            limits.push("SOURCE_COVERAGE_UNQUALIFIED".into());
        }
        Ok(sdk::Coverage {
            state: if gaps {
                sdk::CoverageState::Gapped
            } else {
                sdk::CoverageState::Unknown
            },
            limits,
        })
    }
}

#[cfg(test)]
mod supplied {
    use super::*;

    use datafusion::arrow::array::UInt64Array;
    use datafusion::logical_expr::LogicalPlanBuilder;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn input(
        values: &[u64],
    ) -> std::result::Result<sdk::Input, Box<dyn std::error::Error + Send + Sync>> {
        let schema = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
            "value",
            sdk::DataType::UInt64,
            false,
        )]));
        Ok(sdk::Input {
            data: sdk::Dataset {
                name: "input".into(),
                batches: vec![sdk::RecordBatch::try_new(
                    schema,
                    vec![Arc::new(UInt64Array::from(values.to_vec()))],
                )?],
            },
            revision: sdk::Revision {
                owner: "saved".into(),
                id: "revision".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Gapped,
                limits: vec!["SAVED_GAP".into()],
            },
        })
    }

    fn scope(origins: &[SourceOrigin]) -> Result<Inputs> {
        let model = sdk::Model::new(
            "call",
            vec![sdk::Port::new(
                "input",
                sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
            )],
            Vec::new(),
        );
        Inputs::from_plans(
            &model,
            &[LogicalPlanBuilder::empty(false).build().context(SqlSnafu)?],
            vec![origins.iter().cloned().collect()],
        )
    }

    #[test]
    fn supplied_scope_is_local() -> TestResult {
        let expected = input(&[1])?;
        for origins in [
            Vec::new(),
            vec![SourceOrigin::Durable("events".into())],
            vec![
                SourceOrigin::Local("fixture".into()),
                SourceOrigin::Durable("context_versions".into()),
            ],
        ] {
            assert!(scope(&origins)?
                .check_supplied(std::slice::from_ref(&expected))
                .is_err());
        }
        let scope = scope(&[SourceOrigin::Local("fixture".into())])?;
        scope.check_supplied(std::slice::from_ref(&expected))?;
        assert!(scope.check_supplied(&[]).is_err());
        assert!(scope
            .check_supplied(&[expected.clone(), expected.clone()])
            .is_err());
        let mut foreign = expected;
        foreign.data.name = "other".into();
        assert!(scope.check_supplied(&[foreign]).is_err());
        Ok(())
    }

    #[test]
    fn supplied_rows_are_exact() -> TestResult {
        let scope = scope(&[SourceOrigin::Local("fixture".into())])?;
        let expected = input(&[1, 2, 3])?;
        let mut actual = input(&[1])?;
        actual.data.batches.extend(input(&[2, 3])?.data.batches);
        actual.revision.id = "computed".into();
        scope.supplied_inputs(
            std::slice::from_mut(&mut actual),
            std::slice::from_ref(&expected),
        )?;
        assert_eq!(actual.revision, expected.revision);
        assert_eq!(actual.coverage, expected.coverage);
        for values in [&[1, 3, 2][..], &[1, 2][..], &[1, 2, 3, 4][..]] {
            assert!(scope
                .supplied_inputs(&mut [input(values)?], std::slice::from_ref(&expected))
                .is_err());
        }
        scope.supplied_inputs(&mut [input(&[])?], &[input(&[])?])?;
        Ok(())
    }
}
