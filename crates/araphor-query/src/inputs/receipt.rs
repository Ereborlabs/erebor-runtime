use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisReferenceOriginV1, AnalysisReferenceV1, AnalysisSelectionV1,
    AnalysisSourceSnapshotV1, AnalysisTableRequests, CoverageInterval, CoverageReport,
};
use datafusion::arrow::ipc::writer::StreamWriter;
use datafusion::logical_expr::interval_arithmetic::Interval;
use datafusion::physical_plan::ExecutionPlan;
use prost::Message as _;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::Inputs;
use crate::sources::{ArrowSnapshot, SourceOrigin, SourceSnapshot};
use crate::{InvalidSnafu, Result, SqlSnafu};

pub(super) struct PortScope {
    pub(super) slot: usize,
    pub(super) selection: AnalysisSelectionV1,
}

impl Inputs {
    pub(super) fn scopes(
        &self,
        original: &AnalysisSelectionV1,
        physical: &[Arc<dyn ExecutionPlan>],
        requests: &mut AnalysisTableRequests,
        bounds: &mut BTreeMap<&'static str, Interval>,
    ) -> Result<Vec<PortScope>> {
        if physical.len() != self.plans.len() {
            return InvalidSnafu {
                field: "input physical plans",
            }
            .fail();
        }
        self.plans
            .iter()
            .zip(physical)
            .map(|(port, physical)| {
                let sources = port
                    .origins
                    .iter()
                    .filter_map(|origin| origin.durable().map(|name| (name.to_owned(), None)))
                    .collect();
                let selection = SourceSnapshot::selection(original, &sources)?;
                let ranges = SourceSnapshot::requests(requests, std::slice::from_ref(physical))
                    .context(SqlSnafu)?;
                SourceSnapshot::extend_bounds(bounds, &ranges).context(SqlSnafu)?;
                let trace = sources.contains_key("trace_output")
                    || sources.contains_key("trace_measurements");
                Ok(PortScope {
                    slot: port.slot,
                    selection: if trace {
                        selection
                    } else {
                        SourceSnapshot::prune_selection(selection, &ranges)
                    },
                })
            })
            .collect()
    }

    pub(super) fn input(
        &self,
        data: sdk::Dataset,
        snapshot: &ArrowSnapshot,
        scope: &PortScope,
        inherited: &[sdk::Input],
        package: Option<&sdk::Coverage>,
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
                AnalysisReferenceOriginV1::Graph => [
                    "findings",
                    "relationships",
                    "graph_subjects",
                    "graph_branches",
                    "correlation_packages",
                    "policy_observations",
                    "graph_manifest",
                ]
                .iter()
                .any(|name| has(name)),
                AnalysisReferenceOriginV1::Notification => has("notifications"),
                AnalysisReferenceOriginV1::ExplicitResult => package.is_none(),
                AnalysisReferenceOriginV1::Package(index) => self
                    .packages
                    .get(*index)
                    .is_some_and(|(slot, _)| port.origins.contains(&SourceOrigin::Package(*slot))),
            };
        let mut contexts = Vec::new();
        let mut results = Vec::new();
        for reference in &snapshot.page.extraction.references {
            match reference {
                AnalysisReferenceV1::Context { reference, origins }
                    if origins
                        .iter()
                        .any(|origin| includes(origin, Some(&reference.key))) =>
                {
                    contexts.push(reference);
                }
                AnalysisReferenceV1::Result { reference, origins }
                    if origins.iter().any(|origin| includes(origin, None)) =>
                {
                    results.push(reference);
                }
                _ => {}
            }
        }
        contexts.sort_by(|left, right| {
            left.key
                .cmp(&right.key)
                .then(left.commit_revision.cmp(&right.commit_revision))
        });
        contexts.dedup();
        results.sort_by(|left, right| {
            left.result_id
                .cmp(&right.result_id)
                .then(left.commit_revision.cmp(&right.commit_revision))
        });
        results.dedup();
        if let Some(coverage) = package {
            let Some((_, reference)) = self.packages.iter().find(|(slot, _)| *slot == scope.slot)
            else {
                return InvalidSnafu {
                    field: "input package coverage",
                }
                .fail();
            };
            let [result] = results.as_slice() else {
                return InvalidSnafu {
                    field: "input package result",
                }
                .fail();
            };
            return Ok(sdk::Input {
                data,
                revision: sdk::Revision {
                    owner: format!("{}.{}", reference.package, reference.export),
                    id: format!("{}:{}", result.result_id, result.commit_revision),
                    window: None,
                },
                coverage: coverage.clone(),
            });
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
        let mut coverage = Self::source_coverage(&sources, missing)?;
        let mut inherited = inherited.iter().collect::<Vec<_>>();
        inherited.sort_by(|left, right| left.data.name.cmp(&right.data.name));
        if !inherited.is_empty() {
            let builtin = port.origins.iter().any(|origin| origin.durable().is_some());
            coverage = Self::coverage(
                inherited
                    .iter()
                    .map(|input| &input.coverage)
                    .chain(builtin.then_some(&coverage)),
            );
        }
        let receipts = sources
            .iter()
            .map(|source| {
                (
                    &source.receipt.identity,
                    source.receipt.cpu_id,
                    source.receipt.contiguous_cursor,
                    source.receipt.coverage_revision,
                    source.receipt.retained_floor,
                    &source.expired,
                    &source.recovery,
                    &source.pending,
                )
            })
            .collect::<Vec<_>>();
        let mut hash = Sha256::new();
        hash.update(b"ARAPHOR-SQL-INPUT-V1\0");
        serde_json::to_writer(
            &mut hash,
            &(&scope.selection, receipts, contexts, results, &coverage),
        )
        .context(araphor_data::PackageEncodingSnafu)?;
        if !inherited.is_empty() {
            let revisions = inherited
                .iter()
                .map(|input| &input.revision)
                .collect::<Vec<_>>();
            serde_json::to_writer(&mut hash, &revisions)
                .context(araphor_data::PackageEncodingSnafu)?;
        }
        let schema = data
            .batches
            .first()
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "input batches",
                }
                .build()
            })?
            .schema();
        {
            let mut writer = StreamWriter::try_new(&mut hash, &schema)
                .map_err(sdk::Error::from)
                .context(araphor_data::AnalysisContractSnafu)?;
            for batch in &data.batches {
                writer
                    .write(batch)
                    .map_err(sdk::Error::from)
                    .context(araphor_data::AnalysisContractSnafu)?;
            }
            writer
                .finish()
                .map_err(sdk::Error::from)
                .context(araphor_data::AnalysisContractSnafu)?;
        }
        Ok(sdk::Input {
            data,
            revision: sdk::Revision {
                owner: "araphor-query.Inputs".into(),
                id: format!("{:x}", hash.finalize()),
                window: None,
            },
            coverage,
        })
    }

    pub(super) fn coverage<'a>(values: impl Iterator<Item = &'a sdk::Coverage>) -> sdk::Coverage {
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
