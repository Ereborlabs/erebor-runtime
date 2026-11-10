use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_analysis_types::{
    values as algorithm, DomainRelations, FindingMember, GraphStateMember,
};
use araphor_graph::Staged;

use sdk::arrow_array::{Array, BinaryArray, StructArray, UInt8Array};
use snafu::ResultExt as _;

use crate::{
    AnalysisContextRefV1, DiscoveryRecordIdV1, EvidenceBasis, GraphEdgeKeyV1, GraphEdgeV1,
    GraphFactV1, GraphReplayInputV1, PackageErrorCodeV1 as Code, Result,
};

mod basis;
mod contexts;
pub(in crate::analysis) use basis::Basis;
pub(in crate::analysis) use contexts::ContextInputs;

#[derive(Default)]
pub(in crate::analysis) struct DomainCommands {
    subjects: Vec<algorithm::SubjectChange>,
    edges: Vec<algorithm::RelationshipChange>,
    findings: Vec<FindingMember>,
    states: Vec<GraphStateMember>,
    records: BTreeSet<DiscoveryRecordIdV1>,
}

struct DomainInput {
    records: Vec<crate::DiscoveryRecordV1>,
    contexts: Vec<crate::AnalysisContextVersionV1>,
    observations: Vec<algorithm::Observation>,
    facts: Vec<GraphFactV1>,
    revision: crate::GraphRevisionV1,
}

impl Default for DomainInput {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            contexts: Vec::new(),
            observations: Vec::new(),
            facts: Vec::new(),
            revision: crate::GraphRevisionV1 {
                evidence: Vec::new(),
                coverage: Vec::new(),
                context: Vec::new(),
                missing_ranges: Vec::new(),
            },
        }
    }
}

impl DomainInput {
    fn manifest_bytes(input: &GraphReplayInputV1) -> Result<usize> {
        let mut bytes = input
            .records
            .len()
            .checked_mul(std::mem::size_of::<DiscoveryRecordIdV1>())
            .and_then(|bytes| {
                bytes.checked_add(
                    input
                        .coverage_keys
                        .len()
                        .checked_mul(std::mem::size_of::<crate::GraphCoverageKeyV1>())?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    input
                        .facts
                        .len()
                        .checked_mul(std::mem::size_of::<crate::AnalysisContextKeyV1>())?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    input
                        .missing_ranges
                        .len()
                        .checked_mul(std::mem::size_of::<(u64, u64)>())?,
                )
            })
            .ok_or_else(|| Code::Limit.error("canonical Graph manifest memory"))?;
        for record in &input.records {
            bytes = bytes
                .checked_add(record.id.allocated_bytes())
                .ok_or_else(|| Code::Limit.error("canonical Graph manifest memory"))?;
        }
        for context in &input.facts {
            bytes = bytes
                .checked_add(context.key.allocated_bytes())
                .ok_or_else(|| Code::Limit.error("canonical Graph manifest memory"))?;
        }
        for key in &input.coverage_keys {
            bytes = bytes
                .checked_add(key.source.node_id.len())
                .and_then(|bytes| {
                    bytes.checked_add(
                        key.gap_reasons
                            .len()
                            .checked_mul(std::mem::size_of::<String>())?,
                    )
                })
                .ok_or_else(|| Code::Limit.error("canonical Graph manifest memory"))?;
            for reason in &key.gap_reasons {
                bytes = bytes
                    .checked_add(reason.len())
                    .ok_or_else(|| Code::Limit.error("canonical Graph manifest memory"))?;
            }
        }
        bytes
            .checked_mul(4)
            .ok_or_else(|| Code::Limit.error("canonical Graph manifest memory"))
    }

    fn append(&mut self, input: GraphReplayInputV1, scratch: &mut DomainScratch<'_>) -> Result<()> {
        input.validate()?;
        scratch.charge(Self::manifest_bytes(&input)?)?;
        let revision = input.manifest();
        revision.validate(input.source.tenant_id)?;
        scratch.charge(
            input
                .records
                .len()
                .checked_mul(4 * std::mem::size_of::<algorithm::Observation>())
                .and_then(|bytes| {
                    input.records.iter().try_fold(bytes, |bytes, record| {
                        bytes.checked_add(record.id.stream.node_id.len().checked_mul(8)?)
                    })
                })
                .ok_or_else(|| Code::Limit.error("canonical Graph observation memory"))?,
        )?;
        self.observations.extend(EvidenceBasis::qualify(&input)?);
        self.records.extend(input.records);
        self.contexts.extend(input.facts);
        self.revision.evidence.extend(revision.evidence);
        self.revision.coverage.extend(revision.coverage);
        self.revision.context.extend(revision.context);
        self.revision.missing_ranges.extend(revision.missing_ranges);
        Ok(())
    }

    fn finish(&mut self, tenant: [u8; 16], scratch: &mut DomainScratch<'_>) -> Result<()> {
        self.records
            .sort_unstable_by(|left, right| left.id.cmp(&right.id));
        self.observations
            .sort_unstable_by(|left, right| left.id.cmp(&right.id));
        self.contexts
            .sort_unstable_by(|left, right| left.key.cmp(&right.key));
        if self.records.windows(2).any(|pair| pair[0].id == pair[1].id)
            || self
                .contexts
                .windows(2)
                .any(|pair| pair[0].key == pair[1].key)
        {
            return Err(Code::Denied.error("canonical Graph duplicate evidence"));
        }
        scratch.charge(
            self.contexts
                .iter()
                .try_fold(0usize, |bytes, context| {
                    bytes.checked_add(context.body.len().checked_mul(8)?)
                })
                .ok_or_else(|| Code::Limit.error("canonical Graph fact memory"))?,
        )?;
        self.facts = self
            .contexts
            .iter()
            .map(GraphFactV1::try_from)
            .collect::<Result<_>>()?;
        self.revision.evidence.sort_unstable();
        self.revision.coverage.sort_unstable();
        self.revision.coverage.dedup();
        self.revision.context.sort_unstable();
        self.revision.context.dedup();
        self.revision.missing_ranges.sort_unstable();
        self.revision.missing_ranges.dedup();
        self.revision.validate(tenant)?;
        Ok(())
    }
}

pub(in crate::analysis) struct DomainScratch<'a> {
    pub(in crate::analysis) budget: &'a dyn super::ManagedBudget,
    pub(in crate::analysis) memory: &'a super::super::budget::PreparedMemory<'a>,
    pub(in crate::analysis) bytes: usize,
    pub(in crate::analysis) leases: Vec<Box<dyn std::any::Any + Send + Sync>>,
}

impl DomainScratch<'_> {
    pub(in crate::analysis) fn charge(&mut self, bytes: usize) -> Result<()> {
        self.budget.check()?;
        if bytes == 0 {
            return Ok(());
        }
        let total = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.budget.limit())
            .ok_or_else(|| Code::Limit.error("domain Graph validation memory"))?;
        self.leases.push(self.memory.reserve(bytes)?);
        self.bytes = total;
        Ok(())
    }

    fn array_bytes(array: &dyn Array) -> Option<usize> {
        let data = array.to_data();
        let mut bytes = array.len().checked_mul(4 * std::mem::size_of::<usize>())?;
        for child in data.child_data() {
            bytes = bytes.checked_add(Self::array_bytes(
                sdk::arrow_array::make_array(child.clone()).as_ref(),
            )?)?;
        }
        Some(bytes)
    }
}

impl DomainCommands {
    pub(in crate::analysis) fn is_empty(&self) -> bool {
        self.records.is_empty() && self.states.is_empty()
    }

    pub(in crate::analysis) fn read(
        journal: &araphor_graph::Journal,
        spec: &sdk::GraphSpec,
        relations: &BTreeMap<String, u64>,
        basis: &Basis,
        package: &sdk::Package,
        model: &sdk::Model,
        scratch: &mut DomainScratch<'_>,
    ) -> Result<Self> {
        let mut commands = Self::default();
        for staged in journal.batches() {
            scratch.charge(0)?;
            let Staged::Edits {
                relation, batch, ..
            } = staged
            else {
                continue;
            };
            let declaration = spec
                .relations
                .iter()
                .find(|value| relations[&value.name] == *relation)
                .ok_or_else(|| Code::Invalid.error("domain Graph relation"))?;
            let subjects = DomainRelations::subjects(declaration);
            let edges = DomainRelations::relationships(declaration, spec);
            let findings = DomainRelations::findings(declaration);
            let states = DomainRelations::states(declaration);
            if !subjects && !edges && !findings && !states {
                continue;
            }
            let width = std::mem::size_of::<algorithm::SubjectChange>()
                .max(std::mem::size_of::<algorithm::RelationshipChange>())
                .max(std::mem::size_of::<FindingMember>())
                .max(std::mem::size_of::<GraphStateMember>());
            let mut bytes = batch
                .get_array_memory_size()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(batch.num_rows().checked_mul(2 * width)?))
                .ok_or_else(|| Code::Limit.error("domain Graph decode memory"))?;
            for column in batch.columns() {
                bytes = bytes
                    .checked_add(
                        DomainScratch::array_bytes(column.as_ref())
                            .ok_or_else(|| Code::Limit.error("domain Graph child memory"))?,
                    )
                    .ok_or_else(|| Code::Limit.error("domain Graph decode memory"))?;
            }
            scratch.charge(bytes)?;
            let operations = batch
                .column_by_name("operation")
                .and_then(|value| value.as_any().downcast_ref::<UInt8Array>())
                .ok_or_else(|| Code::Invalid.error("domain Graph operations"))?;
            let properties = batch
                .column_by_name("properties")
                .and_then(|value| value.as_any().downcast_ref::<StructArray>())
                .ok_or_else(|| Code::Invalid.error("domain Graph properties"))?;
            let mut start = 0;
            while start < batch.num_rows() {
                scratch.charge(0)?;
                if operations.value(start) == araphor_graph::Write::Remove as u8 {
                    start += 1;
                    continue;
                }
                let mut end = start + 1;
                while end < batch.num_rows()
                    && operations.value(end) != araphor_graph::Write::Remove as u8
                {
                    end += 1;
                }
                let values = properties.slice(start, end - start);
                if values.null_count() != 0 {
                    return Err(Code::Invalid.error("domain Graph property null"));
                }
                let data = sdk::Dataset {
                    name: if subjects {
                        algorithm::SubjectChange::port().name
                    } else if edges {
                        algorithm::RelationshipChange::port().name
                    } else if states {
                        GraphStateMember::port().name
                    } else {
                        FindingMember::port().name
                    },
                    batches: vec![sdk::RecordBatch::try_new(
                        Arc::new(declaration.properties.clone()),
                        values.columns().to_vec(),
                    )
                    .context(crate::PackageArrowSnafu)?],
                };
                if subjects {
                    let decoded = algorithm::SubjectChange::decode(&data)
                        .context(crate::AnalysisContractSnafu)?;
                    for (row, value) in decoded.into_iter().enumerate() {
                        scratch.charge(0)?;
                        Self::check_key(batch, start + row, "key", &value.key)?;
                        if basis.subject(*relation, batch, start + row, &value)? {
                            continue;
                        }
                        commands.anchor(&value.anchor);
                        commands.subjects.push(value);
                    }
                } else if edges {
                    let decoded = algorithm::RelationshipChange::decode(&data)
                        .context(crate::AnalysisContractSnafu)?;
                    for (row, value) in decoded.into_iter().enumerate() {
                        scratch.charge(0)?;
                        let row = start + row;
                        Self::check_key(batch, row, "key", &value.key)?;
                        Self::check_key(batch, row, "from", &value.key.from)?;
                        Self::check_key(batch, row, "to", &value.key.to)?;
                        Self::check_key(batch, row, "label", &value.key.edge_type)?;
                        if value.key.package_id == package.id
                            && basis.edge(*relation, batch, row, &value)?
                        {
                            continue;
                        }
                        commands.anchor(&value.anchor);
                        commands.records.extend(value.key.evidence.iter().cloned());
                        commands.edges.push(value);
                    }
                } else if states {
                    for (row, value) in GraphStateMember::decode(&data)
                        .context(crate::AnalysisContractSnafu)?
                        .into_iter()
                        .enumerate()
                    {
                        scratch.charge(0)?;
                        Self::check_key(batch, start + row, "key", &value.record)?;
                        Self::check_key(batch, start + row, "owner", &value.record)?;
                        if basis.state(*relation, batch, start + row, &value)? {
                            continue;
                        }
                        if let Some(record) = &value.record {
                            commands.records.insert(record.clone());
                        }
                        commands.states.push(value);
                    }
                } else {
                    let decoded =
                        FindingMember::decode(&data).context(crate::AnalysisContractSnafu)?;
                    for (row, value) in decoded.into_iter().enumerate() {
                        scratch.charge(0)?;
                        Self::check_key(batch, start + row, "key", &value.value.finding_id)?;
                        Self::finding_declaration(&value, package, model)?;
                        if basis.finding(*relation, batch, start + row, &value)? {
                            continue;
                        }
                        commands.anchor(&value.anchor);
                        commands
                            .records
                            .extend(value.value.evidence.iter().cloned());
                        commands.findings.push(value);
                    }
                }
                start = end;
            }
        }
        Ok(commands)
    }

    fn finding_declaration(
        row: &FindingMember,
        package: &sdk::Package,
        model: &sdk::Model,
    ) -> Result<()> {
        let value = &row.value;
        if value.package_id != package.id || value.tenant_id != row.anchor.record.stream.tenant_id {
            return Err(Code::Denied.error("domain Graph finding package"));
        }
        let code = match &value.reason {
            crate::FindingReasonV1::Declared(reason) => {
                reason
                    .validate(&package.id)
                    .context(crate::AnalysisContractSnafu)?;
                if !model
                    .reasons
                    .iter()
                    .any(|item| item.code == reason.code && item.details == reason.schema)
                {
                    return Err(Code::Denied.error("domain Graph reason schema"));
                }
                reason.code.clone()
            }
            reason => format!(
                "{}.{}",
                package.id,
                reason.label().context(crate::AnalysisContractSnafu)?
            ),
        };
        if !model.reasons.iter().any(|reason| reason.code == code) {
            return Err(Code::Denied.error("domain Graph reason declaration"));
        }
        Ok(())
    }

    fn anchor(&mut self, anchor: &algorithm::Anchor) {
        self.records.insert(anchor.record.clone());
        if let Some(fact) = &anchor.fact {
            self.records.insert(fact.record.clone());
        }
    }

    fn check_key(
        batch: &sdk::RecordBatch,
        row: usize,
        column: &str,
        value: &impl serde::Serialize,
    ) -> Result<()> {
        let keys = batch
            .column_by_name(column)
            .and_then(|value| value.as_any().downcast_ref::<BinaryArray>())
            .ok_or_else(|| Code::Invalid.error("domain Graph key column"))?;
        let expected = DomainRelations::key(value).context(crate::AnalysisContractSnafu)?;
        if keys.is_null(row) || keys.value(row) != expected {
            return Err(Code::Denied.error("domain Graph command identity"));
        }
        Ok(())
    }

    fn positions(
        input: &DomainInput,
        facts: &[GraphFactV1],
        anchor: &algorithm::Anchor,
    ) -> Result<(u32, Option<u32>)> {
        let record = input
            .records
            .binary_search_by(|value| value.id.cmp(&anchor.record))
            .ok()
            .and_then(|index| u32::try_from(index).ok())
            .ok_or_else(|| Code::Denied.error("domain Graph anchor record"))?;
        let context = anchor
            .fact
            .as_ref()
            .map(|fact| {
                input
                    .contexts
                    .binary_search_by(|value| value.key.cmp(&fact.key))
                    .ok()
                    .filter(|&index| {
                        facts[index].record_id == fact.record
                            && facts[index].value == fact.value
                            && input.contexts[index].sensitivity == fact.sensitivity
                    })
                    .and_then(|index| u32::try_from(index).ok())
                    .ok_or_else(|| Code::Denied.error("domain Graph anchor fact"))
            })
            .transpose()?;
        Ok((record, context))
    }

    fn validate(
        &self,
        input: &DomainInput,
        package: &sdk::Package,
        model: &sdk::Model,
        restricted: bool,
        scratch: &mut DomainScratch<'_>,
    ) -> Result<()> {
        scratch.charge(0)?;
        let facts = &input.facts;
        let basis = EvidenceBasis::from_records(
            &input.records,
            &input.observations,
            &input.revision,
            facts,
            restricted,
        );
        for row in self.subjects.iter() {
            scratch.charge(0)?;
            let (record, context) = Self::positions(input, &facts, &row.anchor)?;
            basis.validate_subject(&algorithm::Subject {
                record,
                context,
                key: row.key.clone(),
            })?;
        }
        for row in self.edges.iter() {
            scratch.charge(0)?;
            if row.key.package_id != package.id {
                return Err(Code::Denied.error("domain Graph relationship package"));
            }
            let (record, fact) = Self::positions(input, &facts, &row.anchor)?;
            let evidence = row
                .key
                .evidence
                .iter()
                .map(|id| {
                    input
                        .records
                        .binary_search_by(|value| value.id.cmp(id))
                        .ok()
                        .and_then(|index| u32::try_from(index).ok())
                        .ok_or_else(|| Code::Denied.error("domain Graph edge evidence"))
                })
                .collect::<Result<Vec<_>>>()?;
            let subjects = [
                algorithm::Subject {
                    record,
                    context: fact,
                    key: row.key.from.clone(),
                },
                algorithm::Subject {
                    record,
                    context: fact,
                    key: row.key.to.clone(),
                },
            ];
            basis.validate_edge(
                &algorithm::Relationship {
                    record,
                    fact,
                    edge: GraphEdgeV1 {
                        key: GraphEdgeKeyV1 {
                            from: 0,
                            to: 1,
                            edge_type: row.key.edge_type,
                            package_id: row.key.package_id.clone(),
                            evidence,
                            cause: row.key.cause,
                        },
                        proof_quality: row.proof_quality,
                        required_coverage_interval_ids: row.required_coverage_interval_ids.clone(),
                        first_boottime_ns: row.first_boottime_ns,
                        last_boottime_ns: row.last_boottime_ns,
                    },
                },
                &subjects,
            )?;
        }
        for row in &self.states {
            scratch.charge(0)?;
            row.validate().context(crate::AnalysisContractSnafu)?;
            let Some(record) = &row.record else {
                continue;
            };
            let index = input
                .records
                .binary_search_by(|value| value.id.cmp(record))
                .map_err(|_| Code::Denied.error("domain Graph state record"))?;
            if row.position != Some(input.observations[index].position)
                || row.fact.as_ref().is_some_and(|key| {
                    !input
                        .facts
                        .iter()
                        .zip(&input.contexts)
                        .any(|(fact, context)| &context.key == key && &fact.record_id == record)
                })
            {
                return Err(Code::Denied.error("domain Graph state provenance"));
            }
        }
        for row in self.findings.iter() {
            scratch.charge(0)?;
            Self::finding_declaration(row, package, model)?;
            let value = &row.value;
            let (record, context) = Self::positions(input, &facts, &row.anchor)?;
            basis.validate_finding(record, context, value)?;
        }
        Ok(())
    }
}

pub(in crate::analysis) struct DomainPreparation {
    pub(in crate::analysis) commands: DomainCommands,
    pub(in crate::analysis) contexts: ContextInputs,
    pub(in crate::analysis) bytes: usize,
    pub(in crate::analysis) leases: Vec<Box<dyn std::any::Any + Send + Sync>>,
}

impl DomainPreparation {
    pub(in crate::analysis) fn validate<'a>(
        self,
        tenant: [u8; 16],
        frame: &crate::ManagedSourceFrame,
        calls: &BTreeSet<u64>,
        package: &sdk::Package,
        model: &sdk::Model,
        derived: impl IntoIterator<Item = &'a crate::AnalysisContextVersionV1>,
        restricted: bool,
        budget: &dyn super::ManagedBudget,
        memory: &mut super::super::budget::PreparedMemory<'_>,
        mut eligible: impl FnMut(
            &BTreeSet<DiscoveryRecordIdV1>,
            &[&(crate::AnalysisContextVersionV1, AnalysisContextRefV1)],
            &mut DomainScratch<'_>,
        ) -> Result<Vec<(crate::AnalysisContextVersionV1, GraphFactV1)>>,
    ) -> Result<Option<super::super::model::GraphProof>> {
        let mut scratch = DomainScratch {
            budget,
            memory,
            bytes: self.bytes,
            leases: self.leases,
        };
        let commands = self.commands;
        let contexts = self.contexts;
        let records =
            frame.canonical_events(&commands.records, calls, &mut |bytes| scratch.charge(bytes))?;
        frame.charge_contexts(calls, &mut |bytes| scratch.charge(bytes))?;
        let handles = frame.call_derived(calls)?;
        let known = handles
            .iter()
            .flat_map(|handle| &handle.contexts)
            .map(|context| &context.key)
            .collect::<BTreeSet<_>>();
        let saved = contexts
            .values
            .values()
            .filter(|(value, _)| !known.contains(&value.key))
            .collect::<Vec<_>>();
        let mut facts = eligible(&commands.records, &saved, &mut scratch)?;
        let mut keys = BTreeSet::new();
        for value in derived {
            scratch.charge(0)?;
            if !keys.insert(&value.key) {
                continue;
            }
            scratch.charge(
                value
                    .body
                    .len()
                    .checked_mul(8)
                    .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<GraphFactV1>()))
                    .ok_or_else(|| Code::Limit.error("canonical Graph fact memory"))?,
            )?;
            let fact = GraphFactV1::try_from(value)?;
            if commands.records.contains(&fact.record_id) {
                facts.push((value.clone(), fact));
            }
        }
        facts.sort_unstable_by(|left, right| left.0.key.cmp(&right.0.key));
        let sources = commands
            .records
            .iter()
            .map(|id| id.stream.clone())
            .collect::<BTreeSet<_>>();
        let mut joined = DomainInput::default();
        let mut proof_sources = Vec::new();
        for source in sources {
            scratch.charge(0)?;
            let mut input = GraphReplayInputV1 {
                source: source.clone(),
                records: Vec::new(),
                input_positions: Vec::new(),
                coverage: Vec::new(),
                coverage_keys: Vec::new(),
                missing_ranges: Vec::new(),
                facts: facts
                    .iter()
                    .filter(|value| value.1.record_id.stream == source)
                    .map(|value| value.0.clone())
                    .collect(),
            };
            for (id, (record, position)) in &records {
                if id.stream == source {
                    input.records.push(record.clone());
                    input.input_positions.push((id.clone(), *position));
                }
            }
            frame.canonical_coverage(&mut input, &mut |bytes| scratch.charge(bytes))?;
            let cpu = input
                .records
                .first()
                .ok_or_else(|| Code::Invalid.error("Graph proof source records"))?
                .id
                .cpu_id;
            let (report, missing) = frame.source_metadata(&source)?;
            scratch.charge(
                (std::mem::size_of::<super::super::model::GraphProofSource>()
                    + source.node_id.len()
                    + missing.len() * std::mem::size_of::<(u64, u64)>())
                .checked_mul(4)
                .ok_or_else(|| Code::Limit.error("Graph proof source memory"))?,
            )?;
            let mut missing = missing.to_vec();
            missing.sort_unstable();
            missing.dedup();
            proof_sources.push(super::super::model::GraphProofSource {
                source,
                cpu,
                report,
                missing,
            });
            joined.append(input, &mut scratch)?;
        }
        joined.finish(tenant, &mut scratch)?;
        commands.validate(&joined, package, model, restricted, &mut scratch)?;
        let proof = super::super::model::GraphProof {
            coverage: std::mem::take(&mut joined.revision.coverage),
            sources: proof_sources,
        };
        let lease = memory.reserve(
            proof
                .allocation_bytes()
                .and_then(|bytes| bytes.checked_mul(4))
                .ok_or_else(|| Code::Limit.error("Graph canonical proof memory"))?,
        )?;
        drop(joined);
        drop(records);
        drop(facts);
        drop(commands);
        drop(known);
        drop(handles);
        drop(saved);
        drop(scratch);
        memory.hold(lease);
        Ok(Some(proof))
    }
}
