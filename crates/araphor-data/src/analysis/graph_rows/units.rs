use super::basis::CallBasis;
use super::*;
use crate::{AnalysisContractSnafu, GraphValidate as _};

pub(super) struct UnitEffects {
    pub touched: BTreeSet<(u8, Vec<u8>)>,
    pub state: GraphPackageStateV1,
    pub work: (u64, u64, u64),
    pub root_cursors: (u64, u64),
}

struct UnitBatch {
    units: BTreeMap<crate::DiscoveryRecordIdV1, Unit>,
    before: BTreeSet<crate::DiscoveryRecordIdV1>,
    records: Vec<Observation>,
    contexts: BTreeMap<crate::AnalysisContextKeyV1, u64>,
    basis: CallBasis,
    contributions: Vec<Contribution>,
    subjects: Vec<SubjectChange>,
    edges: Vec<RelationshipChange>,
    changes: Vec<FindingChange>,
    owners: [Vec<usize>; 3],
    default: GraphPackageStateV1,
}

impl UnitBatch {
    fn new(
        writer: &Connection,
        root: &std::path::Path,
        metadata: &GraphManifest,
        returned: &crate::ManagedReturn<'_>,
        pin: &crate::ManagedCall,
        reset: bool,
        restricted: bool,
    ) -> Result<Self> {
        let evaluation = returned.evaluation;
        let output = returned.output;
        if evaluation.checkpoint.is_some()
            || output.checkpoint.is_some()
            || !evaluation.previous_outputs.is_empty()
        {
            return Err(GraphRows::invalid("graph unit saved state"));
        }
        let input = |name| {
            evaluation
                .input(name)
                .map(|input| &input.data)
                .context(AnalysisContractSnafu)
        };
        let dataset = |name: &str| {
            output
                .datasets
                .iter()
                .find(|data| data.name == name)
                .ok_or_else(|| GraphRows::invalid("graph unit dataset"))
        };
        let mut units = BTreeMap::new();
        for unit in Unit::decode(input("units")?).context(AnalysisContractSnafu)? {
            if units.insert(unit.record.clone(), unit).is_some() {
                return Err(GraphRows::invalid("graph duplicate unit"));
            }
        }
        let mut before = BTreeSet::new();
        for unit in Unit::decode(input("unit_removals")?).context(AnalysisContractSnafu)? {
            if unit.record.stream != metadata.scope.identity || !before.insert(unit.record) {
                return Err(GraphRows::invalid("graph historical unit"));
            }
        }
        if reset && !before.is_empty() {
            return Err(GraphRows::invalid("graph reset removals"));
        }
        let records = Observation::decode(input("records")?).context(AnalysisContractSnafu)?;
        let facts = Fact::decode(input("facts")?).context(AnalysisContractSnafu)?;
        let basis = CallBasis::new(evaluation)?;
        let mut expected = BTreeMap::new();
        let mut expected_facts = BTreeMap::new();
        let window = metadata
            .packages
            .iter()
            .find(|package| package.package_id == pin.package.package_id)
            .ok_or_else(|| GraphRows::invalid("graph unit package"))?
            .window_ns;
        for unit in units.values() {
            if unit.record.stream != metadata.scope.identity
                || unit.window_ns != window
                || unit
                    .support
                    .windows(2)
                    .any(|pair| pair[0].record >= pair[1].record)
                || !unit
                    .support
                    .iter()
                    .any(|support| support.record == unit.record)
            {
                return Err(GraphRows::invalid("graph unit identity"));
            }
            for support in &unit.support {
                if support.record.stream != metadata.scope.identity
                    || metadata
                        .input_manifest
                        .evidence
                        .binary_search(&support.record)
                        .is_err()
                    || support.facts.windows(2).any(|pair| pair[0] >= pair[1])
                {
                    return Err(GraphRows::invalid("graph unit current support"));
                }
                if expected
                    .insert(support.record.clone(), support.proof)
                    .is_some_and(|old| old != support.proof)
                {
                    return Err(GraphRows::invalid("graph unit proof conflict"));
                }
                for key in &support.facts {
                    if expected_facts
                        .insert(key.clone(), support.record.clone())
                        .is_some_and(|old| old != support.record)
                    {
                        return Err(GraphRows::invalid("graph unit fact conflict"));
                    }
                }
            }
        }
        if records.len() != expected.len()
            || records.iter().any(|record| {
                expected.get(&record.id) != Some(&record.proof_quality)
                    || metadata
                        .input_positions
                        .binary_search_by(|(id, _)| id.cmp(&record.id))
                        .ok()
                        .is_none_or(|index| {
                            metadata.input_positions[index].1.commit_revision
                                != record.position.commit_revision
                                || metadata.input_positions[index].1.ordinal
                                    != record.position.ordinal
                        })
            })
            || facts.len() != expected_facts.len()
            || facts.iter().any(|fact| {
                records
                    .get(fact.record as usize)
                    .is_none_or(|record| expected_facts.get(&fact.key) != Some(&record.id))
            })
        {
            return Err(GraphRows::invalid("graph unit lookup union"));
        }
        let contexts = Self::contexts(writer, root, metadata, &facts, &records)?;
        if units.values().any(|unit| unit.restricted != restricted) {
            return Err(GraphRows::invalid("graph unit sensitivity"));
        }
        let contributions =
            Contribution::decode(dataset("contributions")?).context(AnalysisContractSnafu)?;
        let subjects =
            SubjectChange::decode(dataset("subjects")?).context(AnalysisContractSnafu)?;
        let edges =
            RelationshipChange::decode(dataset("relationships")?).context(AnalysisContractSnafu)?;
        let changes = FindingChange::decode(dataset("findings")?).context(AnalysisContractSnafu)?;
        let owners = Contribution::validate(
            units.values(),
            &records,
            &facts,
            &contributions,
            [subjects.len(), edges.len(), changes.len()],
        )
        .context(AnalysisContractSnafu)?;
        let states =
            GraphPackageStateV1::decode(dataset("state")?).context(AnalysisContractSnafu)?;
        let [default] = states.as_slice() else {
            return Err(GraphRows::invalid("graph unit default state"));
        };
        Ok(Self {
            units,
            before,
            records,
            contexts,
            basis,
            contributions,
            subjects,
            edges,
            changes,
            owners,
            default: default.clone(),
        })
    }

    fn anchor(&self, owner: usize, anchor: &Anchor) -> Result<()> {
        let unit = &self.units[&self.contributions[owner].record];
        self.basis.local_for(unit, anchor).map(|_| ())
    }

    fn evidence(&self, owner: usize, records: &[crate::DiscoveryRecordIdV1]) -> Result<()> {
        let unit = &self.units[&self.contributions[owner].record];
        if records
            .iter()
            .any(|record| !unit.support.iter().any(|support| &support.record == record))
        {
            return Err(GraphRows::invalid("graph unit evidence ownership"));
        }
        Ok(())
    }

    fn dependencies(
        &self,
        writer: &Connection,
        records: &BTreeMap<crate::DiscoveryRecordIdV1, u64>,
    ) -> Result<BTreeMap<crate::DiscoveryRecordIdV1, Vec<araphor_graph::Member>>> {
        writer.execute_batch("CREATE TEMP TABLE graph_dependency_records(evidence_id UBIGINT,member_key BLOB,commit_revision UBIGINT,ordinal UINTEGER)")
            .context(AnalysisDatabaseSnafu { operation: "stage graph unit dependencies" })?;
        let result = (|| {
            {
                let mut appender =
                    writer
                        .appender("graph_dependency_records")
                        .context(AnalysisDatabaseSnafu {
                            operation: "open graph record dependencies",
                        })?;
                for record in &self.records {
                    appender
                        .append_row(params![
                            records[&record.id],
                            GraphRows::member_key(&record.id)?,
                            record.position.commit_revision,
                            record.position.ordinal
                        ])
                        .context(AnalysisDatabaseSnafu {
                            operation: "append graph record dependency",
                        })?;
                }
                appender.flush().context(AnalysisDatabaseSnafu {
                    operation: "flush graph record dependencies",
                })?;
            }
            writer.execute_batch("INSERT INTO graph_position_values SELECT nextval('graph_position_values_seq'),stage.evidence_id,stage.commit_revision,stage.ordinal FROM graph_dependency_records stage WHERE NOT EXISTS(SELECT 1 FROM graph_position_values saved WHERE saved.evidence_id=stage.evidence_id AND saved.commit_revision=stage.commit_revision AND saved.ordinal=stage.ordinal)")
                .context(AnalysisDatabaseSnafu { operation: "intern graph dependency values" })?;
            let mut statement = writer.prepare("SELECT stage.evidence_id,stage.member_key,saved.value_ref FROM graph_dependency_records stage JOIN graph_position_values saved USING(evidence_id,commit_revision,ordinal)")
                .context(AnalysisDatabaseSnafu { operation: "prepare graph record dependencies" })?;
            let members = statement
                .query_map([], |row| {
                    let record = row.get::<_, u64>(0)?;
                    Ok((
                        record,
                        araphor_graph::Member {
                            kind: MemberKind::UnitRecord as u8,
                            key: row.get(1)?,
                            value: row.get(2)?,
                            record: Some(record),
                            fact: None,
                            reason: None,
                            ordinal: 0,
                        },
                    ))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read graph record dependencies",
                })?
                .collect::<duckdb::Result<BTreeMap<_, _>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode graph record dependencies",
                })?;
            drop(statement);
            if members.len() != self.records.len() {
                return Err(GraphRows::invalid("graph record dependency count"));
            }
            self.units
                .values()
                .map(|unit| {
                    let mut dependencies = Vec::new();
                    for support in &unit.support {
                        dependencies.push(members[&records[&support.record]].clone());
                        for key in &support.facts {
                            dependencies.push(araphor_graph::Member {
                                kind: MemberKind::UnitFact as u8,
                                key: super::super::context::version_key(key)?,
                                value: self.contexts[key],
                                record: Some(records[&support.record]),
                                fact: None,
                                reason: None,
                                ordinal: 0,
                            });
                        }
                    }
                    Ok((unit.record.clone(), dependencies))
                })
                .collect()
        })();
        let cleanup = writer
            .execute_batch("DROP TABLE graph_dependency_records")
            .context(AnalysisDatabaseSnafu {
                operation: "release graph unit dependencies",
            });
        let result = result?;
        cleanup?;
        Ok(result)
    }

    fn contexts(
        writer: &Connection,
        root: &std::path::Path,
        metadata: &GraphManifest,
        facts: &[Fact],
        records: &[Observation],
    ) -> Result<BTreeMap<crate::AnalysisContextKeyV1, u64>> {
        if metadata.input_manifest.context.is_empty() {
            if !facts.is_empty() {
                return Err(GraphRows::invalid("graph unit context keys"));
            }
            return Ok(BTreeMap::new());
        }
        writer.execute_batch("CREATE TEMP TABLE graph_unit_contexts(tenant_id BLOB,owner_id VARCHAR,entity_key BLOB,lifetime_key BLOB,owner_revision UBIGINT,wanted BOOLEAN)")
            .context(AnalysisDatabaseSnafu {operation:"stage graph unit contexts"})?;
        let result = (|| {
            let wanted = facts
                .iter()
                .map(|fact| (&fact.key, fact))
                .collect::<BTreeMap<_, _>>();
            if wanted.len() != facts.len()
                || wanted
                    .keys()
                    .any(|key| metadata.input_manifest.context.binary_search(key).is_err())
            {
                return Err(GraphRows::invalid("graph unit context keys"));
            }
            {
                let mut appender =
                    writer
                        .appender("graph_unit_contexts")
                        .context(AnalysisDatabaseSnafu {
                            operation: "open graph unit contexts",
                        })?;
                for key in &metadata.input_manifest.context {
                    appender
                        .append_row(params![
                            key.tenant_id.as_slice(),
                            key.owner_id,
                            key.entity_key,
                            key.lifetime_key,
                            key.owner_revision,
                            wanted.contains_key(key)
                        ])
                        .context(AnalysisDatabaseSnafu {
                            operation: "append graph unit context",
                        })?;
                }
                appender.flush().context(AnalysisDatabaseSnafu {
                    operation: "flush graph unit contexts",
                })?;
            }
            let missing:bool=writer.query_row("SELECT EXISTS(SELECT 1 FROM graph_unit_contexts wanted LEFT JOIN context_versions context USING(tenant_id,owner_id,entity_key,lifetime_key,owner_revision) WHERE context.commit_revision IS NULL)",[],|row|row.get(0)).context(AnalysisDatabaseSnafu {operation:"check graph unit context references"})?;
            if missing {
                return Err(GraphRows::invalid("graph unit context reference"));
            }
            let mut statement=writer.prepare("SELECT context.tenant_id,context.owner_id,context.entity_key,context.lifetime_key,context.owner_revision,context.valid_from_utc_ns,context.valid_until_utc_ns,context.sensitivity,context.body,context.commit_revision FROM graph_unit_contexts wanted LEFT JOIN context_versions context USING(tenant_id,owner_id,entity_key,lifetime_key,owner_revision) WHERE wanted.wanted")
                .context(AnalysisDatabaseSnafu {operation:"prepare graph unit context values"})?;
            let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
                operation: "read graph unit context values",
            })?;
            let mut seen = BTreeMap::new();
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance graph unit context values",
            })? {
                let key = crate::AnalysisContextKeyV1 {
                    tenant_id: GraphRows::column::<Vec<u8>>(row, 0)?
                        .try_into()
                        .map_err(|_| GraphRows::invalid("graph unit context tenant"))?,
                    owner_id: GraphRows::column(row, 1)?,
                    entity_key: GraphRows::column(row, 2)?,
                    lifetime_key: GraphRows::column(row, 3)?,
                    owner_revision: GraphRows::column(row, 4)?,
                };
                let (context, committed) = super::super::AnalysisStore::decode_context_row(
                    root,
                    key.clone(),
                    (
                        GraphRows::column(row, 5)?,
                        GraphRows::column(row, 6)?,
                        GraphRows::column(row, 7)?,
                        GraphRows::column(row, 8)?,
                        GraphRows::column(row, 9)?,
                    ),
                )?;
                let value = crate::GraphFactV1::try_from(&context)?;
                let fact = wanted
                    .get(&key)
                    .ok_or_else(|| GraphRows::invalid("graph unit context value"))?;
                let record = records
                    .get(fact.record as usize)
                    .ok_or_else(|| GraphRows::invalid("graph unit fact record"))?;
                if seen.insert(key, committed).is_some()
                    || value.record_id != record.id
                    || value.value != fact.value
                    || context.sensitivity != fact.sensitivity
                    || !metadata.facts.contains(&value)
                {
                    return Err(GraphRows::invalid("graph unit fact value"));
                }
            }
            if seen.len() != wanted.len() {
                return Err(GraphRows::invalid("graph unit context count"));
            }
            Ok(seen)
        })();
        let cleanup = writer
            .execute_batch("DROP TABLE graph_unit_contexts")
            .context(AnalysisDatabaseSnafu {
                operation: "release graph unit contexts",
            });
        let result = result?;
        cleanup?;
        Ok(result)
    }
}

impl GraphRows {
    #[expect(
        clippy::too_many_arguments,
        reason = "The unit write keeps its producer cut and checked metadata sensitivity."
    )]
    pub(super) fn apply_units(
        writer: &Connection,
        root: &std::path::Path,
        scope: u64,
        revision: u64,
        metadata: &GraphManifest,
        returned: &crate::ManagedReturn<'_>,
        pin: &crate::ManagedCall,
        restricted: bool,
    ) -> Result<UnitEffects> {
        let reset = sdk::ChangeInputs {
            reset: "reset".into(),
            ports: Vec::new(),
        }
        .is_reset(returned.evaluation)
        .context(AnalysisContractSnafu)?;
        let batch = UnitBatch::new(writer, root, metadata, returned, pin, reset, restricted)?;
        let mut reasons = BTreeMap::new();
        for reason in &returned.output.reasons {
            if reason.output.dataset != "findings"
                || reasons.insert(reason.output.row, reason).is_some()
            {
                return Err(Self::invalid("graph finding reason"));
            }
        }
        if reasons.len() != batch.changes.len() {
            return Err(Self::invalid("graph finding reason"));
        }
        for (index, row) in batch.subjects.iter().enumerate() {
            batch.anchor(batch.owners[0][index], &row.anchor)?;
            row.key.validate()?;
            if row.key.tenant_id != metadata.scope.identity.tenant_id {
                return Err(Self::invalid("graph subject tenant"));
            }
        }
        for (index, row) in batch.edges.iter().enumerate() {
            batch.anchor(batch.owners[1][index], &row.anchor)?;
            batch.evidence(batch.owners[1][index], &row.key.evidence)?;
            if row.key.from.tenant_id != metadata.scope.identity.tenant_id
                || row.key.to.tenant_id != metadata.scope.identity.tenant_id
                || row.key.package_id != pin.package.package_id
                || row.first_boottime_ns > row.last_boottime_ns
                || row.key.evidence.is_empty()
                || row.key.evidence.windows(2).any(|pair| pair[0] >= pair[1])
                || (row.key.edge_type == GraphEdgeTypeV1::NativeParent
                    && (row.key.from.authority != row.key.to.authority
                        || !matches!(
                            row.key.from.authority,
                            GraphSubjectAuthorityV1::Native { .. }
                        )))
            {
                return Err(Self::invalid("graph edge value"));
            }
        }
        let positions = batch
            .basis
            .records
            .iter()
            .map(|(record, index)| (record, *index))
            .collect();
        let mut findings = Vec::with_capacity(batch.changes.len());
        for (index, row) in batch.changes.iter().enumerate() {
            let owner = batch.owners[2][index];
            batch.anchor(owner, &row.anchor)?;
            let (record, context) = batch.basis.local(&row.anchor)?;
            if row.prior_reason.is_some() {
                return Err(Self::invalid("graph finding prior reason"));
            }
            let reason = FindingReasonV1::from_output(
                &row.package_id,
                &row.local(record, context),
                &positions,
                reasons
                    .get(&(index as u64))
                    .ok_or_else(|| Self::invalid("graph finding reason"))?,
            )
            .context(AnalysisContractSnafu)?;
            let finding = row.clone().into_finding(reason);
            metadata.input_manifest.validate_finding(&finding)?;
            batch.evidence(owner, &finding.evidence)?;
            for policy in &finding.policy_provenance {
                batch.evidence(owner, &policy.observations)?;
            }
            let unit = &batch.units[&batch.contributions[owner].record];
            if finding.tenant_id != metadata.scope.identity.tenant_id
                || finding.package_id != pin.package.package_id
                || !metadata.packages.iter().any(|package| {
                    package.package_id == finding.package_id
                        && package.package_version == finding.package_version
                })
                || (unit.restricted && finding.sensitivity != ContextSensitivityV1::HostRestricted)
            {
                return Err(Self::invalid("graph finding authority"));
            }
            findings.push(finding);
        }
        let record_keys = batch
            .records
            .iter()
            .map(|record| record.id.clone())
            .chain(batch.before.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let records = Self::intern_records(writer, &metadata.scope.identity, &record_keys)?;
        let keys = batch
            .subjects
            .iter()
            .map(|row| row.key.clone())
            .chain(
                batch
                    .edges
                    .iter()
                    .flat_map(|row| [row.key.from.clone(), row.key.to.clone()]),
            )
            .chain(findings.iter().map(|row| row.subject_id.clone()))
            .collect::<Vec<_>>();
        let subjects = Self::intern_subjects(writer, &keys)?;
        let mut unique_edges = BTreeMap::new();
        let mut edge_rows = Vec::with_capacity(batch.edges.len());
        for edge in &batch.edges {
            let key = Self::encode_value(&(
                &edge.key,
                &edge.proof_quality,
                &edge.required_coverage_interval_ids,
                edge.first_boottime_ns,
                edge.last_boottime_ns,
            ))?;
            let next = unique_edges.len();
            let index = unique_edges
                .entry(key)
                .or_insert_with(|| (next, EdgeValue::from(edge)))
                .0;
            edge_rows.push(index);
        }
        let mut edge_values = unique_edges.into_values().collect::<Vec<_>>();
        edge_values.sort_by_key(|(index, _)| *index);
        let edge_values = edge_values
            .into_iter()
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        let edges = Self::intern_edges(writer, &subjects, &records, &edge_values)?;
        let mut unique_findings = BTreeMap::new();
        for finding in &findings {
            if unique_findings
                .insert(finding.finding_id.clone(), finding.clone())
                .is_some_and(|old| old != *finding)
            {
                return Err(Self::invalid("graph unit finding conflict"));
            }
        }
        let finding_values = unique_findings.into_values().collect::<Vec<_>>();
        let finding_ids = Self::intern_findings(writer, &subjects, &records, &finding_values)?;
        let state_rows = batch
            .contributions
            .iter()
            .filter_map(|row| row.state.as_ref().map(|state| (row, state)))
            .map(|(row, state)| {
                let anchor = state
                    .fact
                    .as_ref()
                    .map(|key| -> Result<_> {
                        let (_, anchor) = batch
                            .basis
                            .facts
                            .get(key)
                            .ok_or_else(|| Self::invalid("graph unit state fact"))?;
                        if !records.contains_key(&anchor.record) {
                            return Err(Self::invalid("graph unit state fact record"));
                        }
                        Ok(anchor)
                    })
                    .transpose()?;
                Ok((row, state, anchor))
            })
            .collect::<Result<Vec<_>>>()?;
        let bodies = state_rows
            .iter()
            .filter_map(|(_, _, anchor)| *anchor)
            .map(|anchor| {
                Self::encode_value(&crate::GraphFactV1 {
                    record_id: anchor.record.clone(),
                    value: anchor.value.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut facts = Self::intern_values(
            writer,
            metadata.scope.identity.tenant_id,
            MemberKind::Fact,
            bodies,
        )?
        .into_iter();
        let states = state_rows
            .into_iter()
            .map(|(row, state, anchor)| {
                let anchor = anchor
                    .map(|anchor| -> Result<_> {
                        let fact = facts
                            .next()
                            .ok_or_else(|| Self::invalid("graph unit state fact reference"))?;
                        Ok((anchor, fact))
                    })
                    .transpose()?;
                Ok(araphor_graph::StateValue {
                    unit: records[&row.record],
                    state: state.clone(),
                    anchor,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let state_ids = araphor_graph::StateRows::intern(writer, &states)?;
        let mut dependencies = batch.dependencies(writer, &records)?;
        let mut members = batch
            .contributions
            .iter()
            .map(|row| {
                dependencies
                    .remove(&row.record)
                    .ok_or_else(|| Self::invalid("graph unit dependencies"))
            })
            .collect::<Result<Vec<_>>>()?;
        for (index, row) in batch.subjects.iter().enumerate() {
            members[batch.owners[0][index]].push(araphor_graph::Member {
                kind: 2,
                key: Self::member_key(&row.key)?,
                value: subjects[&row.key],
                record: Some(records[&row.anchor.record]),
                fact: row
                    .anchor
                    .fact
                    .as_ref()
                    .map(Self::encode_value)
                    .transpose()?,
                reason: None,
                ordinal: 0,
            });
        }
        for (index, row) in batch.edges.iter().enumerate() {
            members[batch.owners[1][index]].push(araphor_graph::Member {
                kind: 3,
                key: Self::member_key(&row.key)?,
                value: edges[edge_rows[index]],
                record: Some(records[&row.anchor.record]),
                fact: row
                    .anchor
                    .fact
                    .as_ref()
                    .map(Self::encode_value)
                    .transpose()?,
                reason: None,
                ordinal: 0,
            });
        }
        for (index, row) in batch.changes.iter().enumerate() {
            members[batch.owners[2][index]].push(araphor_graph::Member {
                kind: 4,
                key: Self::member_key(&row.finding_id)?,
                value: finding_ids[&row.finding_id],
                record: Some(records[&row.anchor.record]),
                fact: row
                    .anchor
                    .fact
                    .as_ref()
                    .map(Self::encode_value)
                    .transpose()?,
                reason: Some(row.reason_code.clone()),
                ordinal: 0,
            });
        }
        let mut state_index = 0;
        for (index, row) in batch.contributions.iter().enumerate() {
            if row.state.is_some() {
                members[index].push(araphor_graph::Member {
                    kind: 8,
                    key: Self::member_key(&row.record)?,
                    value: state_ids[state_index],
                    record: Some(records[&row.record]),
                    fact: states[state_index]
                        .anchor
                        .map(|(anchor, _)| Self::encode_value(anchor))
                        .transpose()?,
                    reason: None,
                    ordinal: 0,
                });
                state_index += 1;
            }
        }
        let mut replacements = batch
            .before
            .iter()
            .map(|record| {
                (
                    records[record],
                    araphor_graph::Replacement {
                        unit: Some(records[record]),
                        members: Vec::new(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        for (row, members) in batch.contributions.iter().zip(members) {
            let unit = records[&row.record];
            replacements.insert(
                unit,
                araphor_graph::Replacement {
                    unit: Some(unit),
                    members,
                },
            );
        }
        let replacements = replacements.into_values().collect::<Vec<_>>();
        let mut touched = replacements
            .iter()
            .flat_map(|row| row.members.iter())
            .filter(|member| (2..=4).contains(&member.kind))
            .map(|member| (member.kind, member.key.clone()))
            .collect::<BTreeSet<_>>();
        writer
            .execute_batch("CREATE TEMP TABLE graph_unit_roots(unit_ref UBIGINT PRIMARY KEY)")
            .context(AnalysisDatabaseSnafu {
                operation: "stage changed graph units",
            })?;
        {
            let mut appender =
                writer
                    .appender("graph_unit_roots")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open changed graph units",
                    })?;
            for row in &replacements {
                appender
                    .append_row(params![row.unit])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append changed graph unit",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush changed graph units",
            })?;
        }
        let mut statement=writer.prepare("SELECT DISTINCT member_kind,member_key,value_ref FROM graph_producer_members WHERE scope_id=? AND (? OR unit_ref IN (SELECT unit_ref FROM graph_unit_roots)) AND valid_to IS NULL AND member_kind IN (2,3,4)").context(AnalysisDatabaseSnafu {operation:"prepare removed graph unit keys"})?;
        let mut rows = statement
            .query(params![scope, reset])
            .context(AnalysisDatabaseSnafu {
                operation: "read removed graph unit keys",
            })?;
        let mut previous = Vec::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance removed graph unit keys",
        })? {
            let kind = Self::column(row, 0)?;
            let key = Self::column::<Vec<u8>>(row, 1)?;
            touched.insert((kind, key.clone()));
            previous.push((kind, key, Self::column::<u64>(row, 2)?));
        }
        drop(rows);
        drop(statement);
        writer
            .execute_batch("DROP TABLE graph_unit_roots")
            .context(AnalysisDatabaseSnafu {
                operation: "release changed graph units",
            })?;
        let needed = previous
            .iter()
            .map(|(kind, _, value)| (*kind, *value))
            .collect();
        let identities = super::stage::GraphStage {
            writer,
            scope,
            revision,
            records: &records,
        }
        .identities(&needed)?;
        for (kind, key, value) in previous {
            if identities.get(&(kind, value)).map(Vec::as_slice) != Some(key.as_slice()) {
                return Err(Self::invalid("graph member identity collision"));
            }
        }
        let mut work =
            araphor_graph::Contributions::apply(writer, scope, revision, &replacements, reset)?;
        work.0 = work.0.saturating_add(
            (record_keys.len()
                + batch.records.len()
                + metadata.input_manifest.context.len()
                + replacements.len()
                + subjects.len()) as u64,
        );
        let state = araphor_graph::StateRows::finish(writer, scope, revision, &batch.default)?;
        let root_cursors = batch
            .units
            .keys()
            .chain(batch.before.iter())
            .map(|record| record.durable_cursor)
            .fold(None, |bounds: Option<(u64, u64)>, cursor| {
                Some(bounds.map_or((cursor, cursor), |(first, last)| {
                    (first.min(cursor), last.max(cursor))
                }))
            })
            .unwrap_or_default();
        Ok(UnitEffects {
            touched,
            state,
            work,
            root_cursors,
        })
    }
}

#[cfg(test)]
mod tests;
