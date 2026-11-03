use super::history::Member;
use super::*;

pub(super) struct GraphStage<'a> {
    pub writer: &'a Connection,
    pub scope: u64,
    pub revision: u64,
    pub records: &'a BTreeMap<crate::DiscoveryRecordIdV1, u64>,
}

impl GraphStage<'_> {
    pub fn replace(&self, additions: Vec<Member>) -> Result<(u64, u64, u64)> {
        let mut selected = BTreeMap::new();
        for member in additions {
            if selected
                .insert((member.kind as u8, member.key.clone()), member)
                .is_some()
            {
                return Err(GraphRows::invalid("graph duplicate addition"));
            }
        }
        let mut previous = BTreeMap::new();
        let mut statement = self.writer.prepare("SELECT member_kind,member_key,value_ref FROM graph_producer_members WHERE scope_id=? AND unit_ref=0 AND valid_to IS NULL")
            .context(AnalysisDatabaseSnafu {operation:"prepare prior Graph members"})?;
        let mut rows = statement
            .query(params![self.scope])
            .context(AnalysisDatabaseSnafu {
                operation: "read prior Graph members",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance prior Graph members",
        })? {
            let kind = GraphRows::column::<u8>(row, 0)?;
            if !matches!(kind, 2..=4 | 6)
                || previous
                    .insert(
                        (kind, GraphRows::column::<Vec<u8>>(row, 1)?),
                        GraphRows::column::<u64>(row, 2)?,
                    )
                    .is_some()
            {
                return Err(GraphRows::invalid("graph active member identity"));
            }
        }
        drop(rows);
        drop(statement);
        let needed = previous
            .iter()
            .map(|((kind, _), value)| (*kind, *value))
            .chain(
                selected
                    .values()
                    .map(|value| (value.kind as u8, value.value)),
            )
            .filter(|(kind, _)| (2..=4).contains(kind))
            .collect();
        let identities = self.identities(&needed)?;
        for ((kind, key), value) in previous
            .iter()
            .map(|(key, value)| (key, *value))
            .chain(selected.iter().map(|(key, value)| (key, value.value)))
        {
            if (2..=4).contains(kind)
                && identities.get(&(*kind, value)).map(Vec::as_slice) != Some(key.as_slice())
            {
                return Err(GraphRows::invalid("graph member identity collision"));
            }
        }
        let staged = (previous.len() + selected.len()) as u64;
        let mut members = Vec::with_capacity(selected.len());
        for (key, member) in selected {
            if let Some(old) = previous.get(&key).filter(|_| (2..=4).contains(&key.0)) {
                if identities.get(&(key.0, *old)) != identities.get(&(key.0, member.value)) {
                    return Err(GraphRows::invalid("graph member identity collision"));
                }
            }
            let record = member
                .anchor
                .as_ref()
                .map(|anchor| {
                    self.records
                        .get(&anchor.record)
                        .copied()
                        .ok_or_else(|| GraphRows::invalid("graph stage anchor record"))
                })
                .transpose()?;
            let fact = member
                .anchor
                .as_ref()
                .and_then(|anchor| anchor.fact.as_ref())
                .map(GraphRows::encode_value)
                .transpose()?;
            members.push(araphor_graph::Member {
                kind: member.kind as u8,
                key: member.key,
                value: member.value,
                record,
                fact,
                reason: member.reason,
                ordinal: member.ordinal,
            });
        }
        let mut work = araphor_graph::Contributions::apply(
            self.writer,
            self.scope,
            self.revision,
            &[araphor_graph::Replacement {
                unit: None,
                members,
            }],
            false,
        )?;
        work.0 = work.0.saturating_add(staged);
        Ok(work)
    }

    pub(super) fn identities(
        &self,
        needed: &BTreeSet<(u8, u64)>,
    ) -> Result<BTreeMap<(u8, u64), Vec<u8>>> {
        let mut identities = BTreeMap::new();
        if needed.is_empty() {
            return Ok(identities);
        }
        self.writer.execute_batch("CREATE TEMP TABLE graph_stage_values(member_kind UTINYINT,value_ref UBIGINT,PRIMARY KEY(member_kind,value_ref))").context(AnalysisDatabaseSnafu {operation:"create Graph native identity candidates"})?;
        {
            let mut appender =
                self.writer
                    .appender("graph_stage_values")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph native identity candidates",
                    })?;
            for (kind, value) in needed {
                appender
                    .append_row(params![kind, value])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph native identity candidate",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph native identity candidates",
            })?;
        }
        let source: Option<crate::EvidenceIntakeIdentityV1> = if needed
            .iter()
            .any(|(kind, _)| *kind == 3)
        {
            let bytes:Vec<u8>=self.writer.query_row("SELECT identity FROM graph_producer_scopes s JOIN graph_sources src USING(source_ref) WHERE s.scope_id=?",params![self.scope],|row|row.get(0)).context(AnalysisDatabaseSnafu {operation:"read Graph staged source"})?;
            Some(GraphRows::decode_value(&bytes)?)
        } else {
            None
        };
        let mut subjects = BTreeMap::new();
        let mut statement=self.writer.prepare("WITH needed AS (SELECT value_ref FROM graph_stage_values WHERE member_kind=2 UNION SELECT e.from_ref FROM graph_stage_values v JOIN graph_edge_values e ON e.edge_id=v.value_ref WHERE v.member_kind=3 UNION SELECT e.to_ref FROM graph_stage_values v JOIN graph_edge_values e ON e.edge_id=v.value_ref WHERE v.member_kind=3) SELECT s.* FROM needed JOIN graph_subject_values s ON s.subject_id=needed.value_ref").context(AnalysisDatabaseSnafu {operation:"prepare Graph staged subjects"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph staged subjects",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph staged subjects",
        })? {
            let id = GraphRows::column::<u64>(row, 0)?;
            let subject = GraphRows::decode_subject(row)?;
            if needed.contains(&(2, id)) {
                identities.insert((2, id), GraphRows::encode_value(&subject)?);
            }
            subjects.insert(id, subject);
        }
        drop(rows);
        drop(statement);
        let mut records = BTreeMap::new();
        if source.is_some() {
            let mut statement=self.writer.prepare("WITH needed AS (SELECT unnest(e.evidence_refs) AS evidence_id FROM graph_stage_values v JOIN graph_edge_values e ON e.edge_id=v.value_ref WHERE v.member_kind=3) SELECT e.evidence_id,e.cpu_id,e.durable_cursor,s.stream_key,s.tenant_id,r.stream_key IS NOT NULL FROM needed JOIN graph_evidence e USING(evidence_id) JOIN graph_sources s USING(source_ref) LEFT JOIN source_receipts r ON r.stream_key=s.stream_key AND r.tenant_id=s.tenant_id").context(AnalysisDatabaseSnafu {operation:"prepare Graph staged evidence"})?;
            let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
                operation: "read Graph staged evidence",
            })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance Graph staged evidence",
            })? {
                let source = source
                    .as_ref()
                    .ok_or_else(|| GraphRows::invalid("graph stage evidence source"))?;
                if GraphRows::column::<Vec<u8>>(row, 3)? != source.key()
                    || GraphRows::column::<Vec<u8>>(row, 4)? != source.tenant_id
                    || !GraphRows::column::<bool>(row, 5)?
                {
                    return Err(GraphRows::invalid("graph stage evidence source"));
                }
                records.insert(
                    GraphRows::column::<u64>(row, 0)?,
                    crate::DiscoveryRecordIdV1 {
                        stream: source.clone(),
                        cpu_id: GraphRows::column(row, 1)?,
                        durable_cursor: GraphRows::column(row, 2)?,
                    },
                );
            }
            drop(rows);
            drop(statement);
        }
        let mut statement=self.writer.prepare("SELECT e.edge_id,e.from_ref,e.to_ref,p.edge_type,p.package_id,p.cause,e.evidence_refs FROM graph_stage_values v JOIN graph_edge_values e ON e.edge_id=v.value_ref LEFT JOIN graph_edge_properties p USING(property_ref) WHERE v.member_kind=3").context(AnalysisDatabaseSnafu {operation:"prepare Graph staged edge identities"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph staged edge identities",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph staged edge identities",
        })? {
            let edge = RelationshipIdentity {
                from: subjects
                    .get(&GraphRows::column::<u64>(row, 1)?)
                    .cloned()
                    .ok_or_else(|| GraphRows::invalid("graph stage edge subject"))?,
                to: subjects
                    .get(&GraphRows::column::<u64>(row, 2)?)
                    .cloned()
                    .ok_or_else(|| GraphRows::invalid("graph stage edge subject"))?,
                edge_type: GraphRows::label_column(row, 3)?,
                package_id: GraphRows::column(row, 4)?,
                cause: GraphRows::label_column(row, 5)?,
                evidence: GraphRows::read_ids(row, 6)?
                    .into_iter()
                    .map(|id| {
                        records
                            .get(&id)
                            .cloned()
                            .ok_or_else(|| GraphRows::invalid("graph stage edge evidence"))
                    })
                    .collect::<Result<_>>()?,
            };
            identities.insert(
                (3, GraphRows::column::<u64>(row, 0)?),
                GraphRows::encode_value(&edge)?,
            );
        }
        drop(rows);
        drop(statement);
        let mut statement=self.writer.prepare("SELECT f.value_id,f.finding_id FROM graph_stage_values v JOIN graph_finding_values f ON f.value_id=v.value_ref WHERE v.member_kind=4").context(AnalysisDatabaseSnafu {operation:"prepare Graph staged finding identities"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph staged finding identities",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph staged finding identities",
        })? {
            identities.insert(
                (4, GraphRows::column::<u64>(row, 0)?),
                GraphRows::encode_value(&GraphRows::column::<String>(row, 1)?)?,
            );
        }
        drop(rows);
        drop(statement);
        self.writer
            .execute_batch("DROP TABLE graph_stage_values")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph native identity candidates",
            })?;
        if identities.len() != needed.len() {
            return Err(GraphRows::invalid("graph staged native identity count"));
        }
        Ok(identities)
    }
}
