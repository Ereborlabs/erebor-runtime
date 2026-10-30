use super::calls::CallBasis;
use super::history::Member;
use super::*;

struct PriorMember {
    value: u64,
    record: Option<u64>,
    fact: Option<Vec<u8>>,
    reason: Option<String>,
    ordinal: u32,
}

pub(super) struct GraphStage<'a> {
    pub writer: &'a Connection,
    pub scope: u64,
    pub revision: u64,
    pub records: &'a BTreeMap<crate::DiscoveryRecordIdV1, u64>,
    pub basis: Option<&'a CallBasis>,
    pub sparse: bool,
    pub full: bool,
}

impl GraphStage<'_> {
    pub fn apply(
        &self,
        additions: Vec<Member>,
        removals: Vec<(MemberKind, Vec<u8>)>,
        progress_root: Option<&[u8]>,
    ) -> Result<()> {
        let mut selected = BTreeMap::new();
        for member in additions {
            if selected
                .insert((member.kind as u8, member.key.clone()), member)
                .is_some()
            {
                return Err(GraphRows::invalid("graph duplicate addition"));
            }
        }
        let mut deleted = BTreeMap::new();
        for (kind, identity) in removals {
            let key = GraphRows::hash(&identity);
            if deleted.insert((kind as u8, key), identity).is_some() {
                return Err(GraphRows::invalid("graph duplicate removal"));
            }
        }
        let touched = selected
            .keys()
            .chain(deleted.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        self.writer.execute_batch("CREATE TEMP TABLE graph_stage_keys(member_kind UTINYINT,member_key BLOB,PRIMARY KEY(member_kind,member_key)); CREATE TEMP TABLE graph_stage_close(member_kind UTINYINT,member_key BLOB,PRIMARY KEY(member_kind,member_key))").context(AnalysisDatabaseSnafu {operation:"create Graph member stage"})?;
        {
            let mut appender =
                self.writer
                    .appender("graph_stage_keys")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph member keys",
                    })?;
            for (kind, key) in &touched {
                appender
                    .append_row(params![kind, key])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph member key",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph member keys",
            })?;
        }
        let mut previous = BTreeMap::new();
        let query = if self.full {
            "SELECT m.member_kind,m.member_key,m.value_ref,m.anchor_record_id,m.anchor_fact,m.reason_code,m.ordinal FROM graph_producer_members m WHERE m.scope_id=? AND m.valid_to IS NULL"
        } else {
            "SELECT m.member_kind,m.member_key,m.value_ref,m.anchor_record_id,m.anchor_fact,m.reason_code,m.ordinal FROM graph_stage_keys wanted JOIN graph_producer_members m USING(member_kind,member_key) WHERE m.scope_id=? AND m.valid_to IS NULL"
        };
        let mut statement = self.writer.prepare(query).context(AnalysisDatabaseSnafu {
            operation: "prepare prior Graph members",
        })?;
        let mut rows = statement
            .query(params![self.scope])
            .context(AnalysisDatabaseSnafu {
                operation: "read prior Graph members",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance prior Graph members",
        })? {
            let kind = GraphRows::column::<u8>(row, 0)?;
            let key = GraphRows::column::<Vec<u8>>(row, 1)?;
            if !(2..=6).contains(&kind)
                || previous
                    .insert(
                        (kind, key),
                        PriorMember {
                            value: GraphRows::column(row, 2)?,
                            record: GraphRows::column(row, 3)?,
                            fact: GraphRows::column(row, 4)?,
                            reason: GraphRows::column(row, 5)?,
                            ordinal: GraphRows::column(row, 6)?,
                        },
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
            .map(|((kind, _), value)| (*kind, value.value))
            .chain(
                selected
                    .values()
                    .map(|value| (value.kind as u8, value.value)),
            )
            .filter(|(kind, _)| (2..=5).contains(kind))
            .collect::<BTreeSet<_>>();
        let identities = self.identities(&needed)?;
        for ((kind, key), old) in &previous {
            if (2..=5).contains(kind) {
                let identity = identities
                    .get(&(*kind, old.value))
                    .ok_or_else(|| GraphRows::invalid("graph stage native identity"))?;
                if GraphRows::hash(identity) != *key {
                    return Err(GraphRows::invalid("graph member identity collision"));
                }
            }
        }
        for ((kind, key), new) in &selected {
            if (2..=5).contains(kind) {
                let identity = identities
                    .get(&(*kind, new.value))
                    .ok_or_else(|| GraphRows::invalid("graph stage native identity"))?;
                if GraphRows::hash(identity) != *key {
                    return Err(GraphRows::invalid("graph member identity collision"));
                }
            }
        }
        let mut counts:[i128;4]=self.writer.query_row("SELECT subject_count,edge_count,finding_count,progress_count FROM graph_producer_versions WHERE scope_id=? AND commit_revision<? ORDER BY commit_revision DESC LIMIT 1",params![self.scope,self.revision],|row|Ok([row.get::<_,u64>(0)? as i128,row.get::<_,u64>(1)? as i128,row.get::<_,u64>(2)? as i128,row.get::<_,u64>(3)? as i128])).optional().context(AnalysisDatabaseSnafu {operation:"read Graph stage counts"})?.unwrap_or([0;4]);
        let mut close = BTreeSet::new();
        let mut opened = Vec::new();
        for ((kind, key), identity) in &deleted {
            let old = previous
                .remove(&(*kind, key.clone()))
                .ok_or_else(|| GraphRows::invalid("graph member removal"))?;
            if (2..=5).contains(kind) && identities.get(&(*kind, old.value)) != Some(identity) {
                return Err(GraphRows::invalid("graph member identity collision"));
            }
            close.insert((*kind, key.clone()));
            if (2..=5).contains(kind) {
                counts[(*kind - 2) as usize] -= 1;
            }
        }
        if self.full {
            let removed = previous
                .keys()
                .filter(|key| !selected.contains_key(*key))
                .cloned()
                .collect::<Vec<_>>();
            for key in removed {
                previous.remove(&key);
                close.insert(key.clone());
                if (2..=5).contains(&key.0) {
                    counts[(key.0 - 2) as usize] -= 1;
                }
            }
        }
        let by_id = self
            .records
            .iter()
            .map(|(record, id)| (*id, record))
            .collect::<BTreeMap<_, _>>();
        for (key, member) in selected {
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
            let old = previous.remove(&key);
            if let Some(old) = old {
                if member.kind == MemberKind::Subject && self.sparse {
                    if old.value != member.value {
                        return Err(GraphRows::invalid("graph sparse subject identity"));
                    }
                    let prior = Anchor {
                        record: by_id
                            .get(
                                &old.record
                                    .ok_or_else(|| GraphRows::invalid("graph sparse anchor"))?,
                            )
                            .cloned()
                            .cloned()
                            .ok_or_else(|| GraphRows::invalid("graph sparse anchor"))?,
                        fact: old
                            .fact
                            .as_deref()
                            .map(GraphRows::decode_value)
                            .transpose()?,
                    };
                    let basis = self
                        .basis
                        .ok_or_else(|| GraphRows::invalid("graph sparse basis"))?;
                    if basis.local(&prior)?
                        <= basis.local(
                            member
                                .anchor
                                .as_ref()
                                .ok_or_else(|| GraphRows::invalid("graph sparse anchor"))?,
                        )?
                    {
                        continue;
                    }
                } else if !self.full {
                    return Err(GraphRows::invalid("graph member already exists"));
                }
                if old.value == member.value
                    && old.record == record
                    && old.fact == fact
                    && old.reason == member.reason
                    && old.ordinal == member.ordinal
                {
                    continue;
                }
                if matches!(
                    member.kind,
                    MemberKind::Subject
                        | MemberKind::Edge
                        | MemberKind::Finding
                        | MemberKind::Progress
                ) && identities.get(&(member.kind as u8, old.value))
                    != identities.get(&(member.kind as u8, member.value))
                {
                    return Err(GraphRows::invalid("graph member identity collision"));
                }
                close.insert(key.clone());
            } else if (2..=5).contains(&key.0) {
                counts[(key.0 - 2) as usize] += 1;
            }
            opened.push((member, record, fact));
        }
        {
            let mut appender =
                self.writer
                    .appender("graph_stage_close")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph close stage",
                    })?;
            for (kind, key) in &close {
                appender
                    .append_row(params![kind, key])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append closed Graph key",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush closed Graph keys",
            })?;
        }
        let changed=self.writer.execute("UPDATE graph_producer_members m SET valid_to=? WHERE m.scope_id=? AND m.valid_to IS NULL AND EXISTS(SELECT 1 FROM graph_stage_close c WHERE c.member_kind=m.member_kind AND c.member_key=m.member_key)",params![self.revision,self.scope]).context(AnalysisDatabaseSnafu {operation:"close changed Graph members"})?;
        if changed != close.len() {
            return Err(GraphRows::invalid("graph closed member count"));
        }
        {
            let mut appender =
                self.writer
                    .appender("graph_producer_members")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph member appender",
                    })?;
            for (member, record, fact) in opened {
                appender
                    .append_row(params![
                        self.scope,
                        member.kind as u8,
                        member.key,
                        member.value,
                        record,
                        fact,
                        member.reason,
                        member.ordinal,
                        self.revision,
                        None::<u64>
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph members",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph members",
            })?;
        }
        let counts = counts
            .into_iter()
            .map(|count| u64::try_from(count).map_err(|_| GraphRows::invalid("graph stage count")))
            .collect::<Result<Vec<_>>>()?;
        self.writer.execute("UPDATE graph_producer_versions SET subject_count=?,edge_count=?,finding_count=?,progress_count=?,derived_progress_digest=? WHERE scope_id=? AND commit_revision=?",params![counts[0],counts[1],counts[2],counts[3],progress_root,self.scope,self.revision]).context(AnalysisDatabaseSnafu {operation:"record Graph stage counts"})?;
        self.writer
            .execute_batch("DROP TABLE graph_stage_close; DROP TABLE graph_stage_keys")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph member stage",
            })?;
        Ok(())
    }

    fn identities(&self, needed: &BTreeSet<(u8, u64)>) -> Result<BTreeMap<(u8, u64), Vec<u8>>> {
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
            .any(|(kind, _)| matches!(kind, 3 | 5))
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
            let mut statement=self.writer.prepare("WITH needed AS (SELECT unnest(e.evidence_refs) AS evidence_id FROM graph_stage_values v JOIN graph_edge_values e ON e.edge_id=v.value_ref WHERE v.member_kind=3 UNION SELECT p.evidence_id FROM graph_stage_values v JOIN graph_progress_values p ON p.value_ref=v.value_ref WHERE v.member_kind=5) SELECT e.evidence_id,e.cpu_id,e.durable_cursor,s.stream_key,s.tenant_id,r.stream_key IS NOT NULL FROM needed JOIN graph_evidence e USING(evidence_id) JOIN graph_sources s USING(source_ref) LEFT JOIN source_receipts r ON r.stream_key=s.stream_key AND r.tenant_id=s.tenant_id").context(AnalysisDatabaseSnafu {operation:"prepare Graph staged evidence"})?;
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
        let mut statement=self.writer.prepare("SELECT p.value_ref,p.evidence_id FROM graph_stage_values v JOIN graph_progress_values p ON p.value_ref=v.value_ref WHERE v.member_kind=5").context(AnalysisDatabaseSnafu {operation:"prepare Graph staged progress identities"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph staged progress identities",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph staged progress identities",
        })? {
            let record = records
                .get(&GraphRows::column::<u64>(row, 1)?)
                .ok_or_else(|| GraphRows::invalid("graph stage progress evidence"))?;
            identities.insert(
                (5, GraphRows::column::<u64>(row, 0)?),
                GraphRows::encode_value(record)?,
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
