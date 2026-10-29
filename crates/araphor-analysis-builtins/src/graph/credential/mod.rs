use std::collections::{BTreeMap, BTreeSet};

use super::*;

mod join;

#[derive(Default)]
pub(in crate::graph) struct CredentialIndex {
    read_facts_by_row: BTreeMap<u32, Vec<usize>>,
    read_by_task: BTreeMap<u64, Vec<usize>>,
    read_by_process: BTreeMap<[u8; 16], Vec<usize>>,
    read_by_principal: BTreeMap<String, Vec<usize>>,
    authority_by_object: BTreeMap<[u8; 16], Vec<usize>>,
    authority_by_principal: BTreeMap<String, Vec<usize>>,
    channel_by_socket: BTreeMap<[u8; 16], Vec<u32>>,
    conflicted_reads: BTreeSet<u32>,
}

pub(in crate::graph) struct AuthorityMatch {
    pub(in crate::graph) fact_index: usize,
    pub(in crate::graph) direct: bool,
    pub(in crate::graph) channels: Vec<u32>,
}

struct CredentialOutcome {
    read_row: u32,
    matched: Vec<AuthorityMatch>,
    evidence: Vec<u32>,
    limits: Vec<String>,
}

impl CredentialIndex {
    pub(in crate::graph) fn new(computation: &Computation) -> sdk::Result<Self> {
        let mut index = Self::default();
        for (fact_index, fact) in computation.facts.iter().enumerate() {
            let record = computation.record(fact.record)?;
            match &fact.value {
                FactValue::Credential {
                    principal_id,
                    object_id,
                    ..
                } if record.effect.exact_object_id == *object_id => {
                    index
                        .read_facts_by_row
                        .entry(fact.record)
                        .or_default()
                        .push(fact_index);
                    if record.effect.task_cookie > 0 {
                        index
                            .read_by_task
                            .entry(record.effect.task_cookie)
                            .or_default()
                            .push(fact_index);
                    }
                    if let Some(process) = record.process_instance_id {
                        index
                            .read_by_process
                            .entry(process)
                            .or_default()
                            .push(fact_index);
                    }
                    if let Some(principal) = principal_id {
                        index
                            .read_by_principal
                            .entry(principal.clone())
                            .or_default()
                            .push(fact_index);
                    }
                }
                FactValue::AuthorityUse {
                    credential_object_id,
                    principal_id,
                    ..
                } => {
                    if let Some(object) = credential_object_id {
                        index
                            .authority_by_object
                            .entry(*object)
                            .or_default()
                            .push(fact_index);
                    }
                    index
                        .authority_by_principal
                        .entry(principal_id.clone())
                        .or_default()
                        .push(fact_index);
                }
                FactValue::Channel {
                    socket_object_id, ..
                } if record.network() => {
                    index
                        .channel_by_socket
                        .entry(*socket_object_id)
                        .or_default()
                        .push(fact.record);
                }
                _ => {}
            }
        }
        for rows in index.channel_by_socket.values_mut() {
            rows.sort_unstable();
            rows.dedup();
        }
        for (&row, facts) in &index.read_facts_by_row {
            let credentials = facts
                .iter()
                .map(|&fact_index| computation.facts[fact_index].clone())
                .collect::<Vec<_>>();
            if Computation::credential_conflict(computation.policy_conflict(row)?, &credentials) {
                index.conflicted_reads.insert(row);
            }
        }
        Ok(index)
    }

    fn candidates(&self, computation: &Computation, row: u32) -> BTreeSet<usize> {
        let mut candidates = BTreeSet::new();
        candidates.extend(
            self.read_facts_by_row
                .get(&row)
                .into_iter()
                .flatten()
                .copied(),
        );
        let event = &computation.records[row as usize];
        if event.network()
            && computation
                .facts(row)
                .any(|(_, fact)| matches!(fact.value, FactValue::Channel { .. }))
        {
            if event.effect.task_cookie > 0 {
                candidates.extend(
                    self.read_by_task
                        .get(&event.effect.task_cookie)
                        .into_iter()
                        .flatten()
                        .copied(),
                );
            }
            if let Some(process) = event.process_instance_id {
                candidates.extend(
                    self.read_by_process
                        .get(&process)
                        .into_iter()
                        .flatten()
                        .copied(),
                );
            }
        }
        for (_, fact) in computation.facts(row) {
            let FactValue::AuthorityUse {
                task_cookie,
                process_instance_id,
                principal_id,
                ..
            } = &fact.value
            else {
                continue;
            };
            if let Some(task) = task_cookie.filter(|task| *task > 0) {
                candidates.extend(self.read_by_task.get(&task).into_iter().flatten().copied());
            }
            if let Some(process) = process_instance_id {
                candidates.extend(
                    self.read_by_process
                        .get(process)
                        .into_iter()
                        .flatten()
                        .copied(),
                );
            }
            candidates.extend(
                self.read_by_principal
                    .get(principal_id)
                    .into_iter()
                    .flatten()
                    .copied(),
            );
        }
        candidates
    }
}

impl Computation {
    pub(super) fn credentials(&mut self, affected: &[bool]) -> sdk::Result<()> {
        let index = CredentialIndex::new(self)?;
        for (row, affected) in affected.iter().copied().enumerate() {
            if affected {
                self.progress[row].state = self.credential_event(row as u32, &index)?;
            }
        }
        self.state = self
            .progress
            .iter()
            .rev()
            .find_map(|progress| progress.state.clone())
            .unwrap_or_else(|| "WAITING".into());
        Ok(())
    }

    fn credential_event(
        &mut self,
        row: u32,
        index: &CredentialIndex,
    ) -> sdk::Result<Option<String>> {
        #[cfg(test)]
        {
            self.work += 1;
        }
        if index.conflicted_reads.contains(&row) {
            self.subject(row, None)?;
            self.finding(
                row,
                "CONTRADICTION",
                false,
                vec![row],
                vec!["CREDENTIAL_FACTS_CONTRADICTED".into()],
            )?;
            return Ok(Some("CONTRADICTED".into()));
        }
        let event = self.record(row)?.clone();
        let mut outcomes = Vec::new();
        for fact_index in index.candidates(self, row) {
            let credential = self.facts[fact_index].clone();
            let read_row = credential.record;
            if index.conflicted_reads.contains(&read_row) {
                continue;
            }
            let read = self.record(read_row)?.clone();
            let FactValue::Credential {
                object_id,
                expected_access,
                ..
            } = &credential.value
            else {
                continue;
            };
            if *expected_access
                || read.effect.exact_object_id != *object_id
                || !matches!(
                    read.operation(),
                    Operation::OpenRead | Operation::Read | Operation::MmapRead
                )
                || !read.same_lifetime(&event)
                || read.position > event.position
                || !self.bounded(&read, &event)
                || (event.network() && !read.same_task(&event))
            {
                continue;
            }
            if let Some(outcome) =
                self.credential(read_row, &read, &credential, row, event.position, index)?
            {
                outcomes.push(outcome);
            }
        }
        if outcomes.is_empty() {
            return Ok(None);
        }
        let matched = outcomes
            .iter()
            .flat_map(|outcome| {
                outcome
                    .matched
                    .iter()
                    .map(|value| (value.fact_index, value.direct))
            })
            .collect::<Vec<_>>();
        let contradicted = self.authority_conflict(&matched);
        let direct = !matched.is_empty()
            && outcomes.iter().all(|outcome| {
                !outcome.matched.is_empty() && outcome.matched.iter().all(|value| value.direct)
            });
        let (reason, state) = if contradicted {
            ("CONTRADICTION", "CONTRADICTED")
        } else if direct {
            ("CREDENTIAL_PIVOT", "DIRECT_PIVOT")
        } else if matched.is_empty() {
            ("MISSING_AUTHORITY_PROOF", "COVERAGE_INSUFFICIENT")
        } else {
            ("CONTEXTUAL_CREDENTIAL_PIVOT", "CONTEXTUAL_PIVOT")
        };
        let mut evidence = vec![row];
        let mut limits = Vec::new();
        for outcome in &outcomes {
            evidence.extend(&outcome.evidence);
            limits.extend(outcome.limits.iter().cloned());
            for authority in &outcome.matched {
                let fact_record = self.facts[authority.fact_index].record;
                let mut edge_evidence = vec![outcome.read_row, fact_record];
                edge_evidence.extend(&authority.channels);
                self.edge(
                    outcome.read_row,
                    Some(authority.fact_index as u32),
                    EdgeKind::Authority,
                    if contradicted {
                        Cause::Contradicted
                    } else if authority.direct {
                        Cause::Direct
                    } else {
                        Cause::Contextual
                    },
                    edge_evidence,
                )?;
            }
        }
        if !direct {
            limits.extend(
                [
                    "CREDENTIAL_SPECIFIC_RESPONSE_UNPROVEN",
                    "CARRIED_REQUEST_OR_COMPLETION_MISSING",
                    "EXACT_TASK_SOCKET_REQUEST_PROOF_INSUFFICIENT",
                ]
                .map(str::to_owned),
            );
        }
        Self::canonical(&mut evidence);
        let confirmed = direct
            && !contradicted
            && evidence
                .iter()
                .all(|&evidence_row| self.records[evidence_row as usize].complete());
        self.finding(row, reason, confirmed, evidence, limits)?;
        Ok(Some(state.into()))
    }

    fn credential_conflict(policy_conflict: bool, credentials: &[Fact]) -> bool {
        let classifications: BTreeSet<_> = credentials
            .iter()
            .filter_map(|fact| match &fact.value {
                FactValue::Credential {
                    expected_access, ..
                } => Some(*expected_access),
                _ => None,
            })
            .collect();
        let mut completions = BTreeMap::new();
        let mut conflict =
            classifications.len() > 1 || (!credentials.is_empty() && policy_conflict);
        for completion in credentials.iter().filter_map(|fact| match &fact.value {
            FactValue::Credential { completion, .. } => completion.as_ref(),
            _ => None,
        }) {
            if completions
                .insert((&completion.owner, &completion.completion_id), completion)
                .is_some_and(|previous| previous != completion)
            {
                conflict = true;
            }
        }
        conflict
    }

    fn credential(
        &mut self,
        read_row: u32,
        read: &Observation,
        credential: &Fact,
        trigger_row: u32,
        horizon: Position,
        index: &CredentialIndex,
    ) -> sdk::Result<Option<CredentialOutcome>> {
        let FactValue::Credential {
            object_id,
            completion,
            proof_quality,
            ..
        } = &credential.value
        else {
            return Err(Self::invalid("graph Credential input"));
        };
        let reviewed = self.reviewed(credential)?;
        let bytes = read.admitted()
            && reviewed
            && proof_quality.succeeded()
            && completion.as_ref().is_some_and(|completion| {
                completion.byte_count > 0
                    && completion.result > 0
                    && completion.task_cookie == read.effect.task_cookie
                    && Some(completion.process_instance_id) == read.process_instance_id
                    && completion.object_id == *object_id
                    && matches!(
                        completion.path,
                        ReadPath::Read | ReadPath::InheritedFd | ReadPath::IoUring
                    )
                    && read.operation() == Operation::Read
            });
        let trigger_channel = (self.record(trigger_row)?.network()
            && self
                .facts(trigger_row)
                .any(|(_, fact)| matches!(fact.value, FactValue::Channel { .. })))
        .then_some(trigger_row);
        let matched = self.authorities(
            read,
            &credential.value,
            bytes,
            horizon,
            trigger_channel,
            index,
        )?;
        if trigger_row != read_row
            && !matched.iter().any(|authority| {
                self.facts[authority.fact_index].record == trigger_row
                    || authority.channels.contains(&trigger_row)
            })
        {
            return Ok(None);
        }
        self.subject(read_row, None)?;
        let mut evidence = vec![read_row];
        for authority in &matched {
            evidence.push(self.facts[authority.fact_index].record);
            evidence.extend(&authority.channels);
        }
        Self::canonical(&mut evidence);
        let mut limits = vec!["TLS_PAYLOAD_UNOBSERVABLE".into()];
        if !bytes {
            limits.push("CREDENTIAL_BYTES_UNPROVEN".into());
        }
        if !reviewed {
            limits.push("REVIEWED_CREDENTIAL_PROVENANCE_MISSING".into());
        }
        if matched.is_empty() {
            limits.push("AUTHORITATIVE_REMOTE_RESULT_MISSING".into());
        }
        Ok(Some(CredentialOutcome {
            read_row,
            matched,
            evidence,
            limits,
        }))
    }

    fn authority_conflict(&self, matched: &[(usize, bool)]) -> bool {
        let mut results = BTreeMap::<_, BTreeSet<OperationResultAuthorityV1>>::new();
        for (index, _) in matched {
            let FactValue::AuthorityUse {
                authority_id,
                request_id,
                credential_lease_id,
                principal_id,
                operation_id,
                proof_quality,
                ..
            } = &self.facts[*index].value
            else {
                continue;
            };
            if request_id.is_some() {
                results
                    .entry((
                        authority_id,
                        request_id,
                        credential_lease_id,
                        principal_id,
                        operation_id,
                    ))
                    .or_default()
                    .insert(proof_quality.operation_result_authority);
            }
        }
        results.values().any(|values| {
            values.contains(&OperationResultAuthorityV1::AuthoritativeSucceeded)
                && values.contains(&OperationResultAuthorityV1::AuthoritativeDenied)
        })
    }
}
