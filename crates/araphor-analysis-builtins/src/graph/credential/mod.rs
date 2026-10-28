use std::collections::{BTreeMap, BTreeSet};

use super::*;

mod join;

impl Computation {
    pub(super) fn credentials(&mut self, affected: &[bool]) -> sdk::Result<()> {
        for (row, affected) in affected.iter().copied().enumerate() {
            if affected {
                let state = self.credential_record(row as u32)?;
                self.progress[row].state = state;
            }
        }
        self.state.value = self
            .progress
            .iter()
            .rev()
            .find_map(|progress| progress.state.clone())
            .unwrap_or_else(|| "WAITING".into());
        Ok(())
    }

    fn credential_record(&mut self, row: u32) -> sdk::Result<Option<String>> {
        #[cfg(test)]
        {
            self.work += 1;
        }
        let record = self.record(row)?.clone();
        let credentials: Vec<_> = self
            .facts(row)
            .filter_map(|(_, fact)| match &fact.value {
                FactValue::Credential { object_id, .. }
                    if record.effect.exact_object_id == *object_id =>
                {
                    Some(fact.clone())
                }
                _ => None,
            })
            .collect();
        if Self::credential_conflict(self.policy_conflict(row)?, &credentials) {
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
        let mut state = None;
        for credential in credentials {
            if matches!(
                &credential.value,
                FactValue::Credential {
                    expected_access: true,
                    ..
                }
            ) || !matches!(
                record.operation(),
                Operation::OpenRead | Operation::Read | Operation::MmapRead
            ) {
                continue;
            }
            state = Some(self.credential(row, &record, &credential)?);
        }
        Ok(state)
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
        row: u32,
        record: &Observation,
        credential: &Fact,
    ) -> sdk::Result<String> {
        let FactValue::Credential {
            object_id,
            completion,
            proof_quality,
            ..
        } = &credential.value
        else {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "graph Credential input",
            ));
        };
        self.subject(row, None)?;
        let reviewed = self.reviewed(credential)?;
        let bytes = record.admitted()
            && reviewed
            && proof_quality.succeeded()
            && completion.as_ref().is_some_and(|completion| {
                completion.byte_count > 0
                    && completion.result > 0
                    && completion.task_cookie == record.effect.task_cookie
                    && Some(completion.process_instance_id) == record.process_instance_id
                    && completion.object_id == *object_id
                    && matches!(
                        completion.path,
                        ReadPath::Read | ReadPath::InheritedFd | ReadPath::IoUring
                    )
                    && record.operation() == Operation::Read
            });
        let mut evidence = vec![row];
        let mut limits = vec!["TLS_PAYLOAD_UNOBSERVABLE".into()];
        if !bytes {
            limits.push("CREDENTIAL_BYTES_UNPROVEN".into());
        }
        if !reviewed {
            limits.push("REVIEWED_CREDENTIAL_PROVENANCE_MISSING".into());
        }
        let matched = self.authorities(record, &credential.value, bytes, &mut evidence)?;
        let contradicted = self.authority_conflict(&matched);
        let direct = !matched.is_empty() && matched.iter().all(|(_, direct)| *direct);
        let reason = if matched.is_empty() {
            "MISSING_AUTHORITY_PROOF"
        } else if contradicted {
            "CONTRADICTION"
        } else if direct {
            "CREDENTIAL_PIVOT"
        } else {
            "CONTEXTUAL_CREDENTIAL_PIVOT"
        };
        let state = if contradicted {
            "CONTRADICTED"
        } else if direct {
            "DIRECT_PIVOT"
        } else if matched.is_empty() {
            "COVERAGE_INSUFFICIENT"
        } else {
            "CONTEXTUAL_PIVOT"
        }
        .into();
        if matched.is_empty() {
            limits.push("AUTHORITATIVE_REMOTE_RESULT_MISSING".into());
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
        let mut edge_evidence = evidence.clone();
        Self::canonical(&mut edge_evidence);
        for (index, exact) in matched {
            let fact_record = self.facts[index].record;
            evidence.push(fact_record);
            edge_evidence.push(fact_record);
            self.edge(
                row,
                Some(index as u32),
                EdgeKind::Authority,
                if contradicted {
                    Cause::Contradicted
                } else if exact {
                    Cause::Direct
                } else {
                    Cause::Contextual
                },
                edge_evidence.clone(),
            )?;
        }
        self.finding(
            row,
            reason,
            direct && !contradicted && record.complete(),
            evidence,
            limits,
        )?;
        Ok(state)
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
