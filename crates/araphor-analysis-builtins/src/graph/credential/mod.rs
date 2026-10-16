use std::collections::{BTreeMap, BTreeSet};

use super::*;

mod join;

impl Computation {
    pub(super) fn credentials(&mut self) -> sdk::Result<()> {
        for row in 0..self.records.len() {
            let record = self.record(row as u64)?.clone();
            let credentials: Vec<_> = self
                .facts(row as u64)
                .filter_map(|(_, fact)| match &fact.value {
                    FactValue::Credential { object_id, .. } if record.object == *object_id => {
                        Some(fact.clone())
                    }
                    _ => None,
                })
                .collect();
            if Self::credential_conflict(&record, &credentials) {
                self.state.value = "CONTRADICTED".into();
                self.subjects.push(Subject {
                    record: row as u64,
                    context: None,
                });
                self.finding(
                    row as u64,
                    "CONTRADICTION",
                    false,
                    vec![row as u64],
                    vec!["CREDENTIAL_FACTS_CONTRADICTED".into()],
                );
                continue;
            }
            for credential in credentials {
                if matches!(
                    &credential.value,
                    FactValue::Credential {
                        expected_access: true,
                        ..
                    }
                ) || !matches!(
                    record.operation,
                    Operation::OpenRead | Operation::Read | Operation::MmapRead
                ) {
                    continue;
                }
                self.credential(row as u64, &record, &credential)?;
            }
        }
        Ok(())
    }

    fn credential_conflict(record: &Observation, credentials: &[Fact]) -> bool {
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
            classifications.len() > 1 || (!credentials.is_empty() && record.policy_conflict);
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

    fn credential(&mut self, row: u64, record: &Observation, credential: &Fact) -> sdk::Result<()> {
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
        self.state.value = "CREDENTIAL_OBSERVED".into();
        self.subjects.push(Subject {
            record: row,
            context: None,
        });
        let bytes = record.admitted
            && credential.reviewed
            && proof_quality.succeeded()
            && completion.as_ref().is_some_and(|completion| {
                completion.byte_count > 0
                    && completion.result > 0
                    && completion.task_cookie == record.task
                    && Some(completion.process_instance_id) == record.process
                    && completion.object_id == *object_id
                    && matches!(
                        completion.path,
                        ReadPath::Read | ReadPath::InheritedFd | ReadPath::IoUring
                    )
                    && record.operation == Operation::Read
            });
        let mut evidence = vec![row];
        let mut limits = vec!["TLS_PAYLOAD_UNOBSERVABLE".into()];
        if !bytes {
            limits.push("CREDENTIAL_BYTES_UNPROVEN".into());
        }
        if !credential.reviewed {
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
        self.state.value = if contradicted {
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
            if self.records.len() as u64 == self.manifest.window_records {
                limits.push("JOIN_WINDOW_RECORD_LIMIT".into());
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
        let mut edge_evidence = evidence.clone();
        Self::canonical(&mut edge_evidence);
        for (index, exact) in matched {
            let fact_record = self.facts[index].record;
            evidence.push(fact_record);
            edge_evidence.push(fact_record);
            self.edge(
                row,
                Some(index as u64),
                EdgeKind::Authority,
                if contradicted {
                    Cause::Contradicted
                } else if exact {
                    Cause::Direct
                } else {
                    Cause::Contextual
                },
                edge_evidence.clone(),
            );
        }
        self.finding(
            row,
            reason,
            direct && !contradicted && record.complete,
            evidence,
            limits,
        );
        Ok(())
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
