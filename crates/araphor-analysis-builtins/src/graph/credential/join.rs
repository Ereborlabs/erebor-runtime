use super::*;

impl Computation {
    pub(in crate::graph) fn authorities(
        &self,
        record: &Observation,
        credential: &FactValue,
        bytes: bool,
        evidence: &mut Vec<u32>,
    ) -> sdk::Result<Vec<(usize, bool)>> {
        let FactValue::Credential {
            object_id,
            completion,
            principal_id,
            ..
        } = credential
        else {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "graph Credential input",
            ));
        };
        let mut qualified: Vec<(usize, bool)> = Vec::new();
        let mut positions = BTreeMap::new();
        for (row, channel) in self.records.iter().enumerate() {
            if !channel.same_lifetime(record)
                || !self.bounded(record, channel)
                || !channel.network()
                || !((channel.effect.task_cookie == record.effect.task_cookie
                    && record.effect.task_cookie > 0)
                    || (record.process_instance_id.is_some()
                        && channel.process_instance_id == record.process_instance_id))
            {
                continue;
            }
            for (index, fact) in self.facts.iter().enumerate() {
                let FactValue::AuthorityUse {
                    process_instance_id,
                    task_cookie,
                    credential_object_id,
                    socket_object_id,
                    credential_lease_id,
                    principal_id: authority_principal,
                    outside_reviewed_behavior,
                    proof_quality,
                    ..
                } = &fact.value
                else {
                    continue;
                };
                let local = (*task_cookie == Some(record.effect.task_cookie)
                    && record.effect.task_cookie > 0)
                    || (record.process_instance_id.is_some()
                        && *process_instance_id == record.process_instance_id);
                let socket =
                    socket_object_id.is_some_and(|socket| channel.effect.exact_object_id == socket);
                if !*outside_reviewed_behavior
                    || !self.bounded(record, self.record(fact.record)?)
                    || (!(local && socket && *credential_object_id == Some(*object_id))
                        && !Self::contextual(record, principal_id, &fact.value))
                {
                    continue;
                }
                let direct = bytes
                    && local
                    && socket
                    && *credential_object_id == Some(*object_id)
                    && completion.as_ref().is_some_and(|completion| {
                        completion.credential_lease_id == *credential_lease_id
                            && completion.credential_lease_id.is_some()
                            && completion.principal_id.as_ref() == Some(authority_principal)
                    })
                    && channel.admitted()
                    && channel.complete()
                    && proof_quality.authority_direct()
                    && self.carried(row as u32, channel, &fact.value);
                evidence.push(row as u32);
                let position = *positions.entry(self.fact_ids[index]).or_insert_with(|| {
                    let position = qualified.len();
                    qualified.push((index, false));
                    position
                });
                qualified[position].1 |= direct;
            }
        }
        for (index, fact) in self.facts.iter().enumerate() {
            let FactValue::AuthorityUse {
                outside_reviewed_behavior,
                ..
            } = &fact.value
            else {
                continue;
            };
            if *outside_reviewed_behavior
                && Self::contextual(record, principal_id, &fact.value)
                && self.bounded(record, self.record(fact.record)?)
                && !positions.contains_key(&self.fact_ids[index])
            {
                positions.insert(self.fact_ids[index], qualified.len());
                qualified.push((index, false));
            }
        }
        qualified.sort_by_key(|(index, _)| self.facts[*index].record);
        Ok(qualified)
    }

    pub(in crate::graph) fn bounded(&self, record: &Observation, later: &Observation) -> bool {
        later.observed_boottime_ns >= record.observed_boottime_ns
            && later.observed_boottime_ns - record.observed_boottime_ns <= self.manifest.window_ns
    }

    fn contextual(record: &Observation, principal: &Option<String>, authority: &FactValue) -> bool {
        let FactValue::AuthorityUse {
            workload_binding,
            principal_id,
            proof_quality,
            ..
        } = authority
        else {
            return false;
        };
        record.effect.execution_set_id.iter().any(|byte| *byte != 0)
            && workload_binding
                .as_ref()
                .is_some_and(|subject| subject.identity == record.effect.execution_set_id)
            && principal.as_ref() == Some(principal_id)
            && proof_quality.authority_contextual()
    }

    fn carried(&self, row: u32, record: &Observation, authority: &FactValue) -> bool {
        let FactValue::AuthorityUse {
            authority_id,
            request_id,
            credential_lease_id,
            principal_id,
            operation_id,
            ..
        } = authority
        else {
            return false;
        };
        self.facts(row).any(|(_, fact)| {
            let FactValue::Channel {
                task_cookie,
                process_instance_id,
                socket_object_id,
                authority_id: channel_authority,
                carried_request_id,
                credential_lease_id: channel_lease,
                principal_id: channel_principal,
                operation_id: channel_operation,
                proof_quality,
            } = &fact.value
            else {
                return false;
            };
            *task_cookie == record.effect.task_cookie
                && Some(*process_instance_id) == record.process_instance_id
                && record.effect.exact_object_id == *socket_object_id
                && channel_authority == authority_id
                && Some(carried_request_id) == request_id.as_ref()
                && Some(channel_lease) == credential_lease_id.as_ref()
                && channel_principal == principal_id
                && channel_operation == operation_id
                && proof_quality.succeeded()
        })
    }
}
