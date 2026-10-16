use super::*;

impl Computation {
    pub(in crate::graph) fn authorities(
        &self,
        record: &Observation,
        credential: &FactValue,
        bytes: bool,
        evidence: &mut Vec<u64>,
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
            if channel.lifetime != record.lifetime
                || !self.bounded(record, channel)
                || !channel.network
                || !((channel.task == record.task && record.task > 0)
                    || (record.process.is_some() && channel.process == record.process))
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
                let local = (*task_cookie == Some(record.task) && record.task > 0)
                    || (record.process.is_some() && *process_instance_id == record.process);
                let socket = socket_object_id.is_some_and(|socket| channel.object == socket);
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
                    && channel.admitted
                    && channel.complete
                    && proof_quality.authority_direct()
                    && self.carried(row as u64, channel, &fact.value);
                evidence.push(row as u64);
                let position = *positions.entry(fact.identity).or_insert_with(|| {
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
                && !positions.contains_key(&fact.identity)
            {
                positions.insert(fact.identity, qualified.len());
                qualified.push((index, false));
            }
        }
        qualified.sort_by_key(|(index, _)| self.facts[*index].record);
        Ok(qualified)
    }

    fn bounded(&self, record: &Observation, later: &Observation) -> bool {
        later.boottime >= record.boottime
            && later.boottime - record.boottime <= self.manifest.window_ns
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
        record.execution.iter().any(|byte| *byte != 0)
            && workload_binding
                .as_ref()
                .is_some_and(|subject| subject.identity == record.execution)
            && principal.as_ref() == Some(principal_id)
            && proof_quality.authority_contextual()
    }

    fn carried(&self, row: u64, record: &Observation, authority: &FactValue) -> bool {
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
            *task_cookie == record.task
                && Some(*process_instance_id) == record.process
                && record.object == *socket_object_id
                && channel_authority == authority_id
                && Some(carried_request_id) == request_id.as_ref()
                && Some(channel_lease) == credential_lease_id.as_ref()
                && channel_principal == principal_id
                && channel_operation == operation_id
                && proof_quality.succeeded()
        })
    }
}
