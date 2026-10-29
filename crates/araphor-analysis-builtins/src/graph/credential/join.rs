use super::*;

impl Computation {
    pub(in crate::graph) fn authorities(
        &self,
        read: &Observation,
        credential: &FactValue,
        bytes: bool,
        horizon: Position,
        trigger_channel: Option<u32>,
        index: &CredentialIndex,
    ) -> sdk::Result<Vec<AuthorityMatch>> {
        let FactValue::Credential {
            object_id,
            completion,
            principal_id,
            ..
        } = credential
        else {
            return Err(Self::invalid("graph Credential input"));
        };
        let mut candidates = BTreeSet::new();
        candidates.extend(
            index
                .authority_by_object
                .get(object_id)
                .into_iter()
                .flatten(),
        );
        if let Some(principal) = principal_id {
            candidates.extend(
                index
                    .authority_by_principal
                    .get(principal)
                    .into_iter()
                    .flatten(),
            );
        }
        let mut matched = BTreeMap::<usize, AuthorityMatch>::new();
        for &fact_index in candidates {
            let fact = &self.facts[fact_index];
            let remote = self.record(fact.record)?;
            if remote.position > horizon || !self.bounded(read, remote) {
                continue;
            }
            let FactValue::AuthorityUse {
                authority_id,
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
            if !outside_reviewed_behavior {
                continue;
            }
            let local = match (read.effect.task_cookie, *task_cookie) {
                (task, Some(authority)) if task > 0 && authority > 0 => task == authority,
                _ => {
                    read.process_instance_id.is_some()
                        && *process_instance_id == read.process_instance_id
                }
            };
            let mut channels = Vec::new();
            if local && *credential_object_id == Some(*object_id) {
                if let Some(socket) = socket_object_id {
                    for &row in index.channel_by_socket.get(socket).into_iter().flatten() {
                        if trigger_channel.is_some_and(|trigger| trigger != row) {
                            continue;
                        }
                        let channel = self.record(row)?;
                        if channel.position <= horizon
                            && channel.same_lifetime(read)
                            && channel.same_task(read)
                            && self.bounded(read, channel)
                            && self.channel_binding(row, read, socket, authority_id)
                        {
                            channels.push(row);
                        }
                    }
                }
            }
            if channels.is_empty() && !Self::contextual(read, principal_id, &fact.value) {
                continue;
            }
            let direct = bytes
                && !channels.is_empty()
                && completion.as_ref().is_some_and(|completion| {
                    completion.credential_lease_id == *credential_lease_id
                        && completion.credential_lease_id.is_some()
                        && completion.principal_id.as_ref() == Some(authority_principal)
                })
                && proof_quality.authority_direct()
                && channels.iter().any(|&row| {
                    let channel = &self.records[row as usize];
                    channel.admitted()
                        && channel.complete()
                        && self.carried(row, channel, &fact.value)
                });
            matched
                .entry(self.fact_ids[fact_index])
                .and_modify(|value| {
                    value.direct |= direct;
                    value.channels.extend(&channels);
                    value.channels.sort_unstable();
                    value.channels.dedup();
                })
                .or_insert(AuthorityMatch {
                    fact_index,
                    direct,
                    channels,
                });
        }
        let mut matched = matched.into_values().collect::<Vec<_>>();
        matched.sort_by_key(|value| (self.facts[value.fact_index].record, value.fact_index));
        Ok(matched)
    }

    pub(in crate::graph) fn bounded(&self, record: &Observation, later: &Observation) -> bool {
        later.observed_boottime_ns >= record.observed_boottime_ns
            && later.observed_boottime_ns - record.observed_boottime_ns <= self.manifest.window_ns
    }

    fn contextual(read: &Observation, principal: &Option<String>, authority: &FactValue) -> bool {
        let FactValue::AuthorityUse {
            workload_binding,
            principal_id,
            proof_quality,
            ..
        } = authority
        else {
            return false;
        };
        read.effect.execution_set_id.iter().any(|byte| *byte != 0)
            && workload_binding
                .as_ref()
                .is_some_and(|subject| subject.identity == read.effect.execution_set_id)
            && principal.as_ref() == Some(principal_id)
            && proof_quality.authority_contextual()
    }

    fn channel_binding(
        &self,
        row: u32,
        read: &Observation,
        socket: &[u8; 16],
        authority_id: &str,
    ) -> bool {
        let channel = &self.records[row as usize];
        self.facts(row).any(|(_, fact)| {
            let FactValue::Channel {
                task_cookie,
                process_instance_id,
                socket_object_id,
                authority_id: channel_authority,
                ..
            } = &fact.value
            else {
                return false;
            };
            channel.effect.exact_object_id == *socket
                && channel.effect.task_cookie == *task_cookie
                && channel.process_instance_id == Some(*process_instance_id)
                && *task_cookie == read.effect.task_cookie
                && Some(*process_instance_id) == read.process_instance_id
                && socket_object_id == socket
                && channel_authority == authority_id
        })
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
