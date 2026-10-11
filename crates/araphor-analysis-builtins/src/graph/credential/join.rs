use super::*;

impl Computation {
    pub(super) fn authorities(
        &self,
        record: &Observation,
        credential: &Credential,
        bytes: bool,
        evidence: &mut Vec<u64>,
    ) -> sdk::Result<Vec<(usize, bool)>> {
        let mut matched = Vec::new();
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
                let FactValue::Authority(authority) = &fact.value else {
                    continue;
                };
                let local = (authority.task == Some(record.task) && record.task > 0)
                    || (record.process.is_some() && authority.process == record.process);
                let socket = authority
                    .socket
                    .is_some_and(|socket| channel.object == socket);
                if !authority.outside
                    || !self.bounded(record, self.record(fact.record)?)
                    || (!(local && socket && authority.credential == Some(credential.object))
                        && !Self::contextual(record, credential, authority))
                {
                    continue;
                }
                let carried = self.carried(row as u64, channel, authority);
                let direct = bytes
                    && local
                    && socket
                    && authority.credential == Some(credential.object)
                    && credential.completion.as_ref().is_some_and(|completion| {
                        completion.lease == authority.lease
                            && completion.lease.is_some()
                            && completion.principal.as_ref() == Some(&authority.principal)
                    })
                    && carried
                    && channel.admitted
                    && channel.complete
                    && authority.direct;
                evidence.push(row as u64);
                matched.push((index, direct));
            }
        }
        for (index, fact) in self.facts.iter().enumerate() {
            let FactValue::Authority(authority) = &fact.value else {
                continue;
            };
            if authority.outside
                && Self::contextual(record, credential, authority)
                && self.bounded(record, self.record(fact.record)?)
                && !matched
                    .iter()
                    .any(|(prior, _)| self.facts[*prior].identity == fact.identity)
            {
                matched.push((index, false));
            }
        }
        let mut qualified: Vec<(usize, bool)> = Vec::new();
        for (index, direct) in matched {
            if let Some((_, existing)) = qualified
                .iter_mut()
                .find(|(prior, _)| self.facts[*prior].identity == self.facts[index].identity)
            {
                *existing |= direct;
            } else {
                qualified.push((index, direct));
            }
        }
        qualified.sort_by_key(|(index, _)| self.facts[*index].record);
        Ok(qualified)
    }

    fn bounded(&self, record: &Observation, later: &Observation) -> bool {
        later.boottime >= record.boottime
            && later.boottime - record.boottime <= self.manifest.window_ns
    }

    fn contextual(record: &Observation, credential: &Credential, authority: &Authority) -> bool {
        record.execution.iter().any(|byte| *byte != 0)
            && authority.workload.as_ref() == Some(&record.execution)
            && credential.principal.as_ref() == Some(&authority.principal)
            && authority.contextual
    }

    fn carried(&self, row: u64, record: &Observation, authority: &Authority) -> bool {
        self.facts(row).any(|(_, fact)| {
            let FactValue::Channel(channel) = &fact.value else {
                return false;
            };
            channel.task == record.task
                && Some(channel.process) == record.process
                && record.object == channel.socket
                && channel.authority == authority.id
                && Some(&channel.request) == authority.request.as_ref()
                && Some(&channel.lease) == authority.lease.as_ref()
                && channel.principal == authority.principal
                && channel.operation == authority.operation
                && channel.successful
        })
    }
}
