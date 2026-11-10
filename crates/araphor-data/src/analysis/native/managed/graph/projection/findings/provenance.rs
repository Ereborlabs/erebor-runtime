use super::*;

impl FindingRead<'_> {
    fn parents(
        &mut self,
        owner: &FindingOrigin,
        records: &BTreeSet<DiscoveryRecordIdV1>,
        consumer: &Producer,
    ) -> Result<Vec<(FindingOrigin, BTreeSet<DiscoveryRecordIdV1>)>> {
        let mut parents = Vec::new();
        for pin in consumer.origin.rows.iter().filter(|pin| {
            pin.relation == owner.relation && pin.owner == owner.owner && pin.key == owner.key
        }) {
            self.charge(0)?;
            let Some((_, _, reference)) =
                consumer.origin.reads.iter().find(|(writer, revision, _)| {
                    *writer == pin.writer && *revision == pin.revision
                })
            else {
                continue;
            };
            let producer = self.producer(pin.writer, pin.revision)?;
            if producer.origin.reference != *reference
                || producer.origin.graph != consumer.origin.graph
            {
                continue;
            }
            let at = self.store.read_at(pin.revision)?;
            let graph = Graph::new(producer.origin.graph)?.view(
                at.snapshot.clone(),
                BTreeMap::new(),
                &|writer, bytes, total| self.reserve(writer, bytes, total),
            )?;
            if graph.head(pin.writer)? != Some(producer.origin.layer) {
                return Err(Code::Denied.error("native finding parent layer"));
            }
            let Some(member) = graph.member(
                pin.writer,
                pin.relation,
                &pin.owner,
                &pin.key,
                &|writer, bytes, total| self.reserve(writer, bytes, total),
            )?
            else {
                continue;
            };
            if member.revision != pin.revision {
                continue;
            }
            let finding = self.decode(&member)?;
            if pin.revision == 0
                || pin.revision >= owner.revision
                || finding.value.tenant_id != self.tenant
                || DomainRelations::key(&finding.value.finding_id)
                    .context(crate::AnalysisContractSnafu)?
                    != owner.key
            {
                return Err(Code::Denied.error("native finding parent authority"));
            }
            let mut evidence = finding.value.evidence.into_iter().collect::<BTreeSet<_>>();
            evidence.insert(finding.anchor.record);
            if let Some(fact) = finding.anchor.fact {
                evidence.insert(fact.record);
            }
            evidence.retain(|record| records.contains(record));
            if !evidence.is_empty() {
                self.charge(
                    (reference.result_id.len() + pin.owner.len() + pin.key.len())
                        .saturating_mul(4)
                        .saturating_add(12 * size_of::<FindingOrigin>()),
                )?;
                parents.push((
                    FindingOrigin {
                        result: reference.result_id.clone(),
                        revision: pin.revision,
                        relation: pin.relation,
                        writer: pin.writer,
                        owner: pin.owner.clone(),
                        key: pin.key.clone(),
                    },
                    evidence,
                ));
            }
        }
        Ok(parents)
    }

    pub(super) fn basis(
        &mut self,
        rows: &[FindingRow],
        require_proof: bool,
    ) -> Result<(
        Vec<AnalysisWitnessV1>,
        Vec<AnalysisContextRefV1>,
        GraphRevisionV1,
    )> {
        let mut owners = BTreeMap::<FindingOrigin, BTreeSet<DiscoveryRecordIdV1>>::new();
        for row in rows {
            self.charge(0)?;
            let records = owners.entry(row.origin.clone()).or_default();
            records.extend(row.finding.value.evidence.iter().cloned());
            records.insert(row.finding.anchor.record.clone());
            if let Some(fact) = &row.finding.anchor.fact {
                records.insert(fact.record.clone());
            }
        }
        let evidence = owners
            .values()
            .flat_map(|records| records.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut basis = FindingBasis::default();
        while let Some((owner, mut records)) = owners.pop_first() {
            self.charge(0)?;
            basis.visit(&owner, &mut records);
            if records.is_empty() {
                continue;
            }
            let producer = self.producer(owner.writer, owner.revision)?;
            if producer.origin.reference.result_id != owner.result {
                return Err(Code::Denied.error("native finding producer reference"));
            }
            let uncovered = basis.observe(&records, &producer.record);
            let parents = self.parents(&owner, &records, &producer)?;
            basis.parents(&mut owners, uncovered, parents)?;
            let mut keys = BTreeSet::new();
            for record in &records {
                let key = DomainRelations::key(record).context(crate::AnalysisContractSnafu)?;
                self.charge(key.len() + size_of::<DiscoveryRecordIdV1>())?;
                keys.insert(key);
            }
            self.charge(
                crate::analysis::managed::source::SourceEvidence::metadata_bytes(
                    std::iter::empty::<&AnalysisWitnessV1>(),
                    producer
                        .record
                        .contexts
                        .iter()
                        .chain(&producer.record.derived),
                )?
                .saturating_mul(4),
            )?;
            let contexts = crate::AnalysisStore::join_contexts(
                &producer.record.contexts,
                &producer.record.derived,
            )?;
            for reference in contexts {
                self.charge(0)?;
                let id = ContextRecord::id(&reference.key, |key| {
                    Records::read(key, &self.view.snapshot)
                })?
                .ok_or_else(|| Code::Missing.error("native finding context identity"))?;
                let retained = Records::read(
                    &References::key(References::CONTEXT, &[producer.id, id]),
                    &self.view.snapshot,
                )?;
                if retained
                    .map(|value| NativeStore::number(&value))
                    .transpose()?
                    != Some(reference.commit_revision)
                {
                    return Err(Code::Denied.error("native finding context reference"));
                }
                let (value, revision) = self
                    .view
                    .context_record(&reference.key, id, &mut |bytes| self.charge(bytes))?
                    .ok_or_else(|| Code::Missing.error("native finding context"))?;
                if revision != reference.commit_revision {
                    return Err(Code::Conflict.error("native finding context revision"));
                }
                self.view.verify_context(&value)?;
                let fact = DataView::fact_record(
                    id,
                    &value,
                    |key| Records::read(key, &self.view.snapshot),
                    &mut |bytes| self.charge(bytes),
                )?;
                basis.context(
                    &reference,
                    &records,
                    &producer.record.proofs,
                    fact.is_some(),
                    fact.as_ref()
                        .is_some_and(|fact| keys.contains(&fact.record)),
                )?;
            }
        }
        basis.finish(self.tenant, evidence, require_proof)
    }
}
