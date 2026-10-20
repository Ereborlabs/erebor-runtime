use super::*;

impl DiscoveryInputManifestV1 {
    pub fn validate_result(&self, result: &DiscoveryRecordedResultV1) -> Result<()> {
        self.validate()?;
        result.snapshot.validate()?;
        let input = self;
        let records = BehaviorSnapshotV1::unique_rows(
            input.records.iter().map(|record| (&record.id, record)),
            "record bytes",
        )?;
        let contexts = BehaviorSnapshotV1::unique_rows(
            input
                .contexts
                .iter()
                .map(|context| (&context.record_id, context)),
            "context values",
        )?;
        let excluded = BehaviorSnapshotV1::unique_rows(
            input.exclusions.iter().map(|item| (&item.record_id, item)),
            "exclusion reason",
        )?;
        let snapshot = &result.snapshot;
        require(
            snapshot.accepted_records == records.len() as u64
                && result.duplicate_deliveries == (input.records.len() - records.len()) as u64,
            "analysis source accounting",
        )?;
        require(
            snapshot
                .excluded
                .iter()
                .map(|item| (&item.record_id, item))
                .collect::<BTreeMap<_, _>>()
                == excluded,
            "analysis source exclusions",
        )?;
        let unresolved: BTreeSet<_> = snapshot
            .unresolved
            .iter()
            .map(|item| &item.record_id)
            .collect();
        require(
            unresolved.iter().all(|id| records.contains_key(id)),
            "analysis source disposition",
        )?;
        let mut sources = BTreeMap::<_, BTreeSet<_>>::new();
        for (id, record) in &records {
            if excluded.contains_key(id) || unresolved.contains(id) {
                continue;
            }
            let context = contexts.get(id).ok_or_else(|| {
                DiscoveryInvalidSnafu {
                    field: "analysis source context",
                }
                .build()
            })?;
            let key = Self::source_atom_key(record, context, input.proof_kind)?;
            sources.entry(key).or_default().insert(*id);
        }
        Self::validate_source_atoms(snapshot, &sources)?;
        BehaviorSnapshotV1::validate_coverage(
            &snapshot.coverage,
            &self.recorded_coverage(records.into_values())?,
        )?;
        BehaviorSnapshotV1::validate_lifecycle(&snapshot.lifecycle, input.lifecycle.iter())
    }

    fn validate_source_atoms(
        snapshot: &BehaviorSnapshotV1,
        sources: &BTreeMap<BehaviorAtomKeyV1, BTreeSet<&DiscoveryRecordIdV1>>,
    ) -> Result<()> {
        require(
            snapshot.atoms.len() == sources.len(),
            "analysis source atoms",
        )?;
        for atom in &snapshot.atoms {
            let ids = sources.get(&atom.key).ok_or_else(|| {
                DiscoveryInvalidSnafu {
                    field: "analysis source atom key",
                }
                .build()
            })?;
            require(
                atom.count == ids.len() as u64
                    && atom.first_cursor
                        == ids.iter().map(|id| id.durable_cursor).min().unwrap_or(0)
                    && atom.last_cursor
                        == ids.iter().map(|id| id.durable_cursor).max().unwrap_or(0)
                    && atom.evidence_sample.iter().all(|id| ids.contains(id)),
                "analysis source atom evidence",
            )?;
        }
        Ok(())
    }

    fn source_atom_key(
        record: &DiscoveryRecordV1,
        context: &DiscoveryContextBindingV1,
        proof: DiscoveryProofKindV1,
    ) -> Result<BehaviorAtomKeyV1> {
        let wire = record.decode()?;
        require(
            Self::context_matches(&wire, context, record, proof),
            "analysis source context",
        )?;
        Ok(BehaviorAtomKeyV1 {
            stream: record.id.stream.clone(),
            cpu_id: record.id.cpu_id,
            subject_revision: context.subject_revision.clone(),
            image_digest: context.image_digest.clone(),
            configuration_digest: context.configuration_digest.clone(),
            process_instance_id: context.process_instance_id,
            entry_instance_id: context.entry_instance_id,
            binding_id: context.binding_id,
            role_id: context.role_id,
            state_id: context.state_id,
            entry_rule_id: context.entry_rule_id,
            catalog_revision: context.catalog_revision,
            static_key: context.static_key.clone(),
            policy_revision: context.policy_revision.clone(),
            generation: wire.profile_generation_ref_id.unwrap_or_default(),
            coverage_interval_id: wire.coverage_interval_id.as_ref().try_into().map_err(|_| {
                DiscoveryInvalidSnafu {
                    field: "record fields",
                }
                .build()
            })?,
            temporal_coverage: wire.temporal_coverage,
            effect: (&wire).into(),
            physical_result: if wire.decision == 1 && wire.kernel_result < 0 {
                DiscoveryPhysicalResultV1::Prevented
            } else {
                DiscoveryPhysicalResultV1::Unknown
            },
            proof_kind: proof,
        })
    }

    fn context_matches(
        wire: &EvidenceRecord,
        context: &DiscoveryContextBindingV1,
        record: &DiscoveryRecordV1,
        proof: DiscoveryProofKindV1,
    ) -> bool {
        let operation = &context.static_key;
        wire.profile_generation_ref_id.is_some()
            && !wire.exact_object_id.is_empty()
            && u32::from(operation.effect_family) == wire.effect_family
            && u32::from(operation.operation) == wire.operation
            && (operation.argument_wildcard
                || operation.operation_argument == wire.operation_argument.unwrap_or_default())
            && wire.decision_context.as_ref().map_or(
                proof != DiscoveryProofKindV1::ObservedRuntime,
                |source| {
                    source.process_instance_id.as_ref() == context.process_instance_id
                        && source.entry_instance_id.as_ref() == context.entry_instance_id
                        && source.binding_id.as_ref() == context.binding_id
                        && source.role_id == context.role_id
                        && source.state_id == context.state_id
                        && source.entry_rule_id == context.entry_rule_id
                        && source.original_kernel_sequence
                            == record.original_kernel_sequence.unwrap_or_default()
                },
            )
    }
}
