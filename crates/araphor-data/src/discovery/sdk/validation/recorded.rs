use super::*;

impl Adapter {
    pub(in crate::discovery::sdk) fn validate_recorded(
        input: &DiscoveryInputManifestV1,
        result: &DiscoveryRecordedResultV1,
    ) -> Result<()> {
        let records = Self::unique_rows(
            input.records.iter().map(|record| (&record.id, record)),
            "record bytes",
        )?;
        let contexts = Self::unique_rows(
            input
                .contexts
                .iter()
                .map(|context| (&context.record_id, context)),
            "context values",
        )?;
        let excluded = Self::unique_rows(
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
        Self::validate_coverage(
            &snapshot.coverage,
            &Self::recorded_coverage(input, records.into_values())?,
        )?;
        Self::validate_lifecycle(&snapshot.lifecycle, input.lifecycle.iter())
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
        let mut key: BehaviorAtomKeyV1 = Self::decode(&Self::atom_key(record, context, proof)?)?;
        key.physical_result = if wire.decision == 1 && wire.kernel_result < 0 {
            DiscoveryPhysicalResultV1::Prevented
        } else {
            DiscoveryPhysicalResultV1::Unknown
        };
        Ok(key)
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
