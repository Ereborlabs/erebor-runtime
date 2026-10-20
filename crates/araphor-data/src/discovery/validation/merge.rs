use super::*;

impl BehaviorSnapshotV1 {
    pub fn validate_merge(
        &self,
        right: &BehaviorSnapshotV1,
        output: &BehaviorSnapshotV1,
    ) -> Result<()> {
        self.validate()?;
        right.validate()?;
        output.validate()?;
        let left = self;
        let inputs = if left == right {
            vec![left]
        } else {
            vec![left, right]
        };
        same(
            inputs.iter().all(|input| {
                input.tenant_id == output.tenant_id
                    && input.source_revision == output.source_revision
                    && input.proof_kind == output.proof_kind
            }),
            "snapshot source",
        )?;
        let counts = |input: &BehaviorSnapshotV1| {
            [
                input.accepted_records,
                input.included_records,
                input.unresolved_records,
                input.excluded_records,
            ]
        };
        for (index, actual) in counts(output).into_iter().enumerate() {
            require(
                actual == inputs.iter().map(|input| counts(input)[index]).sum::<u64>(),
                "analysis merge accounting",
            )?;
        }
        Self::validate_merge_atoms(&inputs, output)?;
        Self::validate_merge_dispositions(
            &output.unresolved,
            inputs.iter().flat_map(|input| &input.unresolved),
        )?;
        Self::validate_merge_dispositions(
            &output.excluded,
            inputs.iter().flat_map(|input| &input.excluded),
        )?;
        Self::validate_coverage(
            &output.coverage,
            &inputs
                .iter()
                .flat_map(|input| input.coverage.clone())
                .collect::<Vec<_>>(),
        )?;
        Self::validate_lifecycle(
            &output.lifecycle,
            inputs.iter().flat_map(|input| &input.lifecycle),
        )
    }

    fn validate_merge_atoms(
        inputs: &[&BehaviorSnapshotV1],
        output: &BehaviorSnapshotV1,
    ) -> Result<()> {
        let mut source_atoms = BTreeMap::<_, Vec<_>>::new();
        for atom in inputs.iter().flat_map(|input| &input.atoms) {
            source_atoms.entry(&atom.key).or_default().push(atom);
        }
        require(
            output.atoms.len() == source_atoms.len(),
            "analysis merge atoms",
        )?;
        for atom in &output.atoms {
            let sources = source_atoms.get(&atom.key).ok_or_else(|| {
                DiscoveryInvalidSnafu {
                    field: "analysis merge atom key",
                }
                .build()
            })?;
            require(
                atom.count == sources.iter().map(|source| source.count).sum::<u64>()
                    && atom.first_cursor
                        == sources
                            .iter()
                            .map(|source| source.first_cursor)
                            .min()
                            .unwrap_or(0)
                    && atom.last_cursor
                        == sources
                            .iter()
                            .map(|source| source.last_cursor)
                            .max()
                            .unwrap_or(0)
                    && atom.evidence_sample.iter().all(|id| {
                        sources
                            .iter()
                            .any(|source| source.evidence_sample.contains(id))
                    }),
                "analysis merge atom evidence",
            )?;
        }
        Ok(())
    }

    fn validate_merge_dispositions<'a>(
        output: &[DiscoveryUnresolvedV1],
        inputs: impl Iterator<Item = &'a DiscoveryUnresolvedV1>,
    ) -> Result<()> {
        let expected = Self::unique_rows(
            inputs.map(|item| (&item.record_id, item)),
            "exclusion reason",
        )?;
        require(
            output.iter().eq(expected.into_values()),
            "analysis merge dispositions",
        )
    }
}
