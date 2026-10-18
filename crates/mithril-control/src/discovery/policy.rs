#[cfg(test)]
mod tests {
    use crate::{Result, StaticDecisionKeyV1};
    use araphor_data::DiscoveryPolicyKeyV1;

    #[test]
    fn discovery_context_key_roundtrip() -> Result<()> {
        let policy = crate::PolicyDocumentV1::parse(
            std::path::Path::new("policy-v1.yaml"),
            include_bytes!("../../tests/fixtures/policy-v1.yaml"),
        )?;
        for cell in crate::PolicyCompiler.compile(&policy)?.compiled_cells {
            let key = DiscoveryPolicyKeyV1::try_from(&cell.key)?;
            assert_eq!(StaticDecisionKeyV1::try_from(&key)?, cell.key);
            for change in 0..6 {
                let mut changed = key.clone();
                match change {
                    0 => changed.operation += 1,
                    1 => changed.operation_argument += 1,
                    2 => changed.argument_wildcard = !changed.argument_wildcard,
                    3 => changed.entry_kind = "UNSUPPORTED".into(),
                    4 => changed.binding_lifecycle = "UNSUPPORTED".into(),
                    _ => changed.effect_family = 0,
                }
                assert!(StaticDecisionKeyV1::try_from(&changed).is_err());
            }
        }
        Ok(())
    }
}
