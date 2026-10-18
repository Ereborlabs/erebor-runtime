pub(super) use araphor_data::InputByteLimit;

pub(super) fn require(valid: bool, field: &'static str) -> araphor_data::Result<()> {
    if valid {
        Ok(())
    } else {
        araphor_data::DiscoveryInvalidSnafu { field }.fail()
    }
}

pub(super) fn same(valid: bool, kind: &'static str) -> araphor_data::Result<()> {
    if valid {
        Ok(())
    } else {
        araphor_data::DiscoveryConflictSnafu { kind }.fail()
    }
}

pub(super) fn add(count: &mut u64, value: u64) -> araphor_data::Result<()> {
    *count = count
        .checked_add(value)
        .ok_or_else(|| araphor_data::DiscoveryInvalidSnafu { field: "count" }.build())?;
    Ok(())
}
