use super::*;

pub(in crate::graph) fn check_receipt_budget(
    owner: &GraphAndFindingOwner,
    tenant: [u8; 16],
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let current = owner.next_current_findings(tenant, None, 2)?;
    assert_eq!(current.len(), 2);
    let first_bytes = serde_json::to_vec(&current[..1])?.len();
    assert_eq!(
        owner.select_current_findings(tenant, None, None, 2, first_bytes)?,
        current[..1]
    );
    let next_bytes = serde_json::to_vec(&current[1..])?.len();
    assert_eq!(
        owner.select_current_findings(
            tenant,
            Some(&current[0].1.finding_id),
            None,
            2,
            next_bytes,
        )?,
        current[1..]
    );
    assert!(matches!(
        owner.select_current_findings(tenant, None, None, 2, first_bytes - 1),
        Err(crate::Error::GraphEncoding { .. })
    ));
    Ok(())
}
