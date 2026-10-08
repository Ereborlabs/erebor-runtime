use super::*;

type Receipt = (String, FindingV1);

#[test]
fn control_graph_finding_pages() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let provider = Arc::new(Inputs::default());
    let owner = GraphAndFindingOwner::new(store.clone(), provider.clone())?;
    let records = (1..=383)
        .map(|cursor| record(cursor, &wire(cursor, DeniedBeforeEffect, 2, 2, [20; 16])))
        .collect::<Result<Vec<_>>>()?;
    for batch in records.chunks(128) {
        accept(&store, batch)?;
    }
    coverage(&store, 383, 1, "HEALTHY")?;
    for _ in 0..32 {
        owner.process(10)?;
        if store
            .processor_health(&GraphAndFindingOwner::scope(&source()))?
            .ok_or("processor health")?
            .consumed_cursor
            == 383
        {
            break;
        }
    }
    assert_eq!(
        owner.snapshot(&source())?.ok_or("snapshot")?.last_cursor,
        383
    );
    let original = overlapping_receipt(&store, &owner)?;
    let revised = refresh_receipt(&owner, &provider, &records, original)?;
    check_pages(&owner, &revised)?;
    super::super::read::tests::check_receipt_budget(&owner, source().tenant_id)?;
    check_finding_scope(&owner)?;
    Ok(())
}

fn overlapping_receipt(
    store: &AnalysisStore,
    owner: &GraphAndFindingOwner,
) -> std::result::Result<Receipt, Box<dyn std::error::Error>> {
    let mut windows = Vec::new();
    let mut after = None;
    loop {
        let page = store.graph_snapshots(source().tenant_id, None, after.as_deref(), true)?;
        if page.is_empty() {
            break;
        }
        after = page.last().map(|row| row.0.clone());
        windows.extend(page);
    }
    let latest = windows
        .iter()
        .find(|newer| {
            windows.iter().any(|older| {
                older.2 < newer.2
                    && older.1.first_cursor < newer.1.first_cursor
                    && older.1.last_cursor >= newer.1.first_cursor
            })
        })
        .ok_or("overlapping source windows")?;
    let overlap = latest
        .1
        .findings
        .iter()
        .find(|finding| finding.evidence[0].durable_cursor == latest.1.first_cursor)
        .ok_or("overlapping finding")?;
    let original = owner
        .current_finding(source().tenant_id, &overlap.finding_id)?
        .ok_or("original finding")?;
    assert_eq!(original.0, latest.0);
    Ok(original)
}

fn refresh_receipt(
    owner: &GraphAndFindingOwner,
    provider: &Inputs,
    records: &[DiscoveryRecordV1],
    original: Receipt,
) -> std::result::Result<Receipt, Box<dyn std::error::Error>> {
    let anchor = &records[usize::try_from(original.1.revision.evidence[0].durable_cursor - 2)?];
    provider
        .0
        .lock()
        .map_err(|_| "provider")?
        .extend([policy(anchor, 1)?, activation(anchor)?]);
    assert!(owner.refresh(&source(), 11)?);
    let revised = owner
        .current_finding(source().tenant_id, &original.1.finding_id)?
        .ok_or("revised finding")?;
    assert_ne!(revised.0, original.0);
    assert!(
        revised.1.revision.evidence[0].durable_cursor
            < original.1.revision.evidence[0].durable_cursor
    );
    assert_eq!(
        owner.finding_result(source().tenant_id, &original.0, &original.1.finding_id)?,
        Some(original.1)
    );
    Ok(revised)
}

fn check_pages(owner: &GraphAndFindingOwner, revised: &Receipt) -> TestResult {
    let mut after = None;
    let mut observed = std::collections::BTreeSet::new();
    let mut keys = std::collections::BTreeSet::new();
    let mut revised_seen = false;
    let mut pages = 0;
    loop {
        let page = owner.next_current_findings(source().tenant_id, after.as_deref(), 256)?;
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 256);
        assert!(serde_json::to_vec(&page)?.len() <= crate::analysis::MAX_RESULT_BYTES);
        assert!(page
            .windows(2)
            .all(|pair| pair[0].1.finding_id < pair[1].1.finding_id));
        pages += 1;
        for receipt in &page {
            let finding = &receipt.1;
            assert!(after.as_ref().is_none_or(|id| finding.finding_id > *id));
            assert!(keys.insert(finding.finding_id.clone()));
            assert!(observed.insert(finding.evidence[0].durable_cursor));
            if finding.finding_id == revised.1.finding_id {
                assert_eq!(receipt, revised);
                revised_seen = true;
            }
        }
        after = page.last().map(|(_, finding)| finding.finding_id.clone());
    }
    assert!(pages > 1);
    assert!(revised_seen);
    assert_eq!(observed, (1..=383).collect());
    assert_eq!(keys.len(), 383);
    Ok(())
}

fn check_finding_scope(owner: &GraphAndFindingOwner) -> TestResult {
    assert!(owner.next_current_findings([99; 16], None, 256)?.is_empty());
    assert!(owner
        .next_current_findings(source().tenant_id, None, 0)
        .is_err());
    assert!(owner
        .next_current_findings(source().tenant_id, None, 257)
        .is_err());
    assert!(owner
        .next_current_findings(source().tenant_id, Some(""), 1)
        .is_err());
    assert!(owner.next_current_findings([0; 16], None, 1).is_err());
    Ok(())
}
