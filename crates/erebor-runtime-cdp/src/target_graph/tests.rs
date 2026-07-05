use cdp_protocol::target;

use super::{BrowserTargetGraph, BrowserTargetId, BrowserTargetKind, BrowserTargetStatus};

#[test]
fn target_graph_stores_multiple_page_targets() {
    let mut graph = BrowserTargetGraph::default();

    graph.record_target_info(&target_info("page-1", "page", "https://mail.example.test/"));
    graph.record_target_info(&target_info(
        "page-2",
        "page",
        "https://calendar.example.test/",
    ));

    let targets = graph.targets();
    assert_eq!(targets.len(), 2);
    assert_eq!(
        graph
            .target(&BrowserTargetId::new("page-1"))
            .and_then(|target| target.url.clone()),
        Some(String::from("https://mail.example.test/"))
    );
}

#[test]
fn target_graph_records_popup_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let mut graph = BrowserTargetGraph::default();
    let mut popup = target_info("popup-1", "page", "https://popup.example.test/");
    popup.opener_id = Some(String::from("page-1"));

    graph.record_target_info(&popup);
    graph.record_target_destroyed("popup-1");

    let target = graph
        .target(&BrowserTargetId::new("popup-1"))
        .ok_or_else(|| std::io::Error::other("target should exist"))?;
    assert_eq!(target.kind, BrowserTargetKind::Page);
    assert_eq!(
        target.opener.as_ref().map(BrowserTargetId::as_str),
        Some("page-1")
    );
    assert_eq!(target.status, BrowserTargetStatus::Closed);
    Ok(())
}

fn target_info(id: &str, kind: &str, url: &str) -> target::TargetInfo {
    target::TargetInfo {
        target_id: id.to_owned(),
        r#type: kind.to_owned(),
        title: String::new(),
        url: url.to_owned(),
        attached: false,
        opener_id: None,
        can_access_opener: false,
        opener_frame_id: None,
        parent_frame_id: None,
        browser_context_id: None,
        subtype: None,
    }
}
