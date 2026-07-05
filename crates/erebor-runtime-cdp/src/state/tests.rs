use cdp_protocol::page;

use super::{CdpSessionState, PageStatusKind};
use crate::{CdpCommandDecoder, GovernedCdpCommand};

#[test]
fn command_target_uses_provisional_page_url_for_script_eval(
) -> Result<(), Box<dyn std::error::Error>> {
    let state = CdpSessionState::from_browser_url("ws://127.0.0.1:1/devtools/page/page-1");
    let navigate = CdpCommandDecoder::decode(
        r#"{ "id": 1, "method": "Page.navigate", "params": { "url": "https://mail.example.test/compose" } }"#,
    )?;
    let Some(GovernedCdpCommand::PageNavigate(navigate)) = navigate.protocol_command() else {
        return Err(std::io::Error::other("expected page navigate command").into());
    };
    state.record_provisional_forwarded_command(&GovernedCdpCommand::PageNavigate(navigate.clone()));
    let evaluate = CdpCommandDecoder::decode(
        r#"{ "id": 2, "method": "Runtime.evaluate", "params": { "expression": "send()" } }"#,
    )?;
    let target = evaluate
        .protocol_command()
        .and_then(|command| state.target_for_command(command));

    assert_eq!(
        target.and_then(|target| target.uri),
        Some(String::from("https://mail.example.test/compose"))
    );
    assert_eq!(
        state.snapshot().active_page.map(|page| page.status),
        Some(PageStatusKind::ProvisionalNavigation)
    );
    Ok(())
}

#[test]
fn frame_tree_refresh_updates_browser_page_url() {
    let state = CdpSessionState::from_browser_url("ws://127.0.0.1:1/devtools/page/page-1");

    state.record_frame_tree(&frame_tree("https://browser-state.example.test/compose"));

    assert_eq!(
        state.snapshot().active_page.and_then(|page| page.url),
        Some(String::from("https://browser-state.example.test/compose"))
    );
}

#[test]
fn browser_confirmed_frame_tree_overrides_provisional_command_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let state = CdpSessionState::from_browser_url("ws://127.0.0.1:1/devtools/page/page-1");
    let navigate = CdpCommandDecoder::decode(
        r#"{ "id": 1, "method": "Page.navigate", "params": { "url": "https://mail.example.test/compose" } }"#,
    )?;
    let Some(GovernedCdpCommand::PageNavigate(navigate)) = navigate.protocol_command() else {
        return Err(std::io::Error::other("expected page navigate command").into());
    };
    state.record_provisional_forwarded_command(&GovernedCdpCommand::PageNavigate(navigate.clone()));
    state.record_frame_tree(&frame_tree("https://calendar.example.test/day"));

    let evaluate = CdpCommandDecoder::decode(
        r#"{ "id": 2, "method": "Runtime.evaluate", "params": { "expression": "send()" } }"#,
    )?;
    let target = evaluate
        .protocol_command()
        .and_then(|command| state.target_for_command(command));

    assert_eq!(
        target.and_then(|target| target.uri),
        Some(String::from("https://calendar.example.test/day"))
    );
    assert_eq!(
        state.snapshot().active_page.map(|page| page.status),
        Some(PageStatusKind::Active)
    );
    Ok(())
}

fn frame_tree(url: &str) -> page::FrameTree {
    page::FrameTree {
        frame: page::Frame {
            id: String::from("frame-1"),
            parent_id: None,
            loader_id: String::from("loader-1"),
            name: None,
            url: url.to_owned(),
            url_fragment: None,
            domain_and_registry: String::from("example.test"),
            security_origin: String::from("https://browser-state.example.test"),
            security_origin_details: None,
            mime_type: String::from("text/html"),
            unreachable_url: None,
            ad_frame_status: None,
            secure_context_type: page::SecureContextType::Secure,
            cross_origin_isolated_context_type: page::CrossOriginIsolatedContextType::NotIsolated,
            gated_api_features: vec![],
        },
        child_frames: None,
    }
}
