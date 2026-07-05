use cdp_protocol::{page, types::Method};
use snafu::ResultExt;

use super::{CdpCommandDecoder, CdpEventDecoder, GovernedCdpCommand};
use crate::error::{InvalidProtocolSnafu, UnsupportedMethodSnafu};
use crate::CdpError;

#[test]
fn decodes_governed_command_from_protocol_method_call_shape() -> Result<(), CdpError> {
    let navigate = page::Navigate {
        url: String::from("https://example.com/"),
        referrer: None,
        transition_type: None,
        frame_id: None,
        referrer_policy: None,
    };
    let source =
        serde_json::to_string(&navigate.to_method_call(1)).context(InvalidProtocolSnafu)?;
    let command = CdpCommandDecoder::decode(&source)?;

    assert!(matches!(
        command.protocol_command(),
        Some(GovernedCdpCommand::PageNavigate(_))
    ));
    assert_eq!(command.id, 1);
    assert_eq!(
        command
            .protocol_command()
            .and_then(GovernedCdpCommand::target)
            .and_then(|target| target.uri),
        Some(String::from("https://example.com/"))
    );
    assert_eq!(
        command.params().and_then(|params| params.get("url")),
        Some(&serde_json::Value::String(String::from(
            "https://example.com/"
        )))
    );
    Ok(())
}

#[test]
fn rejects_invalid_governed_command_protocol_params() {
    let result = CdpCommandDecoder::decode(
        r#"
            {
              "id": 1,
              "method": "Input.dispatchMouseEvent",
              "params": { "type": "notAMouseEvent", "x": 1, "y": 1 }
            }
            "#,
    );

    assert!(matches!(result, Err(CdpError::InvalidProtocol { .. })));
}

#[test]
fn decodes_target_management_commands_as_governed() -> Result<(), CdpError> {
    let command = CdpCommandDecoder::decode(
        r#"
            {
              "id": 4,
              "method": "Target.setAutoAttach",
              "params": {
                "autoAttach": true,
                "waitForDebuggerOnStart": false,
                "flatten": true
              }
            }
            "#,
    )?;

    let Some(GovernedCdpCommand::TargetManagement(target_command)) = command.protocol_command()
    else {
        return UnsupportedMethodSnafu {
            method: String::from("Target.setAutoAttach"),
        }
        .fail();
    };
    assert_eq!(target_command.method(), "Target.setAutoAttach");
    assert_eq!(
        command.params().and_then(|params| params.get("flatten")),
        Some(&serde_json::Value::Bool(true))
    );
    Ok(())
}

#[test]
fn decodes_optional_target_management_params_with_protocol_defaults() -> Result<(), CdpError> {
    let command = CdpCommandDecoder::decode(r#"{ "id": 4, "method": "Target.getTargets" }"#)?;

    let Some(GovernedCdpCommand::TargetManagement(target_command)) = command.protocol_command()
    else {
        return UnsupportedMethodSnafu {
            method: String::from("Target.getTargets"),
        }
        .fail();
    };
    assert!(matches!(
        target_command.as_ref(),
        super::target_management::TargetManagementCommand::GetTargets(_)
    ));
    assert_eq!(target_command.method(), "Target.getTargets");
    assert_eq!(command.params(), Some(&serde_json::json!({})));
    Ok(())
}

#[test]
fn decodes_context_event_through_protocol_event_enum() -> Result<(), CdpError> {
    let event = CdpEventDecoder::decode(
        r#"
            {
              "method": "Network.loadingFailed",
              "params": {
                "requestId": "network-1",
                "timestamp": 1.0,
                "type": "Document",
                "errorText": "net::ERR_FAILED",
                "canceled": false
              }
            }
            "#,
    )?
    .ok_or_else(|| {
        UnsupportedMethodSnafu {
            method: String::from("Network.loadingFailed"),
        }
        .build()
    })?;

    assert_eq!(event.method(), "Network.loadingFailed");
    assert_eq!(event.event_id(), "network-1");
    assert_eq!(
        event.params().get("errorText"),
        Some(&serde_json::Value::String(String::from("net::ERR_FAILED")))
    );
    Ok(())
}

#[test]
fn ignores_cdp_responses_without_event_method() -> Result<(), CdpError> {
    let event = CdpEventDecoder::decode(r#"{ "id": 1, "result": {} }"#)?;

    assert_eq!(event, None);
    Ok(())
}
