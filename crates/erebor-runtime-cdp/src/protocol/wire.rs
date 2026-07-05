use cdp_protocol::types::{CallId, Method};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use snafu::{Location, ResultExt};

use super::GovernedCdpCommand;
use crate::{
    error::{InvalidProtocolSnafu, UnexpectedMethodSnafu},
    CdpError,
};

pub(super) struct ProtocolWire;

impl ProtocolWire {
    pub(super) fn deserialize<T>(source: &str) -> Result<T, CdpError>
    where
        T: DeserializeOwned,
    {
        serde_json::from_str(source).map_err(|error| {
            if error.is_syntax() || error.is_eof() {
                CdpError::InvalidJson {
                    source: error,
                    location: Location::default(),
                }
            } else {
                CdpError::InvalidProtocol {
                    source: error,
                    location: Location::default(),
                }
            }
        })
    }

    pub(super) fn params_value<T>(params: &T) -> Result<Value, CdpError>
    where
        T: Serialize,
    {
        serde_json::to_value(params).context(InvalidProtocolSnafu)
    }

    pub(super) fn decode_method_call<T>(source: &str) -> Result<IncomingMethodCall<T>, CdpError>
    where
        T: Method + DeserializeOwned,
    {
        let call: IncomingMethodCall<T> = Self::deserialize(source)?;
        if call.method != T::NAME {
            return UnexpectedMethodSnafu {
                expected: T::NAME,
                actual: call.method,
            }
            .fail();
        }

        Ok(call)
    }

    pub(super) fn decode_method_call_or<T>(
        source: &str,
        fallback_params: Value,
    ) -> Result<IncomingMethodCall<T>, CdpError>
    where
        T: Method + DeserializeOwned,
    {
        let call: IncomingRawMethodCall = Self::deserialize(source)?;
        if call.method != T::NAME {
            return UnexpectedMethodSnafu {
                expected: T::NAME,
                actual: call.method,
            }
            .fail();
        }

        let params = match call.params {
            Some(Value::Null) | None => fallback_params,
            Some(params) => params,
        };
        let params = serde_json::from_value(params).context(InvalidProtocolSnafu)?;

        Ok(IncomingMethodCall {
            id: call.id,
            method: call.method,
            params,
        })
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct IncomingMethodHead {
    pub(super) id: CallId,
    #[serde(rename = "method")]
    pub(super) method: String,
    #[serde(rename = "sessionId")]
    pub(super) session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct IncomingEventHead {
    pub(super) method: Option<String>,
    #[serde(rename = "sessionId")]
    pub(super) session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct IncomingMethodCall<T> {
    pub(super) id: CallId,
    #[serde(rename = "method")]
    pub(super) method: String,
    pub(super) params: T,
}

#[derive(Debug, Deserialize)]
pub(super) struct IncomingGenericMethodCall {
    pub(super) id: CallId,
    #[serde(rename = "method")]
    pub(super) method: String,
    pub(super) params: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct IncomingRawMethodCall {
    id: CallId,
    #[serde(rename = "method")]
    method: String,
    params: Option<Value>,
}

#[derive(Debug)]
pub(super) struct DecodedGovernedCommand {
    pub(super) id: CallId,
    pub(super) params: Value,
    pub(super) command: GovernedCdpCommand,
}
