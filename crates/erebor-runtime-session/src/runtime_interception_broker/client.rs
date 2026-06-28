use erebor_runtime_ipc::v1::{
    GuardHello, GuardHelloAck, InterceptionDecision, InterceptionRequest,
};

use super::{
    endpoint::RuntimeInterceptionEndpoint,
    platform::{Platform, RuntimeInterceptionBrokerPlatform},
    server::RuntimeInterceptionBrokerError,
};

pub struct InterceptionBrokerClient;

impl InterceptionBrokerClient {
    pub fn send_hello(
        endpoint: &RuntimeInterceptionEndpoint,
        hello: GuardHello,
    ) -> Result<GuardHelloAck, RuntimeInterceptionBrokerError> {
        <Platform as RuntimeInterceptionBrokerPlatform>::send_hello(endpoint, hello)
    }

    pub fn request_interception_decision(
        endpoint: &RuntimeInterceptionEndpoint,
        hello: GuardHello,
        request: InterceptionRequest,
    ) -> Result<InterceptionDecision, RuntimeInterceptionBrokerError> {
        <Platform as RuntimeInterceptionBrokerPlatform>::request_interception_decision(
            endpoint, hello, request,
        )
    }
}
