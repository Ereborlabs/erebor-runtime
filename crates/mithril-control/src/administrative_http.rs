use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use erebor_interceptor_abi::Id128V1;
use erebor_runtime_ipc::araphor::{
    AdministrativeExecActivation, AdministrativeExecDraft, AdministrativeExecDraftRequest,
    AdministrativeExecPoll,
};
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewStatus, UserInfo};
use k8s_openapi::api::core::v1::Pod;
use kube::api::Api;
use kube::core::admission::{AdmissionResponse, AdmissionReview, Operation};
use kube::core::DynamicObject;
use kube::{Client, ResourceExt as _};
use openidconnect::RedirectUrl;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ensure;
use uuid::Uuid;

use crate::client_auth::OidcFlow as OidcProof;
use crate::error::AdministrativeApprovalSnafu;
use crate::{
    AdministrativeApprovalConfigV1, AdministrativeApprovalOwner, AdministrativeExecCredentialV1,
    AdministrativeExecRequestV1, AdministrativeExecResolution, ClientAuth, ClientListener,
    ControlPlane, NodeDecommissionHttpOwner, OidcOwner, Result,
};

mod grpc;

const APPROVAL_EXTRA_KEY: &str = "mithril.ereborlabs.com/approval-id";
const MAX_PENDING_REQUESTS: usize = 4096;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrativeConfig {
    pub kubernetes_audience: String,
    pub kubernetes_webhook_token_path: PathBuf,
    pub node_ids_by_kubernetes_name: BTreeMap<String, String>,
    pub request_lifetime_seconds: u64,
    pub approval: AdministrativeApprovalConfigV1,
}

impl AdministrativeConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.kubernetes_webhook_token_path.is_absolute()
                && !self.kubernetes_audience.is_empty()
                && !self.node_ids_by_kubernetes_name.is_empty()
                && (1..=300).contains(&self.request_lifetime_seconds)
                && self.node_ids_by_kubernetes_name.iter().all(|(name, id)| {
                    !name.is_empty()
                        && !name.chars().any(char::is_whitespace)
                        && Uuid::parse_str(id)
                            .is_ok_and(|uuid| uuid.hyphenated().to_string() == *id)
                }),
            AdministrativeApprovalSnafu {
                reason: "administrative configuration is invalid",
            }
        );
        Ok(())
    }
}

pub struct AdministrativeHttpOwner {
    config: PreparedHttpConfig,
    approval: AdministrativeApprovalOwner,
    decommission: Arc<NodeDecommissionHttpOwner>,
    kube: Client,
    oidc: Arc<OidcOwner>,
    state: Mutex<HttpState>,
}

struct PreparedHttpConfig {
    public_base_url: String,
    cluster_uid: String,
    redirect_url: RedirectUrl,
    kubernetes_audience: String,
    kubernetes_webhook_token: String,
    node_ids_by_kubernetes_name: BTreeMap<String, String>,
    request_lifetime_ns: i64,
}

#[derive(Default)]
struct HttpState {
    drafts: BTreeMap<Id128V1, Draft>,
    activation_tokens: BTreeMap<[u8; 32], Id128V1>,
    poll_tokens: BTreeMap<[u8; 32], Id128V1>,
    oidc_flows: BTreeMap<String, OidcFlow>,
}

struct Draft {
    pod_name: String,
    request: AdministrativeExecRequestV1,
    resolution: AdministrativeExecResolution,
    expires_at_utc_ns: i64,
    credential: Option<AdministrativeExecCredentialV1>,
    authenticated_principal: Option<Id128V1>,
    approver: Option<String>,
    browser: Option<String>,
    csrf: Option<String>,
    authentication_started: bool,
    approval_started: bool,
    delivered: bool,
}

struct OidcFlow {
    draft_id: Id128V1,
    activation_token: String,
    proof: OidcProof,
    browser: String,
}

struct OidcCompletion {
    activation_token: String,
    csrf: String,
}

#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PodExecOptionsV1 {
    #[serde(default, rename = "apiVersion")]
    api_version: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    command: Vec<String>,
    container: Option<String>,
    #[serde(default)]
    stdin: bool,
    #[serde(default)]
    stdout: bool,
    #[serde(default)]
    stderr: bool,
    #[serde(default)]
    tty: bool,
}

struct LivePodTarget {
    node_id: String,
    namespace: Vec<u8>,
    pod_uid: Vec<u8>,
    container_name: Vec<u8>,
    full_container_id: Vec<u8>,
}

struct AdmissionIdentity {
    approval_id: Id128V1,
    principal_id: Id128V1,
}

impl AdministrativeHttpOwner {
    pub async fn load(
        config: &AdministrativeConfig,
        control: ControlPlane,
        oidc: Arc<OidcOwner>,
        origin: &str,
    ) -> Result<Self> {
        config.validate()?;
        let kube = Client::try_default()
            .await
            .map_err(|error| approval_error(format!("load Kubernetes client: {error}")))?;
        Self::from_client(config, control, oidc, origin, kube)
    }

    pub fn from_client(
        config: &AdministrativeConfig,
        control: ControlPlane,
        oidc: Arc<OidcOwner>,
        origin: &str,
        kube: Client,
    ) -> Result<Self> {
        config.validate()?;
        let kubernetes_webhook_token =
            std::fs::read_to_string(&config.kubernetes_webhook_token_path)
                .map(|value| value.trim().to_owned())
                .map_err(|error| {
                    approval_error(format!(
                        "read Kubernetes webhook token `{}`: {error}",
                        config.kubernetes_webhook_token_path.display()
                    ))
                })?;
        ensure!(
            kubernetes_webhook_token.len() == 64
                && kubernetes_webhook_token
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            AdministrativeApprovalSnafu {
                reason: "Kubernetes webhook token must be 32 bytes of lowercase hex",
            }
        );
        Ok(Self {
            config: PreparedHttpConfig {
                public_base_url: origin.to_owned(),
                cluster_uid: config.approval.cluster_uid.clone(),
                redirect_url: RedirectUrl::new(format!("{origin}/oidc/callback")).map_err(
                    |error| approval_error(format!("OIDC redirect URL is invalid: {error}")),
                )?,
                kubernetes_audience: config.kubernetes_audience.clone(),
                kubernetes_webhook_token,
                node_ids_by_kubernetes_name: config.node_ids_by_kubernetes_name.clone(),
                request_lifetime_ns: i64::try_from(config.request_lifetime_seconds * 1_000_000_000)
                    .map_err(|error| {
                        approval_error(format!("request lifetime overflow: {error}"))
                    })?,
            },
            approval: AdministrativeApprovalOwner::load(&config.approval, control.clone())?,
            decommission: Arc::new(NodeDecommissionHttpOwner::new(
                &config.approval.cluster_uid,
                control,
            )?),
            kube,
            oidc,
            state: Mutex::new(HttpState::default()),
        })
    }

    pub(crate) fn callbacks(self: Arc<Self>) -> Router {
        let authentication_path = format!(
            "/kubernetes/{}/authenticate",
            self.config.kubernetes_webhook_token
        );
        let admission_path = format!("/kubernetes/{}/admit", self.config.kubernetes_webhook_token);
        Router::new()
            .route("/activate/:activation_token", get(Self::activation_page))
            .route(
                "/activate/:activation_token/authorize",
                get(Self::begin_authorization),
            )
            .route("/oidc/callback", get(Self::oidc_callback))
            .route(&authentication_path, post(Self::token_review))
            .route(&admission_path, post(Self::admission_review))
            .layer(DefaultBodyLimit::max(64 * 1024))
            .with_state(self)
    }

    async fn create_draft(
        &self,
        request: AdministrativeExecDraftRequest,
    ) -> Result<AdministrativeExecDraft> {
        validate_draft(&request)?;
        let target = self
            .live_pod_target(&request.namespace, &request.pod, &request.container)
            .await?;
        let pod_name = request.pod.clone();
        let request = AdministrativeExecRequestV1 {
            node_id: target.node_id,
            namespace: target.namespace,
            pod_uid: target.pod_uid,
            container_name: target.container_name,
            full_container_id: target.full_container_id,
            container_generation: 0,
            argv: request
                .argv
                .iter()
                .map(|argument| argument.as_bytes().to_vec())
                .collect(),
            stream_flags: stream_flags(request.stdin, request.stdout, request.stderr, request.tty),
            approved_role_id: request.approved_role_id,
        };
        let resolution = self.approval.resolve(&request).await?;
        let now = current_utc_ns()?;
        let expires_at_utc_ns = now
            .checked_add(self.config.request_lifetime_ns)
            .ok_or_else(|| approval_error("administrative draft expiry overflow"))?;
        let draft_id = random_id();
        let activation_token = random_secret();
        let poll_token = random_secret();
        let activation_digest = digest(activation_token.as_bytes());
        let poll_digest = digest(poll_token.as_bytes());
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative HTTP state is poisoned"))?;
        state.retain_live(now);
        ensure!(
            state.drafts.len() < MAX_PENDING_REQUESTS
                && !state.activation_tokens.contains_key(&activation_digest)
                && !state.poll_tokens.contains_key(&poll_digest)
                && !state.drafts.contains_key(&draft_id),
            AdministrativeApprovalSnafu {
                reason: "administrative draft capacity or identity is unavailable",
            }
        );
        state.activation_tokens.insert(activation_digest, draft_id);
        state.poll_tokens.insert(poll_digest, draft_id);
        state.drafts.insert(
            draft_id,
            Draft {
                pod_name,
                request,
                resolution,
                expires_at_utc_ns,
                credential: None,
                authenticated_principal: None,
                approver: None,
                browser: None,
                csrf: None,
                authentication_started: false,
                approval_started: false,
                delivered: false,
            },
        );
        Ok(AdministrativeExecDraft {
            activation_url: format!(
                "{}/activate/{activation_token}",
                self.config.public_base_url
            ),
            activation_code: activation_token[..8].to_ascii_uppercase(),
            poll_token,
            expires_at_utc_ns,
        })
    }

    #[allow(clippy::result_large_err)]
    fn poll_draft(
        &self,
        token: &str,
    ) -> std::result::Result<AdministrativeExecPoll, tonic::Status> {
        let now = current_utc_ns().map_err(Self::status)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| tonic::Status::unavailable("administrative state is unavailable"))?;
        state.retain_live(now);
        let id = state
            .poll_tokens
            .get(&digest(token.as_bytes()))
            .copied()
            .ok_or_else(|| {
                tonic::Status::not_found("administrative request is absent or expired")
            })?;
        let draft = state
            .drafts
            .get_mut(&id)
            .ok_or_else(|| tonic::Status::not_found("administrative request is absent"))?;
        if draft.delivered {
            return Err(tonic::Status::failed_precondition(
                "administrative credential was already delivered",
            ));
        }
        let Some(credential) = draft.credential.take() else {
            return Ok(AdministrativeExecPoll {
                state: "PENDING".into(),
                credential: None,
                approval_id: None,
                expires_at_utc_ns: Some(draft.expires_at_utc_ns),
            });
        };
        draft.delivered = true;
        Ok(AdministrativeExecPoll {
            state: "APPROVED".into(),
            credential: Some(credential.credential),
            approval_id: Some(id_string(credential.approval_id)),
            expires_at_utc_ns: Some(credential.expires_at_utc_ns),
        })
    }

    async fn activation_page(
        State(owner): State<Arc<Self>>,
        Path(activation_token): Path<String>,
    ) -> Response {
        match owner.render_activation(&activation_token) {
            Ok(html) => Html(html).into_response(),
            Err(error) => problem(StatusCode::NOT_FOUND, error),
        }
    }

    fn render_activation(&self, token: &str) -> Result<String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative state is unavailable"))?;
        state.retain_live(current_utc_ns()?);
        ensure!(
            state
                .activation_tokens
                .contains_key(&digest(token.as_bytes())),
            AdministrativeApprovalSnafu {
                reason: "administrative activation is absent or expired"
            }
        );
        Ok(format!(
            "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Araphor approval</title>\
             <link rel=stylesheet href=\"/assets/administrative.css\">\
             <main id=administrative-root><h1>Review one administrative exec</h1>\
             <p>Loading the exact approved request.</p>\
             <p><a href=\"/activate/{}/authorize\">Sign in to review</a></p></main>\
             <script type=module src=\"/assets/administrative.js\"></script></html>",
            html_escape(token),
        ))
    }

    #[allow(clippy::result_large_err)]
    fn activation(
        &self,
        token: &str,
        headers: &HeaderMap,
    ) -> std::result::Result<AdministrativeExecActivation, tonic::Status> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| tonic::Status::unavailable("administrative state is unavailable"))?;
        state.retain_live(current_utc_ns().map_err(Self::status)?);
        let id = state
            .activation_tokens
            .get(&digest(token.as_bytes()))
            .copied()
            .ok_or_else(|| {
                tonic::Status::not_found("administrative activation is absent or expired")
            })?;
        let draft = state
            .drafts
            .get(&id)
            .ok_or_else(|| tonic::Status::not_found("administrative draft is absent"))?;
        if draft.authenticated_principal.is_some() {
            draft.browser(headers, &self.config.public_base_url, false)?;
        }
        let resolution = &draft.resolution;
        Ok(AdministrativeExecActivation {
            namespace: String::from_utf8_lossy(&resolution.namespace).into_owned(),
            pod: draft.pod_name.clone(),
            pod_uid: String::from_utf8_lossy(&resolution.pod_uid).into_owned(),
            container: String::from_utf8_lossy(&resolution.container_name).into_owned(),
            argv: resolution
                .argv
                .iter()
                .map(|value| String::from_utf8_lossy(value).into_owned())
                .collect(),
            state: draft.activation_state().into(),
            expires_at_utc_ns: draft.expires_at_utc_ns,
            authenticated: draft.authenticated_principal.is_some(),
            approver: draft.approver.clone().unwrap_or_default(),
            cluster_uid: self.config.cluster_uid.clone(),
            resolved_executable: resolution
                .resolved_executable
                .as_ref()
                .map(|value| String::from_utf8_lossy(&value.resolved_display_path).into_owned())
                .unwrap_or_else(|| "unavailable".into()),
            stream_flags: resolution.stream_flags.to_string(),
            approved_role_id: resolution.approved_role_id.clone(),
        })
    }

    async fn begin_authorization(
        State(owner): State<Arc<Self>>,
        Path(activation_token): Path<String>,
    ) -> Response {
        match owner.authorization_url(&activation_token) {
            Ok((url, browser)) => {
                let mut response = Redirect::to(&url).into_response();
                match ClientListener::cookie(&mut response, "araphor-approval", &browser, true, 300)
                {
                    Ok(()) => response,
                    Err(error) => problem(StatusCode::INTERNAL_SERVER_ERROR, error),
                }
            }
            Err(error) => problem(StatusCode::BAD_REQUEST, error),
        }
    }

    fn authorization_url(&self, activation_token: &str) -> Result<(String, String)> {
        let now = current_utc_ns()?;
        let draft_id = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| approval_error("administrative HTTP state is poisoned"))?;
            state.retain_live(now);
            state
                .activation_tokens
                .get(&digest(activation_token.as_bytes()))
                .copied()
                .ok_or_else(|| approval_error("administrative activation is missing or expired"))?
        };
        let (url, csrf, proof) = self.oidc.begin(&self.config.redirect_url);
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative HTTP state is poisoned"))?;
        ensure!(
            !state.oidc_flows.contains_key(csrf.secret()),
            AdministrativeApprovalSnafu {
                reason: "OIDC state identity collided",
            }
        );
        let draft = state
            .drafts
            .get_mut(&draft_id)
            .ok_or_else(|| approval_error("administrative draft is missing"))?;
        ensure!(
            !draft.authentication_started
                && draft.authenticated_principal.is_none()
                && !draft.approval_started,
            AdministrativeApprovalSnafu {
                reason: "administrative authentication is already in progress",
            }
        );
        draft.authentication_started = true;
        let browser = random_secret();
        draft.browser = Some(browser.clone());
        state.oidc_flows.insert(
            csrf.secret().clone(),
            OidcFlow {
                draft_id,
                activation_token: activation_token.to_owned(),
                proof,
                browser: browser.clone(),
            },
        );
        Ok((url, browser))
    }

    async fn oidc_callback(
        State(owner): State<Arc<Self>>,
        headers: HeaderMap,
        Query(query): Query<OidcCallbackQuery>,
    ) -> Response {
        let browser = match ClientAuth::cookie(&headers, "araphor-approval") {
            Ok(Some(value)) => value,
            _ => return StatusCode::UNAUTHORIZED.into_response(),
        };
        match owner.complete_oidc(query, browser).await {
            Ok(completion) => {
                let mut response =
                    Redirect::to(&format!("/activate/{}", completion.activation_token))
                        .into_response();
                match ClientListener::cookie(
                    &mut response,
                    "araphor-approval-csrf",
                    &completion.csrf,
                    false,
                    300,
                ) {
                    Ok(()) => response,
                    Err(error) => problem(StatusCode::INTERNAL_SERVER_ERROR, error),
                }
            }
            Err(error) => problem(StatusCode::BAD_REQUEST, error),
        }
    }

    async fn complete_oidc(
        &self,
        query: OidcCallbackQuery,
        browser: &str,
    ) -> Result<OidcCompletion> {
        ensure!(
            query.error.is_none(),
            AdministrativeApprovalSnafu {
                reason: "OIDC authorization failed"
            }
        );
        let key = query
            .state
            .ok_or_else(|| approval_error("OIDC callback has no state"))?;
        let flow = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| approval_error("administrative state is unavailable"))?;
            state.retain_live(current_utc_ns()?);
            ensure!(
                key.len() <= 256
                    && state
                        .oidc_flows
                        .get(&key)
                        .is_some_and(|flow| flow.browser == browser),
                AdministrativeApprovalSnafu {
                    reason: "OIDC state is absent or bound to another browser"
                }
            );
            state
                .oidc_flows
                .remove(&key)
                .ok_or_else(|| approval_error("OIDC state was consumed"))?
        };
        let code = query
            .code
            .ok_or_else(|| approval_error("OIDC callback has no authorization code"))?;
        let identity = self
            .oidc
            .complete(&self.config.redirect_url, code, flow.proof)
            .await?;
        let principal = principal_id(&identity.issuer, &identity.subject);
        let csrf = random_secret();
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative state is unavailable"))?;
        state.retain_live(current_utc_ns()?);
        let draft = state
            .drafts
            .get_mut(&flow.draft_id)
            .ok_or_else(|| approval_error("administrative draft expired during OIDC"))?;
        ensure!(
            draft.authentication_started
                && draft.authenticated_principal.is_none()
                && !draft.approval_started
                && draft.browser.as_deref() == Some(browser),
            AdministrativeApprovalSnafu {
                reason: "administrative authentication was completed or changed"
            }
        );
        let expiry = i64::try_from(identity.expires_ns)
            .map_err(|_| approval_error("OIDC identity expiry is invalid"))?;
        draft.expires_at_utc_ns = draft.expires_at_utc_ns.min(expiry);
        ensure!(
            current_utc_ns()? < draft.expires_at_utc_ns,
            AdministrativeApprovalSnafu {
                reason: "administrative identity expired during OIDC"
            }
        );
        draft.authenticated_principal = Some(principal);
        draft.approver = Some(identity.display);
        draft.csrf = Some(csrf.clone());
        Ok(OidcCompletion {
            activation_token: flow.activation_token,
            csrf,
        })
    }

    #[allow(clippy::result_large_err)]
    fn approve_draft(
        &self,
        activation_token: &str,
        headers: &HeaderMap,
    ) -> std::result::Result<(), tonic::Status> {
        let draft_id = {
            let now = current_utc_ns().map_err(Self::status)?;
            let mut state = self
                .state
                .lock()
                .map_err(|_| tonic::Status::unavailable("administrative state is unavailable"))?;
            state.retain_live(now);
            state
                .activation_tokens
                .get(&digest(activation_token.as_bytes()))
                .copied()
                .ok_or_else(|| {
                    tonic::Status::not_found("administrative activation is absent or expired")
                })?
        };
        let (principal, request, resolution) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| tonic::Status::unavailable("administrative state is unavailable"))?;
            let draft = state
                .drafts
                .get(&draft_id)
                .ok_or_else(|| tonic::Status::not_found("administrative draft is absent"))?;
            draft.browser(headers, &self.config.public_base_url, true)?;
            state
                .begin_approval(draft_id, current_utc_ns().map_err(Self::status)?)
                .map_err(Self::status)?
        };
        let pending = self
            .approval
            .request_resolved(principal, request, resolution)
            .map_err(Self::status)?;
        let credential = self
            .approval
            .approve(pending.request_id, principal)
            .map_err(Self::status)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| tonic::Status::unavailable("administrative state is unavailable"))?;
        let draft = state.drafts.get_mut(&draft_id).ok_or_else(|| {
            tonic::Status::internal("administrative draft disappeared after approval")
        })?;
        if draft.credential.replace(credential).is_some() {
            return Err(tonic::Status::internal(
                "administrative draft was approved twice",
            ));
        }
        Ok(())
    }

    async fn token_review(
        State(owner): State<Arc<Self>>,
        Json(mut review): Json<TokenReview>,
    ) -> Json<TokenReview> {
        let audiences = review.spec.audiences.clone();
        let authenticated = review
            .spec
            .token
            .as_deref()
            .and_then(|token| owner.approval.authenticate_credential(token).ok())
            .filter(|_| {
                audiences.as_ref().is_none_or(|values| {
                    values
                        .iter()
                        .any(|value| value == &owner.config.kubernetes_audience)
                })
            });
        review.status = Some(match authenticated {
            Some(authenticated) => {
                let approval_id = id_string(authenticated.approval_id);
                TokenReviewStatus {
                    authenticated: Some(true),
                    audiences: audiences.map(|_| vec![owner.config.kubernetes_audience.clone()]),
                    user: Some(UserInfo {
                        username: Some(format!("mithril:administrative-exec:{approval_id}")),
                        uid: Some(id_string(authenticated.principal_id)),
                        groups: Some(vec![
                            "system:authenticated".to_owned(),
                            "mithril:administrative-exec".to_owned(),
                        ]),
                        extra: Some(BTreeMap::from([(
                            APPROVAL_EXTRA_KEY.to_owned(),
                            vec![approval_id],
                        )])),
                    }),
                    error: None,
                }
            }
            None => TokenReviewStatus {
                authenticated: Some(false),
                ..Default::default()
            },
        });
        Json(review)
    }

    async fn admission_review(
        State(owner): State<Arc<Self>>,
        Json(review): Json<AdmissionReview<DynamicObject>>,
    ) -> Json<AdmissionReview<DynamicObject>> {
        let request = match review.try_into() {
            Ok(request) => request,
            Err(error) => return Json(AdmissionResponse::invalid(error).into_review()),
        };
        let response = match owner.admit_request(&request).await {
            Ok(()) => AdmissionResponse::from(&request),
            Err(error) => AdmissionResponse::from(&request).deny(error.to_string()),
        };
        Json(response.into_review())
    }

    async fn admit_request(
        &self,
        request: &kube::core::admission::AdmissionRequest<DynamicObject>,
    ) -> Result<()> {
        ensure!(
            request.operation == Operation::Connect
                && request.kind.group.is_empty()
                && request.kind.version == "v1"
                && request.kind.kind == "PodExecOptions"
                && request.resource.group.is_empty()
                && request.resource.version == "v1"
                && request.resource.resource == "pods"
                && request.sub_resource.as_deref() == Some("exec")
                && !request.uid.is_empty()
                && !request.dry_run,
            AdministrativeApprovalSnafu {
                reason: "admission request is not CONNECT pods/exec",
            }
        );
        let namespace = request
            .namespace
            .as_deref()
            .ok_or_else(|| approval_error("pods/exec admission has no namespace"))?;
        let object = request
            .object
            .as_ref()
            .ok_or_else(|| approval_error("pods/exec admission has no PodExecOptions"))?;
        let options: PodExecOptionsV1 = serde_json::from_value(object.data.clone())
            .map_err(|error| approval_error(format!("PodExecOptions is invalid: {error}")))?;
        validate_exec_options(&options)?;
        let identity = approval_identity_from_user(&request.user_info)?;
        let target = self
            .live_pod_target(
                namespace,
                &request.name,
                options.container.as_deref().unwrap_or_default(),
            )
            .await?;
        let target = self.approval.admission_target(
            identity.approval_id,
            identity.principal_id,
            request.uid.as_bytes().to_vec(),
            target.namespace,
            target.pod_uid,
            target.container_name,
            target.full_container_id,
            options
                .command
                .iter()
                .map(|argument| argument.as_bytes().to_vec())
                .collect(),
            stream_flags(options.stdin, options.stdout, options.stderr, options.tty),
        )?;
        self.approval.admit(identity.approval_id, target).await?;
        Ok(())
    }

    async fn live_pod_target(
        &self,
        namespace: &str,
        pod_name: &str,
        container_name: &str,
    ) -> Result<LivePodTarget> {
        ensure!(
            !namespace.is_empty() && !pod_name.is_empty() && !container_name.is_empty(),
            AdministrativeApprovalSnafu {
                reason: "namespace, Pod, and container are required",
            }
        );
        let pod = Api::<Pod>::namespaced(self.kube.clone(), namespace)
            .get(pod_name)
            .await
            .map_err(|error| approval_error(format!("resolve Pod: {error}")))?;
        live_pod_target(
            &pod,
            container_name,
            &self.config.node_ids_by_kubernetes_name,
        )
    }
}

impl Draft {
    fn activation_state(&self) -> &'static str {
        if self.delivered {
            "DELIVERED"
        } else if self.credential.is_some() {
            "APPROVED"
        } else if self.approval_started {
            "ATTEMPTED"
        } else {
            "PENDING"
        }
    }

    #[allow(clippy::result_large_err)]
    fn browser(
        &self,
        headers: &HeaderMap,
        origin: &str,
        mutation: bool,
    ) -> std::result::Result<(), tonic::Status> {
        let mut origins = headers.get_all(axum::http::header::ORIGIN).iter();
        let supplied = origins.next();
        let browser = ClientAuth::cookie(headers, "araphor-approval")
            .map_err(AdministrativeHttpOwner::status)?;
        let mut values = headers.get_all("x-araphor-csrf").iter();
        let csrf = values.next().and_then(|value| value.to_str().ok());
        if supplied.is_none_or(|value| value != origin)
            || origins.next().is_some()
            || browser.is_none()
            || browser != self.browser.as_deref()
            || (mutation
                && (csrf.is_none() || csrf != self.csrf.as_deref() || values.next().is_some()))
        {
            return Err(tonic::Status::permission_denied(
                "administrative browser binding or CSRF is invalid",
            ));
        }
        Ok(())
    }
}

impl HttpState {
    fn begin_approval(
        &mut self,
        draft_id: Id128V1,
        now: i64,
    ) -> Result<(
        Id128V1,
        AdministrativeExecRequestV1,
        AdministrativeExecResolution,
    )> {
        self.retain_live(now);
        let draft = self
            .drafts
            .get_mut(&draft_id)
            .ok_or_else(|| approval_error("administrative draft expired during OIDC"))?;
        let principal = draft
            .authenticated_principal
            .ok_or_else(|| approval_error("administrative draft has no authenticated approver"))?;
        ensure!(
            !draft.approval_started && draft.credential.is_none() && !draft.delivered,
            AdministrativeApprovalSnafu {
                reason: "administrative draft is already being approved",
            }
        );
        draft.approval_started = true;
        Ok((principal, draft.request.clone(), draft.resolution.clone()))
    }

    fn retain_live(&mut self, now: i64) {
        let live = self
            .drafts
            .iter()
            .filter_map(|(id, draft)| (draft.expires_at_utc_ns >= now).then_some(*id))
            .collect::<std::collections::BTreeSet<_>>();
        self.drafts.retain(|id, _| live.contains(id));
        self.activation_tokens.retain(|_, id| live.contains(id));
        self.poll_tokens.retain(|_, id| live.contains(id));
        self.oidc_flows
            .retain(|_, flow| live.contains(&flow.draft_id));
    }
}

fn live_pod_target(
    pod: &Pod,
    container_name: &str,
    node_ids: &BTreeMap<String, String>,
) -> Result<LivePodTarget> {
    let namespace = pod
        .namespace()
        .ok_or_else(|| approval_error("Pod has no namespace"))?;
    let pod_uid = pod
        .metadata
        .uid
        .as_deref()
        .ok_or_else(|| approval_error("Pod has no UID"))?;
    let node_name = pod
        .spec
        .as_ref()
        .and_then(|spec| spec.node_name.as_deref())
        .ok_or_else(|| approval_error("Pod is not assigned to a node"))?;
    let node_id = node_ids
        .get(node_name)
        .cloned()
        .ok_or_else(|| approval_error("Pod node has no enrolled Mithril node ID"))?;
    let status = pod
        .status
        .as_ref()
        .ok_or_else(|| approval_error("Pod has no runtime status"))?;
    let container_id = status
        .container_statuses
        .iter()
        .flatten()
        .chain(status.init_container_statuses.iter().flatten())
        .chain(status.ephemeral_container_statuses.iter().flatten())
        .find(|status| status.name == container_name)
        .and_then(|status| status.container_id.as_deref())
        .ok_or_else(|| approval_error("container has no live runtime ID"))?;
    let (_, full_container_id) = container_id
        .split_once("://")
        .ok_or_else(|| approval_error("container runtime ID has no scheme"))?;
    ensure!(
        (32..=128).contains(&full_container_id.len()),
        AdministrativeApprovalSnafu {
            reason: "container runtime ID is outside the approved bound",
        }
    );
    Ok(LivePodTarget {
        node_id,
        namespace: namespace.into_bytes(),
        pod_uid: pod_uid.as_bytes().to_vec(),
        container_name: container_name.as_bytes().to_vec(),
        full_container_id: full_container_id.as_bytes().to_vec(),
    })
}

fn validate_draft(request: &AdministrativeExecDraftRequest) -> Result<()> {
    ensure!(
        (1..=253).contains(&request.namespace.len())
            && (1..=253).contains(&request.pod.len())
            && (1..=253).contains(&request.container.len())
            && !request.argv.is_empty()
            && request.argv.len() <= 256
            && !request.argv[0].is_empty()
            && request
                .argv
                .iter()
                .all(|value| value.len() <= 4096 && !value.contains('\0'))
            && (1..=4096).contains(&request.argv.iter().map(String::len).sum::<usize>())
            && (request.stdin || request.stdout || request.stderr)
            && (!request.tty || (request.stdin && request.stdout && !request.stderr)),
        AdministrativeApprovalSnafu {
            reason: "administrative exec request or stream shape is invalid",
        }
    );
    Ok(())
}

fn validate_exec_options(options: &PodExecOptionsV1) -> Result<()> {
    let valid_type_metadata = match (&options.api_version, &options.kind) {
        (None, None) => true,
        (Some(api_version), Some(kind)) => api_version == "v1" && kind == "PodExecOptions",
        _ => false,
    };
    ensure!(
        valid_type_metadata
            && options
                .container
                .as_ref()
                .is_some_and(|value| !value.is_empty())
            && !options.command.is_empty()
            && options.command.len() <= 256
            && !options.command[0].is_empty()
            && options
                .command
                .iter()
                .all(|value| value.len() <= 4096 && !value.contains('\0'))
            && (1..=4096).contains(&options.command.iter().map(String::len).sum::<usize>())
            && (options.stdin || options.stdout || options.stderr)
            && (!options.tty || (options.stdin && options.stdout && !options.stderr)),
        AdministrativeApprovalSnafu {
            reason: "PodExecOptions is incomplete or outside the approved bounds",
        }
    );
    Ok(())
}

fn approval_identity_from_user(user: &UserInfo) -> Result<AdmissionIdentity> {
    let values = user
        .extra
        .as_ref()
        .and_then(|extra| extra.get(APPROVAL_EXTRA_KEY))
        .ok_or_else(|| approval_error("admission identity has no Mithril approval ID"))?;
    ensure!(
        values.len() == 1
            && user.username.as_deref()
                == Some(&format!("mithril:administrative-exec:{}", values[0]))
            && user.groups.as_ref().is_some_and(|groups| {
                groups
                    .iter()
                    .any(|group| group == "mithril:administrative-exec")
            }),
        AdministrativeApprovalSnafu {
            reason: "admission identity does not match one Mithril approval",
        }
    );
    Ok(AdmissionIdentity {
        approval_id: parse_id(&values[0])?,
        principal_id: parse_id(
            user.uid
                .as_deref()
                .ok_or_else(|| approval_error("admission identity has no principal ID"))?,
        )?,
    })
}

fn principal_id(issuer: &str, subject: &str) -> Id128V1 {
    let mut hash = Sha256::new();
    hash.update(issuer.as_bytes());
    hash.update([0]);
    hash.update(subject.as_bytes());
    let digest = hash.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    if bytes == [0; 16] {
        bytes[15] = 1;
    }
    let value = u128::from_be_bytes(bytes);
    Id128V1::new((value >> 64) as u64, value as u64)
}

fn stream_flags(stdin: bool, stdout: bool, stderr: bool, tty: bool) -> u8 {
    u8::from(stdin) | (u8::from(stdout) << 1) | (u8::from(stderr) << 2) | (u8::from(tty) << 3)
}

fn random_id() -> Id128V1 {
    let value = u128::from_be_bytes(*Uuid::new_v4().as_bytes());
    Id128V1::new((value >> 64) as u64, value as u64)
}

fn random_secret() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn id_string(value: Id128V1) -> String {
    Uuid::from_u128((u128::from(value.high) << 64) | u128::from(value.low)).to_string()
}

fn parse_id(value: &str) -> Result<Id128V1> {
    let uuid = Uuid::parse_str(value)
        .map_err(|error| approval_error(format!("approval ID is invalid: {error}")))?;
    ensure!(
        uuid.hyphenated().to_string() == value,
        AdministrativeApprovalSnafu {
            reason: "approval ID is not canonical",
        }
    );
    let value = uuid.as_u128();
    let id = Id128V1::new((value >> 64) as u64, value as u64);
    ensure!(
        !id.is_zero(),
        AdministrativeApprovalSnafu {
            reason: "approval ID is zero",
        }
    );
    Ok(id)
}

fn current_utc_ns() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| approval_error(format!("system clock precedes Unix epoch: {error}")))?;
    i64::try_from(duration.as_nanos())
        .map_err(|error| approval_error(format!("system clock exceeds i64 nanoseconds: {error}")))
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[derive(Serialize)]
struct ProblemV1 {
    error: String,
}

fn problem(status: StatusCode, error: crate::Error) -> Response {
    (
        status,
        Json(ProblemV1 {
            error: error.to_string(),
        }),
    )
        .into_response()
}

fn approval_error(reason: impl Into<String>) -> crate::Error {
    AdministrativeApprovalSnafu {
        reason: reason.into(),
    }
    .build()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::SigningKey;
    use erebor_interceptor_abi::Id128V1;
    use k8s_openapi::api::authentication::v1::UserInfo;
    use serde_json::json;

    use super::{
        approval_identity_from_user, html_escape, principal_id, stream_flags,
        validate_exec_options, Draft, HttpState, PodExecOptionsV1, APPROVAL_EXTRA_KEY,
    };
    use crate::{
        AdministrativeExecRequestV1, AllowedNodeIdentity, ControlPlane, ControlStore,
        NodeDecommissionAuthorizationV1, NodeDecommissionHttpOwner, SignedNodeDecommissionV1,
        TrustGenerationV1,
    };

    #[tokio::test]
    async fn decommission_https_owner_accepts_only_its_cluster_artifact(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let proof = crate::startup_absence_proof_digest("node-a", &[1; 16], 1, true, true);
        store.register_node_physical_session(
            "node-a",
            &[1; 16],
            1,
            Some("worker-a.example"),
            &proof,
            true,
            true,
            1,
        )?;
        let control = ControlPlane::with_control_store(
            vec![AllowedNodeIdentity {
                node_id: "node-a".to_owned(),
                certificate_sha256: "a".repeat(64),
                tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            }],
            TrustGenerationV1 {
                generation: 1,
                bundle_digest: "b".repeat(64),
                policy_issuer_sequence_epoch: 0,
                policy_signers: Vec::new(),
            },
            store,
        )?;
        let owner =
            NodeDecommissionHttpOwner::new("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", control)?;
        let signed = |cluster| {
            SignedNodeDecommissionV1::sign(
                &NodeDecommissionAuthorizationV1::new(
                    cluster,
                    "node-a".to_owned(),
                    "01010101-0101-0101-0101-010101010101",
                    i64::MAX,
                    "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                )?,
                "offline-decommission-v1".to_owned(),
                &SigningKey::from_bytes(&[7; 32]),
            )?
            .to_bytes()
        };
        assert!(owner
            .submit(signed("dddddddd-dddd-4ddd-8ddd-dddddddddddd")?)
            .await
            .is_err());
        let status = owner
            .submit(signed("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")?)
            .await?;
        assert_eq!(owner.status(&status.artifact_sha256)?, status);
        Ok(())
    }

    #[test]
    fn principal_identity_is_stable_and_issuer_scoped() {
        assert_eq!(
            principal_id("https://idp.example", "alice"),
            principal_id("https://idp.example", "alice")
        );
        assert_ne!(
            principal_id("https://idp.example", "alice"),
            principal_id("https://other.example", "alice")
        );
        assert_ne!(
            principal_id("https://idp.example", "alice"),
            principal_id("https://idp.example", "bob")
        );
    }

    #[test]
    fn exact_stream_flags_match_the_signed_contract() {
        assert_eq!(stream_flags(true, true, false, true), 0b1011);
        assert_eq!(stream_flags(false, true, true, false), 0b0110);
    }

    #[test]
    fn pod_exec_options_accept_kubernetes_type_metadata() {
        let options = serde_json::from_value::<PodExecOptionsV1>(json!({
            "apiVersion": "v1",
            "kind": "PodExecOptions",
            "command": ["/var/lib/mithril/admin-exec", "sleep", "20"],
            "container": "runtime",
            "stdout": true,
            "stderr": true,
        }));
        assert!(options.is_ok());
        if let Ok(options) = options {
            assert!(validate_exec_options(&options).is_ok());
        }

        let without_type_metadata = serde_json::from_value::<PodExecOptionsV1>(json!({
            "command": ["/var/lib/mithril/admin-exec"],
            "container": "runtime",
            "stdout": true,
        }));
        assert!(without_type_metadata.is_ok());
        if let Ok(without_type_metadata) = without_type_metadata {
            assert!(validate_exec_options(&without_type_metadata).is_ok());
        }

        let partial = serde_json::from_value::<PodExecOptionsV1>(json!({
            "apiVersion": "v1",
            "command": ["/var/lib/mithril/admin-exec"],
            "container": "runtime",
            "stdout": true,
        }));
        assert!(partial.is_ok());
        if let Ok(partial) = partial {
            assert!(validate_exec_options(&partial).is_err());
        }

        let mismatched = serde_json::from_value::<PodExecOptionsV1>(json!({
            "apiVersion": "v1",
            "kind": "PodAttachOptions",
            "command": ["/var/lib/mithril/admin-exec"],
            "container": "runtime",
            "stdout": true,
        }));
        assert!(mismatched.is_ok());
        if let Ok(mismatched) = mismatched {
            assert!(validate_exec_options(&mismatched).is_err());
        }
    }

    #[test]
    fn activation_page_escapes_untrusted_display_text() {
        assert_eq!(
            html_escape("<script>'x' & \"y\"</script>"),
            "&lt;script&gt;&#39;x&#39; &amp; &quot;y&quot;&lt;/script&gt;"
        );
    }

    #[test]
    fn one_draft_starts_only_one_approval() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let draft_id = Id128V1::new(1, 1);
        let mut state = HttpState::default();
        state.drafts.insert(
            draft_id,
            Draft {
                pod_name: "pod".into(),
                request: AdministrativeExecRequestV1 {
                    node_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                    namespace: b"default".to_vec(),
                    pod_uid: b"pod".to_vec(),
                    container_name: b"app".to_vec(),
                    full_container_id: vec![b'a'; 64],
                    container_generation: 0,
                    argv: vec![b"/bin/sh".to_vec()],
                    stream_flags: 0b0110,
                    approved_role_id: "administrative-diagnostic".to_owned(),
                },
                resolution: Default::default(),
                expires_at_utc_ns: 10,
                credential: None,
                authenticated_principal: Some(Id128V1::new(2, 2)),
                approver: Some("operator".into()),
                browser: Some("a".repeat(64)),
                csrf: Some("b".repeat(64)),
                authentication_started: true,
                approval_started: false,
                delivered: false,
            },
        );
        let draft = state.drafts.get(&draft_id).ok_or("draft is absent")?;
        assert_eq!(draft.activation_state(), "PENDING");
        let mut headers = axum::http::HeaderMap::new();
        assert!(draft
            .browser(&headers, "https://control.example", true)
            .is_err());
        headers.insert("origin", "https://control.example".parse()?);
        headers.insert(
            "cookie",
            format!("araphor-approval={}", "a".repeat(64)).parse()?,
        );
        draft.browser(&headers, "https://control.example", false)?;
        assert!(draft
            .browser(&headers, "https://control.example", true)
            .is_err());
        headers.insert("x-araphor-csrf", "b".repeat(64).parse()?);
        draft.browser(&headers, "https://control.example", true)?;
        assert!(draft
            .browser(&headers, "https://foreign.example", true)
            .is_err());
        headers.append("x-araphor-csrf", "b".repeat(64).parse()?);
        assert!(draft
            .browser(&headers, "https://control.example", true)
            .is_err());
        headers.remove("x-araphor-csrf");
        headers.insert(
            "cookie",
            format!("araphor-approval={}", "c".repeat(64)).parse()?,
        );
        assert!(draft
            .browser(&headers, "https://control.example", false)
            .is_err());
        assert!(state.begin_approval(draft_id, 1).is_ok());
        assert!(state.begin_approval(draft_id, 1).is_err());
        let draft = state.drafts.get_mut(&draft_id).ok_or("draft is absent")?;
        assert_eq!(draft.activation_state(), "ATTEMPTED");
        draft.delivered = true;
        assert_eq!(draft.activation_state(), "DELIVERED");
        Ok(())
    }

    #[test]
    fn admission_identity_requires_the_approval_group_and_principal() {
        let approval = "aaaaaaaa-0000-0000-0000-000000000001";
        let principal = "bbbbbbbb-0000-0000-0000-000000000002";
        let mut user = UserInfo {
            username: Some(format!("mithril:administrative-exec:{approval}")),
            uid: Some(principal.to_owned()),
            groups: Some(vec!["mithril:administrative-exec".to_owned()]),
            extra: Some(BTreeMap::from([(
                APPROVAL_EXTRA_KEY.to_owned(),
                vec![approval.to_owned()],
            )])),
        };
        assert_eq!(
            approval_identity_from_user(&user)
                .map(|identity| (identity.approval_id, identity.principal_id))
                .ok(),
            Some((
                Id128V1::new(0xaaaaaaaa00000000, 1),
                Id128V1::new(0xbbbbbbbb00000000, 2),
            ))
        );
        user.groups = Some(Vec::new());
        assert!(approval_identity_from_user(&user).is_err());
    }
}
