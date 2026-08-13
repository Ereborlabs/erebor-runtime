use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use erebor_interceptor_abi::Id128V1;
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewStatus, UserInfo};
use k8s_openapi::api::core::v1::Pod;
use kube::api::Api;
use kube::core::admission::{AdmissionResponse, AdmissionReview, Operation};
use kube::core::DynamicObject;
use kube::{Client, ResourceExt as _};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse as _, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ensure;
use uuid::Uuid;

use crate::error::AdministrativeApprovalSnafu;
use crate::{
    AdministrativeApprovalConfigV1, AdministrativeApprovalOwner, AdministrativeExecCredentialV1,
    AdministrativeExecRequestV1, AdministrativeExecResolution, ControlPlane, Result,
};

const APPROVAL_EXTRA_KEY: &str = "mithril.ereborlabs.com/approval-id";
const MAX_PENDING_REQUESTS: usize = 4096;

type ConfiguredOidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrativeHttpConfigV1 {
    pub listen: SocketAddr,
    pub public_base_url: String,
    pub tls_certificate_path: PathBuf,
    pub tls_private_key_path: PathBuf,
    pub oidc_issuer_url: String,
    pub oidc_client_id: String,
    pub oidc_client_secret_path: Option<PathBuf>,
    pub oidc_ca_path: Option<PathBuf>,
    pub kubernetes_audience: String,
    pub kubernetes_webhook_token_path: PathBuf,
    pub node_ids_by_kubernetes_name: BTreeMap<String, String>,
    pub request_lifetime_seconds: u64,
    pub approval: AdministrativeApprovalConfigV1,
}

impl AdministrativeHttpConfigV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        let public_url = reqwest::Url::parse(&self.public_base_url).ok();
        ensure!(
            public_url.as_ref().is_some_and(|url| {
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none()
            }) && !self.public_base_url.ends_with('/')
                && !self.oidc_client_id.is_empty()
                && self
                    .oidc_ca_path
                    .as_ref()
                    .is_none_or(|path| path.is_absolute())
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
                reason: "administrative HTTPS configuration is invalid",
            }
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrativeExecDraftRequestV1 {
    pub namespace: String,
    pub pod: String,
    pub container: String,
    pub argv: Vec<String>,
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
    pub tty: bool,
    pub approved_role_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrativeExecDraftResponseV1 {
    pub activation_url: String,
    pub activation_code: String,
    pub poll_token: String,
    pub expires_at_utc_ns: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrativeExecPollResponseV1 {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_utc_ns: Option<i64>,
}

pub struct AdministrativeHttpOwner {
    config: PreparedHttpConfig,
    approval: AdministrativeApprovalOwner,
    kube: Client,
    provider: CoreProviderMetadata,
    http: reqwest::Client,
    state: Mutex<HttpState>,
}

struct PreparedHttpConfig {
    public_base_url: String,
    cluster_uid: String,
    oidc_client_id: String,
    oidc_client_secret: Option<String>,
    redirect_url: String,
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
    request: AdministrativeExecRequestV1,
    resolution: AdministrativeExecResolution,
    expires_at_utc_ns: i64,
    credential: Option<AdministrativeExecCredentialV1>,
    authenticated_principal: Option<Id128V1>,
    authentication_started: bool,
    approval_started: bool,
    delivered: bool,
}

struct OidcFlow {
    draft_id: Id128V1,
    activation_token: String,
    nonce: String,
    pkce_verifier: String,
}

struct OidcCompletion {
    activation_token: String,
    display: String,
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
    pub async fn load(config: &AdministrativeHttpConfigV1, control: ControlPlane) -> Result<Self> {
        config.validate()?;
        let mut http = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());
        if let Some(path) = &config.oidc_ca_path {
            let pem = std::fs::read(path).map_err(|error| {
                approval_error(format!("read OIDC CA `{}`: {error}", path.display()))
            })?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|error| approval_error(format!("parse OIDC CA: {error}")))?;
            http = http.add_root_certificate(certificate);
        }
        let http = http
            .build()
            .map_err(|error| approval_error(format!("build OIDC HTTP client: {error}")))?;
        let provider = CoreProviderMetadata::discover_async(
            IssuerUrl::new(config.oidc_issuer_url.clone())
                .map_err(|error| approval_error(format!("OIDC issuer URL is invalid: {error}")))?,
            &http,
        )
        .await
        .map_err(|error| approval_error(format!("OIDC discovery failed: {error}")))?;
        let oidc_client_secret = config
            .oidc_client_secret_path
            .as_ref()
            .map(|path| {
                std::fs::read_to_string(path)
                    .map(|value| value.trim().to_owned())
                    .map_err(|error| {
                        approval_error(format!(
                            "read OIDC client secret `{}`: {error}",
                            path.display()
                        ))
                    })
            })
            .transpose()?;
        if oidc_client_secret.as_deref().is_some_and(str::is_empty) {
            return AdministrativeApprovalSnafu {
                reason: "OIDC client secret is empty",
            }
            .fail();
        }
        let kube = Client::try_default()
            .await
            .map_err(|error| approval_error(format!("load Kubernetes client: {error}")))?;
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
                public_base_url: config.public_base_url.clone(),
                cluster_uid: config.approval.cluster_uid.clone(),
                oidc_client_id: config.oidc_client_id.clone(),
                oidc_client_secret,
                redirect_url: format!("{}/oidc/callback", config.public_base_url),
                kubernetes_audience: config.kubernetes_audience.clone(),
                kubernetes_webhook_token,
                node_ids_by_kubernetes_name: config.node_ids_by_kubernetes_name.clone(),
                request_lifetime_ns: i64::try_from(config.request_lifetime_seconds * 1_000_000_000)
                    .map_err(|error| {
                        approval_error(format!("request lifetime overflow: {error}"))
                    })?,
            },
            approval: AdministrativeApprovalOwner::load(&config.approval, control)?,
            kube,
            provider,
            http,
            state: Mutex::new(HttpState::default()),
        })
    }

    fn router(self: Arc<Self>) -> Router {
        let authentication_path = format!(
            "/kubernetes/{}/authenticate",
            self.config.kubernetes_webhook_token
        );
        let admission_path = format!("/kubernetes/{}/admit", self.config.kubernetes_webhook_token);
        Router::new()
            .route(
                "/v1/administrative-exec/requests",
                post(Self::create_request),
            )
            .route(
                "/v1/administrative-exec/requests/:poll_token",
                get(Self::poll_request),
            )
            .route("/activate/:activation_token", get(Self::activation_page))
            .route(
                "/activate/:activation_token/authorize",
                get(Self::begin_authorization),
            )
            .route(
                "/activate/:activation_token/approve",
                post(Self::approve_request),
            )
            .route("/oidc/callback", get(Self::oidc_callback))
            .route(&authentication_path, post(Self::token_review))
            .route(&admission_path, post(Self::admission_review))
            .layer(DefaultBodyLimit::max(64 * 1024))
            .with_state(self)
    }

    async fn create_request(
        State(owner): State<Arc<Self>>,
        Json(request): Json<AdministrativeExecDraftRequestV1>,
    ) -> Response {
        match owner.create_draft(request).await {
            Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
            Err(error) => problem(StatusCode::BAD_REQUEST, error),
        }
    }

    async fn create_draft(
        &self,
        request: AdministrativeExecDraftRequestV1,
    ) -> Result<AdministrativeExecDraftResponseV1> {
        validate_draft(&request)?;
        let target = self
            .live_pod_target(&request.namespace, &request.pod, &request.container)
            .await?;
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
                request,
                resolution,
                expires_at_utc_ns,
                credential: None,
                authenticated_principal: None,
                authentication_started: false,
                approval_started: false,
                delivered: false,
            },
        );
        Ok(AdministrativeExecDraftResponseV1 {
            activation_url: format!(
                "{}/activate/{activation_token}",
                self.config.public_base_url
            ),
            activation_code: activation_token[..8].to_ascii_uppercase(),
            poll_token,
            expires_at_utc_ns,
        })
    }

    async fn poll_request(
        State(owner): State<Arc<Self>>,
        Path(poll_token): Path<String>,
    ) -> Response {
        let now = match current_utc_ns() {
            Ok(value) => value,
            Err(error) => return problem(StatusCode::INTERNAL_SERVER_ERROR, error),
        };
        let mut state = match owner.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    approval_error("administrative HTTP state is poisoned"),
                );
            }
        };
        state.retain_live(now);
        let Some(draft_id) = state
            .poll_tokens
            .get(&digest(poll_token.as_bytes()))
            .copied()
        else {
            return problem(
                StatusCode::NOT_FOUND,
                approval_error("administrative request is missing or expired"),
            );
        };
        let Some(draft) = state.drafts.get_mut(&draft_id) else {
            return problem(
                StatusCode::NOT_FOUND,
                approval_error("administrative request is missing"),
            );
        };
        if draft.delivered {
            return problem(
                StatusCode::GONE,
                approval_error("administrative credential was already delivered"),
            );
        }
        let Some(credential) = draft.credential.take() else {
            return (
                StatusCode::ACCEPTED,
                Json(AdministrativeExecPollResponseV1 {
                    state: "PENDING".to_owned(),
                    credential: None,
                    approval_id: None,
                    expires_at_utc_ns: Some(draft.expires_at_utc_ns),
                }),
            )
                .into_response();
        };
        draft.delivered = true;
        (
            StatusCode::OK,
            Json(AdministrativeExecPollResponseV1 {
                state: "APPROVED".to_owned(),
                credential: Some(credential.credential),
                approval_id: Some(id_string(credential.approval_id)),
                expires_at_utc_ns: Some(credential.expires_at_utc_ns),
            }),
        )
            .into_response()
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

    fn render_activation(&self, activation_token: &str) -> Result<String> {
        let now = current_utc_ns()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative HTTP state is poisoned"))?;
        state.retain_live(now);
        let draft_id = state
            .activation_tokens
            .get(&digest(activation_token.as_bytes()))
            .copied()
            .ok_or_else(|| approval_error("administrative activation is missing or expired"))?;
        let draft = state
            .drafts
            .get(&draft_id)
            .ok_or_else(|| approval_error("administrative draft is missing"))?;
        let resolution = &draft.resolution;
        let argv = resolution
            .argv
            .iter()
            .map(|value| html_escape(&String::from_utf8_lossy(value)))
            .collect::<Vec<_>>()
            .join(" ");
        let path = resolution
            .resolved_executable
            .as_ref()
            .map(|value| html_escape(&String::from_utf8_lossy(&value.resolved_display_path)))
            .unwrap_or_else(|| "unavailable".to_owned());
        Ok(format!(
            "<!doctype html><meta charset=utf-8><title>Mithril administrative exec</title>\
             <h1>Review one administrative exec</h1>\
             <dl><dt>Cluster</dt><dd>{}</dd><dt>Namespace</dt><dd>{}</dd><dt>Pod UID</dt><dd>{}</dd>\
             <dt>Container</dt><dd>{}</dd><dt>Command</dt><dd><code>{argv}</code></dd>\
             <dt>Resolved executable</dt><dd><code>{path}</code></dd>\
             <dt>Streams</dt><dd>{}</dd><dt>Role</dt><dd>{}</dd></dl>\
             <p>Risk: the first restricted runtime root with the same live container, executable, and arguments can consume the approval. Linux cannot compare the Kubernetes stream settings.</p>\
             <p>Sign in first. The next page shows the authenticated approver before approval.</p>\
             <p><a href=\"/activate/{}/authorize\">Sign in to review</a></p>",
            html_escape(&self.config.cluster_uid),
            html_escape(&String::from_utf8_lossy(&resolution.namespace)),
            html_escape(&String::from_utf8_lossy(&resolution.pod_uid)),
            html_escape(&String::from_utf8_lossy(&resolution.container_name)),
            resolution.stream_flags,
            html_escape(&resolution.approved_role_id),
            html_escape(activation_token),
        ))
    }

    async fn begin_authorization(
        State(owner): State<Arc<Self>>,
        Path(activation_token): Path<String>,
    ) -> Response {
        match owner.authorization_url(&activation_token) {
            Ok(url) => Redirect::to(&url).into_response(),
            Err(error) => problem(StatusCode::BAD_REQUEST, error),
        }
    }

    fn authorization_url(&self, activation_token: &str) -> Result<String> {
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
        let client = self.oidc_client()?;
        let csrf = CsrfToken::new(random_secret());
        let nonce = Nonce::new(random_secret());
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, csrf, nonce) = client
            .authorize_url(CoreAuthenticationFlow::AuthorizationCode, || csrf, || nonce)
            .add_scope(Scope::new("email".to_owned()))
            .add_scope(Scope::new("profile".to_owned()))
            .set_pkce_challenge(challenge)
            .url();
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
        state.oidc_flows.insert(
            csrf.secret().clone(),
            OidcFlow {
                draft_id,
                activation_token: activation_token.to_owned(),
                nonce: nonce.secret().clone(),
                pkce_verifier: verifier.secret().clone(),
            },
        );
        Ok(url.to_string())
    }

    async fn oidc_callback(
        State(owner): State<Arc<Self>>,
        Query(query): Query<OidcCallbackQuery>,
    ) -> Response {
        match owner.complete_oidc(query).await {
            Ok(completion) => owner
                .render_confirmation(&completion.activation_token, &completion.display)
                .map(Html)
                .map(IntoResponse::into_response)
                .unwrap_or_else(|error| problem(StatusCode::BAD_REQUEST, error)),
            Err(error) => problem(StatusCode::BAD_REQUEST, error),
        }
    }

    async fn complete_oidc(&self, query: OidcCallbackQuery) -> Result<OidcCompletion> {
        ensure!(
            query.error.is_none(),
            AdministrativeApprovalSnafu {
                reason: format!(
                    "OIDC authorization failed: {}",
                    query.error.unwrap_or_default()
                ),
            }
        );
        let state_value = query
            .state
            .ok_or_else(|| approval_error("OIDC callback has no state"))?;
        let flow = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative HTTP state is poisoned"))?
            .oidc_flows
            .remove(&state_value)
            .ok_or_else(|| approval_error("OIDC state is missing or replayed"))?;
        let code = query
            .code
            .ok_or_else(|| approval_error("OIDC callback has no authorization code"))?;
        let client = self.oidc_client()?;
        let token = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|error| {
                approval_error(format!("OIDC token endpoint is unavailable: {error}"))
            })?
            .set_pkce_verifier(PkceCodeVerifier::new(flow.pkce_verifier))
            .request_async(&self.http)
            .await
            .map_err(|error| approval_error(format!("OIDC code exchange failed: {error}")))?;
        let id_token = token
            .extra_fields()
            .id_token()
            .ok_or_else(|| approval_error("OIDC provider returned no ID token"))?;
        let verifier = client.id_token_verifier();
        let claims = id_token
            .claims(&verifier, &Nonce::new(flow.nonce))
            .map_err(|error| approval_error(format!("OIDC ID token is invalid: {error}")))?;
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                token.access_token(),
                id_token.signing_alg().map_err(|error| {
                    approval_error(format!("OIDC signing algorithm is invalid: {error}"))
                })?,
                id_token.signing_key(&verifier).map_err(|error| {
                    approval_error(format!("OIDC signing key is invalid: {error}"))
                })?,
            )
            .map_err(|error| approval_error(format!("OIDC access-token hash failed: {error}")))?;
            ensure!(
                &actual == expected,
                AdministrativeApprovalSnafu {
                    reason: "OIDC access token does not match the ID token",
                }
            );
        }
        let principal = principal_id(self.provider.issuer().as_str(), claims.subject().as_str());
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative HTTP state is poisoned"))?;
        state.retain_live(current_utc_ns()?);
        let draft = state
            .drafts
            .get_mut(&flow.draft_id)
            .ok_or_else(|| approval_error("administrative draft expired during OIDC"))?;
        ensure!(
            draft.authentication_started
                && draft.authenticated_principal.is_none()
                && !draft.approval_started,
            AdministrativeApprovalSnafu {
                reason: "administrative authentication was already completed",
            }
        );
        draft.authenticated_principal = Some(principal);
        Ok(OidcCompletion {
            activation_token: flow.activation_token,
            display: claims
                .email()
                .map_or_else(|| claims.subject().as_str(), |email| email.as_str())
                .to_owned(),
        })
    }

    fn render_confirmation(&self, activation_token: &str, approver: &str) -> Result<String> {
        let now = current_utc_ns()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative HTTP state is poisoned"))?;
        state.retain_live(now);
        let draft_id = state
            .activation_tokens
            .get(&digest(activation_token.as_bytes()))
            .copied()
            .ok_or_else(|| approval_error("administrative activation is missing or expired"))?;
        let draft = state
            .drafts
            .get(&draft_id)
            .ok_or_else(|| approval_error("administrative draft is missing"))?;
        ensure!(
            draft.authenticated_principal.is_some() && !draft.approval_started,
            AdministrativeApprovalSnafu {
                reason: "administrative draft is not ready for approval",
            }
        );
        let resolution = &draft.resolution;
        let argv = resolution
            .argv
            .iter()
            .map(|value| html_escape(&String::from_utf8_lossy(value)))
            .collect::<Vec<_>>()
            .join(" ");
        let path = resolution
            .resolved_executable
            .as_ref()
            .map(|value| html_escape(&String::from_utf8_lossy(&value.resolved_display_path)))
            .unwrap_or_else(|| "unavailable".to_owned());
        Ok(format!(
            "<!doctype html><meta charset=utf-8><title>Mithril approval</title>\
             <h1>Approve one administrative exec</h1>\
             <dl><dt>Approver</dt><dd>{}</dd><dt>Cluster</dt><dd>{}</dd>\
             <dt>Namespace</dt><dd>{}</dd><dt>Pod UID</dt><dd>{}</dd>\
             <dt>Container</dt><dd>{}</dd><dt>Command</dt><dd><code>{argv}</code></dd>\
             <dt>Resolved executable</dt><dd><code>{path}</code></dd>\
             <dt>Streams</dt><dd>{}</dd><dt>Role</dt><dd>{}</dd></dl>\
             <p>Another restricted runtime root with the same live container, executable, and arguments can consume this one-use slot first. Stream settings are checked here but are not a Linux-task match field.</p>\
             <form method=post action=\"/activate/{}/approve\"><button type=submit>I accept this race and approve once</button></form>",
            html_escape(approver),
            html_escape(&self.config.cluster_uid),
            html_escape(&String::from_utf8_lossy(&resolution.namespace)),
            html_escape(&String::from_utf8_lossy(&resolution.pod_uid)),
            html_escape(&String::from_utf8_lossy(&resolution.container_name)),
            resolution.stream_flags,
            html_escape(&resolution.approved_role_id),
            html_escape(activation_token),
        ))
    }

    async fn approve_request(
        State(owner): State<Arc<Self>>,
        Path(activation_token): Path<String>,
    ) -> Response {
        match owner.approve_draft(&activation_token) {
            Ok(()) => Html(
                "<!doctype html><meta charset=utf-8><title>Mithril approval complete</title>\
                 <h1>Administrative exec approved</h1><p>Return to the terminal.</p>",
            )
            .into_response(),
            Err(error) => problem(StatusCode::BAD_REQUEST, error),
        }
    }

    fn approve_draft(&self, activation_token: &str) -> Result<()> {
        let draft_id = {
            let now = current_utc_ns()?;
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
        let (principal, request, resolution) = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative HTTP state is poisoned"))?
            .begin_approval(draft_id, current_utc_ns()?)?;
        let pending = self
            .approval
            .request_resolved(principal, request, resolution)?;
        let credential = self.approval.approve(pending.request_id, principal)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative HTTP state is poisoned"))?;
        let draft = state
            .drafts
            .get_mut(&draft_id)
            .ok_or_else(|| approval_error("administrative draft disappeared after approval"))?;
        ensure!(
            draft.credential.replace(credential).is_none(),
            AdministrativeApprovalSnafu {
                reason: "administrative draft was approved twice",
            }
        );
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

    fn oidc_client(&self) -> Result<ConfiguredOidcClient> {
        let secret = self
            .config
            .oidc_client_secret
            .as_ref()
            .map(|value| ClientSecret::new(value.clone()));
        Ok(CoreClient::from_provider_metadata(
            self.provider.clone(),
            ClientId::new(self.config.oidc_client_id.clone()),
            secret,
        )
        .set_redirect_uri(
            RedirectUrl::new(self.config.redirect_url.clone()).map_err(|error| {
                approval_error(format!("OIDC redirect URL is invalid: {error}"))
            })?,
        ))
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

pub async fn serve_administrative_http(
    config: AdministrativeHttpConfigV1,
    control: ControlPlane,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let owner = Arc::new(AdministrativeHttpOwner::load(&config, control).await?);
    let tls =
        RustlsConfig::from_pem_file(&config.tls_certificate_path, &config.tls_private_key_path)
            .await
            .map_err(|error| {
                approval_error(format!("load administrative TLS identity: {error}"))
            })?;
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    axum_server::bind_rustls(config.listen, tls)
        .handle(handle)
        .serve(owner.router().into_make_service())
        .await
        .map_err(|error| approval_error(format!("administrative HTTPS server failed: {error}")))
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

fn validate_draft(request: &AdministrativeExecDraftRequestV1) -> Result<()> {
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
    ensure!(
        options
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

    use erebor_interceptor_abi::Id128V1;
    use k8s_openapi::api::authentication::v1::UserInfo;

    use super::{
        approval_identity_from_user, html_escape, principal_id, stream_flags, Draft, HttpState,
        APPROVAL_EXTRA_KEY,
    };
    use crate::AdministrativeExecRequestV1;

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
    fn activation_page_escapes_untrusted_display_text() {
        assert_eq!(
            html_escape("<script>'x' & \"y\"</script>"),
            "&lt;script&gt;&#39;x&#39; &amp; &quot;y&quot;&lt;/script&gt;"
        );
    }

    #[test]
    fn one_draft_starts_only_one_approval() {
        let draft_id = Id128V1::new(1, 1);
        let mut state = HttpState::default();
        state.drafts.insert(
            draft_id,
            Draft {
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
                authentication_started: true,
                approval_started: false,
                delivered: false,
            },
        );
        assert!(state.begin_approval(draft_id, 1).is_ok());
        assert!(state.begin_approval(draft_id, 1).is_err());
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
