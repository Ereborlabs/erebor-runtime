use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use araphor_data::{QueryAuthorization, QueryGrant};
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreTokenIntrospectionResponse,
    CoreTokenResponse, CoreTokenType,
};
use openidconnect::{
    AccessToken, AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IntrospectionUrl, IssuerUrl, Nonce,
    OAuth2TokenResponse as _, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenIntrospectionResponse as _,
};
use serde::Deserialize;
use snafu::{ensure, ResultExt as _};
use tokio::sync::watch;
use uuid::Uuid;

use crate::error::{
    ClientDeniedSnafu, ClientStateSnafu, ClientUnauthenticatedSnafu, InvalidConfigurationSnafu,
    IoSnafu,
};
use crate::{Error, Result};

const MAX_ENTRIES: usize = 4096;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const LOGIN_SECONDS: u64 = 300;

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret_path: Option<PathBuf>,
    pub ca_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAuthConfig {
    pub introspection_url: String,
    pub audience: String,
    pub max_age_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigateGrant {
    pub subject: String,
    pub tenant_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthConfig {
    pub origin: String,
    pub oidc: OidcConfig,
    pub service: Option<ServiceAuthConfig>,
    pub investigators: Vec<InvestigateGrant>,
    pub session_seconds: u64,
}

pub struct OidcOwner {
    config: OidcConfig,
    client: OidcClient,
    http: reqwest::Client,
    issuer: String,
}

pub(crate) struct OidcFlow {
    nonce: Nonce,
    verifier: PkceCodeVerifier,
}

pub(crate) struct OidcIdentity {
    pub issuer: String,
    pub subject: String,
    pub display: String,
    pub expires_ns: u64,
}

pub struct ClientAuth {
    oidc: Arc<OidcOwner>,
    origin: String,
    redirect: RedirectUrl,
    service: Option<ServiceAuthConfig>,
    session_seconds: u64,
    state: Mutex<ClientState>,
    changes: watch::Sender<u64>,
}

pub struct ClientLogin {
    pub url: String,
    pub binding: String,
    pub expires_ns: u64,
}

pub struct ClientSession {
    pub token: String,
    pub csrf: String,
    pub expires_ns: u64,
}

pub struct ClientAccess {
    owner: Arc<ClientAuth>,
    subject: String,
    tenant_id: [u8; 16],
    revision: u64,
    expires_ns: u64,
    session: Option<String>,
}

struct ClientState {
    revision: u64,
    grants: BTreeMap<(String, [u8; 16]), u64>,
    flows: BTreeMap<String, LoginFlow>,
    sessions: BTreeMap<String, BrowserSession>,
}

struct LoginFlow {
    proof: OidcFlow,
    binding: String,
    expires_ns: u64,
}

struct BrowserSession {
    subject: String,
    csrf: String,
    expires_ns: u64,
}

impl OidcOwner {
    pub async fn load(config: &OidcConfig) -> Result<Self> {
        ensure!(
            !config.client_id.is_empty(),
            InvalidConfigurationSnafu {
                reason: "OIDC client ID is empty",
            }
        );
        let mut http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10));
        if let Some(path) = &config.ca_path {
            let pem = std::fs::read(path).context(IoSnafu { path })?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|source| Self::failure("parse CA", false, source))?;
            http = http.add_root_certificate(certificate);
        }
        let http = http
            .build()
            .map_err(|source| Self::failure("build HTTP client", false, source))?;
        let issuer = IssuerUrl::new(config.issuer_url.clone())
            .map_err(|source| Self::failure("parse issuer", false, source))?;
        let provider = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|source| Self::failure("discover provider", false, source))?;
        let secret = config
            .client_secret_path
            .as_ref()
            .map(|path| {
                std::fs::read_to_string(path)
                    .context(IoSnafu { path })
                    .map(|value| value.trim().to_owned())
            })
            .transpose()?;
        ensure!(
            secret.as_ref().is_none_or(|value| !value.is_empty()),
            InvalidConfigurationSnafu {
                reason: "OIDC client secret is empty",
            }
        );
        let issuer = provider.issuer().as_str().to_owned();
        let client = CoreClient::from_provider_metadata(
            provider,
            ClientId::new(config.client_id.clone()),
            secret.map(ClientSecret::new),
        );
        Ok(Self {
            config: config.clone(),
            client,
            http,
            issuer,
        })
    }

    pub(crate) fn matches(&self, config: &OidcConfig) -> bool {
        &self.config == config
    }

    pub(crate) fn begin(&self, redirect: &RedirectUrl) -> (String, CsrfToken, OidcFlow) {
        let client = self.client.clone().set_redirect_uri(redirect.clone());
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".to_owned()))
            .add_scope(Scope::new("profile".to_owned()))
            .set_pkce_challenge(challenge)
            .url();
        (url.to_string(), state, OidcFlow { nonce, verifier })
    }

    pub(crate) async fn complete(
        &self,
        redirect: &RedirectUrl,
        code: String,
        flow: OidcFlow,
    ) -> Result<OidcIdentity> {
        ensure!(
            !code.is_empty() && code.len() <= MAX_TOKEN_BYTES,
            ClientUnauthenticatedSnafu {
                reason: "OIDC code is absent or too large",
            }
        );
        let client = self.client.clone().set_redirect_uri(redirect.clone());
        let token = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|source| Self::failure("select token endpoint", false, source))?
            .set_pkce_verifier(flow.verifier)
            .request_async(&self.http)
            .await
            .map_err(|source| Self::failure("exchange code", false, source))?;
        self.identity(&token, &flow.nonce)
    }

    fn identity(&self, token: &CoreTokenResponse, nonce: &Nonce) -> Result<OidcIdentity> {
        let id_token = token.extra_fields().id_token().ok_or_else(|| {
            ClientUnauthenticatedSnafu {
                reason: "OIDC response has no ID token",
            }
            .build()
        })?;
        let verifier = self.client.id_token_verifier();
        let claims = id_token
            .claims(&verifier, nonce)
            .map_err(|source| Self::failure("verify ID token", true, source))?;
        if let Some(expected) = claims.access_token_hash() {
            let algorithm = id_token
                .signing_alg()
                .map_err(|source| Self::failure("read token algorithm", true, source))?;
            let key = id_token
                .signing_key(&verifier)
                .map_err(|source| Self::failure("read token key", true, source))?;
            let actual = AccessTokenHash::from_token(token.access_token(), algorithm, key)
                .map_err(|source| Self::failure("verify access token", true, source))?;
            ensure!(
                &actual == expected,
                ClientUnauthenticatedSnafu {
                    reason: "OIDC access token does not match the ID token",
                }
            );
        }
        let expires_ns = claims
            .expiration()
            .timestamp_nanos_opt()
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| {
                ClientUnauthenticatedSnafu {
                    reason: "OIDC expiry is outside the supported range",
                }
                .build()
            })?;
        Ok(OidcIdentity {
            issuer: self.issuer.clone(),
            subject: claims.subject().as_str().to_owned(),
            display: claims
                .email()
                .map_or_else(|| claims.subject().as_str(), |value| value.as_str())
                .to_owned(),
            expires_ns,
        })
    }

    fn failure(
        operation: &'static str,
        unauthenticated: bool,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Error {
        Error::ClientOidc {
            operation,
            unauthenticated,
            source: Box::new(source),
            location: snafu::Location::default(),
        }
    }
}

impl ClientAuthConfig {
    pub fn validate(&self) -> Result<()> {
        let origin = reqwest::Url::parse(&self.origin).ok();
        ensure!(
            origin.as_ref().is_some_and(|url| {
                url.scheme() == "https"
                    && url.origin().ascii_serialization() == self.origin
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none()
            }) && Self::https(&self.oidc.issuer_url)
                && ClientState::valid_subject(&self.oidc.client_id)
                && (1..=86_400).contains(&self.session_seconds)
                && self
                    .oidc
                    .ca_path
                    .as_ref()
                    .is_none_or(|path| path.is_absolute())
                && self
                    .oidc
                    .client_secret_path
                    .as_ref()
                    .is_none_or(|path| path.is_absolute()),
            InvalidConfigurationSnafu {
                reason: "client authentication configuration is invalid",
            }
        );
        ClientState::grants(&self.investigators)?;
        if let Some(service) = &self.service {
            ensure!(
                Self::https(&service.introspection_url)
                    && ClientState::valid_subject(&service.audience)
                    && service.audience != self.oidc.client_id
                    && (1..=300).contains(&service.max_age_seconds)
                    && self.oidc.client_secret_path.is_some(),
                InvalidConfigurationSnafu {
                    reason: "service authentication requires HTTPS introspection, a dedicated audience, credentials, and a bounded validity period",
                }
            );
        }
        Ok(())
    }

    fn https(value: &str) -> bool {
        value.len() <= 4096
            && reqwest::Url::parse(value).is_ok_and(|url| {
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            })
    }
}

impl ClientAuth {
    pub async fn load(config: &ClientAuthConfig) -> Result<Self> {
        config.validate()?;
        let oidc = Arc::new(OidcOwner::load(&config.oidc).await?);
        Self::new(config.clone(), oidc)
    }

    pub fn new(config: ClientAuthConfig, oidc: Arc<OidcOwner>) -> Result<Self> {
        config.validate()?;
        ensure!(
            oidc.matches(&config.oidc),
            InvalidConfigurationSnafu {
                reason: "client authentication has a different OIDC configuration",
            }
        );
        let redirect = RedirectUrl::new(format!("{}/oidc/session", config.origin))
            .map_err(|source| OidcOwner::failure("parse client redirect", false, source))?;
        let grants = ClientState::grants(&config.investigators)?;
        Ok(Self {
            oidc,
            origin: config.origin,
            redirect,
            service: config.service,
            session_seconds: config.session_seconds,
            state: Mutex::new(ClientState {
                revision: 1,
                grants,
                flows: BTreeMap::new(),
                sessions: BTreeMap::new(),
            }),
            changes: watch::channel(1).0,
        })
    }

    pub fn oidc(&self) -> Arc<OidcOwner> {
        Arc::clone(&self.oidc)
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub async fn authenticate(
        self: &Arc<Self>,
        metadata: &tonic::metadata::MetadataMap,
        mutation: bool,
    ) -> Result<ClientAccess> {
        let tenant = Self::metadata(metadata, "x-araphor-tenant")?
            .and_then(|value| Uuid::parse_str(value).ok().map(|tenant| (value, tenant)));
        let tenant = tenant
            .filter(|(value, tenant)| !tenant.is_nil() && tenant.hyphenated().to_string() == *value)
            .ok_or_else(|| {
                ClientUnauthenticatedSnafu {
                    reason: "client tenant is absent or not canonical",
                }
                .build()
            })?
            .1;
        let headers = metadata.clone().into_headers();
        let cookie = Self::cookie(&headers, "araphor-session")?;
        if let Some(value) = Self::metadata(metadata, "authorization")? {
            ensure!(
                cookie.is_none(),
                ClientUnauthenticatedSnafu {
                    reason: "client credentials are ambiguous",
                }
            );
            let token = value.strip_prefix("Bearer ").ok_or_else(|| {
                ClientUnauthenticatedSnafu {
                    reason: "client authorization is not a bearer token",
                }
                .build()
            })?;
            return self.service(token, *tenant.as_bytes()).await;
        }
        self.browser(
            cookie.unwrap_or_default(),
            *tenant.as_bytes(),
            Self::metadata(metadata, "origin")?.unwrap_or_default(),
            Self::metadata(metadata, "x-araphor-csrf")?,
            mutation,
        )
    }

    pub(crate) fn cookie<'a>(
        headers: &'a axum::http::HeaderMap,
        name: &str,
    ) -> Result<Option<&'a str>> {
        let mut result = None;
        let mut length = 0_usize;
        for header in headers.get_all(axum::http::header::COOKIE) {
            length = length.saturating_add(header.as_bytes().len());
            let value = header.to_str().ok();
            ensure!(
                length <= MAX_TOKEN_BYTES && value.is_some(),
                ClientUnauthenticatedSnafu {
                    reason: "browser cookies are invalid or too large"
                }
            );
            for part in value.unwrap_or_default().split(';') {
                if let Some((key, value)) = part.trim().split_once('=') {
                    if key == name {
                        ensure!(
                            result.is_none() && Self::valid_secret(value),
                            ClientUnauthenticatedSnafu {
                                reason: "browser cookie is invalid or repeated"
                            }
                        );
                        result = Some(value);
                    }
                }
            }
        }
        Ok(result)
    }

    fn metadata<'a>(
        metadata: &'a tonic::metadata::MetadataMap,
        name: &'static str,
    ) -> Result<Option<&'a str>> {
        let mut values = metadata.get_all(name).iter();
        let value = values.next().map(|value| value.to_str()).transpose();
        ensure!(
            value.is_ok() && values.next().is_none(),
            ClientUnauthenticatedSnafu {
                reason: "client metadata is invalid or repeated"
            }
        );
        value.map_err(|_| {
            ClientUnauthenticatedSnafu {
                reason: "client metadata is not text",
            }
            .build()
        })
    }

    pub fn begin_login(&self) -> Result<ClientLogin> {
        let now = Self::now()?;
        let (url, key, proof) = self.oidc.begin(&self.redirect);
        let binding = Self::secret();
        let expires_ns = Self::deadline(now, LOGIN_SECONDS)?;
        let mut state = self.state()?;
        state.retain(now);
        ensure!(
            state.flows.len() < MAX_ENTRIES && !state.flows.contains_key(key.secret()),
            ClientStateSnafu {
                reason: "client login capacity is unavailable",
            }
        );
        state.flows.insert(
            key.secret().clone(),
            LoginFlow {
                proof,
                binding: binding.clone(),
                expires_ns,
            },
        );
        Ok(ClientLogin {
            url,
            binding,
            expires_ns,
        })
    }

    pub async fn complete_login(
        &self,
        key: &str,
        binding: &str,
        code: String,
    ) -> Result<ClientSession> {
        let flow = self.take_flow(key, binding, Self::now()?)?;
        let identity = self.oidc.complete(&self.redirect, code, flow.proof).await?;
        let now = Self::now()?;
        ensure!(
            now < flow.expires_ns,
            ClientUnauthenticatedSnafu {
                reason: "client login expired during OIDC",
            }
        );
        self.open_session(identity, now)
    }

    pub fn browser(
        self: &Arc<Self>,
        token: &str,
        tenant_id: [u8; 16],
        origin: &str,
        csrf: Option<&str>,
        mutation: bool,
    ) -> Result<ClientAccess> {
        ensure!(
            Self::valid_secret(token) && origin == self.origin,
            ClientUnauthenticatedSnafu {
                reason: "browser session or origin is invalid",
            }
        );
        let now = Self::now()?;
        let state = self.state()?;
        let session = state
            .sessions
            .get(token)
            .filter(|value| now < value.expires_ns);
        let session = session.ok_or_else(|| {
            ClientUnauthenticatedSnafu {
                reason: "browser session is absent or expired",
            }
            .build()
        })?;
        ensure!(
            !mutation || csrf == Some(session.csrf.as_str()),
            ClientUnauthenticatedSnafu {
                reason: "browser mutation has no matching CSRF value",
            }
        );
        self.access(
            &state,
            &session.subject,
            tenant_id,
            session.expires_ns,
            Some(token.to_owned()),
        )
    }

    pub async fn service(
        self: &Arc<Self>,
        token: &str,
        tenant_id: [u8; 16],
    ) -> Result<ClientAccess> {
        ensure!(
            !token.is_empty()
                && token.len() <= MAX_TOKEN_BYTES
                && !token.chars().any(char::is_control),
            ClientUnauthenticatedSnafu {
                reason: "service token is absent or too large",
            }
        );
        let config = self.service.as_ref().ok_or_else(|| {
            ClientUnauthenticatedSnafu {
                reason: "service authentication is disabled",
            }
            .build()
        })?;
        let endpoint = IntrospectionUrl::new(config.introspection_url.clone())
            .map_err(|source| OidcOwner::failure("parse introspection URL", false, source))?;
        let client = self.oidc.client.clone().set_introspection_url(endpoint);
        let checked_ns = Self::now()?;
        let token = AccessToken::new(token.to_owned());
        let reply = client
            .introspect(&token)
            .set_token_type_hint("access_token")
            .request_async(&self.oidc.http)
            .await
            .map_err(|source| OidcOwner::failure("introspect access token", false, source))?;
        let identity = config.identity(&reply, &self.oidc.issuer, checked_ns)?;
        ensure!(
            Self::now()? < identity.expires_ns,
            ClientUnauthenticatedSnafu {
                reason: "service authentication expired during introspection",
            }
        );
        let state = self.state()?;
        self.access(
            &state,
            &identity.subject,
            tenant_id,
            identity.expires_ns,
            None,
        )
    }

    pub fn replace_grants(&self, grants: Vec<InvestigateGrant>) -> Result<()> {
        let mut grants = ClientState::grants(&grants)?;
        let mut state = self.state()?;
        if state.grants.keys().eq(grants.keys()) {
            return Ok(());
        }
        let revision = state.next_revision()?;
        for (key, value) in &mut grants {
            *value = state.grants.get(key).copied().unwrap_or(revision);
        }
        state.grants = grants;
        state.revision = revision;
        self.changes.send_replace(revision);
        Ok(())
    }

    pub fn revoke_session(&self, token: &str) -> Result<bool> {
        let mut state = self.state()?;
        if !state.sessions.contains_key(token) {
            return Ok(false);
        }
        let revision = state.next_revision()?;
        state.sessions.remove(token);
        state.revision = revision;
        self.changes.send_replace(revision);
        Ok(true)
    }

    pub fn logout(&self, token: &str, origin: &str, csrf: &str) -> Result<()> {
        ensure!(
            origin == self.origin && Self::valid_secret(token),
            ClientDeniedSnafu
        );
        let mut state = self.state()?;
        let now = Self::now()?;
        let session = state.sessions.get(token).ok_or_else(|| {
            ClientUnauthenticatedSnafu {
                reason: "the browser session is absent",
            }
            .build()
        })?;
        ensure!(
            session.expires_ns > now && session.csrf == csrf,
            ClientDeniedSnafu
        );
        let revision = state.next_revision()?;
        state.sessions.remove(token);
        state.revision = revision;
        self.changes.send_replace(revision);
        Ok(())
    }

    fn access(
        self: &Arc<Self>,
        state: &ClientState,
        subject: &str,
        tenant_id: [u8; 16],
        expires_ns: u64,
        session: Option<String>,
    ) -> Result<ClientAccess> {
        let revision = state
            .grants
            .get(&(subject.to_owned(), tenant_id))
            .copied()
            .ok_or_else(|| ClientDeniedSnafu.build())?;
        Ok(ClientAccess {
            owner: Arc::clone(self),
            subject: subject.to_owned(),
            tenant_id,
            revision,
            expires_ns,
            session,
        })
    }

    fn take_flow(&self, key: &str, binding: &str, now: u64) -> Result<LoginFlow> {
        ensure!(
            key.len() <= 256 && Self::valid_secret(binding),
            ClientUnauthenticatedSnafu {
                reason: "client login state is invalid",
            }
        );
        let mut state = self.state()?;
        state.retain(now);
        ensure!(
            state
                .flows
                .get(key)
                .is_some_and(|flow| flow.binding == binding),
            ClientUnauthenticatedSnafu {
                reason: "client login state is absent, replayed, or bound to another browser",
            }
        );
        state.flows.remove(key).ok_or_else(|| {
            ClientUnauthenticatedSnafu {
                reason: "client login state was already consumed",
            }
            .build()
        })
    }

    fn open_session(&self, identity: OidcIdentity, now: u64) -> Result<ClientSession> {
        ensure!(
            identity.issuer == self.oidc.issuer
                && ClientState::valid_subject(&identity.subject)
                && now < identity.expires_ns,
            ClientUnauthenticatedSnafu {
                reason: "client identity is invalid or expired",
            }
        );
        let token = Self::secret();
        let csrf = Self::secret();
        let expires_ns = identity
            .expires_ns
            .min(Self::deadline(now, self.session_seconds)?);
        let mut state = self.state()?;
        state.retain(now);
        ensure!(
            state
                .grants
                .keys()
                .any(|(subject, _)| subject == &identity.subject),
            ClientDeniedSnafu
        );
        ensure!(
            state.sessions.len() < MAX_ENTRIES && !state.sessions.contains_key(&token),
            ClientStateSnafu {
                reason: "client session capacity is unavailable",
            }
        );
        state.sessions.insert(
            token.clone(),
            BrowserSession {
                subject: identity.subject,
                csrf: csrf.clone(),
                expires_ns,
            },
        );
        Ok(ClientSession {
            token,
            csrf,
            expires_ns,
        })
    }

    fn state(&self) -> Result<MutexGuard<'_, ClientState>> {
        self.state.lock().map_err(|_| {
            ClientStateSnafu {
                reason: "client authentication state is poisoned",
            }
            .build()
        })
    }

    fn now() -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|value| u64::try_from(value.as_nanos()).ok())
            .ok_or_else(|| {
                ClientStateSnafu {
                    reason: "client authentication clock is outside the supported range",
                }
                .build()
            })
    }

    fn deadline(now: u64, seconds: u64) -> Result<u64> {
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| now.checked_add(value))
            .ok_or_else(|| {
                ClientStateSnafu {
                    reason: "client authentication deadline overflowed",
                }
                .build()
            })
    }

    fn secret() -> String {
        format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
    }

    fn valid_secret(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
}

impl ClientState {
    fn valid_subject(value: &str) -> bool {
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
    }

    fn grants(grants: &[InvestigateGrant]) -> Result<BTreeMap<(String, [u8; 16]), u64>> {
        ensure!(
            grants.len() <= MAX_ENTRIES,
            InvalidConfigurationSnafu {
                reason: "client investigate entries exceed 4096",
            }
        );
        let mut result = BTreeMap::new();
        for grant in grants {
            let tenant = Uuid::parse_str(&grant.tenant_id).ok();
            ensure!(
                Self::valid_subject(&grant.subject)
                    && tenant.is_some_and(|value| {
                        !value.is_nil() && value.hyphenated().to_string() == grant.tenant_id
                    }),
                InvalidConfigurationSnafu {
                    reason: "an investigate entry needs a bounded subject and canonical nonzero tenant UUID",
                }
            );
            let tenant = tenant.ok_or_else(|| {
                InvalidConfigurationSnafu {
                    reason: "investigate tenant is absent",
                }
                .build()
            })?;
            ensure!(
                result
                    .insert((grant.subject.clone(), *tenant.as_bytes()), 1)
                    .is_none(),
                InvalidConfigurationSnafu {
                    reason: "an investigate entry is repeated",
                }
            );
        }
        Ok(result)
    }

    fn next_revision(&self) -> Result<u64> {
        self.revision.checked_add(1).ok_or_else(|| {
            ClientStateSnafu {
                reason: "client authentication revision is exhausted",
            }
            .build()
        })
    }

    fn retain(&mut self, now: u64) {
        self.flows.retain(|_, value| now < value.expires_ns);
        self.sessions.retain(|_, value| now < value.expires_ns);
    }
}

impl ServiceAuthConfig {
    fn identity(
        &self,
        reply: &CoreTokenIntrospectionResponse,
        issuer: &str,
        checked_ns: u64,
    ) -> Result<OidcIdentity> {
        let expires_ns = reply
            .exp()
            .and_then(|value| value.timestamp_nanos_opt())
            .and_then(|value| u64::try_from(value).ok());
        let starts_ns = reply.nbf().map(|value| {
            value
                .timestamp_nanos_opt()
                .and_then(|value| u64::try_from(value).ok())
        });
        ensure!(
            reply.active()
                && reply.token_type() == Some(&CoreTokenType::Bearer)
                && reply.iss() == Some(issuer)
                && reply.sub().is_some_and(ClientState::valid_subject)
                && reply.aud().is_some_and(|values| values.iter().any(|value| value == &self.audience))
                && expires_ns.is_some_and(|value| checked_ns < value)
                && starts_ns.is_none_or(|value| value.is_some_and(|value| value <= checked_ns)),
            ClientUnauthenticatedSnafu {
                reason: "service access token is inactive or has invalid issuer, audience, subject, type, or time bounds",
            }
        );
        let expires_ns = expires_ns.ok_or_else(|| {
            ClientUnauthenticatedSnafu {
                reason: "service access token has no expiry",
            }
            .build()
        })?;
        Ok(OidcIdentity {
            issuer: issuer.to_owned(),
            subject: reply.sub().unwrap_or_default().to_owned(),
            display: String::new(),
            expires_ns: expires_ns.min(ClientAuth::deadline(checked_ns, self.max_age_seconds)?),
        })
    }
}

impl ClientAccess {
    pub fn principal(&self) -> &str {
        &self.subject
    }

    pub fn tenant_id(&self) -> [u8; 16] {
        self.tenant_id
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn expires_ns(&self) -> u64 {
        self.expires_ns
    }

    pub fn check(&self) -> Result<()> {
        self.check_at(ClientAuth::now()?)
    }

    pub fn trace_access(&self) -> Result<crate::TraceAccessV1> {
        self.check()?;
        Ok(crate::TraceAccessV1 {
            tenant_id: self.tenant_id,
            principal: self.subject.clone(),
            valid_until_unix_ns: self.expires_ns,
            revoked: false,
        })
    }

    fn check_at(&self, now: u64) -> Result<()> {
        ensure!(
            now < self.expires_ns,
            ClientUnauthenticatedSnafu {
                reason: "client authentication expired",
            }
        );
        let state = self.owner.state()?;
        ensure!(
            state.grants.get(&(self.subject.clone(), self.tenant_id)) == Some(&self.revision),
            ClientDeniedSnafu
        );
        if let Some(token) = &self.session {
            ensure!(
                state.sessions.get(token).is_some_and(|session| {
                    session.subject == self.subject && now < session.expires_ns
                }),
                ClientUnauthenticatedSnafu {
                    reason: "client session was revoked or expired",
                }
            );
        }
        Ok(())
    }
}

impl QueryAuthorization for ClientAccess {
    fn check(&self, grant: &QueryGrant) -> araphor_data::Result<()> {
        if grant.principal != self.subject
            || grant.revision != self.revision
            || grant.selection.tenant_id != self.tenant_id
            || self.check().is_err()
        {
            return Err(araphor_data::Error::QueryDenied {
                location: snafu::Location::default(),
            });
        }
        Ok(())
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.owner.changes.subscribe()
    }

    fn expires_ns(&self) -> Option<u64> {
        Some(self.expires_ns)
    }
}

#[cfg(test)]
pub(crate) mod tests;
