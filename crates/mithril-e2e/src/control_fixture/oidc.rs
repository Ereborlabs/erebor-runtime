use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse as _, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use mithril_control::{ClientAuthConfig, InvestigateGrant, OidcConfig, ServiceAuthConfig};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    CoreRsaPrivateSigningKey, CoreTokenResponse, CoreTokenType,
};
use openidconnect::{
    AccessToken, Audience, EmptyAdditionalClaims, EmptyExtraTokenFields, IssuerUrl, JsonWebKeyId,
    Nonce, PkceCodeChallenge, PkceCodeVerifier, PrivateSigningKey as _, RedirectUrl,
    StandardClaims, SubjectIdentifier,
};
use serde::Deserialize;
use serde_json::json;

use super::CertificateFiles;
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

const CLIENT_ID: &str = "araphor-fixture";
const CLIENT_AUTH: &str = "Basic YXJhcGhvci1maXh0dXJlOm9pZGMtZml4dHVyZS1zZWNyZXQ=";
const CODE_SECONDS: u64 = 60;
const TOKEN_SECONDS: u64 = 300;

pub(crate) struct OidcFixture {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    secret: PathBuf,
    provider: Arc<Provider>,
    handle: axum_server::Handle<std::net::SocketAddr>,
    server: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

struct Provider {
    issuer: IssuerUrl,
    subject: String,
    key: CoreRsaPrivateSigningKey,
    state: Mutex<ProviderState>,
}

#[derive(Default)]
struct ProviderState {
    redirects: BTreeSet<String>,
    codes: BTreeMap<String, Code>,
}

struct Code {
    redirect: String,
    nonce: String,
    challenge: String,
    expires: Instant,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    client_id: String,
    response_type: String,
    redirect_uri: String,
    scope: String,
    state: String,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    client_id: Option<String>,
    grant_type: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
}

impl OidcFixture {
    pub(crate) async fn start(files: &CertificateFiles, subject: &str) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let issuer = format!("https://localhost:{}", address.port());
        let secret = files
            .ca
            .parent()
            .ok_or("fixture CA has no parent")?
            .join("oidc-secret");
        fs::write(&secret, "oidc-fixture-secret")?;
        let provider = Arc::new(Provider::new(&issuer, subject)?);
        let router = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(Provider::discovery),
            )
            .route("/keys", get(Provider::keys))
            .route("/authorize", get(Provider::authorize))
            .route("/token", post(Provider::token))
            .route("/introspect", post(Provider::introspect))
            .with_state(Arc::clone(&provider));
        let tls = RustlsConfig::from_pem_file(&files.server_certificate, &files.server_key).await?;
        let handle = axum_server::Handle::new();
        let stop = handle.clone();
        let server = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)?
                .handle(stop)
                .serve(router.into_make_service())
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), handle.listening())
            .await?
            .ok_or("OIDC fixture did not bind")?;
        Ok(Self {
            issuer,
            subject: subject.to_owned(),
            secret,
            provider,
            handle,
            server: Some(server),
        })
    }

    pub(crate) fn allow_redirect(&self, uri: &str) -> TestResult<()> {
        self.provider.allow_redirect(uri)
    }

    pub(crate) fn auth(
        &self,
        origin: &str,
        tenant: Option<[u8; 16]>,
        ca: PathBuf,
    ) -> ClientAuthConfig {
        ClientAuthConfig {
            origin: origin.into(),
            oidc: OidcConfig {
                issuer_url: self.issuer.clone(),
                client_id: "araphor-fixture".into(),
                client_secret_path: Some(self.secret.clone()),
                ca_path: Some(ca),
            },
            service: Some(ServiceAuthConfig {
                introspection_url: format!("{}/introspect", self.issuer),
                audience: "araphor-client".into(),
                max_age_seconds: 60,
            }),
            investigators: tenant
                .map(|value| InvestigateGrant {
                    subject: self.subject.clone(),
                    tenant_id: uuid::Uuid::from_bytes(value).to_string(),
                })
                .into_iter()
                .collect(),
            session_seconds: TOKEN_SECONDS,
        }
    }

    pub(crate) async fn shutdown(mut self) -> TestResult<()> {
        self.handle.graceful_shutdown(Some(Duration::from_secs(2)));
        if let Some(server) = self.server.take() {
            server.await??;
        }
        Ok(())
    }
}

impl Drop for OidcFixture {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

impl Provider {
    fn new(issuer: &str, subject: &str) -> TestResult<Self> {
        // This public test key signs only this external provider's fixture tokens.
        let key = CoreRsaPrivateSigningKey::from_pem(
            include_str!("../../fixtures/observability/oidc-test-key.pem"),
            Some(JsonWebKeyId::new("araphor-oidc-fixture".into())),
        )?;
        Ok(Self {
            issuer: IssuerUrl::new(issuer.to_owned())?,
            subject: subject.to_owned(),
            key,
            state: Mutex::new(ProviderState::default()),
        })
    }

    fn allow_redirect(&self, uri: &str) -> TestResult<()> {
        let redirect = RedirectUrl::new(uri.to_owned())?;
        let url = redirect.url();
        if uri.len() > 2048
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("OIDC fixture callback must be an exact HTTPS URL".into());
        }
        let mut state = self.state.lock().map_err(|_| "OIDC fixture lock failed")?;
        if state.redirects.len() >= 16 && !state.redirects.contains(uri) {
            return Err("OIDC fixture callback limit reached".into());
        }
        state.redirects.insert(uri.to_owned());
        Ok(())
    }

    async fn discovery(State(owner): State<Arc<Self>>) -> Json<serde_json::Value> {
        let issuer = owner.issuer.as_str();
        Json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/keys"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "code_challenge_methods_supported": ["S256"]
        }))
    }

    async fn keys(State(owner): State<Arc<Self>>) -> Json<CoreJsonWebKeySet> {
        Json(CoreJsonWebKeySet::new(vec![owner
            .key
            .as_verification_key()]))
    }

    async fn authorize(
        State(owner): State<Arc<Self>>,
        Query(form): Query<Authorization>,
    ) -> Response {
        match owner.issue(form) {
            Ok(url) => Redirect::to(&url).into_response(),
            Err(status) => status.into_response(),
        }
    }

    fn issue(&self, form: Authorization) -> Result<String, StatusCode> {
        if form.client_id != CLIENT_ID
            || form.response_type != "code"
            || form.code_challenge_method != "S256"
            || form.code_challenge.len() != 43
            || !form
                .code_challenge
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || b"-_".contains(&value))
            || [&form.state, &form.nonce, &form.scope].iter().any(|value| {
                value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
            })
            || !form.scope.split_whitespace().any(|value| value == "openid")
            || !form
                .scope
                .split_whitespace()
                .all(|value| matches!(value, "openid" | "email" | "profile"))
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        state.codes.retain(|_, code| now < code.expires);
        if !state.redirects.contains(&form.redirect_uri) {
            return Err(StatusCode::BAD_REQUEST);
        }
        if state.codes.len() >= 32 {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let code = uuid::Uuid::new_v4().simple().to_string();
        let mut url = RedirectUrl::new(form.redirect_uri.clone())
            .map_err(|_| StatusCode::BAD_REQUEST)?
            .url()
            .clone();
        url.query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &form.state);
        state.codes.insert(
            code,
            Code {
                redirect: form.redirect_uri,
                nonce: form.nonce,
                challenge: form.code_challenge,
                expires: now + Duration::from_secs(CODE_SECONDS),
            },
        );
        Ok(url.into())
    }

    async fn token(
        State(owner): State<Arc<Self>>,
        headers: HeaderMap,
        Form(form): Form<TokenRequest>,
    ) -> Response {
        match owner.exchange(&headers, form) {
            Ok(token) => Json(token).into_response(),
            Err(status) => {
                let error = match status {
                    StatusCode::UNAUTHORIZED => "invalid_client",
                    StatusCode::INTERNAL_SERVER_ERROR => "server_error",
                    _ => "invalid_grant",
                };
                (status, Json(json!({"error": error}))).into_response()
            }
        }
    }

    fn exchange(
        &self,
        headers: &HeaderMap,
        form: TokenRequest,
    ) -> Result<CoreTokenResponse, StatusCode> {
        if !Self::credential(headers)
            || form
                .client_id
                .as_deref()
                .is_some_and(|value| value != CLIENT_ID)
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        if form.grant_type != "authorization_code" || form.code.len() != 32 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let code = self
            .state
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .codes
            .remove(&form.code)
            .ok_or(StatusCode::BAD_REQUEST)?;
        if Instant::now() >= code.expires
            || form.redirect_uri != code.redirect
            || !(43..=128).contains(&form.code_verifier.len())
            || !form
                .code_verifier
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || b"-._~".contains(&value))
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let challenge = PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(
            form.code_verifier,
        ));
        if challenge.as_str() != code.challenge {
            return Err(StatusCode::BAD_REQUEST);
        }
        let now = SystemTime::now();
        let access = AccessToken::new(uuid::Uuid::new_v4().to_string());
        let claims = CoreIdTokenClaims::new(
            self.issuer.clone(),
            vec![Audience::new(CLIENT_ID.into())],
            (now + Duration::from_secs(TOKEN_SECONDS)).into(),
            now.into(),
            StandardClaims::new(SubjectIdentifier::new(self.subject.clone())),
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(Nonce::new(code.nonce)));
        let token = CoreIdToken::new(
            claims,
            &self.key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            Some(&access),
            None,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let mut response = CoreTokenResponse::new(
            access,
            CoreTokenType::Bearer,
            CoreIdTokenFields::new(Some(token), EmptyExtraTokenFields {}),
        );
        response.set_expires_in(Some(&Duration::from_secs(TOKEN_SECONDS)));
        Ok(response)
    }

    fn credential(headers: &HeaderMap) -> bool {
        let mut values = headers.get_all("authorization").iter();
        values.next().is_some_and(|value| value == CLIENT_AUTH) && values.next().is_none()
    }

    async fn introspect(
        State(owner): State<Arc<Self>>,
        headers: HeaderMap,
        Form(form): Form<BTreeMap<String, String>>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        if !Self::credential(&headers) {
            return (StatusCode::UNAUTHORIZED, Json(json!({"active": false})));
        }
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(value) => value.as_secs(),
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"active": false})),
                )
            }
        };
        let value = if form
            .get("token")
            .is_some_and(|value| value == "fixture-access")
        {
            json!({"active": true, "token_type": "Bearer", "iss": owner.issuer.as_str(), "aud": ["araphor-client"],
                "sub": owner.subject, "exp": now + TOKEN_SECONDS})
        } else {
            json!({"active": false})
        };
        (StatusCode::OK, Json(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mithril_control::{ClientAuth, Error};
    use openidconnect::core::CoreIdTokenVerifier;
    use openidconnect::ClientId;

    #[test]
    fn observability_oidc_codes() -> TestResult<()> {
        let owner = Provider::new("https://localhost:44443", "operator")?;
        let callback = "https://localhost:44444/oidc/session";
        owner.allow_redirect(callback)?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let request = Authorization {
            client_id: CLIENT_ID.into(),
            response_type: "code".into(),
            redirect_uri: callback.into(),
            scope: "openid profile email".into(),
            state: "fixture-state".into(),
            nonce: "fixture-nonce".into(),
            code_challenge: challenge.as_str().into(),
            code_challenge_method: "S256".into(),
        };
        let issue = || -> TestResult<TokenRequest> {
            let location = owner
                .issue(request.clone())
                .map_err(|status| format!("code issue failed: {status}"))?;
            let url = RedirectUrl::new(location)?;
            let values = url
                .url()
                .query_pairs()
                .into_owned()
                .collect::<BTreeMap<_, _>>();
            assert_eq!(
                values.get("state").map(String::as_str),
                Some("fixture-state")
            );
            Ok(TokenRequest {
                client_id: None,
                grant_type: "authorization_code".into(),
                code: values
                    .get("code")
                    .ok_or("authorization code is absent")?
                    .clone(),
                redirect_uri: callback.into(),
                code_verifier: verifier.secret().clone(),
            })
        };
        let mut headers = HeaderMap::new();
        headers.insert("authorization", CLIENT_AUTH.parse()?);
        let form = issue()?;
        let token = owner
            .exchange(&headers, form.clone())
            .map_err(|status| format!("token exchange failed: {status}"))?;
        let verifier = CoreIdTokenVerifier::new_public_client(
            ClientId::new(CLIENT_ID.into()),
            owner.issuer.clone(),
            CoreJsonWebKeySet::new(vec![owner.key.as_verification_key()]),
        );
        let token = token
            .extra_fields()
            .id_token()
            .ok_or("ID token is absent")?;
        let claims = token.claims(&verifier, &Nonce::new("fixture-nonce".into()))?;
        assert_eq!(claims.subject().as_str(), "operator");
        assert!(token
            .claims(&verifier, &Nonce::new("wrong-nonce".into()))
            .is_err());
        assert!(matches!(
            owner.exchange(&headers, form),
            Err(StatusCode::BAD_REQUEST)
        ));

        let form = issue()?;
        assert!(matches!(
            owner.exchange(&HeaderMap::new(), form.clone()),
            Err(StatusCode::UNAUTHORIZED)
        ));
        let mut duplicate = headers.clone();
        duplicate.append("authorization", CLIENT_AUTH.parse()?);
        assert!(matches!(
            owner.exchange(&duplicate, form.clone()),
            Err(StatusCode::UNAUTHORIZED)
        ));
        assert!(owner.exchange(&headers, form).is_ok());

        for change in 0..4 {
            let form = issue()?;
            let mut bad = form.clone();
            match change {
                0 => bad.code_verifier = "short".into(),
                1 => bad.code_verifier = "x".repeat(43),
                2 => bad.redirect_uri = "https://localhost:44444/other".into(),
                _ => {
                    owner
                        .state
                        .lock()
                        .map_err(|_| "fixture lock failed")?
                        .codes
                        .get_mut(&form.code)
                        .ok_or("code was not retained")?
                        .expires = Instant::now() - Duration::from_secs(1)
                }
            }
            assert!(matches!(
                owner.exchange(&headers, bad),
                Err(StatusCode::BAD_REQUEST)
            ));
            assert!(matches!(
                owner.exchange(&headers, form),
                Err(StatusCode::BAD_REQUEST)
            ));
        }
        for change in 0..4 {
            let mut bad = request.clone();
            match change {
                0 => bad.client_id = "other-client".into(),
                1 => bad.redirect_uri = "https://localhost:44444/unregistered".into(),
                2 => bad.code_challenge_method = "plain".into(),
                _ => bad.nonce.clear(),
            }
            assert!(matches!(owner.issue(bad), Err(StatusCode::BAD_REQUEST)));
        }
        assert!(owner
            .allow_redirect("http://localhost:44444/oidc/session")
            .is_err());
        assert!(owner
            .allow_redirect("https://localhost:44444/oidc/session?next=other")
            .is_err());
        assert!(owner
            .allow_redirect("https://localhost:44444/oidc/session#fragment")
            .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn observability_oidc_login() -> TestResult<()> {
        let tls = crate::control_fixture::MtlsFixture::new(false)?;
        let oidc = OidcFixture::start(&tls.files, "operator").await?;
        let origin = "https://localhost:44444";
        oidc.allow_redirect(&format!("{origin}/oidc/session"))?;
        let auth = Arc::new(
            ClientAuth::load(&oidc.auth(origin, Some([1; 16]), tls.files.ca.clone())).await?,
        );
        let http = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(&tls.files.ca)?)?)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        for allowed in [true, false] {
            if !allowed {
                auth.replace_grants(Vec::new())?;
            }
            let login = auth.begin_login()?;
            let reply = http.get(&login.url).send().await?;
            assert_eq!(reply.status(), StatusCode::SEE_OTHER);
            let location = reply
                .headers()
                .get("location")
                .ok_or("OIDC redirect is absent")?
                .to_str()?;
            let url = reqwest::Url::parse(location)?;
            let values = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
            let state = values.get("state").ok_or("OIDC state is absent")?;
            let code = values.get("code").ok_or("OIDC code is absent")?;
            let result = auth
                .complete_login(state, &login.binding, code.clone())
                .await;
            if allowed {
                let session = result?;
                assert!(auth
                    .browser(&session.token, [1; 16], origin, None, false)
                    .is_ok());
                assert!(matches!(
                    auth.complete_login(state, &login.binding, code.clone())
                        .await,
                    Err(Error::ClientUnauthenticated { .. })
                ));
            } else {
                assert!(matches!(result, Err(Error::ClientDenied { .. })));
            }
        }
        oidc.shutdown().await?;
        Ok(())
    }
}
