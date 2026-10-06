use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use erebor_runtime_ipc::araphor::{
    araphor_administrative_service_server::AraphorAdministrativeServiceServer,
    araphor_client_service_server::AraphorClientServiceServer,
};
use serde::Deserialize;
use snafu::ensure;
use tonic_web::GrpcWebLayer;
use tower::{Layer as _, ServiceExt as _};
use tower_http::services::{ServeDir, ServeFile};

use crate::error::InvalidConfigurationSnafu;
use crate::{
    AdministrativeConfig, AdministrativeHttpOwner, ClientAuth, ClientAuthConfig, ClientGrpcConfig,
    ClientGrpcOwner, ControlPlane, Error, Result,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientListenerConfig {
    pub listen: SocketAddr,
    pub tls_certificate_path: PathBuf,
    pub tls_private_key_path: PathBuf,
    pub auth: ClientAuthConfig,
    pub administrative: Option<AdministrativeConfig>,
    pub investigation: Option<ClientGrpcConfig>,
    pub assets: Option<PathBuf>,
}

pub struct ClientListener {
    config: ClientListenerConfig,
    router: Router,
}

#[derive(Deserialize)]
struct LoginReply {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

impl ClientListenerConfig {
    pub fn validate(&self) -> Result<()> {
        self.auth.validate()?;
        ensure!(
            self.tls_certificate_path.is_absolute()
                && self.tls_private_key_path.is_absolute()
                && self.assets.as_ref().is_none_or(|path| path.is_absolute())
                && (self.administrative.is_some() || self.investigation.is_some()),
            InvalidConfigurationSnafu {
                reason: "client listener needs TLS paths and at least one enabled service",
            }
        );
        if let Some(config) = &self.administrative {
            config.validate()?;
        }
        Ok(())
    }
}

impl ClientListener {
    pub async fn load(config: ClientListenerConfig, control: ControlPlane) -> Result<Self> {
        config.validate()?;
        let auth = Arc::new(ClientAuth::load(&config.auth).await?);
        let administrative = match &config.administrative {
            Some(value) => Some(Arc::new(
                AdministrativeHttpOwner::load(value, control.clone(), auth.oidc(), auth.origin())
                    .await?,
            )),
            None => None,
        };
        let investigation = config
            .investigation
            .as_ref()
            .map(|value| ClientGrpcOwner::new(control, Arc::clone(&auth), value.clone()))
            .transpose()?;
        Self::new(config, auth, administrative, investigation)
    }

    pub fn new(
        config: ClientListenerConfig,
        auth: Arc<ClientAuth>,
        administrative: Option<Arc<AdministrativeHttpOwner>>,
        investigation: Option<ClientGrpcOwner>,
    ) -> Result<Self> {
        config.validate()?;
        ensure!(
            config.auth.origin == auth.origin()
                && config.administrative.is_some() == administrative.is_some()
                && config.investigation.is_some() == investigation.is_some(),
            InvalidConfigurationSnafu {
                reason: "client listener owners do not match the enabled services",
            }
        );
        let mut rpc = Router::new();
        if let Some(owner) = investigation {
            let service = GrpcWebLayer::new()
                .layer(AraphorClientServiceServer::new(owner))
                .map_request(|request: Request<Body>| request.map(tonic::body::boxed));
            for name in [
                "Query",
                "SubmitTrace",
                "GetTrace",
                "WatchTrace",
                "CancelTrace",
            ] {
                rpc = rpc.route_service(
                    &format!("/erebor.mithril.control.v1.AraphorClientService/{name}"),
                    service.clone(),
                );
            }
        }
        let mut router = Router::new()
            .route("/login", get(Self::login))
            .route("/logout", post(Self::logout))
            .route("/oidc/session", get(Self::login_reply))
            .with_state(Arc::clone(&auth));
        if let Some(owner) = administrative {
            let service = GrpcWebLayer::new()
                .layer(AraphorAdministrativeServiceServer::from_arc(Arc::clone(
                    &owner,
                )))
                .map_request(|request: Request<Body>| request.map(tonic::body::boxed));
            for name in [
                "CreateAdministrativeExecRequest",
                "PollAdministrativeExecRequest",
                "GetAdministrativeExecActivation",
                "ApproveAdministrativeExec",
                "SubmitNodeDecommission",
                "GetNodeDecommission",
            ] {
                rpc = rpc.route_service(
                    &format!("/erebor.mithril.control.v1.AraphorAdministrativeService/{name}"),
                    service.clone(),
                );
            }
            router = router.merge(owner.callbacks());
        }
        router = router.merge(rpc.route_layer(middleware::from_fn_with_state(
            Arc::<str>::from(auth.origin()),
            Self::origin,
        )));
        if let Some(assets) = &config.assets {
            router = router
                .route_service("/", ServeFile::new(assets.join("index.html")))
                .nest_service(
                    "/assets",
                    ServeDir::new(assets.join("assets")).append_index_html_on_directories(false),
                );
        }
        Ok(Self {
            config,
            router: router.layer(middleware::from_fn(Self::headers)),
        })
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }

    pub async fn serve(self, shutdown: impl Future<Output = ()> + Send + 'static) -> Result<()> {
        let tls = RustlsConfig::from_pem_file(
            &self.config.tls_certificate_path,
            &self.config.tls_private_key_path,
        )
        .await
        .map_err(|source| Self::failure("load client TLS", source))?;
        let handle = axum_server::Handle::new();
        let stop = handle.clone();
        let task = tokio::spawn(async move {
            shutdown.await;
            stop.graceful_shutdown(Some(Duration::from_secs(5)));
        });
        let result = axum_server::bind_rustls(self.config.listen, tls)
            .handle(handle)
            .serve(self.router.into_make_service())
            .await
            .map_err(|source| Self::failure("serve clients", source));
        task.abort();
        result
    }

    async fn origin(
        State(origin): State<Arc<str>>,
        request: Request<Body>,
        next: Next,
    ) -> Response {
        let mut values = request.headers().get_all(header::ORIGIN).iter();
        let value = values.next();
        let matches = value.is_some_and(|value| value.as_bytes() == origin.as_bytes());
        let browser = request
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|value| value.as_bytes().starts_with(b"application/grpc-web"));
        if values.next().is_some() || (value.is_some() && !matches) || (browser && !matches) {
            return StatusCode::FORBIDDEN.into_response();
        }
        let mut response = if request.method() == Method::OPTIONS {
            if !matches
                || request
                    .headers()
                    .get(header::ACCESS_CONTROL_REQUEST_METHOD)
                    .is_none_or(|value| value != "POST")
            {
                return StatusCode::FORBIDDEN.into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        } else {
            next.run(request).await
        };
        if matches {
            let Ok(value) = HeaderValue::from_str(&origin) else {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            };
            let headers = response.headers_mut();
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("POST, OPTIONS"),
            );
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static(
                "content-type,x-grpc-web,x-user-agent,grpc-timeout,x-araphor-tenant,x-araphor-csrf,authorization",
            ));
            headers.insert(
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                HeaderValue::from_static("grpc-status,grpc-message"),
            );
            headers.append(header::VARY, HeaderValue::from_static("Origin"));
        }
        response
    }

    async fn headers(request: Request<Body>, next: Next) -> Response {
        let mut response = next.run(request).await;
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ));
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
        response
    }

    async fn login(State(auth): State<Arc<ClientAuth>>) -> Response {
        match auth.begin_login() {
            Ok(login) => {
                let mut response = Redirect::to(&login.url).into_response();
                if let Err(error) =
                    Self::cookie(&mut response, "araphor-login", &login.binding, true, 300)
                {
                    return Self::auth_error(error);
                }
                response
            }
            Err(error) => Self::auth_error(error),
        }
    }

    async fn logout(State(auth): State<Arc<ClientAuth>>, headers: HeaderMap) -> Response {
        let token = match ClientAuth::cookie(&headers, "araphor-session") {
            Ok(Some(token)) => token,
            _ => return StatusCode::UNAUTHORIZED.into_response(),
        };
        let unique = |name| {
            let mut values = headers.get_all(name).iter();
            let value = values.next()?.to_str().ok()?;
            values.next().is_none().then_some(value)
        };
        let (Some(origin), Some(csrf)) = (unique("origin"), unique("x-araphor-csrf")) else {
            return StatusCode::FORBIDDEN.into_response();
        };
        if let Err(error) = auth.logout(token, origin, csrf) {
            return Self::auth_error(error);
        }
        let mut response = StatusCode::NO_CONTENT.into_response();
        if let Err(error) = Self::cookie(&mut response, "araphor-session", "", true, 0)
            .and_then(|()| Self::cookie(&mut response, "araphor-csrf", "", false, 0))
        {
            return Self::auth_error(error);
        }
        response
    }

    async fn login_reply(
        State(auth): State<Arc<ClientAuth>>,
        Query(reply): Query<LoginReply>,
        headers: HeaderMap,
    ) -> Response {
        let (Some(code), Some(state)) = (reply.code, reply.state) else {
            return StatusCode::UNAUTHORIZED.into_response();
        };
        if reply.error.is_some() {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let binding = match ClientAuth::cookie(&headers, "araphor-login") {
            Ok(Some(value)) => value,
            _ => return StatusCode::UNAUTHORIZED.into_response(),
        };
        match auth.complete_login(&state, binding, code).await {
            Ok(session) => {
                let mut response = Redirect::to("/").into_response();
                if let Err(error) = Self::cookie(
                    &mut response,
                    "araphor-session",
                    &session.token,
                    true,
                    86_400,
                )
                .and_then(|()| {
                    Self::cookie(&mut response, "araphor-csrf", &session.csrf, false, 86_400)
                })
                .and_then(|()| Self::cookie(&mut response, "araphor-login", "", true, 0))
                {
                    return Self::auth_error(error);
                }
                response
            }
            Err(error) => Self::auth_error(error),
        }
    }

    pub(crate) fn cookie(
        response: &mut Response,
        name: &str,
        value: &str,
        private: bool,
        age: u64,
    ) -> Result<()> {
        let cookie = format!(
            "{name}={value}; Path=/; Secure; SameSite=Lax; Max-Age={age}{}",
            if private { "; HttpOnly" } else { "" },
        );
        let value = HeaderValue::from_str(&cookie)
            .map_err(|source| Self::failure("set browser cookie", source))?;
        response.headers_mut().append(header::SET_COOKIE, value);
        Ok(())
    }

    fn auth_error(error: Error) -> Response {
        match error {
            Error::ClientDenied { .. } => StatusCode::FORBIDDEN.into_response(),
            Error::ClientUnauthenticated { .. }
            | Error::ClientOidc {
                unauthenticated: true,
                ..
            } => StatusCode::UNAUTHORIZED.into_response(),
            _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }

    fn failure(
        operation: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Error {
        Error::ClientListener {
            operation,
            source: Box::new(source),
            location: snafu::Location::default(),
        }
    }
}
