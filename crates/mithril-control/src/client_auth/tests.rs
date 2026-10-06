use araphor_data::AnalysisSelectionV1;
use erebor_runtime_error::{ErrorExt as _, RetryHint, StatusCode};
use openidconnect::core::{
    CoreEdDsaPrivateSigningKey, CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields,
    CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
};
use openidconnect::{EmptyExtraTokenFields, PrivateSigningKey as _};
use serde_json::json;

use super::*;

fn config() -> ClientAuthConfig {
    ClientAuthConfig {
        origin: "https://control.example".into(),
        oidc: OidcConfig {
            issuer_url: "https://issuer.example".into(),
            client_id: "browser-client".into(),
            client_secret_path: None,
            ca_path: None,
        },
        service: None,
        investigators: vec![InvestigateGrant {
            subject: "alice".into(),
            tenant_id: Uuid::from_bytes([1; 16]).to_string(),
        }],
        session_seconds: 60,
    }
}

pub(crate) fn owner() -> std::result::Result<Arc<ClientAuth>, Box<dyn std::error::Error>> {
    let config = config();
    let provider: CoreProviderMetadata = serde_json::from_value(json!({
        "issuer": config.oidc.issuer_url,
        "authorization_endpoint": "https://issuer.example/authorize",
        "token_endpoint": "https://issuer.example/token",
        "jwks_uri": "https://issuer.example/keys",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }))?;
    let oidc = OidcOwner {
        config: config.oidc.clone(),
        client: CoreClient::from_provider_metadata(
            provider,
            ClientId::new(config.oidc.client_id.clone()),
            None,
        ),
        http: reqwest::Client::new(),
        issuer: config.oidc.issuer_url.clone(),
    };
    Ok(Arc::new(ClientAuth::new(config, Arc::new(oidc))?))
}

pub(crate) fn session(owner: &ClientAuth) -> Result<ClientSession> {
    let now = ClientAuth::now()?;
    owner.open_session(
        OidcIdentity {
            issuer: owner.oidc.issuer.clone(),
            subject: "alice".into(),
            display: "Alice".into(),
            expires_ns: ClientAuth::deadline(now, 120)?,
        },
        now,
    )
}

#[test]
fn client_auth_configuration() -> std::result::Result<(), Box<dyn std::error::Error>> {
    config().validate()?;
    for origin in [
        "http://control.example",
        "https://control.example/",
        "https://control.example/path",
        "https://user@control.example",
        "https://control.example?query",
    ] {
        let mut value = config();
        value.origin = origin.into();
        assert!(value.validate().is_err(), "accepted origin {origin}");
    }
    let mut value = config();
    value.oidc.issuer_url = "http://issuer.example".into();
    assert!(value.validate().is_err());
    value = config();
    value.investigators.push(value.investigators[0].clone());
    assert!(value.validate().is_err());
    value = config();
    value.investigators[0].tenant_id = Uuid::nil().to_string();
    assert!(value.validate().is_err());
    value = config();
    value.investigators[0].subject = "x".repeat(257);
    assert!(value.validate().is_err());
    value = config();
    value.session_seconds = 86_401;
    assert!(value.validate().is_err());
    value = config();
    value.service = Some(ServiceAuthConfig {
        introspection_url: "https://issuer.example/introspect".into(),
        audience: "araphor-client".into(),
        max_age_seconds: 60,
    });
    assert!(value.validate().is_err());
    value.oidc.client_secret_path = Some("/run/secrets/oidc".into());
    value.validate()?;
    for (endpoint, audience, age) in [
        ("http://issuer.example/introspect", "araphor-client", 60),
        ("https://issuer.example/introspect", "browser-client", 60),
        ("https://issuer.example/introspect", "araphor-client", 301),
        ("https://issuer.example/introspect", "araphor-client", 0),
    ] {
        value.service = Some(ServiceAuthConfig {
            introspection_url: endpoint.into(),
            audience: audience.into(),
            max_age_seconds: age,
        });
        assert!(value.validate().is_err());
    }
    Ok(())
}

#[test]
fn client_auth_browser() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = owner()?;
    let session = session(&owner)?;
    let access = owner.browser(
        &session.token,
        [1; 16],
        &owner.origin,
        Some(&session.csrf),
        true,
    )?;
    access.check()?;
    let trace = access.trace_access()?;
    assert_eq!(trace.tenant_id, [1; 16]);
    assert_eq!(trace.principal, "alice");
    assert_eq!(trace.valid_until_unix_ns, session.expires_ns);
    assert!(!trace.revoked);
    let mut grant = QueryGrant {
        principal: access.principal().into(),
        revision: access.revision(),
        selection: AnalysisSelectionV1::tenant(access.tenant_id()),
    };
    QueryAuthorization::check(&access, &grant)?;
    grant.selection.tenant_id = [2; 16];
    assert!(QueryAuthorization::check(&access, &grant).is_err());
    grant.selection.tenant_id = [1; 16];
    grant.principal = "bob".into();
    assert!(QueryAuthorization::check(&access, &grant).is_err());
    grant.principal = "alice".into();
    grant.revision += 1;
    assert!(QueryAuthorization::check(&access, &grant).is_err());

    for (origin, csrf, mutation) in [
        (
            "https://foreign.example",
            Some(session.csrf.as_str()),
            false,
        ),
        ("", Some(session.csrf.as_str()), false),
        (owner.origin.as_str(), None, true),
        (owner.origin.as_str(), Some("wrong"), true),
    ] {
        assert!(owner
            .browser(&session.token, [1; 16], origin, csrf, mutation)
            .is_err());
    }
    owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    assert!(matches!(
        owner.browser(&session.token, [2; 16], &owner.origin, None, false),
        Err(Error::ClientDenied { .. })
    ));
    assert!(owner
        .browser(
            "mithril-exec-credential",
            [1; 16],
            &owner.origin,
            None,
            false
        )
        .is_err());
    Ok(())
}

#[test]
fn client_auth_membership() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = owner()?;
    let now = ClientAuth::now()?;
    let identity = |subject: &str| OidcIdentity {
        issuer: owner.oidc.issuer.clone(),
        subject: subject.into(),
        display: String::new(),
        expires_ns: now + 60_000_000_000,
    };
    assert!(matches!(
        owner.open_session(identity("non-member"), now),
        Err(Error::ClientDenied { .. })
    ));
    assert!(owner.state()?.sessions.is_empty());
    owner.open_session(identity("alice"), now)?;
    assert_eq!(owner.state()?.sessions.len(), 1);
    owner.replace_grants(Vec::new())?;
    assert!(matches!(
        owner.open_session(identity("alice"), now),
        Err(Error::ClientDenied { .. })
    ));
    assert_eq!(owner.state()?.sessions.len(), 1);
    Ok(())
}

#[test]
fn client_auth_revocation() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = owner()?;
    let session = session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    let mut changes = QueryAuthorization::changes(&access);
    owner.replace_grants(config().investigators)?;
    assert!(!changes.has_changed()?);
    let mut grants = config().investigators;
    grants.push(InvestigateGrant {
        subject: "bob".into(),
        tenant_id: Uuid::from_bytes([2; 16]).to_string(),
    });
    owner.replace_grants(grants)?;
    assert!(changes.has_changed()?);
    changes.borrow_and_update();
    access.check()?;
    owner.replace_grants(Vec::new())?;
    assert!(changes.has_changed()?);
    changes.borrow_and_update();
    assert!(matches!(access.check(), Err(Error::ClientDenied { .. })));
    assert!(access.trace_access().is_err());
    owner.replace_grants(config().investigators)?;
    assert!(access.check().is_err());
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    access.check()?;
    changes.borrow_and_update();
    assert!(owner.revoke_session(&session.token)?);
    assert!(changes.has_changed()?);
    assert!(matches!(
        access.check(),
        Err(Error::ClientUnauthenticated { .. })
    ));
    assert!(!owner.revoke_session(&session.token)?);
    Ok(())
}

#[test]
fn client_auth_login_state() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = owner()?;
    let login = owner.begin_login()?;
    let url = reqwest::Url::parse(&login.url)?;
    let fields = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
    assert_eq!(
        fields.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(
        fields.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert_eq!(
        fields.get("redirect_uri").map(String::as_str),
        Some("https://control.example/oidc/session")
    );
    let key = fields.get("state").ok_or("state is absent")?;
    assert!(owner
        .take_flow(key, &ClientAuth::secret(), ClientAuth::now()?)
        .is_err());
    let flow = owner.take_flow(key, &login.binding, ClientAuth::now()?)?;
    assert_eq!(fields.get("nonce"), Some(flow.proof.nonce.secret()));
    let challenge = PkceCodeChallenge::from_code_verifier_sha256(&flow.proof.verifier);
    assert_eq!(
        fields.get("code_challenge").map(String::as_str),
        Some(challenge.as_str())
    );
    assert!(owner
        .take_flow(key, &login.binding, ClientAuth::now()?)
        .is_err());
    let login = owner.begin_login()?;
    let url = reqwest::Url::parse(&login.url)?;
    let fields = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
    let key = fields.get("state").ok_or("state is absent")?;
    assert!(owner
        .take_flow(key, &login.binding, login.expires_ns)
        .is_err());
    Ok(())
}

#[test]
fn client_auth_logout() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = owner()?;
    let session = session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    assert!(owner
        .logout(&session.token, "https://foreign.example", &session.csrf)
        .is_err());
    assert!(owner
        .logout(&session.token, &owner.origin, "wrong")
        .is_err());
    access.check()?;
    owner.replace_grants(Vec::new())?;
    owner.logout(&session.token, &owner.origin, &session.csrf)?;
    assert!(access.check().is_err());
    assert!(!owner.revoke_session(&session.token)?);
    assert!(owner
        .logout(&session.token, &owner.origin, &session.csrf)
        .is_err());
    Ok(())
}

#[test]
fn client_auth_expiry_capacity() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = owner()?;
    let session = session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    access.check_at(access.expires_ns() - 1)?;
    assert!(access.check_at(access.expires_ns()).is_err());
    assert_eq!(
        QueryAuthorization::expires_ns(&access),
        Some(session.expires_ns)
    );
    let now = ClientAuth::now()?;
    let expires_ns = ClientAuth::deadline(now, 120)?;
    let mut state = owner.state()?;
    state.sessions.clear();
    for index in 0..MAX_ENTRIES {
        state.sessions.insert(
            format!("{index:064x}"),
            BrowserSession {
                subject: "alice".into(),
                csrf: ClientAuth::secret(),
                expires_ns,
            },
        );
    }
    drop(state);
    assert!(matches!(
        owner.open_session(
            OidcIdentity {
                issuer: owner.oidc.issuer.clone(),
                subject: "alice".into(),
                display: String::new(),
                expires_ns,
            },
            now
        ),
        Err(Error::ClientState { .. })
    ));
    owner.state()?.retain(expires_ns);
    assert!(owner.state()?.sessions.is_empty());
    let short = owner.open_session(
        OidcIdentity {
            issuer: owner.oidc.issuer.clone(),
            subject: "alice".into(),
            display: String::new(),
            expires_ns: now + 1,
        },
        now,
    )?;
    assert_eq!(short.expires_ns, now + 1);
    assert!(owner
        .open_session(
            OidcIdentity {
                issuer: "https://foreign.example".into(),
                subject: "alice".into(),
                display: String::new(),
                expires_ns,
            },
            now
        )
        .is_err());
    Ok(())
}

#[test]
fn client_auth_service_claims() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let config = ServiceAuthConfig {
        introspection_url: "https://issuer.example/introspect".into(),
        audience: "araphor-client".into(),
        max_age_seconds: 60,
    };
    let source = json!({
        "active": true, "token_type": "Bearer", "iss": "https://issuer.example",
        "sub": "alice", "aud": ["araphor-client"], "nbf": 90, "exp": 200,
    });
    let reply = serde_json::from_value(source.clone())?;
    let identity = config.identity(&reply, "https://issuer.example", 100_000_000_000)?;
    assert_eq!(identity.subject, "alice");
    assert_eq!(identity.expires_ns, 160_000_000_000);
    for (field, value) in [
        ("active", json!(false)),
        ("token_type", json!("id_token")),
        ("iss", json!("https://foreign.example")),
        ("sub", json!("")),
        ("sub", json!("x".repeat(257))),
        ("aud", json!(["browser-client"])),
        ("nbf", json!(101)),
        ("exp", json!(100)),
    ] {
        let mut changed = source.clone();
        changed[field] = value;
        let reply = serde_json::from_value(changed)?;
        assert!(
            config
                .identity(&reply, "https://issuer.example", 100_000_000_000)
                .is_err(),
            "accepted invalid {field}"
        );
    }
    for field in ["token_type", "iss", "sub", "aud", "exp"] {
        let mut changed = source.clone();
        changed
            .as_object_mut()
            .ok_or("claims are not an object")?
            .remove(field);
        let reply = serde_json::from_value(changed)?;
        assert!(
            config
                .identity(&reply, "https://issuer.example", 100_000_000_000)
                .is_err(),
            "accepted absent {field}"
        );
    }
    let mut changed = source;
    changed["exp"] = json!(120);
    let reply = serde_json::from_value(changed)?;
    assert_eq!(
        config
            .identity(&reply, "https://issuer.example", 100_000_000_000)?
            .expires_ns,
        120_000_000_000
    );
    Ok(())
}

#[test]
fn client_auth_oidc_claims() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let key = CoreEdDsaPrivateSigningKey::from_ed25519_pem(
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICWeYPLxoZKHZlQ6rkBi11E9JwchynXtljATLqym/XS9\n-----END PRIVATE KEY-----",
        None,
    )?;
    let config = config();
    let provider: CoreProviderMetadata = serde_json::from_value(json!({
        "issuer": config.oidc.issuer_url,
        "authorization_endpoint": "https://issuer.example/authorize",
        "token_endpoint": "https://issuer.example/token",
        "jwks_uri": "https://issuer.example/keys",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"]
    }))?;
    let oidc = OidcOwner {
        config: config.oidc.clone(),
        client: CoreClient::from_provider_metadata(
            provider.set_jwks(CoreJsonWebKeySet::new(vec![key.as_verification_key()])),
            ClientId::new(config.oidc.client_id),
            None,
        ),
        http: reqwest::Client::new(),
        issuer: config.oidc.issuer_url,
    };
    let now = ClientAuth::now()? / 1_000_000_000;
    let source = json!({
        "iss": "https://issuer.example", "aud": ["browser-client"], "sub": "alice",
        "exp": now + 60, "iat": now - 1, "nonce": "test-nonce",
    });
    let access = AccessToken::new("test-access-token".into());
    let token = |source| -> std::result::Result<CoreTokenResponse, Box<dyn std::error::Error>> {
        let claims: CoreIdTokenClaims = serde_json::from_value(source)?;
        let id = CoreIdToken::new(
            claims,
            &key,
            CoreJwsSigningAlgorithm::EdDsa,
            Some(&access),
            None,
        )?;
        Ok(CoreTokenResponse::new(
            access.clone(),
            CoreTokenType::Bearer,
            CoreIdTokenFields::new(Some(id), EmptyExtraTokenFields {}),
        ))
    };
    let nonce = Nonce::new("test-nonce".into());
    let reply = token(source.clone())?;
    assert_eq!(oidc.identity(&reply, &nonce)?.subject, "alice");
    assert!(oidc
        .identity(&reply, &Nonce::new("other-nonce".into()))
        .is_err());
    for (field, value) in [
        ("iss", json!("https://foreign.example")),
        ("aud", json!(["other-client"])),
        ("exp", json!(now - 1)),
    ] {
        let mut changed = source.clone();
        changed[field] = value;
        assert!(
            oidc.identity(&token(changed)?, &nonce).is_err(),
            "accepted invalid {field}"
        );
    }
    let mut changed = reply;
    changed.set_access_token(AccessToken::new("different-access-token".into()));
    assert!(oidc.identity(&changed, &nonce).is_err());
    let absent = CoreTokenResponse::new(
        access,
        CoreTokenType::Bearer,
        CoreIdTokenFields::new(None, EmptyExtraTokenFields {}),
    );
    assert!(oidc.identity(&absent, &nonce).is_err());
    Ok(())
}

#[tokio::test]
async fn client_auth_no_service() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = owner()?;
    assert!(matches!(
        owner.service("access-token", [1; 16]).await,
        Err(Error::ClientUnauthenticated { .. })
    ));
    assert!(owner
        .service(&"x".repeat(MAX_TOKEN_BYTES + 1), [1; 16])
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn client_auth_metadata() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = owner()?;
    let session = session(&owner)?;
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(
        "x-araphor-tenant",
        Uuid::from_bytes([1; 16]).to_string().parse()?,
    );
    metadata.insert("origin", owner.origin.parse()?);
    metadata.insert(
        "cookie",
        format!("araphor-session={}", session.token).parse()?,
    );
    metadata.insert("x-araphor-csrf", session.csrf.parse()?);
    owner.authenticate(&metadata, true).await?.check()?;
    metadata.remove("x-araphor-csrf");
    assert!(owner.authenticate(&metadata, true).await.is_err());
    owner.authenticate(&metadata, false).await?.check()?;
    metadata.insert(
        "x-araphor-tenant",
        Uuid::from_bytes([2; 16]).to_string().parse()?,
    );
    assert!(matches!(
        owner.authenticate(&metadata, false).await,
        Err(Error::ClientDenied { .. })
    ));
    metadata.insert(
        "x-araphor-tenant",
        Uuid::from_bytes([1; 16]).to_string().parse()?,
    );
    metadata.append(
        "x-araphor-tenant",
        Uuid::from_bytes([1; 16]).to_string().parse()?,
    );
    assert!(owner.authenticate(&metadata, false).await.is_err());
    metadata.remove("x-araphor-tenant");
    metadata.insert(
        "x-araphor-tenant",
        Uuid::from_bytes([1; 16]).to_string().parse()?,
    );
    metadata.insert("authorization", "Bearer different-token".parse()?);
    assert!(owner.authenticate(&metadata, false).await.is_err());
    metadata.remove("authorization");
    metadata.append(
        "cookie",
        format!("araphor-session={}", session.token).parse()?,
    );
    assert!(owner.authenticate(&metadata, false).await.is_err());
    Ok(())
}

#[test]
fn client_auth_error_classes() {
    let denied = ClientDeniedSnafu.build();
    assert_eq!(denied.status_code(), StatusCode::PermissionDenied);
    assert_eq!(denied.retry_hint(), RetryHint::NonRetryable);
    let source = std::io::Error::other("private provider details");
    let invalid = OidcOwner::failure("verify ID token", true, source);
    assert_eq!(invalid.status_code(), StatusCode::PermissionDenied);
    assert!(!invalid.to_string().contains("private provider details"));
    let source = std::io::Error::other("private token reply");
    let unavailable = OidcOwner::failure("introspect access token", false, source);
    assert_eq!(unavailable.status_code(), StatusCode::Unavailable);
    assert_eq!(unavailable.retry_hint(), RetryHint::Retryable);
    assert!(!unavailable.to_string().contains("private token reply"));
}
