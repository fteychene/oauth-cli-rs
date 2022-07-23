use anyhow::Result;
use axum::{
    extract::{Extension, Query},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use log::debug;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    TokenResponse, TokenUrl,
};
use serde::Deserialize;
use std::net::SocketAddr;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Debug, Clone)]
pub struct OauthConfig {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub auth_url: AuthUrl,
    pub token_url: TokenUrl,
}

pub async fn oauth(oauth_config: OauthConfig) -> Result<String> {
    let oauth_client = oauth_client(oauth_config);

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let (token_tx, token_rx) = tokio::sync::oneshot::channel::<String>();

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, _csrf_token) = oauth_client
        .authorize_url(CsrfToken::new_random)
        // Add scope
        // Add extra param for like audience
        .set_pkce_challenge(pkce_challenge)
        .url();

    let app = Router::new()
        .route("/callback", get(auth_callback))
        .layer(Extension(oauth_client))
        .layer(Extension(tx))
        .layer(Extension(pkce_verifier.secret().clone()));

    debug!("Start http server on localhost:5000 for authentification");
    let addr = SocketAddr::from(([127, 0, 0, 1], 5000));
    tokio::spawn(
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .with_graceful_shutdown(async move {
                let token_received = rx.recv().await.unwrap();
                debug!("Stopping http server");
                token_tx.send(token_received).unwrap();
            }),
    );

    debug!("Open {} to start authentication flow", auth_url);
    open::that(auth_url.as_str())?;

    let token = token_rx.await?;
    debug!("Generated token : {}...", token);
    Ok(token)
}

fn oauth_client(oauth_config: OauthConfig) -> BasicClient {
    BasicClient::new(
        oauth_config.client_id,
        Some(oauth_config.client_secret),
        oauth_config.auth_url,
        Some(oauth_config.token_url),
    )
    .set_redirect_uri(RedirectUrl::new("http://localhost:5000/callback".to_string()).unwrap())
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AuthRequest {
    code: String,
    state: String,
}

async fn auth_callback(
    Query(query): Query<AuthRequest>,
    Extension(oauth_client): Extension<BasicClient>,
    Extension(sender): Extension<UnboundedSender<String>>,
    Extension(verifier_secret): Extension<String>,
) -> impl IntoResponse {
    debug!("Authentication callback received. Generating token");
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .set_pkce_verifier(PkceCodeVerifier::new(verifier_secret))
        .request_async(async_http_client)
        .await
        .unwrap()
        .access_token()
        .secret()
        .clone();
    debug!("Token generated");
    sender.send(token).unwrap();
    Html(format!("Generated token, you can close this tab"))
}
