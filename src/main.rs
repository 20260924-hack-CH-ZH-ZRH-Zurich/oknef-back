mod api;
mod application;
mod config;
mod domain;
mod infrastructure;
pub mod proto {
    tonic::include_proto!("oknef.v1");
}
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
#[derive(Clone)]
pub struct App {
    passkeys: application::passkeys::PasskeyState,
    config: Arc<config::Config>,
    db: infrastructure::Database,
    client: reqwest::Client,
    grpc: proto::ai_core_client::AiCoreClient<tonic::transport::Channel>,
    events: tokio::sync::broadcast::Sender<Value>,
    limits: Arc<Mutex<HashMap<String, (u64, u32)>>>,
}
impl App {
    fn limit(&self, key: &str, max: u32, window: u64) -> AppResult<()> {
        let now = domain::now();
        let mut limits = self
            .limits
            .lock()
            .map_err(|_| AppError::unavailable("Rate limit unavailable"))?;
        if limits.len() > 10000 {
            limits.retain(|_, (start, _)| now.saturating_sub(*start) < 300);
        }
        let entry = limits.entry(key.into()).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= window {
            *entry = (now, 0);
        }
        if entry.1 >= max {
            return Err(AppError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests. Please wait before retrying.",
            ));
        }
        entry.1 += 1;
        Ok(())
    }
    fn event(&self, user: &Value, kind: &str) {
        let _ = self
            .events
            .send(json!({"tenant_id":user["tenant_id"],"type":kind,"timestamp":domain::now()}));
    }
}
#[derive(Debug)]
pub struct AppError {
    status: StatusCode,
    message: String,
}
type AppResult<T> = Result<T, AppError>;
impl AppError {
    fn new(status: StatusCode, message: &str) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn bad(message: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    fn unavailable(message: &str) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }
}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error":self.message}))).into_response()
    }
}
async fn security(State(app): State<App>, request: axum::extract::Request, next: Next) -> Response {
    let origin = request
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok());
    let mutation = !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    let websocket = request.uri().path() == "/api/ws";
    if origin.is_some_and(|origin| origin != app.config.origin)
        || (mutation && request.headers().contains_key("cookie") && origin.is_none())
        || (websocket && origin != Some(app.config.origin.as_str()))
    {
        return AppError::new(StatusCode::FORBIDDEN, "Request origin is not permitted")
            .into_response();
    }
    let mut response = next.run(request).await;
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("info")
        .init();
    let config = Arc::new(config::Config::from_env()?);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(180))
        .build()?;
    let mut endpoint = tonic::transport::Channel::from_shared(config.core_grpc_url.clone())?
        .timeout(std::time::Duration::from_secs(180));
    if config.core_grpc_url.starts_with("https://") {
        endpoint =
            endpoint.tls_config(tonic::transport::ClientTlsConfig::new().with_webpki_roots())?;
    }
    let channel = endpoint.connect_lazy();
    let (events, _) = tokio::sync::broadcast::channel(256);
    let app = App {
        passkeys: application::passkeys::PasskeyState::new(&config.origin)
            .map_err(|e| e.message)?,
        db: infrastructure::Database {
            client: client.clone(),
            base: config.db_url.clone(),
            token: config.db_token.clone(),
        },
        client,
        grpc: proto::ai_core_client::AiCoreClient::new(channel),
        events,
        limits: Arc::new(Mutex::new(HashMap::new())),
        config: config.clone(),
    };
    let router = Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"status":"ok","service":"oknef-back"})) }),
        )
        .merge(api::routes())
        .layer(DefaultBodyLimit::max(21 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), security))
        .with_state(app);
    axum::serve(tokio::net::TcpListener::bind(&config.bind).await?, router).await?;
    Ok(())
}
