use crate::{App, AppError, AppResult, application::auth};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    email: String,
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    name: String,
    email: String,
    password: String,
    account_type: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Demo {
    mode: Option<String>,
}
async fn signed_in(app: &App, user: Value) -> AppResult<axum::response::Response> {
    let (cookie, user) = auth::create_session(app, &user).await?;
    let mut response = Json(json!({"user":user})).into_response();
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&cookie)
            .map_err(|_| AppError::unavailable("Session creation failed"))?,
    );
    Ok(response)
}
pub async fn login(
    State(app): State<App>,
    Json(body): Json<Login>,
) -> AppResult<axum::response::Response> {
    app.limit(
        &format!("auth:{}", auth::token_hash(&body.email.to_lowercase())),
        8,
        300,
    )?;
    let user = auth::login(&app, body.email, body.password).await?;
    signed_in(&app, user).await
}
pub async fn register(
    State(app): State<App>,
    Json(body): Json<Register>,
) -> AppResult<axum::response::Response> {
    app.limit("register", 30, 300)?;
    let user = auth::register(
        &app,
        body.name,
        body.email,
        body.password,
        body.account_type,
    )
    .await?;
    signed_in(&app, user).await
}
pub async fn demo(
    State(app): State<App>,
    body: Option<Json<Demo>>,
) -> AppResult<axum::response::Response> {
    app.limit("demo", 60, 300)?;
    let mode = body
        .as_ref()
        .and_then(|body| body.mode.as_deref())
        .unwrap_or("personal");
    let user = auth::demo_profile(&app, mode).await?;
    signed_in(&app, user).await
}
pub async fn me(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    Ok(Json(json!({"user":auth::session(&app,&headers).await?})))
}
pub async fn logout(
    State(app): State<App>,
    headers: HeaderMap,
) -> AppResult<axum::response::Response> {
    if let Some(token) = auth::token(&headers) {
        app.db
            .call(
                reqwest::Method::DELETE,
                &format!("/v1/sessions/{}", auth::token_hash(&token)),
                None,
                None,
            )
            .await?;
    }
    let secure = if app.config.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "oknef_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"
        ))
        .unwrap(),
    );
    Ok(response)
}
