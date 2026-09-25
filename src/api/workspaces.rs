use crate::{
    App, AppError, AppResult,
    application::{auth, security, workspaces},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

pub async fn list(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    workspaces::list(&app, &user).await.map(Json)
}
pub async fn invitations(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    workspaces::invitations(&app, &user).await.map(Json)
}
pub async fn invite(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    workspaces::invite(&app, &user, body).await.map(Json)
}
pub async fn accept(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    security::fields(&body, &[])?;
    let user = auth::session(&app, &headers).await?;
    workspaces::accept(&app, &user, &id).await.map(Json)
}
pub async fn switch(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Response> {
    security::fields(&body, &["tenant_id"])?;
    let tenant = security::text(&body, "tenant_id", 100)?;
    let user = auth::session(&app, &headers).await?;
    let membership = workspaces::memberships(&app, &user)
        .await?
        .into_iter()
        .find(|m| m["tenant_id"] == tenant)
        .ok_or_else(|| {
            AppError::new(
                StatusCode::FORBIDDEN,
                "You are not a member of this workspace",
            )
        })?;
    let (cookie, user) = auth::create_session(&app, &membership).await?;
    if let Some(old) = auth::token(&headers) {
        app.db
            .call(
                reqwest::Method::DELETE,
                &format!("/v1/sessions/{}", auth::token_hash(&old)),
                None,
                None,
            )
            .await?;
    }
    let mut response = Json(json!({"user":user})).into_response();
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&cookie)
            .map_err(|_| AppError::unavailable("Session creation failed"))?,
    );
    Ok(response)
}
