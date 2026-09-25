use crate::{
    App, AppResult,
    application::{approvals, auth},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde_json::Value;

pub async fn list(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    approvals::list(&app, &user).await.map(Json)
}
pub async fn policy(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    approvals::policy(&app, &user, body).await.map(Json)
}
pub async fn request(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    approvals::request(&app, &user, body).await.map(Json)
}
pub async fn vote(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    approvals::vote(&app, &user, &id, body).await.map(Json)
}
