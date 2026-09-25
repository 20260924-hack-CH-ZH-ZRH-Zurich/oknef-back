use crate::{
    App, AppResult,
    application::{auth, records, security, security_overview},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde_json::{Value, json};

pub async fn overview(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    security_overview::overview(&app, &user).await.map(Json)
}
pub async fn sessions(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    Ok(Json(
        json!({"sessions":app.db.records(records::tenant(&user)?,"security_sessions").await?}),
    ))
}
pub async fn create(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    security::create(&app, &user, body, false).await.map(Json)
}
pub async fn get(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    security::get(&app, &user, &id).await.map(Json)
}
pub async fn question(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    security::question(&app, &user, &id, body).await.map(Json)
}
pub async fn mode(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    security_overview::mode(&app, &user, body).await.map(Json)
}
pub async fn simulate(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    security::simulation(&app, &user, body).await.map(Json)
}
