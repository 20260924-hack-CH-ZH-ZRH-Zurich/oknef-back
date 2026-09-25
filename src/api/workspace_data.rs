use crate::{
    App, AppResult,
    application::{auth, chat_sessions, connections, graph, records, voice_policy},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde_json::{Value, json};

pub async fn integrations(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    Ok(Json(
        json!({"integrations":app.db.records(records::tenant(&user)?, "integrations").await?}),
    ))
}
pub async fn create_integration(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    connections::create(&app, &user, body).await.map(Json)
}
pub async fn delete_integration(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    records::find(&app, &user, "integrations", &id).await?;
    let result = app
        .db
        .call(
            reqwest::Method::DELETE,
            &format!("/v1/records/integrations/{id}"),
            Some(records::tenant(&user)?),
            None,
        )
        .await?;
    app.event(&user, "integration.removed");
    Ok(Json(result))
}
pub async fn graph(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    graph::get(&app, &user).await.map(Json)
}
pub async fn chats(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    Ok(Json(
        json!({"sessions":app.db.records(records::tenant(&user)?, "chat_sessions").await?}),
    ))
}
pub async fn create_chat(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    chat_sessions::create(&app, &user, body).await.map(Json)
}
pub async fn chat(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    chat_sessions::get(&app, &user, &id).await.map(Json)
}
pub async fn transcript(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    chat_sessions::transcript(&app, &user, &id, body)
        .await
        .map(Json)
}
pub async fn voice_policy(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    voice_policy::get(&app, &user).await.map(Json)
}
pub async fn set_voice_policy(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    voice_policy::set(&app, &user, body).await.map(Json)
}
pub async fn workflow_runs(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    Ok(Json(
        json!({"runs":app.db.records(records::tenant(&user)?, "workflow_runs").await?}),
    ))
}
