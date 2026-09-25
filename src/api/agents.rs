use super::ai::{authorize, provider_error};
use crate::{
    App, AppError, AppResult,
    application::{auth, workflow_runs},
};
use axum::{Json, extract::State, http::HeaderMap};
use serde_json::Value;

pub async fn workflows(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = authorize(&app, &headers).await?;
    workflow_runs::run(&app, &user, body).await.map(Json)
}

pub async fn agent_catalog(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    auth::session(&app, &headers).await?;
    let response = app
        .client
        .get(format!("{}/v1/catalog", app.config.covenant_url))
        .bearer_auth(&app.config.covenant_token)
        .send()
        .await
        .map_err(|_| AppError::unavailable("Agent catalog unavailable"))?;
    if !response.status().is_success() {
        return Err(provider_error(response).await);
    }
    response
        .json()
        .await
        .map(Json)
        .map_err(|_| AppError::unavailable("Invalid agent catalog response"))
}
