use crate::{
    App, AppResult,
    application::{auth, records},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde_json::{Value, json};
pub async fn assets(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    Ok(Json(
        json!({"assets":app.db.records(records::tenant(&user)?,"assets").await?}),
    ))
}
pub async fn create_asset(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    let result = records::create_asset(&app, &user, body).await?;
    app.event(&user, "asset.created");
    Ok(Json(result))
}
pub async fn patch_asset(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    let result = records::patch_asset(&app, &user, &id, body).await?;
    app.event(&user, "asset.updated");
    Ok(Json(result))
}
pub async fn delete_asset(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    records::find(&app, &user, "assets", &id).await?;
    let result = app
        .db
        .call(
            reqwest::Method::DELETE,
            &format!("/v1/records/assets/{id}"),
            Some(records::tenant(&user)?),
            None,
        )
        .await?;
    app.event(&user, "asset.deleted");
    Ok(Json(result))
}
pub async fn plans(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    Ok(Json(
        json!({"plans":app.db.records(records::tenant(&user)?,"succession").await?}),
    ))
}
pub async fn create_plan(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    let value = records::create_plan(&app, &user, body).await?;
    app.event(&user, "succession.created");
    Ok(Json(value))
}
pub async fn review(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    let value = records::review(&app, &user, &id, false).await?;
    app.event(&user, "succession.review_requested");
    Ok(Json(value))
}
pub async fn cancel(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    let value = records::review(&app, &user, &id, true).await?;
    app.event(&user, "succession.cancelled");
    Ok(Json(value))
}
async fn member_data(app: &App, user: &Value) -> AppResult<Vec<Value>> {
    crate::application::workspaces::members(app, user).await
}
pub async fn members(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    Ok(Json(json!({"members":member_data(&app,&user).await?})))
}
pub async fn dashboard(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    let tenant = records::tenant(&user)?;
    let assets = app.db.records(tenant, "assets").await?;
    let plans = app.db.records(tenant, "succession").await?;
    let total: f64 = assets
        .iter()
        .filter(|a| a["currency"] == "CHF")
        .filter_map(|a| a["value"].as_f64())
        .sum();
    Ok(Json(
        json!({"asset_count":assets.len(),"assets":assets,"total_value":total,"currency":"CHF","plans":plans,"members":member_data(&app,&user).await?,"account_type":user["account_type"],"demo":user["demo"],
        "security":{"metadata_only":true,"passkeys":true,"post_quantum":false,"release_enabled":false}}),
    ))
}
