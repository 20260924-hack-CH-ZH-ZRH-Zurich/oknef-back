use crate::{
    App, AppResult,
    api::vault::{Envelope, validate_size},
    application::{auth, records},
    domain::now,
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upload {
    envelope: Envelope,
}

pub async fn list(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    Ok(Json(
        json!({"items":app.db.records(records::tenant(&user)?, "drive").await?}),
    ))
}
pub async fn upload(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Upload>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    app.limit(&format!("drive:{}", records::tenant(&user)?), 10, 300)?;
    validate_size(&body.envelope, 8 * 1024 * 1024)?;
    let id = uuid::Uuid::new_v4().to_string();
    let item = json!({"id":id,"envelope":body.envelope,"created_at":now(),"created_by":user["id"],"synthetic":user["demo"]==true});
    app.db
        .create(records::tenant(&user)?, "drive", &id, &item)
        .await?;
    app.event(&user, "drive.file_saved");
    Ok(Json(item))
}
pub async fn delete(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    records::find(&app, &user, "drive", &id).await?;
    let result = app
        .db
        .call(
            reqwest::Method::DELETE,
            &format!("/v1/records/drive/{id}"),
            Some(records::tenant(&user)?),
            None,
        )
        .await?;
    app.event(&user, "drive.file_removed");
    Ok(Json(result))
}
