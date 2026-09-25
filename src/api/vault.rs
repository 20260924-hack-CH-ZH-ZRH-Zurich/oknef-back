use crate::{
    App, AppError, AppResult,
    application::{auth, records},
    domain::now,
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    version: u8,
    algorithm: String,
    iv: String,
    ciphertext: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    envelope: Envelope,
}
fn validate(e: &Envelope) -> AppResult<()> {
    validate_size(e, 65536)
}
pub(crate) fn validate_size(e: &Envelope, max_ciphertext: usize) -> AppResult<()> {
    if e.version != 1
        || e.algorithm != "AES-256-GCM"
        || STANDARD.decode(&e.iv).map_or(true, |v| v.len() != 12)
        || STANDARD
            .decode(&e.ciphertext)
            .map_or(true, |v| v.len() < 16 || v.len() > max_ciphertext)
    {
        return Err(AppError::bad(
            "A valid AES-256-GCM envelope with 12-byte IV is required",
        ));
    }
    Ok(())
}
pub async fn list(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    Ok(Json(
        json!({"items":app.db.records(records::tenant(&user)?,"vault").await?}),
    ))
}
pub async fn create(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Create>,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    validate(&body.envelope)?;
    let id = uuid::Uuid::new_v4().to_string();
    let item = json!({"id":id,"envelope":body.envelope,"created_at":now(),"updated_at":now()});
    app.db
        .save(records::tenant(&user)?, "vault", &id, &item)
        .await
        .map(Json)
}
pub async fn delete(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    records::find(&app, &user, "vault", &id).await?;
    app.db
        .call(
            reqwest::Method::DELETE,
            &format!("/v1/records/vault/{id}"),
            Some(records::tenant(&user)?),
            None,
        )
        .await
        .map(Json)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_short_iv_and_plaintext() {
        assert!(
            validate(&Envelope {
                version: 1,
                algorithm: "AES-256-GCM".into(),
                iv: "abcd".into(),
                ciphertext: "password".into()
            })
            .is_err()
        );
        assert!(serde_json::from_value::<Create>(json!({"envelope":{"version":1,"algorithm":"AES-256-GCM","iv":"","ciphertext":"","secret":"x"}})).is_err());
    }
}
