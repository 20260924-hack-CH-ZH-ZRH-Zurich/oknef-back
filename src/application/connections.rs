use crate::{
    App, AppError, AppResult,
    application::{evidence, records, security},
    domain::now,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub fn validate(body: &Value) -> AppResult<Vec<String>> {
    security::fields(body, &["name", "provider", "account_label", "asset_ids"])?;
    security::text(body, "name", 160)?;
    security::text(body, "account_label", 200)?;
    if !body["provider"].as_str().is_some_and(|provider| {
        ["mail", "cloud-drive", "bank", "telecom", "custom"].contains(&provider)
    }) {
        return Err(AppError::bad(
            "Choose mail, cloud-drive, bank, telecom, or custom",
        ));
    }
    evidence::asset_ids(body)
}

pub async fn create(app: &App, user: &Value, body: Value) -> AppResult<Value> {
    let ids = validate(&body)?;
    evidence::owned_assets(app, user, &ids).await?;
    let id = Uuid::new_v4().to_string();
    let value = json!({"id":id,"name":body["name"],"provider":body["provider"],"account_label":body["account_label"],"asset_ids":ids,
        "status":"registered","connection_verified":false,"background_sync":false,"credential_storage":false,
        "created_at":now(),"created_by":user["id"],"synthetic":user["demo"]==true});
    app.db
        .create(records::tenant(user)?, "integrations", &id, &value)
        .await?;
    app.event(user, "integration.registered");
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_cannot_claim_provider_access_or_store_credentials() {
        let base =
            json!({"provider":"mail","name":"My mailbox","account_label":"Work","asset_ids":[]});
        assert!(validate(&base).is_ok());
        for key in [
            "access_token",
            "password",
            "status",
            "connection_verified",
            "tenant_id",
        ] {
            let mut value = base.clone();
            value[key] = json!("forged");
            assert!(validate(&value).is_err());
        }
    }
}
