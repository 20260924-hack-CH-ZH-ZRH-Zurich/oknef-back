use crate::{App, AppResult, application::records, domain::now};
use serde_json::{Value, json};

pub async fn create(app: &App, user: &Value, session_id: &str, body: Value) -> AppResult<Value> {
    let session = records::find(app, user, "security_sessions", session_id).await?;
    let mut asset = records::asset_record(body)?;
    asset["source_session_id"] = json!(session_id);
    asset["source_provenance"] = json!("user_confirmed_evidence");
    asset["created_by"] = user["id"].clone();
    asset["synthetic"] = session["synthetic"].clone();
    let audit = json!({"id":uuid::Uuid::new_v4().to_string(),"action":"asset.created_from_evidence",
        "asset_id":asset["id"],"session_id":session_id,"actor_id":user["id"],"created_at":now(),
        "synthetic":session["synthetic"],"ownership_verified":false});
    app.db
        .create_batch(
            records::tenant(user)?,
            &[
                json!({"collection":"assets","id":asset["id"],"value":asset}),
                json!({"collection":"audit","id":audit["id"],"value":audit}),
            ],
        )
        .await?;
    app.event(user, "asset.created");
    Ok(asset)
}
