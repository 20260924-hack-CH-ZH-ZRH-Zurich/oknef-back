use crate::{
    App, AppError, AppResult,
    application::{records, security},
    domain::now,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub fn metadata(body: &Value) -> AppResult<Value> {
    let Some(items) = body.get("evidence") else {
        return Ok(json!([]));
    };
    let items = items
        .as_array()
        .filter(|items| items.len() <= 12)
        .ok_or_else(|| AppError::bad("Provide at most 12 evidence metadata records"))?;
    let mut result = Vec::new();
    for item in items {
        security::fields(
            item,
            &[
                "name",
                "mime_type",
                "size_bytes",
                "sha256",
                "source",
                "captured_at",
            ],
        )?;
        security::text(item, "name", 200)?;
        let mime = security::text(item, "mime_type", 100)?;
        if ![
            "image/png",
            "image/jpeg",
            "image/webp",
            "video/mp4",
            "video/webm",
            "video/quicktime",
            "audio/webm",
            "audio/ogg",
            "audio/wav",
            "audio/mpeg",
            "audio/mp4",
            "text/plain",
            "application/pdf",
        ]
        .contains(&mime)
        {
            return Err(AppError::bad("Unsupported evidence content type"));
        }
        if !item["size_bytes"]
            .as_u64()
            .is_some_and(|size| size > 0 && size <= 100 * 1024 * 1024)
            || !item["sha256"]
                .as_str()
                .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()))
            || !item["source"]
                .as_str()
                .is_some_and(|source| ["camera", "upload", "microphone", "text"].contains(&source))
            || item
                .get("captured_at")
                .is_some_and(|date| !date.as_u64().is_some_and(|date| date <= now() + 300))
        {
            return Err(AppError::bad(
                "Evidence needs a size, SHA-256 digest, capture source and valid timestamp",
            ));
        }
        let mut saved = item.clone();
        saved["id"] = json!(Uuid::new_v4().to_string());
        saved["provenance"] = json!("client_reported_metadata");
        saved["bytes_retained"] = json!(false);
        saved["digest_verified"] = json!(false);
        result.push(saved);
    }
    Ok(json!(result))
}

pub fn asset_ids(body: &Value) -> AppResult<Vec<String>> {
    let Some(ids) = body.get("asset_ids") else {
        return Ok(vec![]);
    };
    let ids = ids
        .as_array()
        .filter(|ids| ids.len() <= 30)
        .ok_or_else(|| AppError::bad("Provide at most 30 asset references"))?;
    let mut result = Vec::new();
    for id in ids {
        let id = id
            .as_str()
            .filter(|id| Uuid::parse_str(id).is_ok())
            .ok_or_else(|| AppError::bad("Asset references must be UUIDs"))?;
        if result.iter().any(|existing| existing == id) {
            return Err(AppError::bad("Asset references must be unique"));
        }
        result.push(id.to_owned());
    }
    Ok(result)
}

pub async fn owned_assets(app: &App, user: &Value, ids: &[String]) -> AppResult<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let assets = app.db.records(records::tenant(user)?, "assets").await?;
    if ids
        .iter()
        .any(|id| !assets.iter().any(|asset| asset["id"] == *id))
    {
        return Err(AppError::bad(
            "Every referenced asset must exist in the current workspace",
        ));
    }
    Ok(())
}

pub async fn parent(app: &App, user: &Value, body: &Value) -> AppResult<Value> {
    let Some(id) = body.get("parent_session_id") else {
        return Ok(Value::Null);
    };
    let id = id
        .as_str()
        .filter(|id| Uuid::parse_str(id).is_ok())
        .ok_or_else(|| AppError::bad("Parent session must be a UUID"))?;
    let tenant = records::tenant(user)?;
    for collection in ["security_sessions", "chat_sessions"] {
        let records = app.db.records(tenant, collection).await?;
        if records.iter().any(|record| record["id"] == id) {
            return Ok(json!(id));
        }
    }
    Err(AppError::bad(
        "Parent session must exist in the current workspace",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_never_accepts_forged_assurance_or_inline_bytes() {
        let base = json!({"name":"sample.png","mime_type":"image/png","size_bytes":8,"sha256":"a".repeat(64),"source":"camera"});
        let valid = metadata(&json!({"evidence":[base.clone()]})).unwrap();
        assert_eq!(valid[0]["digest_verified"], false);
        for key in ["data_url", "verified", "tenant_id", "digest_verified"] {
            let mut item = base.clone();
            item[key] = json!(true);
            assert!(metadata(&json!({"evidence":[item]})).is_err());
        }
        assert!(asset_ids(&json!({"asset_ids":["../../other"]})).is_err());
    }
}
