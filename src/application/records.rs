use crate::{
    App, AppError, AppResult,
    domain::{can_review, now, valid_email, valid_name},
};
use serde_json::{Value, json};
use uuid::Uuid;

pub fn tenant(user: &Value) -> AppResult<&str> {
    user["tenant_id"]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::bad("Missing tenant context"))
}
fn fields(body: &Value, allowed: &[&str]) -> bool {
    body.as_object()
        .is_some_and(|o| o.keys().all(|key| allowed.contains(&key.as_str())))
}
pub fn validate_asset(body: &Value, partial: bool) -> AppResult<()> {
    if !fields(
        body,
        &[
            "name",
            "category",
            "institution",
            "value",
            "currency",
            "notes",
            "beneficiary",
        ],
    ) {
        return Err(AppError::bad(
            "Only asset metadata is accepted. Never submit passwords or recovery secrets.",
        ));
    }
    if (!partial || body.get("name").is_some())
        && !body["name"].as_str().is_some_and(|s| valid_name(s, 200))
    {
        return Err(AppError::bad(
            "Asset name is required and must be under 200 characters",
        ));
    }
    for key in ["category", "institution", "notes", "beneficiary"] {
        if body.get(key).is_some() && !body[key].as_str().is_some_and(|s| s.len() <= 2000) {
            return Err(AppError::bad("Invalid asset metadata"));
        }
    }
    if body.get("value").is_some()
        && !body["value"]
            .as_f64()
            .is_some_and(|n| n.is_finite() && (0.0..=1e15).contains(&n))
    {
        return Err(AppError::bad("Value must be a non-negative number"));
    }
    if body.get("currency").is_some()
        && !body["currency"]
            .as_str()
            .is_some_and(|s| s.len() == 3 && s.chars().all(|c| c.is_ascii_uppercase()))
    {
        return Err(AppError::bad(
            "Currency must be a three-letter uppercase code",
        ));
    }
    Ok(())
}
pub async fn create_asset(app: &App, user: &Value, body: Value) -> AppResult<Value> {
    validate_asset(&body, false)?;
    let id = Uuid::new_v4().to_string();
    let mut asset = json!({"id":id,"name":"","category":"other","institution":"","value":0.0,"currency":"CHF","notes":"","beneficiary":"","created_at":now(),"updated_at":now()});
    for (key, value) in body.as_object().unwrap() {
        asset[key] = value.clone();
    }
    app.db.save(tenant(user)?, "assets", &id, &asset).await
}
pub async fn find(app: &App, user: &Value, collection: &str, id: &str) -> AppResult<Value> {
    if Uuid::parse_str(id).is_err() {
        return Err(AppError::new(
            axum::http::StatusCode::NOT_FOUND,
            "Record not found",
        ));
    }
    app.db
        .records(tenant(user)?, collection)
        .await?
        .into_iter()
        .find(|r| r["id"] == id)
        .ok_or_else(|| AppError::new(axum::http::StatusCode::NOT_FOUND, "Record not found"))
}
pub async fn patch_asset(app: &App, user: &Value, id: &str, body: Value) -> AppResult<Value> {
    validate_asset(&body, true)?;
    let mut asset = find(app, user, "assets", id).await?;
    for (key, value) in body.as_object().unwrap() {
        asset[key] = value.clone();
    }
    asset["updated_at"] = json!(now());
    app.db.save(tenant(user)?, "assets", id, &asset).await
}
pub async fn create_plan(app: &App, user: &Value, body: Value) -> AppResult<Value> {
    if !fields(
        &body,
        &[
            "title",
            "beneficiary",
            "guardian_emails",
            "required_approvals",
            "waiting_days",
        ],
    ) {
        return Err(AppError::bad("Invalid succession fields"));
    }
    let title = body["title"]
        .as_str()
        .filter(|s| valid_name(s, 200))
        .ok_or_else(|| AppError::bad("Plan title required"))?;
    let beneficiary = body["beneficiary"]
        .as_str()
        .filter(|s| valid_name(s, 200))
        .ok_or_else(|| AppError::bad("Beneficiary required"))?;
    let guardians = body["guardian_emails"]
        .as_array()
        .filter(|v| {
            !v.is_empty() && v.len() <= 10 && v.iter().all(|s| s.as_str().is_some_and(valid_email))
        })
        .ok_or_else(|| AppError::bad("Provide 1-10 valid guardian emails"))?;
    let unique = guardians
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_lowercase)
        .collect::<std::collections::HashSet<_>>();
    let approvals = body["required_approvals"].as_u64().unwrap_or(1);
    let wait = body["waiting_days"].as_u64().unwrap_or(30);
    if unique.len() != guardians.len()
        || approvals == 0
        || approvals > unique.len() as u64
        || !(7..=365).contains(&wait)
    {
        return Err(AppError::bad(
            "Use unique guardians, a valid quorum, and a 7-365 day waiting period",
        ));
    }
    let id = Uuid::new_v4().to_string();
    let value = json!({"id":id,"title":title,"beneficiary":beneficiary,"guardian_emails":guardians,"required_approvals":approvals,"waiting_days":wait,"status":"draft","created_at":now(),"updated_at":now()});
    app.db.save(tenant(user)?, "succession", &id, &value).await
}
pub async fn review(app: &App, user: &Value, id: &str, cancel: bool) -> AppResult<Value> {
    let mut plan = find(app, user, "succession", id).await?;
    if !cancel && !can_review(plan["status"].as_str().unwrap_or("")) {
        return Err(AppError::new(
            axum::http::StatusCode::CONFLICT,
            "Only a draft can enter review",
        ));
    }
    if cancel && plan["status"] == "cancelled" {
        return Err(AppError::new(
            axum::http::StatusCode::CONFLICT,
            "Plan already cancelled",
        ));
    }
    plan["status"] = json!(if cancel {
        "cancelled"
    } else {
        "review_requested"
    });
    plan["updated_at"] = json!(now());
    app.db.save(tenant(user)?, "succession", id, &plan).await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_plaintext_secret_and_tenant_assignment() {
        assert!(validate_asset(&json!({"name":"a","password":"secret"}), false).is_err());
        assert!(validate_asset(&json!({"name":"a","tenant_id":"victim"}), false).is_err());
        assert!(validate_asset(&json!({"name":"a","value":-1}), false).is_err());
    }
}
