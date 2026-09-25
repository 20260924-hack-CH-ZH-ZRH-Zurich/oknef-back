use crate::{
    App, AppError, AppResult,
    application::{auth, records, security},
    domain::now,
};
use axum::http::StatusCode;
use serde_json::{Value, json};

pub fn validate_input(body: &Value) -> AppResult<()> {
    security::fields(body, &["message", "workflow", "locale"])?;
    let workflow = security::text(body, "workflow", 80)?;
    if ![
        "legacy-review",
        "identity-review",
        "phishing-review",
        "qr-review",
        "call-review",
        "document-review",
        "recovery-review",
        "policy-review",
        "simulation-review",
        "video-review",
        "trusted-voice-review",
        "advisor-review",
    ]
    .contains(&workflow)
    {
        return Err(AppError::bad(
            "Choose an available workflow from the agent catalog",
        ));
    }
    if !body["message"]
        .as_str()
        .is_some_and(|message| !message.trim().is_empty() && message.len() <= 5000)
        || !body["locale"]
            .as_str()
            .is_some_and(|locale| ["en", "es", "de", "fr"].contains(&locale))
    {
        return Err(AppError::bad(
            "Provide a supported locale and 1-5000 bytes of workflow evidence",
        ));
    }
    Ok(())
}

async fn pending(app: &App, user: &Value, body: &Value) -> AppResult<Value> {
    let id = uuid::Uuid::new_v4().to_string();
    let value = json!({"id":id,"workflow":body["workflow"],"locale":body["locale"],"status":"pending","run_state":"pending",
        "created_at":now(),"started_at":now(),"updated_at":now(),"completed_at":null,"created_by":user["id"],"synthetic":user["demo"]==true,
        "input_sha256":auth::token_hash(body["message"].as_str().unwrap()),"executed_actions":[],"provider":"openclaw-via-rust-core"});
    app.db
        .create(records::tenant(user)?, "workflow_runs", &id, &value)
        .await?;
    app.event(user, "workflow.started");
    Ok(value)
}

fn failure_code(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 | 422 => "workflow_rejected",
        401 | 403 => "workflow_gateway_authentication",
        429 => "workflow_capacity",
        _ => "workflow_provider_unavailable",
    }
}

pub fn failed(mut record: Value, code: &str, upstream_status: Option<u16>) -> Value {
    record["run_state"] = json!("failed");
    record["status"] = json!("failed");
    record["error_code"] = json!(code);
    record["upstream_status"] = json!(upstream_status);
    record["updated_at"] = json!(now());
    record["completed_at"] = json!(now());
    record
}

fn completed(mut record: Value, result: &Value) -> AppResult<Value> {
    if result["status"] != "needs_human_review"
        || result["workflow"] != record["workflow"]
        || !result["executed_actions"]
            .as_array()
            .is_some_and(Vec::is_empty)
        || !result["findings"]
            .as_array()
            .is_some_and(|items| items.len() == 2 && items.iter().all(valid_finding))
        || result["review"]["agent"] != "verifier"
        || !valid_finding(&result["review"])
        || result.to_string().len() > 200_000
    {
        return Err(AppError::unavailable("Invalid workflow response"));
    }
    for field in [
        "status",
        "findings",
        "review",
        "catalog_version",
        "skill_ids",
        "review_scope",
    ] {
        record[field] = result[field].clone();
    }
    record["run_state"] = json!("completed");
    record["updated_at"] = json!(now());
    record["completed_at"] = json!(now());
    Ok(record)
}

fn valid_finding(value: &Value) -> bool {
    value.as_object().is_some_and(|item| item.len() == 3)
        && value["agent"]
            .as_str()
            .is_some_and(|name| crate::domain::valid_name(name, 40))
        && value["answer"]
            .as_str()
            .is_some_and(|answer| !answer.trim().is_empty() && answer.len() <= 40_000)
        && value["source"] == "openclaw-via-rust-core"
}

async fn save_failed(
    app: &App,
    user: &Value,
    record: Value,
    code: &str,
    status: StatusCode,
    upstream: Option<u16>,
) -> AppResult<Value> {
    let record = failed(record, code, upstream);
    app.db
        .save(
            records::tenant(user)?,
            "workflow_runs",
            record["id"].as_str().unwrap(),
            &record,
        )
        .await?;
    app.event(user, "workflow.failed");
    Err(AppError::new(
        status,
        &format!("Workflow failed: {code}. The run remains in workspace history."),
    ))
}

pub async fn run(app: &App, user: &Value, body: Value) -> AppResult<Value> {
    validate_input(&body)?;
    let record = pending(app, user, &body).await?;
    let response = match app
        .client
        .post(format!("{}/v1/workflows", app.config.covenant_url))
        .bearer_auth(&app.config.covenant_token)
        .json(&body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return save_failed(
                app,
                user,
                record,
                if error.is_timeout() {
                    "workflow_timeout"
                } else {
                    "workflow_gateway_unavailable"
                },
                StatusCode::SERVICE_UNAVAILABLE,
                None,
            )
            .await;
        }
    };
    let status = response.status();
    if !status.is_success() {
        return save_failed(
            app,
            user,
            record,
            failure_code(status),
            status,
            Some(status.as_u16()),
        )
        .await;
    }
    let result = match response.json::<Value>().await {
        Ok(result) => result,
        Err(_) => {
            return save_failed(
                app,
                user,
                record,
                "workflow_invalid_response",
                StatusCode::BAD_GATEWAY,
                Some(status.as_u16()),
            )
            .await;
        }
    };
    let result = match completed(record.clone(), &result) {
        Ok(result) => result,
        Err(_) => {
            return save_failed(
                app,
                user,
                record,
                "workflow_invalid_response",
                StatusCode::BAD_GATEWAY,
                Some(status.as_u16()),
            )
            .await;
        }
    };
    app.db
        .save(
            records::tenant(user)?,
            "workflow_runs",
            result["id"].as_str().unwrap(),
            &result,
        )
        .await?;
    app.event(user, "workflow.completed");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_workflows_are_rejected_before_audit_creation() {
        for workflow in ["constructor", "unrestricted-tools", "unknown-review"] {
            assert!(
                validate_input(&json!({"workflow":workflow,"locale":"en","message":"test"}))
                    .is_err()
            );
        }
        assert!(
            validate_input(&json!({"workflow":"advisor-review","locale":"en","message":"test"}))
                .is_ok()
        );
    }
    #[test]
    fn failure_record_has_safe_code_and_no_upstream_body() {
        let record = failed(
            json!({"id":"one","created_by":"actor","input_sha256":"digest","executed_actions":[]}),
            "workflow_provider_unavailable",
            Some(502),
        );
        assert_eq!(record["run_state"], "failed");
        assert_eq!(record["upstream_status"], 502);
        assert!(record.get("message").is_none());
        assert!(record.get("upstream_body").is_none());
    }
    #[test]
    fn completion_cannot_invent_executed_actions_or_change_workflow() {
        let record = json!({"workflow":"advisor-review"});
        let finding = |agent| json!({"agent":agent,"answer":"Unverified evidence review","source":"openclaw-via-rust-core"});
        let result = json!({"workflow":"advisor-review","status":"needs_human_review","executed_actions":[],"findings":[finding("advisor"),finding("inventory")],"review":finding("verifier")});
        assert!(completed(record.clone(), &result).is_ok());
        let mut invalid = result.clone();
        invalid["executed_actions"] = json!(["transfer"]);
        assert!(completed(record.clone(), &invalid).is_err());
        invalid = result;
        invalid["workflow"] = json!("other");
        assert!(completed(record, &invalid).is_err());
    }
}
