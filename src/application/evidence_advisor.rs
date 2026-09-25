use crate::{App, AppError, AppResult, application::records, proto};
use serde_json::{Value, json};

pub async fn answer(
    app: &App,
    user: &Value,
    session: &Value,
    question: &str,
    locale: &str,
) -> AppResult<Value> {
    app.limit("ai:global", 60, 60)?;
    app.limit(&format!("ai:{}", records::tenant(user)?), 20, 60)?;
    let evidence: String = session["content"]
        .as_str()
        .unwrap_or("")
        .chars()
        .take(3500)
        .collect();
    let context = json!({"evidence_session":{"kind":session["kind"],"content":evidence,"assessment":session["assessment"],
        "truncated":session["content"].as_str().unwrap_or("").chars().count()>3500},
        "capabilities":{"authenticity_verification":false,"actions_executed":false}});
    let mut request = tonic::Request::new(proto::ChatRequest { payload_json: json!({"message":question,"model":"auto","locale":locale,"history":[],"context":context}).to_string() });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", app.config.core_token)
            .parse()
            .map_err(|_| AppError::unavailable("Invalid core configuration"))?,
    );
    let response = app
        .grpc
        .clone()
        .ask(request)
        .await
        .map_err(|error| AppError::new(axum::http::StatusCode::BAD_GATEWAY, error.message()))?;
    let response: Value = serde_json::from_str(&response.into_inner().payload_json)
        .map_err(|_| AppError::unavailable("Invalid evidence advisor response"))?;
    if !response["answer"]
        .as_str()
        .is_some_and(|text| !text.is_empty() && text.len() <= 40_000)
    {
        return Err(AppError::unavailable("Invalid evidence advisor response"));
    }
    Ok(response)
}
