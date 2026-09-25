use crate::{
    App, AppError, AppResult,
    application::{auth, chat_sessions, records, voice_policy},
    proto,
};
use axum::{
    Json,
    extract::{Multipart, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use reqwest::multipart::{Form, Part};
use serde_json::{Value, json};
pub(super) async fn authorize(app: &App, headers: &HeaderMap) -> AppResult<Value> {
    let user = auth::session(app, headers).await?;
    app.limit("ai:global", 60, 60)?;
    app.limit(&format!("ai:{}", records::tenant(&user)?), 20, 60)?;
    Ok(user)
}
async fn core_json(app: &App, path: &str, body: Option<&Value>) -> AppResult<Value> {
    let request = if body.is_some() {
        app.client.post(format!("{}{}", app.config.core_url, path))
    } else {
        app.client.get(format!("{}{}", app.config.core_url, path))
    };
    let mut request = request.bearer_auth(&app.config.core_token);
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request
        .send()
        .await
        .map_err(|_| AppError::unavailable("AI core unavailable"))?;
    if !response.status().is_success() {
        return Err(provider_error(response).await);
    }
    response
        .json()
        .await
        .map_err(|_| AppError::unavailable("Invalid AI response"))
}
pub(super) async fn provider_error(response: reqwest::Response) -> AppError {
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    AppError::new(
        status,
        body["error"]
            .as_str()
            .unwrap_or("AI provider request failed"),
    )
}
pub async fn models(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    auth::session(&app, &headers).await?;
    core_json(&app, "/v1/models", None).await.map(Json)
}
pub async fn chat(
    State(app): State<App>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = authorize(&app, &headers).await?;
    if !body.is_object() || body.get("context").is_some() {
        return Err(AppError::bad("Client context overrides are forbidden"));
    }
    let session_id = chat_sessions::prepare(&app, &user, &mut body).await?;
    let assets = app.db.records(records::tenant(&user)?, "assets").await?;
    let metadata:Vec<Value>=assets.iter().take(30).map(|a|json!({"name":a["name"],"category":a["category"],"institution":a["institution"],"beneficiary":a["beneficiary"]})).collect();
    body["context"] = json!({"demo":user["demo"],"account_type":user["account_type"],"assets":metadata,"capabilities":{"metadata_only":true,"release_enabled":false,"biometric_verification":false,"post_quantum_encryption":false}});
    app.event(&user, "chat.processing");
    let mut request = tonic::Request::new(proto::ChatRequest {
        payload_json: body.to_string(),
    });
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
        .map_err(|e| AppError::new(StatusCode::BAD_GATEWAY, e.message()))?;
    let mut response: Value = serde_json::from_str(&response.into_inner().payload_json)
        .map_err(|_| AppError::unavailable("Invalid core response"))?;
    chat_sessions::append(&app, &user, &session_id, &body, &response).await?;
    response["session_id"] = json!(session_id);
    app.event(&user, "chat.completed");
    Ok(Json(response))
}
pub async fn image(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = authorize(&app, &headers).await?;
    app.limit("image:global", 12, 300)?;
    app.limit(&format!("image:{}", records::tenant(&user)?), 4, 300)?;
    core_json(&app, "/v1/images", Some(&body)).await.map(Json)
}
pub async fn voice_session(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = authorize(&app, &headers).await?;
    voice_policy::enforce(&app, &user).await?;
    let response = voice_request(
        &app.client,
        &format!("{}/v1/realtime/session", app.config.core_url),
        &app.config.core_token,
        &headers,
    )?
    .json(&json!({}))
    .send()
    .await
    .map_err(|_| AppError::unavailable("Voice core unavailable"))?;
    if !response.status().is_success() {
        return Err(provider_error(response).await);
    }
    response
        .json()
        .await
        .map(Json)
        .map_err(|_| AppError::unavailable("Invalid voice response"))
}
pub async fn voice_call(
    State(app): State<App>,
    headers: HeaderMap,
    body: String,
) -> AppResult<axum::response::Response> {
    let user = authorize(&app, &headers).await?;
    voice_policy::enforce(&app, &user).await?;
    if body.len() > 65536 {
        return Err(AppError::bad("SDP offer too large"));
    }
    let response = voice_request(
        &app.client,
        &format!("{}/v1/realtime/call", app.config.core_url),
        &app.config.core_token,
        &headers,
    )?
    .header("content-type", "application/sdp")
    .body(body)
    .send()
    .await
    .map_err(|_| AppError::unavailable("Voice core unavailable"))?;
    if !response.status().is_success() {
        return Err(provider_error(response).await);
    }
    let sdp = response
        .text()
        .await
        .map_err(|_| AppError::unavailable("Invalid voice response"))?;
    Ok((
        [
            ("content-type", "application/sdp"),
            ("cache-control", "no-store"),
        ],
        sdp,
    )
        .into_response())
}
fn voice_request(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    headers: &HeaderMap,
) -> AppResult<reqwest::RequestBuilder> {
    let values = headers.get_all("x-oknef-locale");
    if values.iter().count() > 1 {
        return Err(AppError::bad("Invalid voice locale"));
    }
    let locale = match headers.get("x-oknef-locale") {
        None => "en",
        Some(value) => match value.to_str().ok() {
            Some("en") => "en",
            Some("de") => "de",
            Some("es") => "es",
            Some("fr") => "fr",
            _ => return Err(AppError::bad("Invalid voice locale")),
        },
    };
    Ok(client
        .post(url)
        .bearer_auth(token)
        .header("x-oknef-locale", locale))
}
pub async fn transcribe(
    State(app): State<App>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> AppResult<Json<Value>> {
    authorize(&app, &headers).await?;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::bad("Invalid audio upload"))?
    {
        if field.name() != Some("file") {
            continue;
        }
        let mime = field
            .content_type()
            .unwrap_or("application/octet-stream")
            .to_owned();
        let bytes = field
            .bytes()
            .await
            .map_err(|_| AppError::bad("Unreadable audio"))?;
        if bytes.len() > 20 * 1024 * 1024 {
            return Err(AppError::bad("Audio must be under 20 MB"));
        }
        let part = Part::bytes(bytes.to_vec())
            .file_name("recording")
            .mime_str(&mime)
            .map_err(|_| AppError::bad("Invalid audio content type"))?;
        let response = app
            .client
            .post(format!("{}/v1/transcriptions", app.config.core_url))
            .bearer_auth(&app.config.core_token)
            .multipart(Form::new().part("file", part))
            .send()
            .await
            .map_err(|_| AppError::unavailable("Transcription unavailable"))?;
        if !response.status().is_success() {
            return Err(provider_error(response).await);
        }
        return response
            .json()
            .await
            .map(Json)
            .map_err(|_| AppError::unavailable("Invalid transcription response"));
    }
    Err(AppError::bad("Audio file required"))
}
pub async fn ocr(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    authorize(&app, &headers).await?;
    core_json(&app, "/v1/ocr", Some(&body)).await.map(Json)
}

pub async fn media_analyze(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = authorize(&app, &headers).await?;
    app.limit(
        &format!("visual-review:{}", records::tenant(&user)?),
        8,
        300,
    )?;
    core_json(&app, "/v1/media/analyze", Some(&body))
        .await
        .map(Json)
}

#[cfg(test)]
#[path = "ai_tests.rs"]
mod tests;
