use crate::{
    App, AppError, AppResult,
    application::{auth, records},
    domain::{now, valid_email},
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Clone)]
pub struct PasskeyState {
    webauthn: Arc<Webauthn>,
    pending: Arc<Mutex<HashMap<String, Pending>>>,
}
struct Pending {
    user: Value,
    expires: u64,
    ceremony: Ceremony,
}
enum Ceremony {
    Register(PasskeyRegistration),
    Login(PasskeyAuthentication),
}
impl PasskeyState {
    pub fn new(origin: &str) -> AppResult<Self> {
        let url = Url::parse(origin).map_err(|_| AppError::bad("Invalid WebAuthn origin"))?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(AppError::bad(
                "WebAuthn requires an origin without credentials or path",
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| AppError::bad("Missing WebAuthn RP ID"))?;
        if url.scheme() != "https" && !(url.scheme() == "http" && host == "localhost") {
            return Err(AppError::bad("WebAuthn requires HTTPS or localhost"));
        }
        let webauthn = WebauthnBuilder::new(host, &url)
            .map_err(|_| AppError::bad("Invalid WebAuthn origin"))?
            .rp_name("Oknef")
            .build()
            .map_err(|_| AppError::unavailable("WebAuthn unavailable"))?;
        Ok(Self {
            webauthn: Arc::new(webauthn),
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    fn insert(&self, user: Value, ceremony: Ceremony) -> AppResult<String> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| AppError::unavailable("WebAuthn unavailable"))?;
        pending.retain(|_, entry| entry.expires > now());
        if pending.len() >= 1000 {
            return Err(AppError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many passkey requests",
            ));
        }
        let id = Uuid::new_v4().to_string();
        pending.insert(
            id.clone(),
            Pending {
                user,
                expires: now() + 120,
                ceremony,
            },
        );
        Ok(id)
    }
    fn consume(&self, id: &str) -> AppResult<Pending> {
        let result = self
            .pending
            .lock()
            .map_err(|_| AppError::unavailable("WebAuthn unavailable"))?
            .remove(id)
            .ok_or_else(failed)?;
        if result.expires <= now() {
            return Err(failed());
        }
        Ok(result)
    }
}
fn failed() -> AppError {
    AppError::new(
        StatusCode::UNAUTHORIZED,
        "Passkey verification failed or expired",
    )
}
fn origin(app: &App, headers: &HeaderMap) -> AppResult<()> {
    if headers.get("origin").and_then(|h| h.to_str().ok()) != Some(app.config.origin.as_str()) {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            "Passkey origin is not permitted",
        ));
    }
    Ok(())
}
async fn stored(app: &App, user: &Value) -> AppResult<Vec<Value>> {
    Ok(app
        .db
        .records(records::tenant(user)?, "passkeys")
        .await?
        .into_iter()
        .filter(|record| record["user_id"] == user["id"])
        .collect())
}
fn keys(records: &[Value]) -> AppResult<Vec<Passkey>> {
    records
        .iter()
        .map(|record| {
            serde_json::from_value(record["passkey"].clone())
                .map_err(|_| AppError::unavailable("Invalid passkey record"))
        })
        .collect()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finish {
    challenge_id: String,
    credential: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    email: String,
}

pub async fn register_start(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    origin(&app, &headers)?;
    let user = auth::session(&app, &headers).await?;
    if user["demo"] == true {
        return Err(AppError::bad(
            "Create a personal account before enrolling a passkey",
        ));
    }
    app.limit(&format!("passkey-register:{}", user["id"]), 10, 300)?;
    let existing = keys(&stored(&app, &user).await?)?;
    if existing.len() >= 5 {
        return Err(AppError::bad("Maximum of five passkeys reached"));
    }
    let id = Uuid::parse_str(user["id"].as_str().ok_or_else(failed)?).map_err(|_| failed())?;
    let (options, state) = app
        .passkeys
        .webauthn
        .start_passkey_registration(
            id,
            user["email"].as_str().ok_or_else(failed)?,
            user["name"].as_str().ok_or_else(failed)?,
            Some(existing.iter().map(|key| key.cred_id().clone()).collect()),
        )
        .map_err(|_| failed())?;
    let challenge_id = app.passkeys.insert(user, Ceremony::Register(state))?;
    Ok(Json(json!({"challenge_id":challenge_id,"options":options})))
}
pub async fn register_finish(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Finish>,
) -> AppResult<Json<Value>> {
    origin(&app, &headers)?;
    let user = auth::session(&app, &headers).await?;
    let pending = app.passkeys.consume(&body.challenge_id)?;
    if pending.user["id"] != user["id"] || pending.user["tenant_id"] != user["tenant_id"] {
        return Err(failed());
    }
    let Ceremony::Register(state) = pending.ceremony else {
        return Err(failed());
    };
    let credential: RegisterPublicKeyCredential =
        serde_json::from_value(body.credential).map_err(|_| failed())?;
    let key = app
        .passkeys
        .webauthn
        .finish_passkey_registration(&credential, &state)
        .map_err(|_| failed())?;
    let id = Uuid::new_v4().to_string();
    let value = json!({"id":id,"user_id":user["id"],"passkey":key,"created_at":now()});
    app.db
        .save(records::tenant(&user)?, "passkeys", &id, &value)
        .await?;
    Ok(Json(json!({"registered":true})))
}
pub async fn login_start(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Login>,
) -> AppResult<Json<Value>> {
    origin(&app, &headers)?;
    if !valid_email(&body.email) {
        return Err(failed());
    }
    app.limit(
        &format!(
            "passkey-login:{}",
            auth::token_hash(&body.email.to_lowercase())
        ),
        8,
        300,
    )?;
    let user = app
        .db
        .identity(&body.email.to_lowercase())
        .await
        .map_err(|_| failed())?;
    let passkeys = keys(&stored(&app, &user).await?)?;
    if passkeys.is_empty() {
        return Err(failed());
    }
    let (options, state) = app
        .passkeys
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| failed())?;
    let challenge_id = app.passkeys.insert(user, Ceremony::Login(state))?;
    Ok(Json(json!({"challenge_id":challenge_id,"options":options})))
}
pub async fn login_finish(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Finish>,
) -> AppResult<Response> {
    origin(&app, &headers)?;
    let pending = app.passkeys.consume(&body.challenge_id)?;
    let Ceremony::Login(state) = pending.ceremony else {
        return Err(failed());
    };
    let credential: PublicKeyCredential =
        serde_json::from_value(body.credential).map_err(|_| failed())?;
    let result = app
        .passkeys
        .webauthn
        .finish_passkey_authentication(&credential, &state)
        .map_err(|_| failed())?;
    if !result.user_verified() {
        return Err(failed());
    }
    let mut updated = false;
    for mut record in stored(&app, &pending.user).await? {
        let mut key: Passkey =
            serde_json::from_value(record["passkey"].clone()).map_err(|_| failed())?;
        if key.cred_id() == result.cred_id() {
            key.update_credential(&result);
            record["passkey"] = serde_json::to_value(key).map_err(|_| failed())?;
            app.db
                .save(
                    records::tenant(&pending.user)?,
                    "passkeys",
                    record["id"].as_str().ok_or_else(failed)?,
                    &record,
                )
                .await?;
            updated = true;
        }
    }
    if !updated {
        return Err(failed());
    }
    let (cookie, user) = auth::create_session(&app, &pending.user).await?;
    let mut response = Json(json!({"user":user})).into_response();
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&cookie).map_err(|_| failed())?,
    );
    Ok(response)
}
#[cfg(test)]
#[path = "passkeys_tests.rs"]
mod tests;
