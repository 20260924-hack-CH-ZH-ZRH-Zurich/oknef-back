use crate::{
    App, AppError, AppResult,
    application::{records, security},
    domain::now,
};
use serde_json::{Value, json};

pub fn policy(mode: &str) -> Value {
    json!({"mode":mode,"speaker_verification_available":false,"deepfake_detection_available":false,
        "session_allowed":mode=="authenticated_session","authority":"signed_in_session",
        "effect":if mode=="trusted_only" {"Voice is blocked until an independently validated speaker and anti-spoofing verifier is connected."} else {"The signed-in user may start voice. Nearby speakers may be heard; no speaker identity is inferred."}})
}

pub async fn get(app: &App, user: &Value) -> AppResult<Value> {
    Ok(app
        .db
        .records(records::tenant(user)?, "voice_policy")
        .await?
        .into_iter()
        .next()
        .unwrap_or_else(|| policy("authenticated_session")))
}

pub async fn set(app: &App, user: &Value, body: Value) -> AppResult<Value> {
    security::fields(&body, &["mode"])?;
    let mode = security::text(&body, "mode", 40)?;
    if !["authenticated_session", "trusted_only"].contains(&mode) {
        return Err(AppError::bad(
            "Choose authenticated_session or trusted_only",
        ));
    }
    if user["role"] != "owner" {
        return Err(AppError::new(
            axum::http::StatusCode::FORBIDDEN,
            "Owner role required",
        ));
    }
    let mut value = policy(mode);
    value["updated_at"] = json!(now());
    app.db
        .save(records::tenant(user)?, "voice_policy", "current", &value)
        .await?;
    app.event(user, "voice.policy_changed");
    Ok(value)
}

pub async fn enforce(app: &App, user: &Value) -> AppResult<()> {
    if get(app, user).await?["session_allowed"] != true {
        return Err(AppError::new(
            axum::http::StatusCode::FORBIDDEN,
            "Trusted-only voice requires a validated speaker and anti-spoofing verifier. Voice remains blocked.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unavailable_biometrics_fail_closed() {
        assert_eq!(policy("trusted_only")["session_allowed"], false);
        assert_eq!(policy("unknown")["session_allowed"], false);
        assert_eq!(
            policy("authenticated_session")["speaker_verification_available"],
            false
        );
    }
}
