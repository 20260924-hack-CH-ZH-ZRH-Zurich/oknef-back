use crate::{
    App, AppError, AppResult,
    domain::{now, valid_email, valid_name},
};
use argon2::{
    Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version,
    password_hash::{PasswordHash, SaltString, rand_core::OsRng},
};
use axum::http::{HeaderMap, StatusCode};
use reqwest::Method;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn public_user(value: &Value) -> Value {
    json!({"id":value["id"],"name":value["name"],"email":value["email"],"tenant_id":value["tenant_id"],"account_type":value["account_type"],"role":value["role"],"demo":value["demo"],"demo_profile":value["demo_profile"]})
}
fn argon() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 1, None).expect("valid Argon2 parameters"),
    )
}
pub async fn password_hash(password: String) -> AppResult<String> {
    tokio::task::spawn_blocking(move || {
        argon()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .map(|h| h.to_string())
    })
    .await
    .map_err(|_| AppError::unavailable("Password processing failed"))?
    .map_err(|_| AppError::unavailable("Password processing failed"))
}
async fn verify_password(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash)
            .is_ok_and(|h| argon().verify_password(password.as_bytes(), &h).is_ok())
    })
    .await
    .unwrap_or(false)
}
pub fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}
pub fn token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(';')
                .find_map(|pair| pair.trim().strip_prefix("oknef_session="))
        })
        .filter(|v| v.len() == 64)
        .map(str::to_owned)
}
pub async fn session(app: &App, headers: &HeaderMap) -> AppResult<Value> {
    let token =
        token(headers).ok_or_else(|| AppError::new(StatusCode::UNAUTHORIZED, "Please sign in"))?;
    let session = app
        .db
        .call(
            Method::GET,
            &format!("/v1/sessions/{}", token_hash(&token)),
            None,
            None,
        )
        .await
        .map_err(|e| {
            if e.status == StatusCode::NOT_FOUND {
                AppError::new(StatusCode::UNAUTHORIZED, "Session expired")
            } else {
                e
            }
        })?;
    if session["expires_at"].as_u64().unwrap_or(0) <= now() {
        return Err(AppError::new(StatusCode::UNAUTHORIZED, "Session expired"));
    }
    Ok(session["user"].clone())
}
pub async fn create_session(app: &App, user: &Value) -> AppResult<(String, Value)> {
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let public = public_user(user);
    let value = json!({"user":public,"expires_at":now()+3600});
    app.db
        .call(
            Method::PUT,
            &format!("/v1/sessions/{}", token_hash(&token)),
            None,
            Some(&value),
        )
        .await?;
    let secure = if app.config.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    Ok((
        format!("oknef_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600{secure}"),
        public,
    ))
}
pub async fn register(
    app: &App,
    name: String,
    email: String,
    password: String,
    account_type: String,
) -> AppResult<Value> {
    if !valid_name(&name, 100)
        || !valid_email(&email)
        || !(12..=128).contains(&password.len())
        || !["personal", "family", "company"].contains(&account_type.as_str())
    {
        return Err(AppError::bad(
            "Use a valid name, email, 12-128 character password and account type",
        ));
    }
    let hash = password_hash(password).await?;
    let user = json!({"id":Uuid::new_v4().to_string(),"tenant_id":Uuid::new_v4().to_string(),"name":name.trim(),"email":email.to_lowercase(),
        "account_type":account_type,"role":"owner","demo":false,"password_hash":hash});
    app.db
        .call(Method::POST, "/v1/identities", None, Some(&user))
        .await
        .map_err(|e| {
            if e.status == StatusCode::CONFLICT {
                AppError::new(StatusCode::CONFLICT, "An account already uses this email")
            } else {
                e
            }
        })?;
    Ok(user)
}
pub async fn login(app: &App, email: String, password: String) -> AppResult<Value> {
    if !valid_email(&email) || password.len() > 128 {
        return Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            "Invalid email or password",
        ));
    }
    if app.config.demo_enabled
        && email.to_lowercase() == app.config.demo_email
        && password == app.config.demo_password
    {
        return demo(app).await;
    }
    let user = app
        .db
        .identity(&email.to_lowercase())
        .await
        .map_err(|_| AppError::new(StatusCode::UNAUTHORIZED, "Invalid email or password"))?;
    if !verify_password(
        password,
        user["password_hash"].as_str().unwrap_or("").into(),
    )
    .await
    {
        return Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            "Invalid email or password",
        ));
    }
    Ok(user)
}
pub async fn demo(app: &App) -> AppResult<Value> {
    demo_profile(app, "personal").await
}
pub async fn demo_profile(app: &App, mode: &str) -> AppResult<Value> {
    if !app.config.demo_enabled {
        return Err(AppError::new(StatusCode::NOT_FOUND, "Demo unavailable"));
    }
    if !["personal", "company", "admin"].contains(&mode) {
        return Err(AppError::bad("Choose personal, company, or admin demo"));
    }
    let account_type = if mode == "personal" {
        "personal"
    } else {
        "company"
    };
    let name = match mode {
        "company" => "Alex · Company workspace",
        "admin" => "Alex · Oknef demo administrator",
        _ => "Alex Morgan",
    };
    let user = json!({"id":Uuid::new_v4().to_string(),"tenant_id":Uuid::new_v4().to_string(),"name":name,"email":"demo@oknef.com","account_type":account_type,"role":"owner","demo":true,"demo_profile":mode});
    for (name, category, institution, value, beneficiary) in [
        (
            "Family savings",
            "banking",
            "Example Swiss Bank",
            42000.0,
            "Jamie Morgan",
        ),
        ("Photo archive", "digital", "Example Cloud", 0.0, "Family"),
        (
            "Pension documents",
            "documents",
            "Example Pension",
            85000.0,
            "Jamie Morgan",
        ),
    ] {
        let id = Uuid::new_v4().to_string();
        let asset = json!({"id":id,"name":name,"category":category,"institution":institution,"value":value,"currency":"CHF","notes":"Synthetic demonstration metadata. Not a verified holding.","beneficiary":beneficiary,"created_at":now(),"updated_at":now()});
        app.db
            .save(user["tenant_id"].as_str().unwrap(), "assets", &id, &asset)
            .await?;
    }
    Ok(user)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn argon2_verifies_and_rejects_wrong_password() {
        let hash = password_hash("a-long-test-password".into()).await.unwrap();
        assert!(hash.contains("m=65536,t=3,p=1"));
        assert!(verify_password("a-long-test-password".into(), hash.clone()).await);
        assert!(!verify_password("wrong".into(), hash).await);
    }
    #[test]
    fn session_hash_never_retains_token() {
        let token = "0123456789";
        assert_ne!(token_hash(token), token);
        assert_eq!(token_hash(token).len(), 64);
    }
}
