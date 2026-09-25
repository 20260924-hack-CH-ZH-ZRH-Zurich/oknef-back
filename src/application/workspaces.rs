use crate::{
    App, AppError, AppResult,
    application::{auth, records, security},
    domain::{now, valid_email},
};
use axum::http::StatusCode;
use reqwest::Method;
use serde_json::{Value, json};
use uuid::Uuid;

pub fn owner(user: &Value) -> AppResult<()> {
    if user["role"] != "owner" {
        return Err(AppError::new(StatusCode::FORBIDDEN, "Owner role required"));
    }
    Ok(())
}

pub async fn members(app: &App, user: &Value) -> AppResult<Vec<Value>> {
    if user["demo"] == true {
        return Ok(vec![auth::public_user(user)]);
    }
    let data = app
        .db
        .call(
            Method::GET,
            "/v1/members",
            Some(records::tenant(user)?),
            None,
        )
        .await?;
    Ok(data["members"]
        .as_array()
        .into_iter()
        .flatten()
        .map(auth::public_user)
        .collect())
}

pub async fn memberships(app: &App, user: &Value) -> AppResult<Vec<Value>> {
    if user["demo"] == true {
        return Ok(vec![user.clone()]);
    }
    let identity = app
        .db
        .identity(
            user["email"]
                .as_str()
                .ok_or_else(|| AppError::bad("Identity required"))?,
        )
        .await?;
    let mut result = vec![auth::public_user(&identity)];
    let data = app
        .db
        .call(
            Method::GET,
            &format!(
                "/v1/memberships/{}",
                user["id"].as_str().unwrap_or_default()
            ),
            None,
            None,
        )
        .await?;
    for member in data["memberships"].as_array().into_iter().flatten() {
        if member["id"] == user["id"]
            && !result.iter().any(|r| r["tenant_id"] == member["tenant_id"])
        {
            result.push(member.clone());
        }
    }
    Ok(result)
}

pub async fn list(app: &App, user: &Value) -> AppResult<Value> {
    let values:Vec<_>=memberships(app,user).await?.iter().map(|m|json!({"tenant_id":m["tenant_id"],
        "account_type":m["account_type"],"name":m.get("workspace_name").unwrap_or(&m["name"]),"role":m["role"]})).collect();
    Ok(json!({"workspaces":values,"current_tenant_id":user["tenant_id"]}))
}

pub async fn invitations(app: &App, user: &Value) -> AppResult<Value> {
    if user["demo"] == true {
        return Ok(json!({"incoming":[],"outgoing":[]}));
    }
    let email = user["email"]
        .as_str()
        .filter(|s| valid_email(s))
        .ok_or_else(|| AppError::bad("Identity email required"))?;
    let incoming = app
        .db
        .call(
            Method::GET,
            &format!("/v1/invitations/recipient/{email}"),
            None,
            None,
        )
        .await?;
    let outgoing = if user["role"] == "owner" {
        app.db
            .call(
                Method::GET,
                "/v1/invitations",
                Some(records::tenant(user)?),
                None,
            )
            .await?
    } else {
        json!({"invitations":[]})
    };
    Ok(json!({"incoming":incoming["invitations"],"outgoing":outgoing["invitations"]}))
}

pub async fn invite(app: &App, user: &Value, body: Value) -> AppResult<Value> {
    owner(user)?;
    security::fields(&body, &["email", "role", "recipient_user_id"])?;
    if user["demo"] == true
        || !["family", "company"]
            .iter()
            .any(|t| user["account_type"] == *t)
    {
        return Err(AppError::bad(
            "Create a real family or company account to invite registered users",
        ));
    }
    let email = security::text(&body, "email", 254)?.to_lowercase();
    if !valid_email(&email) || user["email"] == email {
        return Err(AppError::bad("Use another person's valid email"));
    }
    let role = security::text(&body, "role", 20)?;
    if !["member", "reviewer"].contains(&role) {
        return Err(AppError::bad("Invite as member or reviewer"));
    }
    app.limit(&format!("invite:{}", records::tenant(user)?), 20, 300)?;
    let recipient_id = security::text(&body, "recipient_user_id", 36)?;
    if Uuid::parse_str(recipient_id).is_err() {
        return Err(AppError::bad(
            "Provide the recipient's immutable account ID through a trusted channel",
        ));
    }
    let recipient = app.db.identity(&email).await.map_err(|error| {
        if error.status == StatusCode::NOT_FOUND {
            AppError::bad("Recipient account ID and email must match an existing account")
        } else {
            error
        }
    })?;
    if recipient["id"] != recipient_id {
        return Err(AppError::bad(
            "Recipient account ID and email must match an existing account",
        ));
    }
    ensure_not_invited(app, user, &email).await?;
    let value = json!({"id":Uuid::new_v4().to_string(),"email":email,"role":role,"recipient_user_id":recipient_id,"tenant_id":user["tenant_id"],
        "account_type":user["account_type"],"workspace_name":format!("{} · {}",user["name"].as_str().unwrap_or("Workspace"),user["account_type"].as_str().unwrap_or("family")),
        "inviter_name":user["name"],"status":"pending","created_at":now(),"expires_at":now()+7*86400,
        "delivery":"in_app","email_verified":false});
    app.db
        .call(
            Method::POST,
            "/v1/invitations",
            Some(records::tenant(user)?),
            Some(&value),
        )
        .await?;
    app.event(user, "workspace.invitation_created");
    Ok(value)
}

async fn ensure_not_invited(app: &App, user: &Value, email: &str) -> AppResult<()> {
    if members(app, user)
        .await?
        .iter()
        .any(|m| m["email"] == email)
    {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "This account is already a member",
        ));
    }
    let data = app
        .db
        .call(
            Method::GET,
            "/v1/invitations",
            Some(records::tenant(user)?),
            None,
        )
        .await?;
    if data["invitations"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|i| {
            i["email"] == email
                && i["status"] == "pending"
                && i["expires_at"].as_u64().unwrap_or(0) > now()
        })
    {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "A pending invitation already exists",
        ));
    }
    Ok(())
}

pub async fn accept(app: &App, user: &Value, id: &str) -> AppResult<Value> {
    if user["demo"] == true || Uuid::parse_str(id).is_err() {
        return Err(AppError::bad(
            "A registered recipient and valid invitation are required",
        ));
    }
    let value = app
        .db
        .call(
            Method::POST,
            &format!("/v1/invitations/{id}/accept"),
            None,
            Some(&json!({"email":user["email"],"user_id":user["id"]})),
        )
        .await?;
    app.event(user, "workspace.invitation_accepted");
    if let Some(member) = value.get("membership") {
        app.event(member, "workspace.member_joined");
    }
    Ok(value)
}
