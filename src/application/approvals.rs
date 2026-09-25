use crate::{
    App, AppError, AppResult,
    application::{records, security, workspaces},
    domain::{now, security::approval_status},
};
use axum::http::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

fn reviewers(body: &Value, user: &Value) -> AppResult<(Vec<String>, u64)> {
    let ids: Vec<String> = body["reviewer_ids"]
        .as_array()
        .filter(|v| (2..=10).contains(&v.len()))
        .ok_or_else(|| AppError::bad("Select 2-10 different accepted members"))?
        .iter()
        .map(|id| {
            id.as_str()
                .filter(|s| Uuid::parse_str(s).is_ok())
                .map(str::to_owned)
                .ok_or_else(|| AppError::bad("Invalid reviewer ID"))
        })
        .collect::<AppResult<_>>()?;
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    let required = body["required_approvals"]
        .as_u64()
        .filter(|r| *r >= 2 && *r <= ids.len() as u64)
        .ok_or_else(|| {
            AppError::bad("Require at least two approvals, up to the number of reviewers")
        })?;
    if unique.len() != ids.len() || ids.iter().any(|id| user["id"] == *id) {
        return Err(AppError::bad(
            "Reviewers must be unique and independent of the policy owner",
        ));
    }
    Ok((ids, required))
}

pub async fn policy(app: &App, user: &Value, body: Value) -> AppResult<Value> {
    workspaces::owner(user)?;
    security::fields(&body, &["title", "reviewer_ids", "required_approvals"])?;
    let title = security::text(&body, "title", 160)?;
    let (ids, required) = reviewers(&body, user)?;
    let members = workspaces::members(app, user).await?;
    if ids.iter().any(|id| !members.iter().any(|m| m["id"] == *id)) {
        return Err(AppError::bad(
            "Every reviewer must be an accepted member of this workspace",
        ));
    }
    let id = Uuid::new_v4().to_string();
    let value = json!({"id":id,"title":title,"reviewer_ids":ids,"required_approvals":required,"created_at":now(),
        "created_by":user["id"],"execution_enabled":false});
    app.db
        .create(records::tenant(user)?, "approval_policies", &id, &value)
        .await?;
    app.event(user, "approval.policy_created");
    Ok(value)
}

pub async fn request(app: &App, user: &Value, body: Value) -> AppResult<Value> {
    security::fields(&body, &["policy_id", "title", "description"])?;
    let policy_id = security::text(&body, "policy_id", 50)?;
    let policy = records::find(app, user, "approval_policies", policy_id).await?;
    let title = security::text(&body, "title", 160)?;
    let description = security::text(&body, "description", 4000)?;
    if policy["reviewer_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|id| id == &user["id"])
    {
        return Err(AppError::bad(
            "A requester cannot be a reviewer for their own request",
        ));
    }
    let id = Uuid::new_v4().to_string();
    let value = json!({"id":id,"title":title,"description":description,"policy_id":policy_id,"reviewer_ids":policy["reviewer_ids"],
        "required_approvals":policy["required_approvals"],"created_by":user["id"],"created_at":now(),"status":"pending","votes":[],
        "execution_enabled":false,"scope":"recorded_human_decision_only"});
    app.db
        .create(records::tenant(user)?, "approval_requests", &id, &value)
        .await?;
    app.event(user, "approval.requested");
    Ok(value)
}

fn attach_votes(mut request: Value, votes: &[Value]) -> Value {
    let items: Vec<_> = votes
        .iter()
        .filter(|v| {
            v["request_id"] == request["id"]
                && request["reviewer_ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|id| id == &v["reviewer_id"])
        })
        .cloned()
        .collect();
    let approvals = items.iter().filter(|v| v["decision"] == "approve").count();
    let rejections = items.iter().filter(|v| v["decision"] == "reject").count();
    request["status"] = json!(approval_status(
        approvals,
        rejections,
        request["required_approvals"].as_u64().unwrap_or(u64::MAX) as usize
    ));
    request["votes"] = json!(items);
    request
}

pub async fn list(app: &App, user: &Value) -> AppResult<Value> {
    let tenant = records::tenant(user)?;
    let policies = app.db.records(tenant, "approval_policies").await?;
    let votes = app.db.records(tenant, "approval_votes").await?;
    let requests: Vec<_> = app
        .db
        .records(tenant, "approval_requests")
        .await?
        .into_iter()
        .map(|r| attach_votes(r, &votes))
        .collect();
    Ok(
        json!({"policies":policies,"requests":requests,"members":workspaces::members(app,user).await?}),
    )
}

pub async fn vote(app: &App, user: &Value, id: &str, body: Value) -> AppResult<Value> {
    security::fields(&body, &["decision"])?;
    let decision = security::text(&body, "decision", 10)?;
    if !["approve", "reject"].contains(&decision) {
        return Err(AppError::bad("Choose approve or reject"));
    }
    let request = records::find(app, user, "approval_requests", id).await?;
    authorize_vote(&request, user)?;
    let vote_id = format!("{id}:{}", user["id"].as_str().unwrap_or_default());
    let value = json!({"id":vote_id,"request_id":id,"reviewer_id":user["id"],"reviewer_name":user["name"],"decision":decision,"created_at":now()});
    app.db
        .create(records::tenant(user)?, "approval_votes", &vote_id, &value)
        .await
        .map_err(|e| {
            if e.status == StatusCode::CONFLICT {
                AppError::new(
                    StatusCode::CONFLICT,
                    "Your decision is already recorded and cannot be overwritten",
                )
            } else {
                e
            }
        })?;
    app.event(user, "approval.vote_recorded");
    Ok(attach_votes(
        request,
        &app.db
            .records(records::tenant(user)?, "approval_votes")
            .await?,
    ))
}

fn authorize_vote(request: &Value, user: &Value) -> AppResult<()> {
    if request["created_by"] == user["id"]
        || !request["reviewer_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|id| id == &user["id"])
    {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            "Only a named independent reviewer can record this decision",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_fake_reviewer_and_requester_bypass() {
        let request = json!({"created_by":"owner","reviewer_ids":["reviewer-a","reviewer-b"]});
        assert!(authorize_vote(&request, &json!({"id":"owner"})).is_err());
        assert!(authorize_vote(&request, &json!({"id":"intruder"})).is_err());
        assert!(authorize_vote(&request, &json!({"id":"reviewer-a"})).is_ok());
    }
    #[test]
    fn two_unique_eligible_reviewers_required() {
        let a = Uuid::new_v4().to_string();
        let b = Uuid::new_v4().to_string();
        let user = json!({"id":Uuid::new_v4().to_string()});
        assert!(reviewers(&json!({"reviewer_ids":[a,a],"required_approvals":2}), &user).is_err());
        assert!(reviewers(&json!({"reviewer_ids":[a,b],"required_approvals":1}), &user).is_err());
    }
}
