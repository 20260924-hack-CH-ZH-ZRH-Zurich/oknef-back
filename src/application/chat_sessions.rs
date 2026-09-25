use crate::{
    App, AppError, AppResult,
    application::{records, security},
    domain::now,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub async fn create(app: &App, user: &Value, body: Value) -> AppResult<Value> {
    security::fields(&body, &["title"])?;
    let title = security::text(&body, "title", 160)?;
    let id = Uuid::new_v4().to_string();
    let value = json!({"id":id,"title":title,"created_at":now(),"created_by":user["id"],"synthetic":user["demo"]==true});
    app.db
        .create(records::tenant(user)?, "chat_sessions", &id, &value)
        .await
}

pub async fn get(app: &App, user: &Value, id: &str) -> AppResult<Value> {
    let mut value = records::find(app, user, "chat_sessions", id).await?;
    let mut messages: Vec<_> = app
        .db
        .records(records::tenant(user)?, "chat_messages")
        .await?
        .into_iter()
        .filter(|message| message["session_id"] == id)
        .collect();
    messages.sort_by_key(|message| {
        message["created_at_ms"]
            .as_u64()
            .unwrap_or_else(|| message["created_at"].as_u64().unwrap_or(0) * 1000)
    });
    value["messages"] = json!(messages);
    Ok(value)
}

pub async fn prepare(app: &App, user: &Value, body: &mut Value) -> AppResult<String> {
    let message = body["message"]
        .as_str()
        .filter(|s| !s.trim().is_empty() && s.len() <= 12000)
        .ok_or_else(|| AppError::bad("Message must contain 1-12000 bytes"))?
        .to_owned();
    let session_id = body
        .as_object_mut()
        .and_then(|body| body.remove("session_id"));
    let session = if let Some(id) = session_id {
        let id = id
            .as_str()
            .ok_or_else(|| AppError::bad("Session ID must be a UUID"))?;
        get(app, user, id).await?
    } else {
        let title: String = message.chars().take(80).collect();
        create(
            app,
            user,
            json!({"title":title.replace(['\n','\r','\t'], " ")}),
        )
        .await?
    };
    if let Some(messages) = session["messages"].as_array() {
        let mut history = Vec::new();
        for message in messages
            .iter()
            .rev()
            .take(6)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            if message["source"] == "realtime_transcript" {
                if let Some(text) = message["content"].as_str() {
                    let bounded: String = text.chars().take(1400).collect();
                    history.push(json!({"role":message["role"],"content":bounded}));
                }
                continue;
            }
            for (role, key) in [("user", "message"), ("assistant", "answer")] {
                if let Some(text) = message[key].as_str() {
                    let bounded: String = text.chars().take(1400).collect();
                    history.push(json!({"role":role,"content":bounded}));
                }
            }
        }
        body["history"] = json!(history);
    }
    Ok(session["id"].as_str().unwrap().to_owned())
}

pub async fn append(
    app: &App,
    user: &Value,
    session_id: &str,
    body: &Value,
    response: &Value,
) -> AppResult<()> {
    let id = Uuid::new_v4().to_string();
    let value = json!({"id":id,"session_id":session_id,"message":body["message"],"answer":response["answer"],
        "cards":response["cards"],"model":response["model"],"provider":response["provider"],"request_id":response["request_id"],
        "verification":response["verification"],"created_at":now(),"created_at_ms":timestamp_ms(),"created_by":user["id"],"synthetic":user["demo"]==true});
    app.db
        .create(records::tenant(user)?, "chat_messages", &id, &value)
        .await?;
    app.event(user, "chat.session_updated");
    Ok(())
}

fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub async fn transcript(app: &App, user: &Value, id: &str, body: Value) -> AppResult<Value> {
    security::fields(&body, &["role", "content", "source"])?;
    let content = body["content"]
        .as_str()
        .filter(|text| !text.trim().is_empty() && text.len() <= 12000)
        .ok_or_else(|| AppError::bad("Transcript must contain 1-12000 bytes"))?;
    let role = body["role"]
        .as_str()
        .filter(|role| ["user", "assistant"].contains(role))
        .ok_or_else(|| AppError::bad("Transcript role must be user or assistant"))?;
    if body["source"] != "realtime_transcript" {
        return Err(AppError::bad("Realtime transcript source required"));
    }
    records::find(app, user, "chat_sessions", id).await?;
    app.limit(&format!("transcript:{}", records::tenant(user)?), 120, 60)?;
    let message_id = Uuid::new_v4().to_string();
    let value = json!({"id":message_id,"session_id":id,"role":role,"content":content,"source":"realtime_transcript","created_at":now(),"created_at_ms":timestamp_ms(),
        "created_by":user["id"],"synthetic":user["demo"]==true,"provenance":"client_reported_realtime_transcript","provider_attested":false});
    app.db
        .create(records::tenant(user)?, "chat_messages", &message_id, &value)
        .await?;
    app.event(user, "chat.session_updated");
    Ok(value)
}
