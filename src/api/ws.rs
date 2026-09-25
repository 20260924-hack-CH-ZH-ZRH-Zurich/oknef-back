use crate::{App, AppResult, application::auth};
use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::HeaderMap,
    response::Response,
};
use serde_json::{Value, json};
pub async fn upgrade(
    State(app): State<App>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> AppResult<Response> {
    let user = auth::session(&app, &headers).await?;
    Ok(ws
        .max_message_size(4096)
        .on_upgrade(move |socket| run(socket, app, user, headers)))
}
async fn run(mut socket: WebSocket, app: App, user: Value, headers: HeaderMap) {
    let mut events = app.events.subscribe();
    let mut check = tokio::time::interval(std::time::Duration::from_secs(30));
    let _ = socket
        .send(Message::Text(
            json!({"type":"connected","authenticated":true})
                .to_string()
                .into(),
        ))
        .await;
    loop {
        tokio::select! {
            _=check.tick()=>{if auth::session(&app,&headers).await.is_err(){let _=socket.send(Message::Close(None)).await;break;}}
            incoming=socket.recv()=>{match incoming{
                Some(Ok(Message::Text(text)))=>{
                    let value=serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
                    let reply=if value["type"]=="ping"{json!({"type":"pong"})}else{json!({"type":"error","error":"Only ping is accepted; authenticated HTTP APIs own mutations"})};
                    if socket.send(Message::Text(reply.to_string().into())).await.is_err(){break;}
                },Some(Ok(Message::Ping(data)))=>{if socket.send(Message::Pong(data)).await.is_err(){break;}},Some(Ok(Message::Close(_)))|None|Some(Err(_))=>break,_=>{}
            }}
            event=events.recv()=>{match event{
                Ok(event) if event["tenant_id"]==user["tenant_id"]=>{let public=json!({"type":event["type"],"timestamp":event["timestamp"]});if socket.send(Message::Text(public.to_string().into())).await.is_err(){break;}},
                Err(tokio::sync::broadcast::error::RecvError::Closed)=>break,_=>{}
            }}
        }
    }
}
