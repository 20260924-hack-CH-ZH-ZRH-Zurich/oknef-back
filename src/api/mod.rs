pub mod agents;
pub mod ai;
pub mod approvals;
pub mod auth;
pub mod capture;
pub mod drive;
pub mod records;
pub mod security;
pub mod vault;
pub mod workspace_data;
pub mod workspaces;
pub mod ws;
use crate::App;
use axum::{
    Router,
    routing::{delete, get, patch, post},
};
pub fn routes() -> Router<App> {
    Router::new()
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/register", post(auth::register))
        .route("/api/auth/demo", post(auth::demo))
        .route("/api/auth/me", get(auth::me))
        .route("/api/auth/logout", post(auth::logout))
        .route(
            "/api/assets",
            get(records::assets).post(records::create_asset),
        )
        .route(
            "/api/assets/{id}",
            patch(records::patch_asset).delete(records::delete_asset),
        )
        .route(
            "/api/succession",
            get(records::plans).post(records::create_plan),
        )
        .route("/api/succession/{id}/review", post(records::review))
        .route("/api/succession/{id}/cancel", post(records::cancel))
        .route("/api/dashboard", get(records::dashboard))
        .route("/api/members", get(records::members))
        .route("/api/security/overview", get(security::overview))
        .route(
            "/api/security/sessions",
            get(security::sessions).post(security::create),
        )
        .route("/api/security/sessions/{id}", get(security::get))
        .route("/api/security/sessions/capture", post(capture::create))
        .route(
            "/api/security/sessions/{id}/questions",
            post(security::question),
        )
        .route("/api/security/mode", axum::routing::put(security::mode))
        .route("/api/security/simulations", post(security::simulate))
        .route("/api/workspaces", get(workspaces::list))
        .route("/api/workspaces/switch", post(workspaces::switch))
        .route(
            "/api/invitations",
            get(workspaces::invitations).post(workspaces::invite),
        )
        .route("/api/invitations/{id}/accept", post(workspaces::accept))
        .route("/api/approvals", get(approvals::list))
        .route("/api/approvals/policies", post(approvals::policy))
        .route("/api/approvals/requests", post(approvals::request))
        .route("/api/approvals/requests/{id}/votes", post(approvals::vote))
        .route("/api/models", get(ai::models))
        .route("/api/chat", post(ai::chat))
        .route(
            "/api/chat/sessions",
            get(workspace_data::chats).post(workspace_data::create_chat),
        )
        .route("/api/chat/sessions/{id}", get(workspace_data::chat))
        .route(
            "/api/chat/sessions/{id}/messages",
            post(workspace_data::transcript),
        )
        .route(
            "/api/integrations",
            get(workspace_data::integrations).post(workspace_data::create_integration),
        )
        .route(
            "/api/integrations/{id}",
            delete(workspace_data::delete_integration),
        )
        .route("/api/graph", get(workspace_data::graph))
        .route(
            "/api/voice/policy",
            get(workspace_data::voice_policy).put(workspace_data::set_voice_policy),
        )
        .route("/api/chat/image", post(ai::image))
        .route("/api/voice/session", post(ai::voice_session))
        .route("/api/voice/call", post(ai::voice_call))
        .route("/api/transcribe", post(ai::transcribe))
        .route("/api/ws", get(ws::upgrade))
        .route("/api/vault", get(vault::list).post(vault::create))
        .route("/api/vault/{id}", delete(vault::delete))
        .route("/api/drive", get(drive::list).post(drive::upload))
        .route("/api/drive/{id}", delete(drive::delete))
        .route("/api/workflows", post(agents::workflows))
        .route("/api/workflows/runs", get(workspace_data::workflow_runs))
        .route("/api/agents/catalog", get(agents::agent_catalog))
        .route("/api/ocr", post(ai::ocr))
        .route("/api/media/analyze", post(ai::media_analyze))
        .route(
            "/api/passkeys/register/start",
            post(crate::application::passkeys::register_start),
        )
        .route(
            "/api/passkeys/register/finish",
            post(crate::application::passkeys::register_finish),
        )
        .route(
            "/api/passkeys/login/start",
            post(crate::application::passkeys::login_start),
        )
        .route(
            "/api/passkeys/login/finish",
            post(crate::application::passkeys::login_finish),
        )
}
